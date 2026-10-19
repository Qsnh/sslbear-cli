import { describe, expect, it } from "vitest";
import { huaweiDns } from "../src/dns/huawei.js";
import type { DnsZone, TxtRecord } from "../src/dns/types.js";
import type { AccessKeyCredentials } from "../src/lib/env.js";
import { CloudApiError, type Fetch, type QueryContext } from "../src/lib/http.js";
import { apigAuthorization } from "../src/providers/huawei/sign.js";
import { fakeFetch, type FakeReply, type FakeRequest } from "./helpers.js";

const CREDS: AccessKeyCredentials = { accessKeyId: "HWtestak000000000000", secretAccessKey: "testsk" };
const ctxOf = (fetch: Fetch, sleeps: number[] = []): QueryContext => ({
  env: {},
  fetch,
  now: new Date("2026-10-18T00:00:00Z"),
  timeoutMs: 1000,
  sleep: async (ms) => void sleeps.push(ms),
});

const DNS_HOST = "dns.cn-north-4.myhuaweicloud.com";
// 云解析的业务错误体是 {code, message}；API 网关的是 {error_code, error_msg, request_id}
const dnsError = (status: number, code: string, message = code): FakeReply => ({ status, body: { code, message } });
const apigError = (status: number, code: string, msg = code): FakeReply => ({ status, body: { error_code: code, error_msg: msg, request_id: `rid-${code}` } });

/** IAM 查项目（取 cn-north-4 的系统项目，子项目不算）+ 云解析；其余返回 404 */
const hw = (route: (req: FakeRequest, q: Record<string, string>) => FakeReply) =>
  fakeFetch((req) => {
    if (req.url.host === "iam.myhuaweicloud.com" && req.url.pathname === "/v3/auth/projects") {
      return { body: { projects: [{ id: "p-bj4-sub", name: "cn-north-4_sub" }, { id: "p-bj4", name: "cn-north-4" }, { id: "p-sh1", name: "cn-east-3" }] } };
    }
    return req.url.host === DNS_HOST ? route(req, Object.fromEntries(req.url.searchParams)) : undefined;
  });
const dnsCalls = (fetch: { calls: FakeRequest[] }) => fetch.calls.filter((c) => c.url.host === DNS_HOST);
const brief = (c: FakeRequest) => `${c.method} ${c.url.pathname}`;

const VALUE = "v".repeat(43);
const OTHER = "w".repeat(43);
const ZONE: DnsZone = { name: "example.com", id: "zone-1" };
const rec = (fqdn: string, zone: DnsZone = ZONE, value = VALUE): TxtRecord => ({ zone, fqdn, value });
const SETS = "/v2.1/zones/zone-1/recordsets";
const set = (id: string, records: string[], extra: Record<string, unknown> = {}) => ({
  id,
  name: "_acme-challenge.example.com.",
  type: "TXT",
  records,
  ttl: 300,
  status: "ACTIVE",
  line: "default_view",
  zone_id: "zone-1",
  ...extra,
});
const listed = (recordsets: unknown[]): FakeReply => ({ body: { recordsets, metadata: { total_count: recordsets.length } } });

describe("华为云云解析 listZones", () => {
  it("GET /v2/zones?type=public 按 offset 翻页；只要正常 / 更新中的，域名去结尾点，中文域名转 punycode 并保留原名；带 X-Project-Id", async () => {
    const fetch = hw((req, q) => {
      if (req.url.pathname !== "/v2/zones") return undefined;
      if (q.offset === "0") {
        return {
          body: {
            zones: [
              { id: "z1", name: "Example.COM.", status: "ACTIVE", zone_type: "public" },
              { id: "z2", name: "例子.中国.", status: "PENDING_UPDATE", zone_type: "public" },
              { id: "z3", name: "paused.com.", status: "DISABLE", zone_type: "public" },
            ],
            metadata: { total_count: 5 },
          },
        };
      }
      return {
        body: {
          zones: [
            { id: "z4", name: "frozen.com.", status: "FREEZE" },
            { id: "z5", name: "sub.example.org.", status: "ACTIVE" },
          ],
          metadata: { total_count: 5 },
        },
      };
    });
    expect(await huaweiDns.listZones(ctxOf(fetch), CREDS)).toEqual([
      { name: "example.com", id: "z1" },
      { name: "xn--fsqu00a.xn--fiqs8s", id: "z2", extra: { apiName: "例子.中国" } },
      { name: "sub.example.org", id: "z5" },
    ]);
    const calls = dnsCalls(fetch);
    expect(calls.map((c) => Object.fromEntries(c.url.searchParams))).toEqual([
      { type: "public", limit: "500", offset: "0" },
      { type: "public", limit: "500", offset: "3" },
    ]);
    // 项目 ID 只查一次（一次命令内缓存）
    expect(fetch.calls.filter((c) => c.url.host === "iam.myhuaweicloud.com")).toHaveLength(1);
    const call = calls[0]!;
    expect(call.method).toBe("GET");
    expect(call.headers["x-project-id"]).toBe("p-bj4");
    expect(call.headers.authorization).toBe(
      apigAuthorization({
        accessKeyId: CREDS.accessKeyId,
        secretAccessKey: CREDS.secretAccessKey,
        method: "GET",
        path: call.url.pathname,
        query: Object.fromEntries(call.url.searchParams),
        headers: { Host: call.url.host, "X-Sdk-Date": call.headers["x-sdk-date"]!, "X-Project-Id": "p-bj4" },
      }),
    );
  });

  it("获取锁失败（DNS.0021，HTTP 500）与网关限流（APIGW.0308，HTTP 429）自动重试；其他错误抛 CloudApiError", async () => {
    let n = 0;
    const retried = hw(() => {
      n++;
      if (n === 1) return dnsError(500, "DNS.0021", "Could not acquire the lock, please try again later.");
      if (n === 2) return apigError(429, "APIGW.0308", "The throttling threshold has been reached");
      return { body: { zones: [], metadata: { total_count: 0 } } };
    });
    expect(await huaweiDns.listZones(ctxOf(retried), CREDS)).toEqual([]);
    expect(dnsCalls(retried)).toHaveLength(3);

    const denied = hw(() => apigError(403, "APIGW.0302", "The IAM user is not authorized"));
    const err = await huaweiDns.listZones(ctxOf(denied), CREDS).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CloudApiError);
    expect(err).toMatchObject({ provider: "huawei", code: "APIGW.0302", requestId: "rid-APIGW.0302", httpStatus: 403 });
  });

  it("NS 主机名规则覆盖 .com / .cn / .net / .org", () => {
    for (const ns of ["ns1.huaweicloud-dns.com", "ns1.huaweicloud-dns.cn", "ns1.huaweicloud-dns.net", "ns1.huaweicloud-dns.org"]) {
      expect(huaweiDns.nameServerPattern.test(ns)).toBe(true);
    }
    expect(huaweiDns.nameServerPattern.test("ns1.huaweicloud.com")).toBe(false);
  });
});

describe("华为云云解析 addTxt", () => {
  it("没有同名记录集：POST v2.1 新建，值带双引号、默认线路、TTL 1；查询按名字（不带结尾点）+ 类型", async () => {
    const fetch = hw((req) => {
      if (req.method === "GET" && req.url.pathname === SETS) return listed([]);
      if (req.method === "POST" && req.url.pathname === SETS) return { status: 202, body: { id: "rs-new", status: "PENDING_CREATE" } };
      return undefined;
    });
    expect(await huaweiDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).toBe("rs-new");
    const [list, create] = dnsCalls(fetch) as [FakeRequest, FakeRequest];
    expect(Object.fromEntries(list.url.searchParams)).toEqual({ type: "TXT", name: "_acme-challenge.example.com", limit: "500", offset: "0" });
    expect(create.json).toEqual({ name: "_acme-challenge.example.com.", type: "TXT", records: [`"${VALUE}"`], ttl: 1, line: "default_view" });
    expect(create.headers["x-project-id"]).toBe("p-bj4");
  });

  it("同名记录集已有其他值：PUT 写回原有的值 + 这次的值，name / type 原样回填，不改 TTL", async () => {
    const fetch = hw((req) => {
      if (req.method === "GET") return listed([set("rs1", [`"${OTHER}"`, '"v=spf1 -all"'])]);
      if (req.method === "PUT") return { status: 202, body: { id: "rs1", status: "PENDING_UPDATE" } };
      return undefined;
    });
    expect(await huaweiDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).toBe("rs1");
    const put = dnsCalls(fetch).find((c) => c.method === "PUT")!;
    expect(put.url.pathname).toBe(`${SETS}/rs1`);
    expect(put.json).toEqual({ name: "_acme-challenge.example.com.", type: "TXT", records: [`"${OTHER}"`, '"v=spf1 -all"', `"${VALUE}"`] });
  });

  it("同名同值已存在：不写，返回记录集 ID；名字相近的、其他线路的记录集不算", async () => {
    const fetch = hw((req) =>
      req.method === "GET"
        ? listed([
            set("rs-x", [`"${VALUE}"`], { name: "x._acme-challenge.example.com." }),
            set("rs-ct", [`"${VALUE}"`], { line: "Dianxin" }),
            set("rs1", [`"${OTHER}"`, `"${VALUE}"`]),
          ])
        : undefined,
    );
    expect(await huaweiDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).toBe("rs1");
    expect(dnsCalls(fetch).map(brief)).toEqual([`GET ${SETS}`]);
  });

  it("只有其他线路的同名记录集时新建默认线路的", async () => {
    const fetch = hw((req) => {
      if (req.method === "GET") return listed([set("rs-ct", [`"${OTHER}"`], { line: "Dianxin" })]);
      if (req.method === "POST") return { status: 202, body: { id: "rs-default" } };
      return undefined;
    });
    expect(await huaweiDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).toBe("rs-default");
  });

  it("记录集还在 PENDING_CREATE（刚加了另一个值）：每 2 秒重查，稳定后再追加", async () => {
    let reads = 0;
    const sleeps: number[] = [];
    const fetch = hw((req) => {
      if (req.method === "GET") return listed([set("rs1", [`"${OTHER}"`], { status: ++reads < 3 ? "PENDING_CREATE" : "ACTIVE" })]);
      if (req.method === "PUT") return { status: 202, body: { id: "rs1" } };
      return undefined;
    });
    expect(await huaweiDns.addTxt(ctxOf(fetch, sleeps), CREDS, rec("_acme-challenge.example.com"))).toBe("rs1");
    expect(sleeps).toEqual([2000, 2000]);
    expect(dnsCalls(fetch).map(brief)).toEqual([`GET ${SETS}`, `GET ${SETS}`, `GET ${SETS}`, `PUT ${SETS}/rs1`]);
  });

  it("记录集一直不稳定：等 30 秒后报 RecordSetNotSteady，不写", async () => {
    const sleeps: number[] = [];
    const fetch = hw((req) => (req.method === "GET" ? listed([set("rs1", [`"${OTHER}"`], { status: "PENDING_UPDATE" })]) : undefined));
    await expect(huaweiDns.addTxt(ctxOf(fetch, sleeps), CREDS, rec("_acme-challenge.example.com"))).rejects.toMatchObject({ code: "RecordSetNotSteady" });
    expect(sleeps).toHaveLength(15);
    expect(dnsCalls(fetch).every((c) => c.method === "GET")).toBe(true);
  });

  it("新建时记录集已存在（DNS.0312）：重新查出来按追加处理", async () => {
    let reads = 0;
    const fetch = hw((req) => {
      if (req.method === "GET") return listed(reads++ === 0 ? [] : [set("rs1", [`"${OTHER}"`])]);
      if (req.method === "POST") return dnsError(400, "DNS.0312", "This record set name already exists.");
      if (req.method === "PUT") return { status: 202, body: { id: "rs1" } };
      return undefined;
    });
    expect(await huaweiDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).toBe("rs1");
    expect(dnsCalls(fetch).map(brief)).toEqual([`GET ${SETS}`, `POST ${SETS}`, `GET ${SETS}`, `PUT ${SETS}/rs1`]);
  });

  it("冲突（DNS.0016）且查不到同名 TXT 记录集（如同名 CNAME）：错误码不变，信息里点明 CNAME 冲突", async () => {
    const fetch = hw((req) => (req.method === "GET" ? listed([]) : dnsError(400, "DNS.0016", "This record already exists or conflicts with another record.")));
    const err = await huaweiDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com")).catch((e: unknown) => e);
    expect(err).toMatchObject({ provider: "huawei", code: "DNS.0016", httpStatus: 400 });
    expect((err as Error).message).toMatch(/CNAME/);
  });

  it("记录集名称已存在（DNS.0312）却查不到：原样报错", async () => {
    const fetch = hw((req) => (req.method === "GET" ? listed([]) : dnsError(400, "DNS.0312", "This record set name already exists.")));
    await expect(huaweiDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).rejects.toMatchObject({
      code: "DNS.0312",
      message: "This record set name already exists.",
    });
  });

  it("同名记录集已暂停（DISABLE）：报 RecordSetNotActive，不写", async () => {
    const fetch = hw((req) => (req.method === "GET" ? listed([set("rs1", [`"${OTHER}"`], { status: "DISABLE" })]) : undefined));
    await expect(huaweiDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).rejects.toMatchObject({ code: "RecordSetNotActive" });
    expect(dnsCalls(fetch).map((c) => c.method)).toEqual(["GET"]);
  });

  it("PUT 超时后整体重来：重新读到值已经在了，不再写", async () => {
    let written = false;
    const fetch = hw((req) => {
      if (req.method === "GET") return listed([set("rs1", written ? [`"${OTHER}"`, `"${VALUE}"`] : [`"${OTHER}"`])]);
      if (req.method === "PUT") {
        written = true;
        throw Object.assign(new Error("aborted"), { name: "TimeoutError" });
      }
      return undefined;
    });
    expect(await huaweiDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).toBe("rs1");
    expect(dnsCalls(fetch).map((c) => c.method)).toEqual(["GET", "PUT", "GET"]);
  });

  it("中文域名：记录集名用接口里的原名拼，返回的原名按 punycode 比对", async () => {
    const idn: DnsZone = { name: "xn--fsqu00a.xn--fiqs8s", id: "zone-1", extra: { apiName: "例子.中国" } };
    const fetch = hw((req) => {
      if (req.method === "GET") return listed([set("rs1", [`"${OTHER}"`], { name: "_acme-challenge.例子.中国." })]);
      if (req.method === "PUT") return { status: 202, body: { id: "rs1" } };
      return undefined;
    });
    expect(await huaweiDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.xn--fsqu00a.xn--fiqs8s", idn))).toBe("rs1");
    const [list, put] = dnsCalls(fetch) as [FakeRequest, FakeRequest];
    expect(list.url.searchParams.get("name")).toBe("_acme-challenge.例子.中国");
    expect(put.json).toMatchObject({ name: "_acme-challenge.例子.中国.", records: [`"${OTHER}"`, `"${VALUE}"`] });
  });
});

describe("华为云云解析 removeTxt", () => {
  it("记录集里还有其他值：只去掉这次的值 PUT 写回", async () => {
    const fetch = hw((req) => {
      if (req.method === "GET") return listed([set("rs1", [`"${OTHER}"`, `"${VALUE}"`])]);
      if (req.method === "PUT") return { status: 202, body: { id: "rs1" } };
      return undefined;
    });
    await huaweiDns.removeTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"), "rs1");
    const put = dnsCalls(fetch).find((c) => c.method === "PUT")!;
    expect(put.url.pathname).toBe(`${SETS}/rs1`);
    expect(put.json).toEqual({ name: "_acme-challenge.example.com.", type: "TXT", records: [`"${OTHER}"`] });
  });

  it("只剩这次的值：DELETE 整个记录集（签名按无请求体计算）", async () => {
    const fetch = hw((req) => {
      if (req.method === "GET") return listed([set("rs1", [`"${VALUE}"`])]);
      if (req.method === "DELETE") return { status: 202, body: { id: "rs1", status: "PENDING_DELETE" } };
      return undefined;
    });
    await huaweiDns.removeTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"), "rs1");
    const del = dnsCalls(fetch).find((c) => c.method === "DELETE")!;
    expect(del.url.pathname).toBe(`${SETS}/rs1`);
    expect(del.body).toBe("");
    expect(del.headers.authorization).toBe(
      apigAuthorization({
        accessKeyId: CREDS.accessKeyId,
        secretAccessKey: CREDS.secretAccessKey,
        method: "DELETE",
        path: del.url.pathname,
        query: {},
        headers: { Host: del.url.host, "X-Sdk-Date": del.headers["x-sdk-date"]!, "X-Project-Id": "p-bj4" },
      }),
    );
  });

  it("先等记录集稳定（上一个值刚删掉还在 PENDING_UPDATE）再改", async () => {
    let reads = 0;
    const sleeps: number[] = [];
    const fetch = hw((req) => {
      if (req.method === "GET") return listed([set("rs1", [`"${VALUE}"`], { status: reads++ === 0 ? "PENDING_UPDATE" : "ACTIVE" })]);
      if (req.method === "DELETE") return { status: 202, body: {} };
      return undefined;
    });
    await huaweiDns.removeTxt(ctxOf(fetch, sleeps), CREDS, rec("_acme-challenge.example.com"), "rs1");
    expect(sleeps).toEqual([2000]);
    expect(dnsCalls(fetch).map((c) => c.method)).toEqual(["GET", "GET", "DELETE"]);
  });

  it("值或记录集已经不在、DELETE 时记录集已不存在（DNS.0313）都视为成功", async () => {
    const noValue = hw((req) => (req.method === "GET" ? listed([set("rs1", [`"${OTHER}"`])]) : undefined));
    await huaweiDns.removeTxt(ctxOf(noValue), CREDS, rec("_acme-challenge.example.com"), "rs1");
    expect(dnsCalls(noValue).map((c) => c.method)).toEqual(["GET"]);

    const noSet = hw((req) => (req.method === "GET" ? listed([]) : undefined));
    await huaweiDns.removeTxt(ctxOf(noSet), CREDS, rec("_acme-challenge.example.com"), "rs1");
    expect(dnsCalls(noSet).map((c) => c.method)).toEqual(["GET"]);

    const gone = hw((req) => (req.method === "GET" ? listed([set("rs1", [`"${VALUE}"`])]) : dnsError(404, "DNS.0313", "This record set does not exist.")));
    await expect(huaweiDns.removeTxt(ctxOf(gone), CREDS, rec("_acme-challenge.example.com"), "rs1")).resolves.toBeUndefined();
  });

  it("其他错误照常抛出", async () => {
    const fetch = hw((req) => (req.method === "GET" ? listed([set("rs1", [`"${VALUE}"`])]) : dnsError(403, "DNS.0030", "Operation not allowed for this resource.")));
    await expect(huaweiDns.removeTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"), "rs1")).rejects.toMatchObject({ code: "DNS.0030", httpStatus: 403 });
  });
});
