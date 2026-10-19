import { describe, expect, it } from "vitest";
import { baiduDns } from "../src/dns/baidu.js";
import type { DnsZone, TxtRecord } from "../src/dns/types.js";
import type { AccessKeyCredentials } from "../src/lib/env.js";
import { CloudApiError, type Fetch, type QueryContext } from "../src/lib/http.js";
import { bceAuthorization } from "../src/providers/baidu/sign.js";
import { fakeFetch, type FakeReply, type FakeRequest } from "./helpers.js";

const CREDS: AccessKeyCredentials = { accessKeyId: "test-ak-baidu", secretAccessKey: "test-sk-baidu" };
const ctxOf = (fetch: Fetch, sleeps: number[] = []): QueryContext => ({
  env: {},
  fetch,
  now: new Date("2026-10-18T00:00:00Z"),
  timeoutMs: 1000,
  sleep: async (ms) => void sleeps.push(ms),
});

const bceError = (status: number, code: string, message = code): FakeReply => ({ status, body: { code, message, requestId: "rid-err" } });
/** 只路由公网 DNS 的请求，其余返回 404 */
const bce = (route: (req: FakeRequest, q: Record<string, string>) => FakeReply) =>
  fakeFetch((req) => (req.url.host === "dns.baidubce.com" ? route(req, Object.fromEntries(req.url.searchParams)) : undefined));
const brief = (c: FakeRequest) => `${c.method} ${decodeURIComponent(c.url.pathname)}`;

/** 按收到的请求重算签名，校验 URL 上的路径 / 参数与签名时用的一致 */
function expectSigned(req: FakeRequest) {
  const timestamp = req.headers["x-bce-date"]!;
  const headers: Record<string, string> = { host: req.url.host, "x-bce-date": timestamp };
  if (req.headers["content-type"]) headers["Content-Type"] = req.headers["content-type"];
  expect(req.headers.authorization).toBe(
    bceAuthorization({
      accessKeyId: CREDS.accessKeyId,
      secretAccessKey: CREDS.secretAccessKey,
      method: req.method,
      path: decodeURIComponent(req.url.pathname),
      query: Object.fromEntries(req.url.searchParams),
      headers,
      timestamp,
    }),
  );
}

const VALUE = "v".repeat(43);
const OTHER = "w".repeat(43);
const ZONE: DnsZone = { name: "example.com", id: "example.com", extra: { ttl: "300" } };
const rec = (fqdn: string, zone: DnsZone = ZONE, value = VALUE): TxtRecord => ({ zone, fqdn, value });
const RECORDS = "/v1/dns/zone/example.com/record";
const txt = (id: string, rr: string, value: string, extra: Record<string, unknown> = {}) => ({ id, rr, status: "running", type: "TXT", value, ttl: 300, line: "default", ...extra });
const records = (list: unknown[]): FakeReply => ({ body: { marker: "", isTruncated: false, maxKeys: 1000, records: list } });

describe("百度智能云 DNS listZones", () => {
  it("按 marker 翻页；只要 running 的，域名规范化，中文域名转 punycode、原名作 id，按版本定 TTL", async () => {
    const fetch = bce((req, q) => {
      if (req.url.pathname !== "/v1/dns/zone") return undefined;
      if (!q.marker) {
        return {
          body: {
            marker: "",
            isTruncated: true,
            nextMarker: "m2",
            maxKeys: 1000,
            zones: [
              { id: "1", name: "Example.com", status: "running", productVersion: "free" },
              { id: "2", name: "pending.com", status: "nsunchange", productVersion: "free" },
              { id: "3", name: "例子.中国", status: "running", productVersion: "flagship" },
            ],
          },
        };
      }
      return {
        body: {
          marker: "m2",
          isTruncated: false,
          maxKeys: 1000,
          zones: [
            { id: "4", name: "cheap.com", status: "running", productVersion: "discount" },
            { id: "5", name: "nobeian.com", status: "torenew", productVersion: "free" },
            { id: "6", name: "future.com", status: "running", productVersion: "premium" },
          ],
        },
      };
    });
    expect(await baiduDns.listZones(ctxOf(fetch), CREDS)).toEqual([
      { name: "example.com", id: "example.com", extra: { ttl: "300" } },
      { name: "xn--fsqu00a.xn--fiqs8s", id: "例子.中国", extra: { ttl: "1" } },
      { name: "cheap.com", id: "cheap.com", extra: { ttl: "120" } },
      { name: "future.com", id: "future.com", extra: { ttl: "300" } },
    ]);
    expect(fetch.calls.map((c) => Object.fromEntries(c.url.searchParams))).toEqual([{ maxKeys: "1000" }, { maxKeys: "1000", marker: "m2" }]);
    const call = fetch.calls[0]!;
    expect(call.method).toBe("GET");
    expect(call.url.href).toBe("https://dns.baidubce.com/v1/dns/zone?maxKeys=1000");
    expectSigned(call);
  });

  it("鉴权失败抛 CloudApiError 带错误码与 requestId；限流自动重试", async () => {
    const denied = bce(() => bceError(403, "AccessDenied", "Access denied."));
    const err = await baiduDns.listZones(ctxOf(denied), CREDS).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CloudApiError);
    expect(err).toMatchObject({ provider: "baidu", code: "AccessDenied", requestId: "rid-err", httpStatus: 403 });

    let n = 0;
    const throttled = bce(() => (n++ === 0 ? { status: 429, body: "Too Many Requests" } : { body: { isTruncated: false, zones: [] } }));
    expect(await baiduDns.listZones(ctxOf(throttled), CREDS)).toEqual([]);
    expect(throttled.calls).toHaveLength(2);
  });

  it("NS 主机名规则覆盖基础版 / 普惠版与企业版", () => {
    for (const ns of ["ns1.bdydns.cn", "ns2.bdydns.cn", "sv1.bdydns.cn", "sv4.bdydns.cn"]) expect(baiduDns.nameServerPattern.test(ns)).toBe(true);
    expect(baiduDns.nameServerPattern.test("dns.baidu.com")).toBe(false);
  });
});

describe("百度智能云 DNS addTxt", () => {
  it("按 rr 查，没有同值的就 POST（clientToken 在 query 上），再查一次拿 ID；同名下其他值不动", async () => {
    let added = false;
    const fetch = bce((req) => {
      if (req.method === "GET" && req.url.pathname === RECORDS) {
        return records([txt("r-other", "_acme-challenge", OTHER), ...(added ? [txt("r-new", "_acme-challenge", VALUE)] : [])]);
      }
      if (req.method === "POST" && req.url.pathname === RECORDS) {
        added = true;
        return { body: "" };
      }
      return undefined;
    });
    expect(await baiduDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).toBe("r-new");
    expect(fetch.calls.map(brief)).toEqual([`GET ${RECORDS}`, `POST ${RECORDS}`, `GET ${RECORDS}`]);
    const [list, create] = fetch.calls as [FakeRequest, FakeRequest];
    expect(Object.fromEntries(list.url.searchParams)).toEqual({ rr: "_acme-challenge", maxKeys: "1000" });
    expect([...create.url.searchParams.keys()]).toEqual(["clientToken"]);
    expect(create.url.searchParams.get("clientToken")).toMatch(/^[0-9a-f-]{36}$/);
    expect(create.json).toEqual({ rr: "_acme-challenge", type: "TXT", value: VALUE, ttl: 300, line: "default" });
    expect(create.headers["content-type"]).toBe("application/json;charset=utf-8");
    expectSigned(create);
  });

  it("同名同值（默认线路）已存在时不添加，返回它的 ID；其他线路、其他主机记录上的同值不算，带引号的值去掉引号再比", async () => {
    const fetch = bce((req) =>
      req.method === "GET"
        ? records([txt("r-ct", "_acme-challenge", VALUE, { line: "ct" }), txt("r-x", "x._acme-challenge", VALUE), txt("r-mine", "_acme-challenge", `"${VALUE}"`)])
        : undefined,
    );
    expect(await baiduDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).toBe("r-mine");
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET"]);
  });

  it("记录查询按 marker 翻页", async () => {
    const fetch = bce((req, q) => {
      if (req.method !== "GET") return undefined;
      if (!q.marker) return { body: { isTruncated: true, nextMarker: "p2", records: [txt("r1", "_acme-challenge", OTHER)] } };
      return { body: { isTruncated: false, records: [txt("r2", "_acme-challenge", VALUE)] } };
    });
    expect(await baiduDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).toBe("r2");
    expect(fetch.calls.map((c) => c.url.searchParams.get("marker"))).toEqual([null, "p2"]);
  });

  it("TTL 取 zone 的版本下限；子 zone 下用相对名", async () => {
    const zone: DnsZone = { name: "a.example.com", id: "a.example.com", extra: { ttl: "1" } };
    const fetch = bce((req) => (req.method === "GET" ? records([]) : { body: "" }));
    expect(await baiduDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.www.a.example.com", zone))).toBe("");
    const create = fetch.calls.find((c) => c.method === "POST")!;
    expect(decodeURIComponent(create.url.pathname)).toBe("/v1/dns/zone/a.example.com/record");
    expect(create.json).toMatchObject({ rr: "_acme-challenge.www", ttl: 1 });
  });

  it("POST 限流时用同一个 clientToken 原样重试（幂等，不会加出两条）", async () => {
    let posts = 0;
    const fetch = bce((req) => {
      if (req.method === "GET") return records(posts >= 2 ? [txt("r-new", "_acme-challenge", VALUE)] : []);
      if (req.method === "POST") return posts++ === 0 ? bceError(429, "RequestRateLimitExceeded", "rate limited") : { body: "" };
      return undefined;
    });
    expect(await baiduDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).toBe("r-new");
    const tokens = fetch.calls.filter((c) => c.method === "POST").map((c) => c.url.searchParams.get("clientToken"));
    expect(tokens).toHaveLength(2);
    expect(tokens[0]).toBe(tokens[1]);
  });

  it("每次添加都用新的 clientToken（同一个值删掉后再加不会被当成重复请求）", async () => {
    const fetch = bce((req) => (req.method === "GET" ? records([]) : { body: "" }));
    await baiduDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"));
    await baiduDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"));
    const tokens = fetch.calls.filter((c) => c.method === "POST").map((c) => c.url.searchParams.get("clientToken"));
    expect(tokens[0]).not.toBe(tokens[1]);
  });

  it("POST 被拒但再查发现同值已在（重复记录的错误码文档未写）：用它；查不到则原样报错", async () => {
    let posted = false;
    const dup = bce((req) => {
      if (req.method === "GET") return records(posted ? [txt("r-dup", "_acme-challenge", VALUE)] : []);
      posted = true;
      return bceError(400, "RecordExistInvalid", "record already exists");
    });
    expect(await baiduDns.addTxt(ctxOf(dup), CREDS, rec("_acme-challenge.example.com"))).toBe("r-dup");

    const conflict = bce((req) => (req.method === "GET" ? records([]) : bceError(400, "RecordConflictInvalid", "record conflict")));
    await expect(baiduDns.addTxt(ctxOf(conflict), CREDS, rec("_acme-challenge.example.com"))).rejects.toMatchObject({
      provider: "baidu",
      code: "RecordConflictInvalid",
      requestId: "rid-err",
    });
  });
});

describe("百度智能云 DNS removeTxt", () => {
  it("按值查出这次加的记录，DELETE（带 clientToken、签名按无请求体计算）；同名下其他值不动", async () => {
    const fetch = bce((req) => {
      if (req.method === "GET") return records([txt("r-other", "_acme-challenge", OTHER), txt("r-mine", "_acme-challenge", VALUE)]);
      if (req.method === "DELETE") return { body: "" };
      return undefined;
    });
    await baiduDns.removeTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"), "r-mine");
    expect(fetch.calls.map(brief)).toEqual([`GET ${RECORDS}`, `DELETE ${RECORDS}/r-mine`]);
    const del = fetch.calls[1]!;
    expect(del.url.searchParams.get("clientToken")).toMatch(/^[0-9a-f-]{36}$/);
    expect(del.body).toBe("");
    expect(del.headers["content-type"]).toBeUndefined();
    expectSigned(del);
  });

  it("添加后没拿到 ID（句柄为空）时同样按值删除；已经不在了视为成功", async () => {
    const fetch = bce((req) => (req.method === "GET" ? records([txt("r-mine", "_acme-challenge", VALUE)]) : { body: "" }));
    await baiduDns.removeTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"), "");
    expect(fetch.calls.map(brief)).toEqual([`GET ${RECORDS}`, `DELETE ${RECORDS}/r-mine`]);

    const gone = bce((req) => (req.method === "GET" ? records([txt("r-other", "_acme-challenge", OTHER)]) : undefined));
    await baiduDns.removeTxt(ctxOf(gone), CREDS, rec("_acme-challenge.example.com"), "r-mine");
    expect(gone.calls.map((c) => c.method)).toEqual(["GET"]);
  });

  it("删除失败照常抛出", async () => {
    const fetch = bce((req) => (req.method === "GET" ? records([txt("r-mine", "_acme-challenge", VALUE)]) : bceError(403, "AccessDenied")));
    await expect(baiduDns.removeTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"), "r-mine")).rejects.toMatchObject({ code: "AccessDenied" });
  });
});
