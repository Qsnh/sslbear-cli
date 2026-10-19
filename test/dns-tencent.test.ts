import { describe, expect, it } from "vitest";
import { tencentDns } from "../src/dns/tencent.js";
import type { DnsZone, TxtRecord } from "../src/dns/types.js";
import type { TencentCredentials } from "../src/lib/env.js";
import { isRetryable, type Fetch, type QueryContext } from "../src/lib/http.js";
import { TENCENT_ENV, fakeFetch, type FakeReply } from "./helpers.js";

const CREDS: TencentCredentials = { secretId: TENCENT_ENV.TENCENTCLOUD_SECRET_ID, secretKey: TENCENT_ENV.TENCENTCLOUD_SECRET_KEY };
const ctxOf = (fetch: Fetch, sleeps: number[] = []): QueryContext => ({
  env: {},
  fetch,
  now: new Date("2026-10-18T00:00:00Z"),
  timeoutMs: 1000,
  sleep: async (ms) => void sleeps.push(ms),
});

const ok = (data: Record<string, unknown>): FakeReply => ({ body: { Response: { RequestId: "rid", ...data } } });
// 腾讯云业务错误是 HTTP 200 + Response.Error
const tcError = (Code: string, Message = Code): FakeReply => ({ body: { Response: { RequestId: "rid-err", Error: { Code, Message } } } });
const timeout = () => {
  throw Object.assign(new Error("The operation was aborted due to timeout"), { name: "TimeoutError" });
};
/** 只路由 DNSPod 的请求，其余返回 404 */
const dnspod = (route: (action: string, json: Record<string, unknown>) => FakeReply) =>
  fakeFetch((req) => (req.url.host === "dnspod.tencentcloudapi.com" ? route(req.action ?? "", req.json ?? {}) : undefined));

// 验证值是 43 个字符的 base64url，测试里用一眼能看出是假的值
const VALUE = "v".repeat(43);
const OTHER = "w".repeat(43);
const ZONE: DnsZone = { name: "example.com", id: "123", extra: { ttl: "600" } };
const rec = (fqdn: string, zone: DnsZone = ZONE, value = VALUE): TxtRecord => ({ zone, fqdn, value });
const txt = (RecordId: number, Name: string, Value: string, LineId = "0") => ({ RecordId, Name, Type: "TXT", Value, Line: LineId === "0" ? "默认" : "电信", LineId });

describe("DNSPod listZones", () => {
  it("按 Offset 翻页、以 DomainTotal 为准；跳过暂停 / 封禁的域名，DNS 未指向 DNSPod 的照样返回并带 EffectiveDNS", async () => {
    const fetch = dnspod((action, json) => {
      if (action !== "DescribeDomainList") return undefined;
      if (json.Offset === 0) {
        // 接口一页只给了 3 条（少于 Limit），总数 5，要接着翻
        return ok({
          DomainCountInfo: { DomainTotal: 5, AllTotal: 5 },
          DomainList: [
            { DomainId: 1, Name: "Example.com", Punycode: "example.com", Status: "ENABLE", DNSStatus: "", EffectiveDNS: ["F1G1NS1.DNSPOD.NET.", "f1g1ns2.dnspod.net"], IsVip: "NO" },
            { DomainId: 2, Name: "paused.com", Punycode: "paused.com", Status: "PAUSE", DNSStatus: "", EffectiveDNS: ["f1g1ns1.dnspod.net"] },
            { DomainId: 3, Name: "moved.com", Punycode: "moved.com", Status: "ENABLE", DNSStatus: "DNSERROR", EffectiveDNS: ["ns3.dnsv5.com", "ns4.dnsv5.com"], IsVip: "YES" },
          ],
        });
      }
      return ok({
        DomainCountInfo: { DomainTotal: 5, AllTotal: 5 },
        DomainList: [
          { DomainId: 4, Name: "spam.com", Punycode: "spam.com", Status: "SPAM", EffectiveDNS: [] },
          { DomainId: 5, Name: "例子.中国", Punycode: "xn--fsqu00a.xn--fiqs8s", Status: "ENABLE", EffectiveDNS: null, IsVip: "NO" },
        ],
      });
    });
    const zones = await tencentDns.listZones(ctxOf(fetch), CREDS);
    expect(zones).toEqual([
      { name: "example.com", id: "1", nameServers: ["f1g1ns1.dnspod.net", "f1g1ns2.dnspod.net"], extra: { ttl: "600" } },
      { name: "moved.com", id: "3", nameServers: ["ns3.dnsv5.com", "ns4.dnsv5.com"], extra: { ttl: "60" } },
      { name: "xn--fsqu00a.xn--fiqs8s", id: "5", extra: { ttl: "600" } },
    ]);
    expect(fetch.calls.map((c) => c.json)).toEqual([
      { Type: "ALL", Offset: 0, Limit: 3000 },
      { Type: "ALL", Offset: 3, Limit: 3000 },
    ]);
    const call = fetch.calls[0]!;
    expect(call.headers["x-tc-version"]).toBe("2021-03-23");
    expect(call.headers["x-tc-region"]).toBeUndefined();
  });

  it("账号下没有域名（ResourceNotFound.NoDataOfDomain）返回空列表", async () => {
    const fetch = dnspod(() => tcError("ResourceNotFound.NoDataOfDomain", "域名列表为空"));
    expect(await tencentDns.listZones(ctxOf(fetch), CREDS)).toEqual([]);
    expect(fetch.calls).toHaveLength(1);
  });

  it("RequestLimitExceeded 自动重试；鉴权失败等错误抛 CloudApiError，带错误码与 RequestId", async () => {
    const replies = [tcError("RequestLimitExceeded"), tcError("AuthFailure.SecretIdNotFound", "The SecretId is not found")];
    const fetch = dnspod(() => replies.shift());
    await expect(tencentDns.listZones(ctxOf(fetch), CREDS)).rejects.toMatchObject({
      name: "CloudApiError",
      provider: "tencent",
      code: "AuthFailure.SecretIdNotFound",
      requestId: "rid-err",
    });
    expect(fetch.calls).toHaveLength(2);
  });
});

describe("DNSPod addTxt", () => {
  it("CreateRecord 新增一条：主机记录相对 zone、默认线路、TTL 取 zone 上的值、带 DomainId", async () => {
    const fetch = dnspod((action) => (action === "CreateRecord" ? ok({ RecordId: 162 }) : undefined));
    expect(await tencentDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.www.example.com"))).toBe("162");
    expect(fetch.calls.map((c) => c.action)).toEqual(["CreateRecord"]);
    expect(fetch.calls[0]!.json).toEqual({
      Domain: "example.com",
      DomainId: 123,
      SubDomain: "_acme-challenge.www",
      RecordType: "TXT",
      RecordLine: "默认",
      Value: VALUE,
      TTL: 600,
    });
  });

  it("付费套餐 TTL 60，被拒（LimitExceeded.RecordTtlLimit）时退回 600 重加", async () => {
    const fetch = dnspod((action, json) => {
      if (action !== "CreateRecord") return undefined;
      return json.TTL === 60 ? tcError("LimitExceeded.RecordTtlLimit", "记录的TTL值超出了限制。") : ok({ RecordId: 7 });
    });
    const handle = await tencentDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com", { ...ZONE, extra: { ttl: "60" } }));
    expect(handle).toBe("7");
    expect(fetch.calls.map((c) => [c.json?.SubDomain, c.json?.TTL])).toEqual([
      ["_acme-challenge", 60],
      ["_acme-challenge", 600],
    ]);
  });

  it("同名同值已存在（DomainRecordExist）：查出它的 ID 当句柄，不重复添加、不动同名下的其他值", async () => {
    const fetch = dnspod((action) => {
      if (action === "CreateRecord") return tcError("InvalidParameter.DomainRecordExist", "记录已经存在，无需再次添加。");
      if (action === "DescribeRecordList") {
        return ok({
          RecordCountInfo: { SubdomainCount: 1, ListCount: 3, TotalCount: 3 },
          RecordList: [txt(1, "_acme-challenge", OTHER), txt(2, "_acme-challenge", VALUE, "10=0"), txt(3, "_acme-challenge", `"${VALUE}"`)],
        });
      }
      return undefined;
    });
    expect(await tencentDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).toBe("3");
    expect(fetch.calls.map((c) => c.action)).toEqual(["CreateRecord", "DescribeRecordList"]);
    expect(fetch.calls[1]!.json).toEqual({
      Domain: "example.com",
      DomainId: 123,
      SubDomain: "_acme-challenge",
      RecordType: "TXT",
      ErrorOnEmpty: "no",
      Offset: 0,
      Limit: 100,
    });
  });

  it("记录已存在但还没进索引：隔 10 秒再查", async () => {
    let lookups = 0;
    const fetch = dnspod((action) => {
      if (action === "CreateRecord") return tcError("InvalidParameter.DomainRecordExist");
      if (action === "DescribeRecordList") {
        return ++lookups === 1 ? tcError("ResourceNotFound.NoDataOfRecord", "记录列表为空。") : ok({ RecordList: [txt(9, "_acme-challenge", VALUE)] });
      }
      return undefined;
    });
    const sleeps: number[] = [];
    expect(await tencentDns.addTxt(ctxOf(fetch, sleeps), CREDS, rec("_acme-challenge.example.com"))).toBe("9");
    expect(sleeps).toEqual([10_000]);
  });

  it("报已存在却一直查不到：查 4 次后原样报错", async () => {
    const fetch = dnspod((action) => (action === "CreateRecord" ? tcError("InvalidParameter.DomainRecordExist") : ok({ RecordList: [] })));
    const sleeps: number[] = [];
    await expect(tencentDns.addTxt(ctxOf(fetch, sleeps), CREDS, rec("_acme-challenge.example.com"))).rejects.toMatchObject({
      code: "InvalidParameter.DomainRecordExist",
    });
    expect(fetch.calls.filter((c) => c.action === "DescribeRecordList")).toHaveLength(4);
    expect(sleeps).toEqual([10_000, 10_000, 10_000]);
  });

  it("添加超时但其实已加上：重试前先查到它，不再重复添加", async () => {
    let created = false;
    const fetch = dnspod((action) => {
      if (action === "CreateRecord") {
        created = true;
        timeout();
      }
      if (action === "DescribeRecordList") return ok({ RecordList: created ? [txt(55, "_acme-challenge", VALUE)] : [] });
      return undefined;
    });
    expect(await tencentDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).toBe("55");
    expect(fetch.calls.map((c) => c.action)).toEqual(["CreateRecord", "DescribeRecordList"]);
  });

  it("添加超时且没加上：查不到再发一次", async () => {
    let creates = 0;
    const fetch = dnspod((action) => {
      if (action === "CreateRecord") return ++creates === 1 ? timeout() : ok({ RecordId: 56 });
      if (action === "DescribeRecordList") return ok({ RecordList: [] });
      return undefined;
    });
    expect(await tencentDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).toBe("56");
    expect(fetch.calls.map((c) => c.action)).toEqual(["CreateRecord", "DescribeRecordList", "CreateRecord"]);
  });

  it("重试用完仍限流：等索引跟上再查一次，查不到就报可重试的错误", async () => {
    const fetch = dnspod((action) => (action === "CreateRecord" ? tcError("RequestLimitExceeded") : ok({ RecordList: [] })));
    const err = await tencentDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com")).catch((e: unknown) => e);
    expect(err).toMatchObject({ provider: "tencent", code: "RequestLimitExceeded" });
    expect(isRetryable(err)).toBe(true);
    expect(fetch.calls.filter((c) => c.action === "CreateRecord")).toHaveLength(3);
  });

  it("添加与查询都超时（网络不通）：查询不再层层重试，也不干等索引，总请求数有上限", async () => {
    const fetch = dnspod(() => timeout());
    const sleeps: number[] = [];
    await expect(tencentDns.addTxt(ctxOf(fetch, sleeps), CREDS, rec("_acme-challenge.example.com"))).rejects.toMatchObject({ code: "Timeout" });
    expect(fetch.calls.map((c) => c.action)).toEqual(["CreateRecord", "DescribeRecordList", "DescribeRecordList", "DescribeRecordList"]);
    expect(sleeps.filter((ms) => ms === 10_000)).toEqual([]);
  });

  it("域名锁定等其他错误直接抛出，不重试、不查询", async () => {
    const fetch = dnspod(() => tcError("FailedOperation.DomainIsLocked", "锁定域名不能进行此操作。"));
    await expect(tencentDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).rejects.toMatchObject({
      provider: "tencent",
      code: "FailedOperation.DomainIsLocked",
      requestId: "rid-err",
    });
    expect(fetch.calls.map((c) => c.action)).toEqual(["CreateRecord"]);
  });
});

describe("DNSPod removeTxt", () => {
  it("按记录 ID 删除这一条", async () => {
    const fetch = dnspod((action) => (action === "DeleteRecord" ? ok({}) : undefined));
    await tencentDns.removeTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"), "162");
    expect(fetch.calls.map((c) => c.action)).toEqual(["DeleteRecord"]);
    expect(fetch.calls[0]!.json).toEqual({ Domain: "example.com", DomainId: 123, RecordId: 162 });
  });

  it("记录已不存在（InvalidParameter.RecordIdInvalid）视为成功", async () => {
    const fetch = dnspod(() => tcError("InvalidParameter.RecordIdInvalid", "记录编号错误。"));
    await expect(tencentDns.removeTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"), "162")).resolves.toBeUndefined();
  });

  it("DNSPod 自己的限流码换成可重试的码并自动重试，重试用完后仍是可重试的错误", async () => {
    const fetch = dnspod(() => tcError("FailedOperation.FrequencyLimit", "您操作过于频繁，请稍后重试"));
    const err = await tencentDns.removeTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"), "162").catch((e: unknown) => e);
    expect(err).toMatchObject({ provider: "tencent", code: "Throttling.FailedOperation.FrequencyLimit", requestId: "rid-err" });
    expect(isRetryable(err)).toBe(true);
    expect(fetch.calls).toHaveLength(3);
  });

  it("限流后重试成功", async () => {
    const replies = [tcError("FailedOperation.FrequencyLimit"), ok({})];
    const fetch = dnspod(() => replies.shift());
    await tencentDns.removeTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"), "162");
    expect(fetch.calls).toHaveLength(2);
  });
});

describe("DNSPod nameServerPattern", () => {
  it.each(["f1g1ns1.dnspod.net", "namerich1.dnspod.net", "a.dnspod.com", "ns3.dnsv2.com", "ns4.dnsv4.com", "ns1.dnsv5.com"])("认得 %s", (ns) => {
    expect(tencentDns.nameServerPattern.test(ns)).toBe(true);
  });
  it.each(["dns29.hichina.com", "notdnspod.net", "dnspod.net.example.com", "ns1.dnsv5.com.cn"])("不认 %s", (ns) => {
    expect(tencentDns.nameServerPattern.test(ns)).toBe(false);
  });
});
