import { describe, expect, it } from "vitest";
import { aliyunDns } from "../src/dns/aliyun.js";
import type { DnsZone, TxtRecord } from "../src/dns/types.js";
import type { AliyunCredentials } from "../src/lib/env.js";
import { isRetryable, type Fetch, type QueryContext } from "../src/lib/http.js";
import { ALIYUN_ENV, fakeFetch, type FakeReply, type FakeRequest } from "./helpers.js";

const CREDS: AliyunCredentials = {
  accessKeyId: ALIYUN_ENV.ALIBABA_CLOUD_ACCESS_KEY_ID,
  accessKeySecret: ALIYUN_ENV.ALIBABA_CLOUD_ACCESS_KEY_SECRET,
};
const ctxOf = (fetch: Fetch, sleeps: number[] = []): QueryContext => ({
  env: {},
  fetch,
  now: new Date("2026-10-18T00:00:00Z"),
  timeoutMs: 1000,
  sleep: async (ms) => void sleeps.push(ms),
});

const ok = (body: Record<string, unknown>): FakeReply => ({ body: { RequestId: "req-ok", ...body } });
const rpcError = (status: number, Code: string, Message = Code): FakeReply => ({ status, body: { RequestId: "req-1", Code, Message } });
const timeout = () => {
  throw Object.assign(new Error("The operation was aborted due to timeout"), { name: "TimeoutError" });
};
/** 只路由云解析的请求，其余返回 404 */
const alidns = (route: (action: string, q: URLSearchParams, req: FakeRequest) => FakeReply) =>
  fakeFetch((req) => (req.url.host === "alidns.aliyuncs.com" ? route(req.action ?? "", req.url.searchParams, req) : undefined));
const params = (req: FakeRequest) => Object.fromEntries([...req.url.searchParams].filter(([k]) => /^[A-Z]/.test(k) && !COMMON.has(k)));
const COMMON = new Set(["Format", "Version", "Action", "AccessKeyId", "SignatureMethod", "SignatureVersion", "SignatureNonce", "Timestamp", "Signature"]);

// 验证值是 43 个字符的 base64url，测试里用一眼能看出是假的值
const VALUE = "v".repeat(43);
const OTHER = "w".repeat(43);
const ZONE: DnsZone = { name: "example.com", id: "example.com", extra: { ttl: "600" } };
const rec = (fqdn: string, zone: DnsZone = ZONE, value = VALUE): TxtRecord => ({ zone, fqdn, value });

describe("阿里云云解析 listZones", () => {
  it("按 TotalCount 翻页；域名与 NS 规范化，中文域名用 PunyCode 作 zone 名、原名作 id，按版本定 TTL", async () => {
    const fetch = alidns((action, q) => {
      if (action !== "DescribeDomains") return undefined;
      if (q.get("PageNumber") === "1") {
        return ok({
          TotalCount: 3,
          PageNumber: 1,
          PageSize: 100,
          Domains: {
            Domain: [
              { DomainName: "Example.COM.", DnsServers: { DnsServer: ["DNS29.hichina.com.", "dns30.hichina.com"] }, VersionCode: "mianfei" },
              {
                DomainName: "例子.中国",
                PunyCode: "xn--fsqu00a.xn--fiqs8s",
                VersionCode: "version_enterprise_advanced",
                InstanceExpired: false,
                DnsServers: { DnsServer: ["vip1.alidns.com", "vip2.alidns.com"] },
              },
            ],
          },
        });
      }
      // 第二页：付费实例已过期，按免费版 TTL；没有 DnsServers 时不带 nameServers
      return ok({ TotalCount: 3, PageNumber: 2, Domains: { Domain: [{ DomainName: "expired.com", VersionCode: "version_enterprise_basic", InstanceExpired: true }] } });
    });
    const zones = await aliyunDns.listZones(ctxOf(fetch), CREDS);
    expect(zones).toEqual([
      { name: "example.com", id: "example.com", nameServers: ["dns29.hichina.com", "dns30.hichina.com"], extra: { ttl: "600" } },
      { name: "xn--fsqu00a.xn--fiqs8s", id: "例子.中国", nameServers: ["vip1.alidns.com", "vip2.alidns.com"], extra: { ttl: "60" } },
      { name: "expired.com", id: "expired.com", extra: { ttl: "600" } },
    ]);
    expect(fetch.calls.map((c) => params(c))).toEqual([
      { PageNumber: "1", PageSize: "100" },
      { PageNumber: "2", PageSize: "100" },
    ]);
    const q = fetch.calls[0]!.url.searchParams;
    expect(q.get("Version")).toBe("2015-01-09");
    expect(q.get("AccessKeyId")).toBe(CREDS.accessKeyId);
  });

  it("个人版按免费版 TTL；没有域名时返回空列表", async () => {
    const personal = alidns(() => ok({ TotalCount: 1, Domains: { Domain: [{ DomainName: "p.com", VersionCode: "version_personal" }] } }));
    expect(await aliyunDns.listZones(ctxOf(personal), CREDS)).toEqual([{ name: "p.com", id: "p.com", extra: { ttl: "600" } }]);
    const empty = alidns(() => ok({ TotalCount: 0, Domains: { Domain: [] } }));
    expect(await aliyunDns.listZones(ctxOf(empty), CREDS)).toEqual([]);
    expect(empty.calls).toHaveLength(1);
  });

  it("限流自动重试；其他错误抛 CloudApiError，带错误码与 RequestId；无权限时写出缺少的 RAM 权限", async () => {
    const replies = [rpcError(400, "Throttling.User"), rpcError(403, "Forbidden.RAM", "User not authorized")];
    const fetch = alidns(() => replies.shift());
    await expect(aliyunDns.listZones(ctxOf(fetch), CREDS)).rejects.toMatchObject({
      name: "CloudApiError",
      provider: "aliyun",
      code: "Forbidden.RAM",
      requestId: "req-1",
      httpStatus: 403,
      // 云解析只有签发用到，签发要增删记录，只读策略不够
      message: "User not authorized（缺少 RAM 权限 alidns:DescribeDomains，可授予系统策略 AliyunDNSFullAccess）",
    });
    expect(fetch.calls).toHaveLength(2);
  });
});

describe("阿里云云解析 addTxt", () => {
  it("直接新增一条：主机记录相对 zone、默认线路、TTL 取 zone 上的值，只调用 AddDomainRecord", async () => {
    const fetch = alidns((action) => (action === "AddDomainRecord" ? ok({ RecordId: "2111459169730903040" }) : undefined));
    const handle = await aliyunDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.www.example.com"));
    // 19 位的 RecordId 以字符串原样返回，不能经过 number
    expect(handle).toBe("2111459169730903040");
    expect(fetch.calls.map((c) => c.action)).toEqual(["AddDomainRecord"]);
    expect(params(fetch.calls[0]!)).toEqual({ DomainName: "example.com", RR: "_acme-challenge.www", Type: "TXT", Value: VALUE, TTL: "600" });
  });

  it("根域名的验证记录主机记录为 _acme-challenge；中文域名用原名作 DomainName；付费版 TTL 60", async () => {
    const zone: DnsZone = { name: "xn--fsqu00a.xn--fiqs8s", id: "例子.中国", extra: { ttl: "60" } };
    const fetch = alidns((action) => (action === "AddDomainRecord" ? ok({ RecordId: "1" }) : undefined));
    await aliyunDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.xn--fsqu00a.xn--fiqs8s", zone));
    expect(params(fetch.calls[0]!)).toMatchObject({ DomainName: "例子.中国", RR: "_acme-challenge", TTL: "60" });
  });

  it("TTL 低于版本允许的最小值（QuotaExceeded.TTL）时退回 600 重加", async () => {
    const fetch = alidns((action, q) => {
      if (action !== "AddDomainRecord") return undefined;
      return q.get("TTL") === "60" ? rpcError(400, "QuotaExceeded.TTL", "超出当前配置的允许TTL值 600~86400") : ok({ RecordId: "7" });
    });
    const handle = await aliyunDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com", { ...ZONE, extra: { ttl: "60" } }));
    expect(handle).toBe("7");
    expect(fetch.calls.map((c) => c.url.searchParams.get("TTL"))).toEqual(["60", "600"]);
  });

  it("同名同值已存在（DomainRecordDuplicate）：查出它的 ID 当句柄，不重复添加、不动同名下的其他值", async () => {
    const fetch = alidns((action) => {
      if (action === "AddDomainRecord") return rpcError(400, "DomainRecordDuplicate", "The DNS record already exists.");
      if (action === "DescribeSubDomainRecords") {
        return ok({
          TotalCount: 3,
          DomainRecords: {
            Record: [
              // 泛域名的另一个验证值
              { RecordId: "100", RR: "_acme-challenge", Type: "TXT", Value: OTHER, Line: "default" },
              // 同值但在别的线路上，不是 AddDomainRecord 撞上的那条
              { RecordId: "101", RR: "_acme-challenge", Type: "TXT", Value: VALUE, Line: "telecom" },
              { RecordId: "102", RR: "_ACME-challenge", Type: "TXT", Value: `"${VALUE}"`, Line: "default" },
            ],
          },
        });
      }
      return undefined;
    });
    expect(await aliyunDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).toBe("102");
    expect(fetch.calls.map((c) => c.action)).toEqual(["AddDomainRecord", "DescribeSubDomainRecords"]);
    expect(params(fetch.calls[1]!)).toEqual({
      DomainName: "example.com",
      SubDomain: "_acme-challenge.example.com",
      Type: "TXT",
      PageNumber: "1",
      PageSize: "100",
    });
  });

  it("报已存在却查不到同值的记录：报 RecordMayExist（可能已添加），带 RequestId，不再重试", async () => {
    const fetch = alidns((action) =>
      action === "AddDomainRecord"
        ? rpcError(400, "DomainRecordDuplicate")
        : ok({ TotalCount: 1, DomainRecords: { Record: [{ RecordId: "100", RR: "_acme-challenge", Type: "TXT", Value: OTHER }] } }),
    );
    const err = await aliyunDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com")).catch((e: unknown) => e);
    expect(err).toMatchObject({ provider: "aliyun", code: "RecordMayExist", requestId: "req-1" });
    expect((err as Error).message).toMatch(/DomainRecordDuplicate.*可能已添加/);
    expect(isRetryable(err)).toBe(false);
    expect(fetch.calls.map((c) => c.action)).toEqual(["AddDomainRecord", "DescribeSubDomainRecords"]);
  });

  it("添加超时但其实已加上：重试前先查到它，不再重复添加", async () => {
    let added = false;
    const fetch = alidns((action) => {
      if (action === "AddDomainRecord") {
        added = true;
        timeout();
      }
      if (action === "DescribeSubDomainRecords") {
        const Record = added ? [{ RecordId: "55", RR: "_acme-challenge.www", Type: "TXT", Value: VALUE, Line: "default" }] : [];
        return ok({ TotalCount: Record.length, DomainRecords: { Record } });
      }
      return undefined;
    });
    expect(await aliyunDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.www.example.com"))).toBe("55");
    expect(fetch.calls.map((c) => c.action)).toEqual(["AddDomainRecord", "DescribeSubDomainRecords"]);
  });

  it("添加限流且没加上：查不到再发一次", async () => {
    let adds = 0;
    const fetch = alidns((action) => {
      if (action === "AddDomainRecord") return ++adds === 1 ? rpcError(400, "Throttling.User") : ok({ RecordId: "56" });
      if (action === "DescribeSubDomainRecords") return ok({ TotalCount: 0, DomainRecords: { Record: [] } });
      return undefined;
    });
    expect(await aliyunDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).toBe("56");
    expect(fetch.calls.map((c) => c.action)).toEqual(["AddDomainRecord", "DescribeSubDomainRecords", "AddDomainRecord"]);
  });

  it("重试用完仍超时：最后再查一次，查不到就报可重试的错误", async () => {
    const fetch = alidns((action) => (action === "AddDomainRecord" ? timeout() : ok({ TotalCount: 0, DomainRecords: { Record: [] } })));
    const err = await aliyunDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com")).catch((e: unknown) => e);
    expect(err).toMatchObject({ provider: "aliyun", code: "Timeout" });
    expect(isRetryable(err)).toBe(true);
    expect(fetch.calls.filter((c) => c.action === "AddDomainRecord")).toHaveLength(3);
  });

  it("添加与查询都超时（网络不通）：查询不再层层重试，总请求数有上限", async () => {
    const fetch = alidns(() => timeout());
    await expect(aliyunDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).rejects.toMatchObject({ code: "Timeout" });
    expect(fetch.calls.map((c) => c.action)).toEqual(["AddDomainRecord", "DescribeSubDomainRecords", "DescribeSubDomainRecords", "DescribeSubDomainRecords"]);
  });

  it("没有写权限等其他错误直接抛出，不重试、不查询", async () => {
    const fetch = alidns(() => rpcError(403, "Forbidden.RAM", "User not authorized to operate on the specified resource"));
    await expect(aliyunDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).rejects.toMatchObject({
      provider: "aliyun",
      code: "Forbidden.RAM",
      requestId: "req-1",
    });
    expect(fetch.calls.map((c) => c.action)).toEqual(["AddDomainRecord"]);
  });
});

describe("阿里云云解析 removeTxt", () => {
  it("按记录 ID 删除这一条", async () => {
    const fetch = alidns((action) => (action === "DeleteDomainRecord" ? ok({ RecordId: "2111459169730903040" }) : undefined));
    await aliyunDns.removeTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"), "2111459169730903040");
    expect(fetch.calls.map((c) => c.action)).toEqual(["DeleteDomainRecord"]);
    expect(params(fetch.calls[0]!)).toEqual({ RecordId: "2111459169730903040" });
  });

  it.each(["DomainRecordNotBelongToUser", "InvalidRR.NoExist"])("记录已不存在（%s）视为成功", async (code) => {
    const fetch = alidns(() => rpcError(400, code));
    await expect(aliyunDns.removeTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"), "1")).resolves.toBeUndefined();
  });

  it("限流自动重试；其他错误照常抛出", async () => {
    const replies = [rpcError(503, "ServiceUnavailable"), rpcError(400, "DomainRecordLocked", "禁止操作：解析记录被锁定")];
    const fetch = alidns(() => replies.shift());
    await expect(aliyunDns.removeTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"), "1")).rejects.toMatchObject({
      code: "DomainRecordLocked",
      requestId: "req-1",
    });
    expect(fetch.calls).toHaveLength(2);
  });
});

describe("阿里云云解析 nameServerPattern", () => {
  it.each(["dns29.hichina.com", "ns1.alidns.com", "vip3.alidns.com", "x1.alidns.com"])("认得 %s", (ns) => {
    expect(aliyunDns.nameServerPattern.test(ns)).toBe(true);
  });
  it.each(["f1g1ns1.dnspod.net", "notalidns.com", "alidns.com.example.net"])("不认 %s", (ns) => {
    expect(aliyunDns.nameServerPattern.test(ns)).toBe(false);
  });
});
