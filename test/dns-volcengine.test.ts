import { describe, expect, it } from "vitest";
import { volcengineDns } from "../src/dns/volcengine.js";
import type { DnsZone, TxtRecord } from "../src/dns/types.js";
import type { AccessKeyCredentials } from "../src/lib/env.js";
import { CloudApiError, type Fetch, type QueryContext } from "../src/lib/http.js";
import { fakeFetch, type FakeReply, type FakeRequest } from "./helpers.js";

const CREDS: AccessKeyCredentials = { accessKeyId: "AKLTtest0000", secretAccessKey: "testsecret" };
const ctxOf = (fetch: Fetch, sleeps: number[] = []): QueryContext => ({
  env: {},
  fetch,
  now: new Date("2026-10-18T00:00:00Z"),
  timeoutMs: 1000,
  sleep: async (ms) => void sleeps.push(ms),
});

const ok = (Result?: unknown): FakeReply => ({ body: { ResponseMetadata: { RequestId: "rid-ok" }, ...(Result !== undefined && { Result }) } });
const volcError = (status: number, Code: string, Message = Code): FakeReply => ({
  status,
  body: { ResponseMetadata: { RequestId: "rid-err", Error: { CodeN: 400100, Code, Message } } },
});
const timeout = () => {
  throw Object.assign(new Error("The operation was aborted due to timeout"), { name: "TimeoutError" });
};
/** 只路由云解析的请求，其余返回 404 */
const dns = (route: (action: string, p: Record<string, unknown>, req: FakeRequest) => FakeReply) =>
  fakeFetch((req) => (req.url.host === "dns.volcengineapi.com" ? route(req.action ?? "", params(req), req) : undefined));
/** GET 的参数在 query 上，POST 的在 JSON 里 */
const params = (req: FakeRequest): Record<string, unknown> =>
  req.json ?? Object.fromEntries([...req.url.searchParams].filter(([k]) => k !== "Action" && k !== "Version"));

// 验证值是 43 个字符的 base64url，测试里用一眼能看出是假的值
const VALUE = "v".repeat(43);
const OTHER = "w".repeat(43);
const ZONE: DnsZone = { name: "example.com", id: "2636", extra: { ttl: "600" } };
const rec = (fqdn: string, zone: DnsZone = ZONE, value = VALUE): TxtRecord => ({ zone, fqdn, value });
const txt = (RecordID: string, Host: string, Value: string, extra: Record<string, unknown> = {}) => ({
  RecordID,
  Host,
  Type: "TXT",
  Value,
  Line: "default",
  TTL: 600,
  Enable: true,
  ...extra,
});

describe("火山引擎云解析 listZones", () => {
  it("按 Stage 0 / 5 分别筛选并按 Total 翻页；按 ZID 去重，排除待找回，域名规范化，中文域名转 punycode，按版本定 TTL", async () => {
    const fetch = dns((action, p) => {
      if (action !== "ListZones") return undefined;
      if (p.Stage === "0" && p.PageNumber === "1") {
        return ok({
          Total: 3,
          Zones: [
            { ZID: 2636, ZoneName: "Example.COM.", TradeCode: "free_inner", CacheStage: 0, IsSubDomain: false },
            { ZID: 2637, ZoneName: "例子.中国", TradeCode: "enterprise_inner", CacheStage: 0 },
          ],
        });
      }
      if (p.Stage === "0") return ok({ Total: 3, Zones: [{ ZID: 2638, ZoneName: "pro.example.org", TradeCode: "professional_inner", CacheStage: 0 }] });
      // Stage 5：一个新 zone + 一个与 Stage 0 重复的（接口忽略筛选条件时）+ 一个待找回的
      return ok({
        Total: 3,
        Zones: [
          { ZID: 2639, ZoneName: "old.example.net", TradeCode: "ultimate_inner", CacheStage: 0 },
          { ZID: 2636, ZoneName: "example.com", TradeCode: "free_inner", CacheStage: 0 },
          { ZID: 2640, ZoneName: "claimed.example.net", TradeCode: "free_inner", CacheStage: 1 },
        ],
      });
    });
    const zones = await volcengineDns.listZones(ctxOf(fetch), CREDS);
    expect(zones).toEqual([
      { name: "example.com", id: "2636", extra: { ttl: "600" } },
      { name: "xn--fsqu00a.xn--fiqs8s", id: "2637", extra: { ttl: "60" } },
      { name: "pro.example.org", id: "2638", extra: { ttl: "300" } },
      { name: "old.example.net", id: "2639", extra: { ttl: "1" } },
    ]);
    expect(fetch.calls.map((c) => ({ method: c.method, ...params(c) }))).toEqual([
      { method: "GET", Stage: "0", PageNumber: "1", PageSize: "100" },
      { method: "GET", Stage: "0", PageNumber: "2", PageSize: "100" },
      { method: "GET", Stage: "5", PageNumber: "1", PageSize: "100" },
    ]);
    const call = fetch.calls[0]!;
    expect(call.url.searchParams.get("Action")).toBe("ListZones");
    expect(call.url.searchParams.get("Version")).toBe("2018-08-01");
    expect(call.headers.authorization).toMatch(/^HMAC-SHA256 Credential=AKLTtest0000\/\d{8}\/cn-beijing\/dns\/request, SignedHeaders=host;x-content-sha256;x-date, /);
  });

  it("不认识的版本按免费版 TTL；没有 zone 时返回空列表", async () => {
    const fetch = dns((_a, p) => ok({ Total: p.Stage === "0" ? 1 : 0, Zones: p.Stage === "0" ? [{ ZID: 1, ZoneName: "new.com", TradeCode: "future_inner" }] : null }));
    expect(await volcengineDns.listZones(ctxOf(fetch), CREDS)).toEqual([{ name: "new.com", id: "1", extra: { ttl: "600" } }]);
    expect(await volcengineDns.listZones(ctxOf(dns(() => ok({ Total: 0, Zones: [] }))), CREDS)).toEqual([]);
  });

  it("限流（FlowLimitExceeded，HTTP 429）自动重试；鉴权失败抛 CloudApiError 带错误码与 RequestId", async () => {
    let n = 0;
    const retried = dns(() => (n++ === 0 ? volcError(429, "FlowLimitExceeded") : ok({ Total: 0, Zones: [] })));
    expect(await volcengineDns.listZones(ctxOf(retried), CREDS)).toEqual([]);
    expect(retried.calls).toHaveLength(3);

    const denied = dns(() => volcError(403, "AccessDenied", "User is not authorized to perform: dns:ListZones"));
    const err = await volcengineDns.listZones(ctxOf(denied), CREDS).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CloudApiError);
    expect(err).toMatchObject({ provider: "volcengine", code: "AccessDenied", requestId: "rid-err", httpStatus: 403 });
  });

  it("NS 主机名规则覆盖免费版、付费版、海外与旧 NS", () => {
    for (const ns of ["ns1.volcengine-dns.com", "vip3.volcengine-dns.com", "intl.volcengine-dns.com", "ns5.volcdns.com"]) {
      expect(volcengineDns.nameServerPattern.test(ns)).toBe(true);
    }
    expect(volcengineDns.nameServerPattern.test("ns1.volcengine-dns.com.evil.com")).toBe(false);
    expect(volcengineDns.nameServerPattern.test("dns1.hichina.com")).toBe(false);
  });
});

describe("火山引擎云解析 addTxt", () => {
  it("先按主机记录精确查同名 TXT，没有同值的就 CreateRecord（POST JSON）；同名下其他值不动", async () => {
    const fetch = dns((action, p) => {
      if (action === "ListRecords") return ok({ TotalCount: 1, Records: [txt("3170534137670303887", "_acme-challenge", OTHER)] });
      if (action === "CreateRecord") return ok({ RecordID: "3170534137672596377", Host: p.Host, Type: "TXT", Value: p.Value });
      return undefined;
    });
    const handle = await volcengineDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"));
    expect(handle).toBe("3170534137672596377");
    expect(fetch.calls.map((c) => c.action)).toEqual(["ListRecords", "CreateRecord"]);
    const [list, create] = fetch.calls as [FakeRequest, FakeRequest];
    expect(list.method).toBe("GET");
    expect(params(list)).toEqual({ ZID: "2636", Host: "_acme-challenge", Type: "TXT", SearchMode: "exact", PageNumber: "1", PageSize: "100" });
    expect(create.method).toBe("POST");
    expect(create.url.href).toBe("https://dns.volcengineapi.com/?Action=CreateRecord&Version=2018-08-01");
    expect(create.headers["content-type"]).toBe("application/json");
    expect(create.json).toEqual({ ZID: 2636, Host: "_acme-challenge", Type: "TXT", Value: VALUE, TTL: 600, Line: "default" });
  });

  it("同名同值（默认线路）已存在时不新增，返回它的 RecordID；其他线路、其他主机记录上的同值不算", async () => {
    const fetch = dns((action) =>
      action === "ListRecords"
        ? ok({
            TotalCount: 4,
            Records: [
              txt("1", "_acme-challenge", VALUE, { Line: "telecom" }),
              txt("2", "x._acme-challenge", VALUE),
              txt("3", "_acme-challenge", OTHER),
              txt("4", "_ACME-challenge", VALUE),
            ],
          })
        : undefined,
    );
    expect(await volcengineDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).toBe("4");
    expect(fetch.calls.map((c) => c.action)).toEqual(["ListRecords"]);
  });

  it("记录在 zone 根上时主机记录为 @；子 zone 下用相对名，TTL 取 zone 的版本下限", async () => {
    const sub: DnsZone = { name: "a.example.com", id: "99", extra: { ttl: "60" } };
    const fetch = dns((action) => (action === "ListRecords" ? ok({ TotalCount: 0, Records: [] }) : ok({ RecordID: "r1" })));
    await volcengineDns.addTxt(ctxOf(fetch), CREDS, rec("a.example.com", sub));
    await volcengineDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.www.a.example.com", sub));
    const creates = fetch.calls.filter((c) => c.action === "CreateRecord").map((c) => c.json);
    expect(creates).toEqual([
      { ZID: 99, Host: "@", Type: "TXT", Value: VALUE, TTL: 60, Line: "default" },
      { ZID: 99, Host: "_acme-challenge.www", Type: "TXT", Value: VALUE, TTL: 60, Line: "default" },
    ]);
  });

  it("同名记录按 TotalCount 翻页查完", async () => {
    const fetch = dns((action, p) => {
      if (action !== "ListRecords") return undefined;
      if (p.PageNumber === "1") return ok({ TotalCount: 101, Records: Array.from({ length: 100 }, (_, i) => txt(`o${i}`, "_acme-challenge", `${i}`.padEnd(43, "x"))) });
      return ok({ TotalCount: 101, Records: [txt("mine", "_acme-challenge", VALUE)] });
    });
    expect(await volcengineDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).toBe("mine");
    expect(fetch.calls.map((c) => params(c).PageNumber)).toEqual(["1", "2"]);
  });

  it("ErrDBDuplicated（HTTP 409）：查出已有的那条当句柄", async () => {
    let listed = 0;
    const fetch = dns((action) => {
      if (action === "ListRecords") return ok({ TotalCount: listed++ === 0 ? 0 : 1, Records: listed === 1 ? [] : [txt("dup1", "_acme-challenge", VALUE)] });
      if (action === "CreateRecord") return volcError(409, "ErrDBDuplicated", "duplicated: record");
      return undefined;
    });
    expect(await volcengineDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).toBe("dup1");
    expect(fetch.calls.map((c) => c.action)).toEqual(["ListRecords", "CreateRecord", "ListRecords"]);
  });

  it("ErrDBDuplicated 却查不到同值的记录：报 RecordMayExist（可能已添加），带 RequestId，不再重试", async () => {
    const fetch = dns((action) => {
      if (action === "ListRecords") return ok({ TotalCount: 1, Records: [txt("other", "_acme-challenge", OTHER)] });
      if (action === "CreateRecord") return volcError(409, "ErrDBDuplicated", "duplicated: record");
      return undefined;
    });
    const err = await volcengineDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com")).catch((e: unknown) => e);
    expect(err).toMatchObject({ provider: "volcengine", code: "RecordMayExist", requestId: "rid-err" });
    expect((err as Error).message).toMatch(/ErrDBDuplicated.*可能已添加/);
    expect(fetch.calls.map((c) => c.action)).toEqual(["ListRecords", "CreateRecord", "ListRecords"]);
  });

  it("TTL 不符合版本规格（ErrSpecNotValid）时退回 600 再加一次", async () => {
    const paid: DnsZone = { ...ZONE, extra: { ttl: "1" } };
    const fetch = dns((action, p) => {
      if (action === "ListRecords") return ok({ TotalCount: 0, Records: [] });
      if (action === "CreateRecord") return p.TTL === 1 ? volcError(400, "ErrSpecNotValid", "record ttl not valid when creating record") : ok({ RecordID: "r600" });
      return undefined;
    });
    expect(await volcengineDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com", paid))).toBe("r600");
    expect(fetch.calls.filter((c) => c.action === "CreateRecord").map((c) => c.json?.TTL)).toEqual([1, 600]);
  });

  it("CreateRecord 超时后整体重来：先查到上一次其实已加上的记录，不重复添加", async () => {
    let created = false;
    const sleeps: number[] = [];
    const fetch = dns((action) => {
      if (action === "ListRecords") return ok({ TotalCount: created ? 1 : 0, Records: created ? [txt("late", "_acme-challenge", VALUE)] : [] });
      if (action === "CreateRecord") {
        created = true;
        timeout();
      }
      return undefined;
    });
    expect(await volcengineDns.addTxt(ctxOf(fetch, sleeps), CREDS, rec("_acme-challenge.example.com"))).toBe("late");
    expect(fetch.calls.map((c) => c.action)).toEqual(["ListRecords", "CreateRecord", "ListRecords"]);
    expect(sleeps).toEqual([500]);
  });

  it("业务错误原样抛出（如域名待找回 ErrZoneInactive）", async () => {
    const fetch = dns((action) => (action === "ListRecords" ? volcError(400, "ErrZoneInactive", "zone is inactive") : undefined));
    await expect(volcengineDns.addTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"))).rejects.toMatchObject({
      provider: "volcengine",
      code: "ErrZoneInactive",
      requestId: "rid-err",
    });
  });
});

describe("火山引擎云解析 removeTxt", () => {
  it("按 RecordID 删除（POST JSON），只删这一条", async () => {
    const fetch = dns((action) => (action === "DeleteRecord" ? ok() : undefined));
    await volcengineDns.removeTxt(ctxOf(fetch), CREDS, rec("_acme-challenge.example.com"), "3170534137672596377");
    expect(fetch.calls).toHaveLength(1);
    expect(fetch.calls[0]!.method).toBe("POST");
    expect(fetch.calls[0]!.json).toEqual({ RecordID: "3170534137672596377" });
  });

  it("记录已不存在（ErrDBNotFound）视为成功；其他错误照常抛出", async () => {
    const gone = dns(() => volcError(400, "ErrDBNotFound", "record not found :3170534137672596377"));
    await expect(volcengineDns.removeTxt(ctxOf(gone), CREDS, rec("_acme-challenge.example.com"), "3170534137672596377")).resolves.toBeUndefined();
    const denied = dns(() => volcError(403, "AccessDenied"));
    await expect(volcengineDns.removeTxt(ctxOf(denied), CREDS, rec("_acme-challenge.example.com"), "1")).rejects.toMatchObject({ code: "AccessDenied" });
  });
});
