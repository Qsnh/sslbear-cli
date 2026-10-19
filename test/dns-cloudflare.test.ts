import { describe, expect, it } from "vitest";
import { cloudflareDns } from "../src/dns/cloudflare.js";
import type { DnsZone, TxtRecord } from "../src/dns/types.js";
import { CloudApiError, isRetryable, type Fetch, type QueryContext } from "../src/lib/http.js";
import { fakeFetch, type FakeReply, type FakeRequest } from "./helpers.js";

const CREDS = { apiToken: "cf-test-token" };
const ctx = (fetch: Fetch): QueryContext => ({ fetch, timeoutMs: 1000, now: new Date("2026-10-18T00:00:00Z"), env: {}, sleep: async () => {} });

const ZONE: DnsZone = { name: "example.com", id: "zone-1" };
const RECORD: TxtRecord = { zone: ZONE, fqdn: "_acme-challenge.example.com", value: "value-root" };
const ok = (result: unknown, info?: Record<string, number>): FakeReply => ({ body: { success: true, errors: [], messages: [], result, ...(info && { result_info: info }) } });
const fail = (status: number, code: number, message: string): FakeReply => ({ status, body: { success: false, errors: [{ code, message }], messages: [], result: null } });
const isRecords = (req: FakeRequest) => req.url.pathname === "/client/v4/zones/zone-1/dns_records";

/** 一条 TXT 记录，content 按 Cloudflare 现在的返回形态带引号 */
const txt = (id: string, value: string, name = RECORD.fqdn) => ({ id, type: "TXT", name, content: `"${value}"`, ttl: 60, proxied: false });

describe("Cloudflare listZones", () => {
  it("按 page / per_page 翻页取全，只返回 active 且 type=full 的 zone，NS 规范化", async () => {
    const page1 = Array.from({ length: 50 }, (_, i) => ({ id: `z${i}`, name: `site${i}.com`, status: "active", type: "full", name_servers: ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"] }));
    const page2 = [
      { id: "z-a", name: "Example.COM", status: "active", type: "full", name_servers: ["ADA.ns.cloudflare.com.", "bob.ns.cloudflare.com"], vanity_name_servers: ["ns1.example.com"] },
      { id: "z-p", name: "pending.com", status: "pending", type: "full", name_servers: ["ada.ns.cloudflare.com"] },
      { id: "z-m", name: "moved.com", status: "moved", type: "full", name_servers: ["ada.ns.cloudflare.com"] },
      { id: "z-c", name: "cname-setup.com", status: "active", type: "partial", name_servers: ["ada.ns.cloudflare.com"] },
      { id: "z-s", name: "secondary.com", status: "active", type: "secondary", name_servers: ["ada.ns.cloudflare.com"] },
      // 老接口不带 type：按缺省 full 处理
      { id: "z-o", name: "old.com", status: "active", name_servers: [] },
    ];
    const fetch = fakeFetch((req) => {
      if (req.url.pathname !== "/client/v4/zones") return undefined;
      const page = req.url.searchParams.get("page");
      const info = { page: Number(page), per_page: 50, total_count: 56 };
      return page === "1" ? ok(page1, { ...info, count: 50 }) : page === "2" ? ok(page2, { ...info, count: 6 }) : ok([], { ...info, count: 0 });
    });
    const zones = await cloudflareDns.listZones(ctx(fetch), CREDS);

    expect(fetch.calls.map((c) => c.url.search)).toEqual(["?page=1&per_page=50", "?page=2&per_page=50"]);
    expect(fetch.calls[0]!.headers.authorization).toBe("Bearer cf-test-token");
    expect(zones).toHaveLength(52);
    expect(zones.find((z) => z.id === "z-a")).toEqual({
      name: "example.com",
      id: "z-a",
      nameServers: ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com", "ns1.example.com"],
    });
    expect(zones.find((z) => z.id === "z-o")).toEqual({ name: "old.com", id: "z-o" });
    for (const id of ["z-p", "z-m", "z-c", "z-s"]) expect(zones.some((z) => z.id === id)).toBe(false);
  });

  it("鉴权失败：403 / 10000 的 message 说明需要的令牌权限，不重试", async () => {
    const fetch = fakeFetch(() => fail(403, 10000, "Authentication error"));
    const err = await cloudflareDns.listZones(ctx(fetch), CREDS).catch((e) => e);
    expect(err).toBeInstanceOf(CloudApiError);
    expect(err).toMatchObject({ provider: "cloudflare", code: "10000", httpStatus: 403 });
    expect(err.message).toContain("Zone → Zone → Read");
    expect(err.message).toContain("Zone → DNS → Edit");
    expect(fetch.calls).toHaveLength(1);
  });

  it("令牌格式不对（400 + error_chain 6111）也按鉴权失败提示", async () => {
    const fetch = fakeFetch(() => ({
      status: 400,
      body: { success: false, errors: [{ code: 6003, message: "Invalid request headers", error_chain: [{ code: 6111, message: "Invalid format for Authorization header" }] }], messages: [], result: null },
    }));
    const err = await cloudflareDns.listZones(ctx(fetch), CREDS).catch((e) => e);
    expect(err).toMatchObject({ code: "6003", httpStatus: 400 });
    expect(err.message).toContain("CLOUDFLARE_API_TOKEN");
  });

  it("429 记为 Throttling、5xx（含 HTML 网关页）记为 ServiceUnavailable，都会自动重试", async () => {
    let n = 0;
    const fetch = fakeFetch(() => {
      n++;
      if (n === 1) return fail(429, 971, "Please wait and consider throttling your request speed");
      if (n === 2) return { status: 502, body: "<html>Bad gateway</html>" };
      return ok([], { page: 1, per_page: 50, total_count: 0, count: 0 });
    });
    expect(await cloudflareDns.listZones(ctx(fetch), CREDS)).toEqual([]);
    expect(fetch.calls).toHaveLength(3);

    const throttled = await cloudflareDns.listZones(ctx(fakeFetch(() => fail(429, 971, "slow down"))), CREDS).catch((e) => e);
    expect(throttled).toMatchObject({ code: "Throttling", httpStatus: 429 });
    expect(isRetryable(throttled)).toBe(true);
    const down = await cloudflareDns.listZones(ctx(fakeFetch(() => ({ status: 503, body: "upstream" }))), CREDS).catch((e) => e);
    expect(down).toMatchObject({ code: "ServiceUnavailable", httpStatus: 503 });
    expect(isRetryable(down)).toBe(true);
  });

  it("HTTP 200 但 success: false 也按失败处理", async () => {
    const fetch = fakeFetch(() => ({ body: { success: false, errors: [{ code: 1001, message: "something" }], messages: [], result: null } }));
    await expect(cloudflareDns.listZones(ctx(fetch), CREDS)).rejects.toMatchObject({ code: "1001" });
  });
});

describe("Cloudflare addTxt", () => {
  it("先按类型与完整名精确查找，再 POST 新记录：完整名、带引号的 content、最小 TTL 60", async () => {
    const fetch = fakeFetch((req) => {
      if (!isRecords(req)) return undefined;
      if (req.method === "GET") return ok([], { page: 1, per_page: 100, total_count: 0, count: 0 });
      if (req.method === "POST") return ok(txt("rec-new", RECORD.value));
      return undefined;
    });
    expect(await cloudflareDns.addTxt(ctx(fetch), CREDS, RECORD)).toBe("rec-new");

    const [get, post] = fetch.calls;
    expect(get!.url.searchParams.get("type")).toBe("TXT");
    expect(get!.url.searchParams.get("name.exact")).toBe("_acme-challenge.example.com");
    expect(post!.method).toBe("POST");
    expect(post!.url.href).toBe("https://api.cloudflare.com/client/v4/zones/zone-1/dns_records");
    expect(post!.headers.authorization).toBe("Bearer cf-test-token");
    expect(post!.headers["content-type"]).toBe("application/json");
    expect(post!.json).toEqual({ type: "TXT", name: "_acme-challenge.example.com", content: '"value-root"', ttl: 60 });
  });

  it("同名下已有其他值：照常新增一条，不改动、不删除已有的", async () => {
    const fetch = fakeFetch((req) => {
      if (!isRecords(req)) return undefined;
      if (req.method === "GET") return ok([txt("rec-wild", "value-wild")], { page: 1, per_page: 100, total_count: 1, count: 1 });
      if (req.method === "POST") return ok(txt("rec-new", RECORD.value));
      return undefined;
    });
    expect(await cloudflareDns.addTxt(ctx(fetch), CREDS, RECORD)).toBe("rec-new");
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET", "POST"]);
  });

  it("同名同值已存在（content 带或不带引号）：不新增，返回已有记录的 ID", async () => {
    for (const content of ['"value-root"', "value-root"]) {
      const fetch = fakeFetch((req) =>
        isRecords(req) && req.method === "GET" ? ok([{ ...txt("rec-old", ""), content }], { page: 1, per_page: 100, total_count: 1, count: 1 }) : undefined,
      );
      expect(await cloudflareDns.addTxt(ctx(fetch), CREDS, RECORD)).toBe("rec-old");
      expect(fetch.calls.map((c) => c.method)).toEqual(["GET"]);
    }
  });

  it("本地再按名字过滤：过滤参数没生效、返回了别的名字的同值记录时不认", async () => {
    const fetch = fakeFetch((req) => {
      if (!isRecords(req)) return undefined;
      if (req.method === "GET") return ok([txt("rec-other", RECORD.value, "_acme-challenge.www.example.com")], { page: 1, per_page: 100, total_count: 1, count: 1 });
      return ok(txt("rec-new", RECORD.value));
    });
    expect(await cloudflareDns.addTxt(ctx(fetch), CREDS, RECORD)).toBe("rec-new");
  });

  it("POST 报 81058（已有相同记录）：再查一次，按已存在处理", async () => {
    let gets = 0;
    const fetch = fakeFetch((req) => {
      if (!isRecords(req)) return undefined;
      if (req.method === "GET") return ++gets === 1 ? ok([], { total_count: 0 }) : ok([txt("rec-dup", RECORD.value)], { total_count: 1 });
      return fail(400, 81058, "An identical record already exists.");
    });
    expect(await cloudflareDns.addTxt(ctx(fetch), CREDS, RECORD)).toBe("rec-dup");
  });

  it("POST 遇到 5xx 自动重试前先查重：上一次其实已经加上了就不再提交", async () => {
    let gets = 0;
    const fetch = fakeFetch((req) => {
      if (!isRecords(req)) return undefined;
      if (req.method === "GET") return ++gets === 1 ? ok([], { total_count: 0 }) : ok([txt("rec-created", RECORD.value)], { total_count: 1 });
      return { status: 504, body: "gateway timeout" };
    });
    expect(await cloudflareDns.addTxt(ctx(fetch), CREDS, RECORD)).toBe("rec-created");
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET", "POST", "GET"]);
  });

  it("其他错误（如同名 CNAME 冲突）原样抛出，不重试", async () => {
    const fetch = fakeFetch((req) => {
      if (!isRecords(req)) return undefined;
      if (req.method === "GET") return ok([], { total_count: 0 });
      return fail(400, 81054, "A CNAME record with that host already exists.");
    });
    await expect(cloudflareDns.addTxt(ctx(fetch), CREDS, RECORD)).rejects.toMatchObject({ code: "81054", httpStatus: 400 });
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET", "POST"]);
  });
});

describe("Cloudflare removeTxt", () => {
  it("按句柄（记录 ID）只删这一条", async () => {
    const fetch = fakeFetch((req) => (req.method === "DELETE" && req.url.pathname === "/client/v4/zones/zone-1/dns_records/rec-1" ? ok({ id: "rec-1" }) : undefined));
    await cloudflareDns.removeTxt(ctx(fetch), CREDS, RECORD, "rec-1");
    expect(fetch.calls).toHaveLength(1);
    expect(fetch.calls[0]!.headers.authorization).toBe("Bearer cf-test-token");
  });

  it("记录已不存在（404 / 81044）视为成功", async () => {
    await cloudflareDns.removeTxt(ctx(fakeFetch(() => fail(404, 81044, "Record does not exist."))), CREDS, RECORD, "rec-1");
    await cloudflareDns.removeTxt(ctx(fakeFetch(() => fail(400, 81044, "Record does not exist."))), CREDS, RECORD, "rec-1");
  });

  it("没有删除权限时报错并提示权限", async () => {
    const err = await cloudflareDns.removeTxt(ctx(fakeFetch(() => fail(403, 9109, "Unauthorized to access requested resource"))), CREDS, RECORD, "rec-1").catch((e) => e);
    expect(err).toMatchObject({ code: "9109", httpStatus: 403 });
    expect(err.message).toContain("Zone → DNS → Edit");
  });
});
