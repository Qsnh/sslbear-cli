import { describe, expect, it } from "vitest";
import { digitaloceanDns } from "../src/dns/digitalocean.js";
import type { DnsZone, TxtRecord } from "../src/dns/types.js";
import { CloudApiError, isRetryable, type Fetch, type QueryContext } from "../src/lib/http.js";
import { fakeFetch, type FakeReply, type FakeRequest } from "./helpers.js";

const CREDS = { token: "do-test-token" };
const ctx = (fetch: Fetch): QueryContext => ({ fetch, timeoutMs: 1000, now: new Date("2026-10-18T00:00:00Z"), env: {}, sleep: async () => {} });

const ZONE: DnsZone = { name: "example.com", id: "example.com" };
const RECORD: TxtRecord = { zone: ZONE, fqdn: "_acme-challenge.www.example.com", value: "value-www" };
const RECORDS_PATH = "/v2/domains/example.com/records";

/** 记录列表响应：DigitalOcean 返回的 name 是相对名，非 SRV / CAA 的字段为 null */
const txt = (id: number, data: string, name = "_acme-challenge.www") => ({ id, type: "TXT", name, data, priority: null, port: null, ttl: 30, weight: null, flags: null, tag: null });
const list = (records: unknown[]): FakeReply => ({ body: { domain_records: records, links: {}, meta: { total: records.length } } });
const isRecords = (req: FakeRequest) => req.url.pathname === RECORDS_PATH;
const deleted = (calls: FakeRequest[]) => calls.filter((c) => c.method === "DELETE").map((c) => c.url.pathname.split("/").pop());

describe("DigitalOcean listZones", () => {
  it("按 page / per_page 翻页，以 meta.total 为准（接口截小每页条数也不漏）", async () => {
    const all = [{ name: "Example.com" }, { name: "b.example.org" }, { name: "c.net." }];
    const fetch = fakeFetch((req) => {
      if (req.url.pathname !== "/v2/domains") return undefined;
      const page = Number(req.url.searchParams.get("page"));
      // 每页只给 2 条（小于请求的 200）
      const items = all.slice((page - 1) * 2, page * 2).map((d) => ({ ...d, ttl: 1800, zone_file: "..." }));
      return { body: { domains: items, links: page === 1 ? { pages: { next: "https://api.digitalocean.com/v2/domains?page=2" } } : {}, meta: { total: 3 } } };
    });
    const zones = await digitaloceanDns.listZones(ctx(fetch), CREDS);
    expect(zones).toEqual([
      { name: "example.com", id: "example.com" },
      { name: "b.example.org", id: "b.example.org" },
      { name: "c.net", id: "c.net" },
    ]);
    expect(fetch.calls.map((c) => c.url.search)).toEqual(["?page=1&per_page=200", "?page=2&per_page=200"]);
    expect(fetch.calls[0]!.headers.authorization).toBe("Bearer do-test-token");
  });

  it("NS 规则：ns1~ns3.digitalocean.com", () => {
    expect(digitaloceanDns.nameServerPattern.test("ns2.digitalocean.com")).toBe(true);
    expect(digitaloceanDns.nameServerPattern.test("ns4.digitalocean.com")).toBe(false);
  });

  it("401 的 message 说明令牌需要的权限，带上 request_id", async () => {
    const fetch = fakeFetch(() => ({ status: 401, body: { id: "unauthorized", message: "Unable to authenticate you.", request_id: "req-1" } }));
    const err = await digitaloceanDns.listZones(ctx(fetch), CREDS).catch((e) => e);
    expect(err).toBeInstanceOf(CloudApiError);
    expect(err).toMatchObject({ provider: "digitalocean", code: "unauthorized", requestId: "req-1", httpStatus: 401 });
    expect(err.message).toContain("domain:read 与 domain:update");
    expect(fetch.calls).toHaveLength(1);
  });

  it("429 记为 Throttling、5xx 记为 ServiceUnavailable，自动重试", async () => {
    const throttled = await digitaloceanDns.listZones(ctx(fakeFetch(() => ({ status: 429, body: { id: "too_many_requests", message: "API rate limit exceeded." } }))), CREDS).catch((e) => e);
    expect(throttled).toMatchObject({ code: "Throttling", httpStatus: 429 });
    expect(isRetryable(throttled)).toBe(true);

    let n = 0;
    const fetch = fakeFetch(() => (++n === 1 ? { status: 500, body: { id: "server_error", message: "Unexpected server-side error" } } : { body: { domains: [], links: {}, meta: { total: 0 } } }));
    expect(await digitaloceanDns.listZones(ctx(fetch), CREDS)).toEqual([]);
    expect(fetch.calls).toHaveLength(2);
  });
});

describe("DigitalOcean addTxt", () => {
  it("先按 type 与完整名查找，再 POST 相对名、最小 TTL 30", async () => {
    const fetch = fakeFetch((req) => {
      if (!isRecords(req)) return undefined;
      if (req.method === "GET") return list([]);
      if (req.method === "POST") return { status: 201, body: { domain_record: txt(1001, RECORD.value) } };
      return undefined;
    });
    expect(await digitaloceanDns.addTxt(ctx(fetch), CREDS, RECORD)).toBe("1001");

    const [get, post] = fetch.calls;
    expect(get!.url.searchParams.get("type")).toBe("TXT");
    expect(get!.url.searchParams.get("name")).toBe("_acme-challenge.www.example.com");
    expect(post!.method).toBe("POST");
    expect(post!.url.href).toBe("https://api.digitalocean.com/v2/domains/example.com/records");
    expect(post!.headers.authorization).toBe("Bearer do-test-token");
    expect(post!.headers["content-type"]).toBe("application/json");
    expect(post!.json).toEqual({ type: "TXT", name: "_acme-challenge.www", data: "value-www", ttl: 30 });
  });

  it("同名下已有其他值：照常新增一条，不动已有的", async () => {
    const fetch = fakeFetch((req) => {
      if (!isRecords(req)) return undefined;
      if (req.method === "GET") return list([txt(900, "value-other")]);
      if (req.method === "POST") return { status: 201, body: { domain_record: txt(1001, RECORD.value) } };
      return undefined;
    });
    expect(await digitaloceanDns.addTxt(ctx(fetch), CREDS, RECORD)).toBe("1001");
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET", "POST"]);
  });

  it("同名同值已存在：不新增，返回已有记录的 ID", async () => {
    const fetch = fakeFetch((req) => (isRecords(req) && req.method === "GET" ? list([txt(900, "value-other"), txt(901, RECORD.value)]) : undefined));
    expect(await digitaloceanDns.addTxt(ctx(fetch), CREDS, RECORD)).toBe("901");
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET"]);
  });

  it("POST 超时后自动重试前先查重：上一次其实已经加上了就不再提交", async () => {
    let gets = 0;
    let posts = 0;
    const fetch: Fetch = async (input, init) => {
      if (init?.method === "POST") {
        posts++;
        throw Object.assign(new Error("timed out"), { name: "TimeoutError" });
      }
      return new Response(JSON.stringify({ domain_records: ++gets === 1 ? [] : [txt(1001, RECORD.value)], meta: { total: gets === 1 ? 0 : 1 } }));
    };
    expect(await digitaloceanDns.addTxt(ctx(fetch), CREDS, RECORD)).toBe("1001");
    expect(posts).toBe(1);
  });

  it("POST 报 422 时再查一次：已有就按已存在处理，没有就原样报错", async () => {
    let gets = 0;
    const fetch = fakeFetch((req) => {
      if (!isRecords(req)) return undefined;
      if (req.method === "GET") return list(++gets === 1 ? [] : [txt(1002, RECORD.value)]);
      return { status: 422, body: { id: "unprocessable_entity", message: "Record already exists" } };
    });
    expect(await digitaloceanDns.addTxt(ctx(fetch), CREDS, RECORD)).toBe("1002");

    const conflict = fakeFetch((req) => {
      if (!isRecords(req)) return undefined;
      if (req.method === "GET") return list([]);
      return { status: 422, body: { id: "unprocessable_entity", message: "CNAME records cannot share a name with other records." } };
    });
    await expect(digitaloceanDns.addTxt(ctx(conflict), CREDS, RECORD)).rejects.toMatchObject({ code: "unprocessable_entity", httpStatus: 422 });
  });
});

describe("DigitalOcean removeTxt", () => {
  it("按句柄删除，再清掉同名同值的重复记录；同名下的其他值不动", async () => {
    const fetch = fakeFetch((req) => {
      if (req.method === "DELETE" && req.url.pathname.startsWith(`${RECORDS_PATH}/`)) return { status: 200, body: "" };
      if (isRecords(req) && req.method === "GET") return list([txt(900, "value-other"), txt(1003, RECORD.value)]);
      return undefined;
    });
    await digitaloceanDns.removeTxt(ctx(fetch), CREDS, RECORD, "1001");
    expect(deleted(fetch.calls)).toEqual(["1001", "1003"]);
    expect(fetch.calls[0]!.headers.authorization).toBe("Bearer do-test-token");
  });

  it("记录已不存在（404）视为成功；域名已不在账号里也视为成功", async () => {
    const gone = fakeFetch((req) => {
      if (req.method === "DELETE") return { status: 404, body: { id: "not_found", message: "The resource you were accessing could not be found." } };
      return list([]);
    });
    await digitaloceanDns.removeTxt(ctx(gone), CREDS, RECORD, "1001");
    expect(deleted(gone.calls)).toEqual(["1001"]);

    await digitaloceanDns.removeTxt(ctx(fakeFetch(() => ({ status: 404, body: { id: "not_found", message: "not found" } }))), CREDS, RECORD, "1001");
  });

  it("没有删除权限时报错", async () => {
    const fetch = fakeFetch(() => ({ status: 403, body: { id: "forbidden", message: "You do not have access for the attempted action." } }));
    await expect(digitaloceanDns.removeTxt(ctx(fetch), CREDS, RECORD, "1001")).rejects.toMatchObject({ code: "forbidden", httpStatus: 403 });
  });
});
