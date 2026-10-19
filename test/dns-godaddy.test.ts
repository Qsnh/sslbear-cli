import { describe, expect, it } from "vitest";
import { godaddyDns } from "../src/dns/godaddy.js";
import type { DnsZone, TxtRecord } from "../src/dns/types.js";
import { CloudApiError, isRetryable, type Fetch, type QueryContext } from "../src/lib/http.js";
import { fakeFetch, type FakeRequest } from "./helpers.js";

const CREDS = { apiKey: "gd-test-key", apiSecret: "gd-test-secret" };
const ctx = (fetch: Fetch): QueryContext => ({ fetch, timeoutMs: 1000, now: new Date("2026-10-18T00:00:00Z"), env: {}, sleep: async () => {} });

const ZONE: DnsZone = { name: "example.com", id: "example.com", nameServers: ["ns51.domaincontrol.com", "ns52.domaincontrol.com"] };
const RECORD: TxtRecord = { zone: ZONE, fqdn: "_acme-challenge.www.example.com", value: "value-www" };
const NAME_PATH = "/v1/domains/example.com/records/TXT/_acme-challenge.www";
const isName = (req: FakeRequest) => req.url.pathname === NAME_PATH;
const isPatch = (req: FakeRequest) => req.method === "PATCH" && req.url.pathname === "/v1/domains/example.com/records";
const writes = (calls: FakeRequest[]) => calls.filter((c) => c.method !== "GET").map((c) => `${c.method} ${c.url.pathname}`);

/** 记录查询接口返回的 TXT 记录 */
const txt = (data: string, ttl = 600) => ({ data, name: "_acme-challenge.www", ttl, type: "TXT" });
const domain = (name: string, status: string, nameServers: string[] | null) => ({ domainId: 1, domain: name, status, nameServers, expires: "2027-01-01T00:00:00.000Z", locked: true });

describe("GoDaddy listZones", () => {
  it("按 marker 翻页直到空页，只返回 ACTIVE 且 DNS 在 GoDaddy 的域名", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.pathname !== "/v1/domains") return undefined;
      const marker = req.url.searchParams.get("marker");
      if (marker === null) {
        return {
          body: [
            domain("Example.com", "ACTIVE", ["NS51.DOMAINCONTROL.COM", "ns52.domaincontrol.com."]),
            // DNS 改到了别家：GoDaddy 的解析记录不生效
            domain("elsewhere.com", "ACTIVE", ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"]),
            // 部分 NS 在 GoDaddy：只把 GoDaddy 的填进 nameServers
            domain("mixed.com", "ACTIVE", ["ns01.domaincontrol.com", "ns1.other-dns.net"]),
            domain("expired.com", "EXPIRED", ["ns51.domaincontrol.com"]),
          ],
        };
      }
      if (marker === "expired.com") return { body: [domain("nons.com", "ACTIVE", null)] };
      if (marker === "nons.com") return { body: [] };
      return undefined;
    });
    const zones = await godaddyDns.listZones(ctx(fetch), CREDS);
    expect(zones).toEqual([
      { name: "example.com", id: "example.com", nameServers: ["ns51.domaincontrol.com", "ns52.domaincontrol.com"] },
      { name: "mixed.com", id: "mixed.com", nameServers: ["ns01.domaincontrol.com"] },
      // 接口没返回 NS：照常列出，按 nameServerPattern 判定
      { name: "nons.com", id: "nons.com" },
    ]);

    const first = fetch.calls[0]!;
    expect(first.url.searchParams.get("statuses")).toBe("ACTIVE");
    expect(first.url.searchParams.get("includes")).toBe("nameServers");
    expect(first.url.searchParams.get("limit")).toBe("1000");
    expect(first.headers.authorization).toBe("sso-key gd-test-key:gd-test-secret");
    expect(first.headers.accept).toBe("application/json");
    expect(fetch.calls.map((c) => c.url.searchParams.get("marker"))).toEqual([null, "expired.com", "nons.com"]);
  });

  it("接口忽略 marker、一直返回同一页时停下", async () => {
    const fetch = fakeFetch((req) => (req.url.pathname === "/v1/domains" ? { body: [domain("a.com", "ACTIVE", ["ns1.domaincontrol.com"])] } : undefined));
    expect(await godaddyDns.listZones(ctx(fetch), CREDS)).toHaveLength(1);
    expect(fetch.calls).toHaveLength(2);
  });

  it("403（账号不符合 API 开放条件）的 message 说明原因，不重试", async () => {
    const fetch = fakeFetch(() => ({ status: 403, body: { code: "ACCESS_DENIED", message: "Authenticated user is not allowed access" } }));
    const err = await godaddyDns.listZones(ctx(fetch), CREDS).catch((e) => e);
    expect(err).toBeInstanceOf(CloudApiError);
    expect(err).toMatchObject({ provider: "godaddy", code: "ACCESS_DENIED", httpStatus: 403 });
    expect(err.message).toContain("至少持有 1 个域名");
    expect(err.message).toContain("10 个以上域名");
    expect(fetch.calls).toHaveLength(1);
  });

  it("401 提示检查是否为 Production 密钥", async () => {
    const fetch = fakeFetch(() => ({ status: 401, body: { code: "UNABLE_TO_AUTHENTICATE", message: "Unable to authenticate" } }));
    const err = await godaddyDns.listZones(ctx(fetch), CREDS).catch((e) => e);
    expect(err).toMatchObject({ code: "UNABLE_TO_AUTHENTICATE", httpStatus: 401 });
    expect(err.message).toContain("Production");
  });

  it("429（可能没有响应体）记为 Throttling、5xx 记为 ServiceUnavailable，自动重试", async () => {
    const throttled = await godaddyDns.listZones(ctx(fakeFetch(() => ({ status: 429, body: "" }))), CREDS).catch((e) => e);
    expect(throttled).toMatchObject({ code: "Throttling", httpStatus: 429 });
    expect(isRetryable(throttled)).toBe(true);

    let n = 0;
    const fetch = fakeFetch(() => (++n === 1 ? { status: 500, body: { code: "INTERNAL_SERVER_ERROR", message: "oops" } } : { body: [] }));
    expect(await godaddyDns.listZones(ctx(fetch), CREDS)).toEqual([]);
    expect(fetch.calls).toHaveLength(2);
  });
});

describe("GoDaddy addTxt", () => {
  it("先查这个名字下的 TXT，再 PATCH 追加：相对名、最小 TTL 600，句柄含名字与值", async () => {
    const fetch = fakeFetch((req) => {
      if (isName(req) && req.method === "GET") return { body: [] };
      if (isPatch(req)) return { body: "" };
      return undefined;
    });
    expect(await godaddyDns.addTxt(ctx(fetch), CREDS, RECORD)).toBe("TXT:_acme-challenge.www:value-www");

    const [list, patch] = fetch.calls;
    // recordGet 的 limit 显式带上
    expect(list!.url.href).toBe(`https://api.godaddy.com${NAME_PATH}?limit=100`);
    expect(patch!.url.href).toBe("https://api.godaddy.com/v1/domains/example.com/records");
    expect(patch!.headers.authorization).toBe("sso-key gd-test-key:gd-test-secret");
    expect(patch!.headers["content-type"]).toBe("application/json");
    expect(JSON.parse(patch!.body)).toEqual([{ type: "TXT", name: "_acme-challenge.www", data: "value-www", ttl: 600 }]);
  });

  it("同名下已有其他值：只追加自己的值，不用 PUT 覆盖、不删除", async () => {
    const fetch = fakeFetch((req) => {
      if (isName(req) && req.method === "GET") return { body: [txt("value-other", 3600)] };
      if (isPatch(req)) return { body: "" };
      return undefined;
    });
    await godaddyDns.addTxt(ctx(fetch), CREDS, RECORD);
    expect(writes(fetch.calls)).toEqual(["PATCH /v1/domains/example.com/records"]);
    expect(JSON.parse(fetch.calls[1]!.body)).toHaveLength(1);
  });

  it("同名同值已存在：不追加", async () => {
    const fetch = fakeFetch((req) => (isName(req) && req.method === "GET" ? { body: [txt("value-other"), txt("value-www")] } : undefined));
    expect(await godaddyDns.addTxt(ctx(fetch), CREDS, RECORD)).toBe("TXT:_acme-challenge.www:value-www");
    expect(writes(fetch.calls)).toEqual([]);
  });

  it("名字下没有记录时查询返回 404 也当作空", async () => {
    const fetch = fakeFetch((req) => {
      if (isName(req) && req.method === "GET") return { status: 404, body: { code: "NOT_FOUND", message: "Not found" } };
      if (isPatch(req)) return { body: "" };
      return undefined;
    });
    await godaddyDns.addTxt(ctx(fetch), CREDS, RECORD);
    expect(writes(fetch.calls)).toEqual(["PATCH /v1/domains/example.com/records"]);
  });

  it("PATCH 遇到 5xx 自动重试前先查重：上一次其实已经加上了就不再追加（PATCH 不是幂等的）", async () => {
    let gets = 0;
    const fetch = fakeFetch((req) => {
      if (isName(req) && req.method === "GET") return { body: ++gets === 1 ? [] : [txt("value-www")] };
      if (isPatch(req)) return { status: 504, body: { code: "GATEWAY_TIMEOUT", message: "Gateway timeout" } };
      return undefined;
    });
    await godaddyDns.addTxt(ctx(fetch), CREDS, RECORD);
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET", "PATCH", "GET"]);
  });

  it("PATCH 报 422 重复时再查一次，已有就按已存在处理", async () => {
    let gets = 0;
    const fetch = fakeFetch((req) => {
      if (isName(req) && req.method === "GET") return { body: ++gets === 1 ? [] : [txt("value-www")] };
      if (isPatch(req)) return { status: 422, body: { code: "DUPLICATE_RECORD", message: "Another record with the same attributes already exists" } };
      return undefined;
    });
    expect(await godaddyDns.addTxt(ctx(fetch), CREDS, RECORD)).toBe("TXT:_acme-challenge.www:value-www");
  });

  it("查询返回空响应体时报 InvalidResponse，不当成空列表", async () => {
    const fetch = fakeFetch((req) => (isName(req) ? { body: "" } : undefined));
    await expect(godaddyDns.addTxt(ctx(fetch), CREDS, RECORD)).rejects.toMatchObject({ code: "InvalidResponse" });
  });
});

describe("GoDaddy removeTxt", () => {
  it("同名下还有其他值：PUT 这个名字写回其余值（保留各自 TTL），只去掉自己的", async () => {
    const fetch = fakeFetch((req) => {
      if (!isName(req)) return undefined;
      if (req.method === "GET") return { body: [txt("value-other", 3600), txt("value-www")] };
      if (req.method === "PUT") return { body: "" };
      return undefined;
    });
    await godaddyDns.removeTxt(ctx(fetch), CREDS, RECORD, "TXT:_acme-challenge.www:value-www");
    expect(writes(fetch.calls)).toEqual([`PUT ${NAME_PATH}`]);
    expect(JSON.parse(fetch.calls[1]!.body)).toEqual([{ data: "value-other", ttl: 3600 }]);
  });

  it("只剩自己的值（含重复添加出的多条）：DELETE 这个名字下的 TXT", async () => {
    const fetch = fakeFetch((req) => {
      if (!isName(req)) return undefined;
      if (req.method === "GET") return { body: [txt("value-www"), txt('"value-www"')] };
      if (req.method === "DELETE") return { body: "" };
      return undefined;
    });
    await godaddyDns.removeTxt(ctx(fetch), CREDS, RECORD, "TXT:_acme-challenge.www:value-www");
    expect(writes(fetch.calls)).toEqual([`DELETE ${NAME_PATH}`]);
  });

  it("值已不在（或名字下没有记录 / 404）：不写入，视为成功", async () => {
    const other = fakeFetch((req) => (isName(req) && req.method === "GET" ? { body: [txt("value-other")] } : undefined));
    await godaddyDns.removeTxt(ctx(other), CREDS, RECORD, "h");
    expect(writes(other.calls)).toEqual([]);

    const missing = fakeFetch(() => ({ status: 404, body: { code: "NOT_FOUND", message: "Not found" } }));
    await godaddyDns.removeTxt(ctx(missing), CREDS, RECORD, "h");
    expect(writes(missing.calls)).toEqual([]);
  });

  it("DELETE 时已被删掉（404）视为成功", async () => {
    const fetch = fakeFetch((req) => {
      if (!isName(req)) return undefined;
      if (req.method === "GET") return { body: [txt("value-www")] };
      return { status: 404, body: { code: "NOT_FOUND", message: "Domain not found" } };
    });
    await godaddyDns.removeTxt(ctx(fetch), CREDS, RECORD, "h");
  });

  it("服务端忽略了名字（返回别的名字 / 类型的记录）：本地按名字（大小写不敏感）和类型过滤后再算要保留的值", async () => {
    const fetch = fakeFetch((req) => {
      if (!isName(req)) return undefined;
      if (req.method === "GET") {
        return {
          body: [
            { data: "value-root", name: "@", ttl: 600, type: "TXT" },
            { data: "value-www", name: "_acme-challenge", ttl: 600, type: "TXT" },
            { data: "value-cname", name: "_acme-challenge.www", ttl: 600, type: "CNAME" },
            { data: "value-other", name: "_ACME-Challenge.WWW", ttl: 3600, type: "TXT" },
            txt("value-www"),
          ],
        };
      }
      if (req.method === "PUT") return { body: "" };
      return undefined;
    });
    await godaddyDns.removeTxt(ctx(fetch), CREDS, RECORD, "h");
    expect(writes(fetch.calls)).toEqual([`PUT ${NAME_PATH}`]);
    expect(JSON.parse(fetch.calls[1]!.body)).toEqual([{ data: "value-other", ttl: 3600 }]);

    // 过滤后只剩自己的值：DELETE 这个名字，不把别的名字的记录写进来
    const only = fakeFetch((req) => {
      if (!isName(req)) return undefined;
      if (req.method === "GET") return { body: [{ data: "value-root", name: "@", ttl: 600, type: "TXT" }, txt("value-www")] };
      if (req.method === "DELETE") return { body: "" };
      return undefined;
    });
    await godaddyDns.removeTxt(ctx(only), CREDS, RECORD, "h");
    expect(writes(only.calls)).toEqual([`DELETE ${NAME_PATH}`]);
  });

  it("查询返回条数达到 limit（可能没取全）：不写回、不删除，报 TooManyRecords", async () => {
    const many = [...Array.from({ length: 99 }, (_, i) => txt(`value-${i}`)), txt("value-www")];
    const fetch = fakeFetch((req) => (isName(req) && req.method === "GET" ? { body: many } : undefined));
    const err = await godaddyDns.removeTxt(ctx(fetch), CREDS, RECORD, "h").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CloudApiError);
    expect(err).toMatchObject({ provider: "godaddy", code: "TooManyRecords" });
    expect((err as Error).message).toMatch(/无法安全修改/);
    expect(isRetryable(err)).toBe(false);
    expect(writes(fetch.calls)).toEqual([]);
    expect(fetch.calls[0]!.url.searchParams.get("limit")).toBe("100");

    // 本次的值不在取到的这一页里也不能当成已删除
    const unseen = fakeFetch((req) => (isName(req) && req.method === "GET" ? { body: Array.from({ length: 100 }, (_, i) => txt(`value-${i}`)) } : undefined));
    await expect(godaddyDns.removeTxt(ctx(unseen), CREDS, RECORD, "h")).rejects.toMatchObject({ code: "TooManyRecords" });
  });

  it("根域名（@）的记录名在路径里原样保留", async () => {
    const apex: TxtRecord = { zone: { name: "_acme-challenge.example.com", id: "_acme-challenge.example.com" }, fqdn: "_acme-challenge.example.com", value: "v" };
    const fetch = fakeFetch((req) => (req.url.pathname === "/v1/domains/_acme-challenge.example.com/records/TXT/@" ? { body: [] } : undefined));
    await godaddyDns.removeTxt(ctx(fetch), CREDS, apex, "h");
    expect(fetch.calls).toHaveLength(1);
  });
});
