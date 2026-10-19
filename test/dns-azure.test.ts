import { afterEach, describe, expect, it, vi } from "vitest";
import { azureDns, type AzureCredentials } from "../src/dns/azure.js";
import type { DnsZone, TxtRecord } from "../src/dns/types.js";
import { isRetryable, type Fetch, type QueryContext } from "../src/lib/http.js";
import { fakeFetch, type FakeReply, type FakeRequest } from "./helpers.js";

const SUB = "00000000-0000-0000-0000-00000000000a";
const TENANT = "00000000-0000-0000-0000-00000000000b";
const SECRET = "fake-secret+/=&value";
let seq = 0;
/** 每个测试一个新的 client ID，进程内的令牌缓存互不影响 */
const creds = (): AzureCredentials => ({ tenantId: TENANT, clientId: `00000000-0000-0000-0000-${String(++seq).padStart(12, "0")}`, clientSecret: SECRET, subscriptionId: SUB });

const ctx = (fetch: Fetch): QueryContext => ({ fetch, timeoutMs: 5000, now: new Date(), env: {}, sleep: async () => {} });

const LOGIN_HOST = "login.microsoftonline.com";
const ARM_HOST = "management.azure.com";
const TOKEN_REPLY = { body: { token_type: "Bearer", expires_in: 3599, ext_expires_in: 3599, access_token: "fake-arm-access-token" } };
const armErr = (status: number, code: string, message = code) => ({ status, body: { error: { code, message } } });

const ZONE_ID = `/subscriptions/${SUB}/resourceGroups/dns-rg/providers/Microsoft.Network/dnszones/example.com`;
const ZONE: DnsZone = { name: "example.com", id: ZONE_ID, extra: { resourceGroup: "dns-rg" } };
const FQDN = "_acme-challenge.example.com";
const VALUE = "x".repeat(43);
const OTHER = "y".repeat(43);
const record = (fqdn = FQDN, value = VALUE): TxtRecord => ({ zone: ZONE, fqdn, value });

interface Props {
  TTL: number;
  metadata?: Record<string, string>;
  TXTRecords: { value: string[] }[];
}

/**
 * 内存版 Azure DNS 记录集接口：GET 不存在为 404，PUT / DELETE 与真实接口一样校验 If-Match（etag 对不上 412）
 * 与 If-None-Match: *（已存在 412），每次写入换新 etag；beforeWrite 可在写入前插入别人的改动，模拟并发冲突
 */
function azureDnsFake(initial: Record<string, Props> = {}, opts: { beforeWrite?: (n: number, sets: Map<string, { etag: string; properties: Props }>) => void } = {}) {
  let etagSeq = 0;
  const newEtag = () => `etag-${++etagSeq}`;
  const sets = new Map(Object.entries(initial).map(([k, v]) => [k, { etag: newEtag(), properties: structuredClone(v) }]));
  let writes = 0;
  const bump = (rel: string) => {
    const s = sets.get(rel)!;
    s.etag = newEtag();
  };
  const view = (rel: string) => {
    const s = sets.get(rel)!;
    return { id: `${ZONE_ID}/TXT/${rel}`, name: rel, type: "Microsoft.Network/dnszones/TXT", etag: s.etag, properties: { ...s.properties, fqdn: `${rel}.example.com.` } };
  };
  const fetch = fakeFetch((req): FakeReply => {
    if (req.url.host === LOGIN_HOST) return TOKEN_REPLY;
    if (req.url.host !== ARM_HOST || !req.url.pathname.startsWith(`${ZONE_ID}/TXT/`)) return undefined;
    expect(req.url.searchParams.get("api-version")).toBe("2018-05-01");
    const rel = decodeURIComponent(req.url.pathname.slice(`${ZONE_ID}/TXT/`.length));
    const current = sets.get(rel);
    if (req.method === "GET") return current ? { body: view(rel) } : armErr(404, "NotFound", `The resource record '${rel}' does not exist in resource group 'dns-rg'.`);
    opts.beforeWrite?.(++writes, sets);
    const latest = sets.get(rel);
    const ifMatch = req.headers["if-match"];
    if (ifMatch !== undefined && latest?.etag !== ifMatch) return armErr(412, "PreconditionFailed", "The condition specified using HTTP conditional header(s) is not met.");
    if (req.method === "PUT") {
      if (req.headers["if-none-match"] === "*" && latest) return armErr(412, "PreconditionFailed", "The Record set already exists.");
      const created = !latest;
      sets.set(rel, { etag: "", properties: (req.json as { properties: Props }).properties });
      bump(rel);
      return { status: created ? 201 : 200, body: view(rel) };
    }
    if (req.method === "DELETE") {
      sets.delete(rel);
      return { status: 200, body: "" };
    }
    return undefined;
  });
  return { fetch, sets, writes: () => fetch.calls.filter((c) => c.url.host === ARM_HOST && c.method !== "GET") };
}

const armCalls = (fetch: { calls: FakeRequest[] }) => fetch.calls.filter((c) => c.url.host !== LOGIN_HOST);
const tokenCalls = (fetch: { calls: FakeRequest[] }) => fetch.calls.filter((c) => c.url.host === LOGIN_HOST);

afterEach(() => {
  vi.useRealTimers();
});

describe("azure 凭证", () => {
  it("四个变量都要设置，密码只标明是否已设置", () => {
    expect(azureDns.readCredentials({})).toEqual({ state: "missing" });
    expect(azureDns.readCredentials({ AZURE_TENANT_ID: "t", AZURE_CLIENT_ID: "c" })).toEqual({
      state: "incomplete",
      missing: ["AZURE_CLIENT_SECRET", "AZURE_SUBSCRIPTION_ID"],
    });
    const keys = azureDns.envKeys({ AZURE_TENANT_ID: TENANT, AZURE_CLIENT_SECRET: SECRET });
    expect(keys.find((k) => k.name === "AZURE_CLIENT_SECRET")).toEqual({ name: "AZURE_CLIENT_SECRET", required: true, set: true });
  });

  it("NS 规则匹配全球版 Azure DNS 的四组权威服务器", () => {
    for (const ns of ["ns1-01.azure-dns.com", "ns2-01.azure-dns.net", "ns3-01.azure-dns.org", "ns4-01.azure-dns.info"]) {
      expect(azureDns.nameServerPattern.test(ns)).toBe(true);
    }
    expect(azureDns.nameServerPattern.test("ns1.example.com")).toBe(false);
  });
});

describe("azure 令牌", () => {
  it("客户端凭据流：v2.0 令牌端点、表单字段、ARM 范围；ARM 请求带 Bearer", async () => {
    const c = creds();
    const fetch = fakeFetch((req) => (req.url.host === LOGIN_HOST ? TOKEN_REPLY : { body: { value: [] } }));
    await azureDns.listZones(ctx(fetch), c);
    const t = tokenCalls(fetch)[0]!;
    expect(t.method).toBe("POST");
    expect(t.url.href).toBe(`https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`);
    expect(t.headers["content-type"]).toBe("application/x-www-form-urlencoded");
    expect(Object.fromEntries(new URLSearchParams(t.body))).toEqual({
      client_id: c.clientId,
      scope: "https://management.azure.com/.default",
      client_secret: SECRET,
      grant_type: "client_credentials",
    });
    // 密码里的 + / = & 要 URL 编码，否则服务端解析出来的密码不对
    expect(t.body).toContain("client_secret=fake-secret%2B%2F%3D%26value");
    expect(armCalls(fetch)[0]!.headers.authorization).toBe("Bearer fake-arm-access-token");
  });

  it("令牌在同一进程内按凭证缓存，过期前 60 秒才重新换", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const t0 = Date.parse("2026-10-18T00:00:00Z");
    vi.setSystemTime(t0);
    const c = creds();
    const fetch = fakeFetch((req) => (req.url.host === LOGIN_HOST ? TOKEN_REPLY : { body: { value: [] } }));
    await azureDns.listZones(ctx(fetch), c);
    await azureDns.listZones(ctx(fetch), c);
    vi.setSystemTime(t0 + 3538_000);
    await azureDns.listZones(ctx(fetch), c);
    expect(tokenCalls(fetch)).toHaveLength(1);
    vi.setSystemTime(t0 + 3540_000);
    await azureDns.listZones(ctx(fetch), c);
    expect(tokenCalls(fetch)).toHaveLength(2);
    // 换了密码就是另一组凭证
    await azureDns.listZones(ctx(fetch), { ...c, clientSecret: "another-fake-secret" });
    expect(tokenCalls(fetch)).toHaveLength(3);
  });

  it("令牌错误（AADSTS）转成 CloudApiError：带原因、处理办法与 trace_id，不带密码；失败不缓存", async () => {
    let fail = true;
    const fetch = fakeFetch((req) => {
      if (req.url.host !== LOGIN_HOST) return { body: { value: [] } };
      if (!fail) return TOKEN_REPLY;
      return {
        status: 401,
        body: {
          error: "invalid_client",
          error_description:
            "AADSTS7000215: Invalid client secret provided. Ensure the secret being sent in the request is the client secret value, not the client secret ID.\r\nTrace ID: trace-1\r\nCorrelation ID: corr-1\r\nTimestamp: 2026-10-18 00:00:00Z",
          error_codes: [7000215],
          timestamp: "2026-10-18 00:00:00Z",
          trace_id: "trace-1",
          correlation_id: "corr-1",
        },
      };
    });
    const c = creds();
    const err = await azureDns.listZones(ctx(fetch), c).catch((e: unknown) => e);
    expect(err).toMatchObject({ provider: "azure", code: "invalid_client", requestId: "trace-1", httpStatus: 401 });
    const msg = (err as Error).message;
    expect(msg).toContain("AADSTS7000215: Invalid client secret provided.");
    expect(msg).toContain("AZURE_CLIENT_SECRET 不对");
    expect(msg).not.toContain("Trace ID");
    expect(msg).not.toContain(SECRET);
    expect(isRetryable(err)).toBe(false);
    fail = false;
    await expect(azureDns.listZones(ctx(fetch), c)).resolves.toEqual([]);
  });

  it("令牌端点 5xx / 429 可重试", async () => {
    for (const reply of [{ status: 503, body: { error: "temporarily_unavailable" } }, { status: 429, body: "Too Many Requests" }]) {
      let n = 0;
      const fetch = fakeFetch((req) => (req.url.host !== LOGIN_HOST ? { body: { value: [] } } : ++n === 1 ? reply : TOKEN_REPLY));
      await expect(azureDns.listZones(ctx(fetch), creds())).resolves.toEqual([]);
      expect(tokenCalls(fetch)).toHaveLength(2);
    }
  });

  it("ARM 回 401 时丢掉缓存的令牌，下次重新换", async () => {
    let n = 0;
    const fetch = fakeFetch((req) => {
      if (req.url.host === LOGIN_HOST) return TOKEN_REPLY;
      return ++n === 1 ? armErr(401, "InvalidAuthenticationToken", "The access token is invalid.") : { body: { value: [] } };
    });
    const c = creds();
    await expect(azureDns.listZones(ctx(fetch), c)).rejects.toMatchObject({ code: "InvalidAuthenticationToken", httpStatus: 401 });
    await azureDns.listZones(ctx(fetch), c);
    expect(tokenCalls(fetch)).toHaveLength(2);
  });
});

describe("azure listZones", () => {
  const zone = (rg: string, name: string, extra: Record<string, unknown> = {}) => ({
    id: `/subscriptions/${SUB}/resourceGroups/${rg}/providers/Microsoft.Network/dnszones/${name}`,
    name,
    type: "Microsoft.Network/dnszones",
    etag: "00000000-0000-0000-0000-000000000000",
    location: "global",
    properties: { maxNumberOfRecordSets: 10000, numberOfRecordSets: 2, nameServers: ["ns1-01.azure-dns.com.", "ns2-01.azure-dns.net."], ...extra },
  });

  it("订阅级列出 zone，按 nextLink 翻页，跳过私有 zone，域名与 NS 规范化", async () => {
    const next = `https://management.azure.com/subscriptions/${SUB}/providers/Microsoft.Network/dnszones?api-version=2018-05-01&$skipToken=tok2`;
    const fetch = fakeFetch((req) => {
      if (req.url.host === LOGIN_HOST) return TOKEN_REPLY;
      if (req.url.pathname !== `/subscriptions/${SUB}/providers/Microsoft.Network/dnszones`) return undefined;
      if (!req.url.searchParams.get("$skipToken")) {
        return { body: { value: [zone("dns-rg", "Example.com", { zoneType: "Public" }), zone("dns-rg", "corp.example.com", { zoneType: "Private" })], nextLink: next } };
      }
      return { body: { value: [zone("other-rg", "example.org")] } };
    });
    const zones = await azureDns.listZones(ctx(fetch), creds());
    expect(zones).toEqual([
      {
        name: "example.com",
        id: `/subscriptions/${SUB}/resourceGroups/dns-rg/providers/Microsoft.Network/dnszones/Example.com`,
        nameServers: ["ns1-01.azure-dns.com", "ns2-01.azure-dns.net"],
        extra: { resourceGroup: "dns-rg" },
      },
      {
        name: "example.org",
        id: `/subscriptions/${SUB}/resourceGroups/other-rg/providers/Microsoft.Network/dnszones/example.org`,
        nameServers: ["ns1-01.azure-dns.com", "ns2-01.azure-dns.net"],
        extra: { resourceGroup: "other-rg" },
      },
    ]);
    const calls = armCalls(fetch);
    expect(calls[0]!.url.searchParams.get("api-version")).toBe("2018-05-01");
    expect(calls[1]!.url.searchParams.get("$skipToken")).toBe("tok2");
  });

  it("nextLink 指向 ARM 以外的地址时中止，不把令牌发过去", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.host === LOGIN_HOST) return TOKEN_REPLY;
      if (req.url.host === ARM_HOST) return { body: { value: [], nextLink: "https://attacker.example/next" } };
      return { body: { value: [] } };
    });
    await expect(azureDns.listZones(ctx(fetch), creds())).rejects.toMatchObject({ code: "InvalidResponse" });
    expect(fetch.calls.some((c) => c.url.host === "attacker.example")).toBe(false);
  });

  it("订阅未注册 Microsoft.Network 时按没有 zone 处理", async () => {
    const fetch = fakeFetch((req) =>
      req.url.host === LOGIN_HOST
        ? TOKEN_REPLY
        : armErr(409, "MissingSubscriptionRegistration", "The subscription is not registered to use namespace 'Microsoft.Network'."),
    );
    await expect(azureDns.listZones(ctx(fetch), creds())).resolves.toEqual([]);
  });
});

describe("azure addTxt", () => {
  it("新建记录集：If-None-Match: *，TTL 60", async () => {
    const dns = azureDnsFake();
    const handle = await azureDns.addTxt(ctx(dns.fetch), creds(), record());
    expect(handle).toBe(`${ZONE_ID}/TXT/_acme-challenge`);
    const put = dns.writes()[0]!;
    expect(put.method).toBe("PUT");
    expect(put.url.pathname).toBe(`${ZONE_ID}/TXT/_acme-challenge`);
    expect(put.headers["if-none-match"]).toBe("*");
    expect(put.headers["if-match"]).toBeUndefined();
    expect(put.headers["content-type"]).toBe("application/json");
    expect(put.json).toEqual({ properties: { TTL: 60, TXTRecords: [{ value: [VALUE] }] } });
  });

  it("同名已有其他值：带 If-Match 写回，保留原值、TTL 与 metadata", async () => {
    const dns = azureDnsFake({ "_acme-challenge": { TTL: 300, metadata: { owner: "someone" }, TXTRecords: [{ value: [OTHER] }] } });
    await azureDns.addTxt(ctx(dns.fetch), creds(), record());
    const put = dns.writes()[0]!;
    expect(put.headers["if-match"]).toBe("etag-1");
    expect(put.json).toEqual({ properties: { metadata: { owner: "someone" }, TTL: 300, TXTRecords: [{ value: [OTHER] }, { value: [VALUE] }] } });
  });

  it("同名同值已存在时不写入", async () => {
    const dns = azureDnsFake({ "_acme-challenge": { TTL: 60, TXTRecords: [{ value: [OTHER] }, { value: [VALUE] }] } });
    await expect(azureDns.addTxt(ctx(dns.fetch), creds(), record())).resolves.toBe(`${ZONE_ID}/TXT/_acme-challenge`);
    expect(dns.writes()).toEqual([]);
  });

  it("zone 顶点的记录名为 @", async () => {
    const dns = azureDnsFake();
    await azureDns.addTxt(ctx(dns.fetch), creds(), record("example.com"));
    expect(dns.writes()[0]!.url.pathname).toBe(`${ZONE_ID}/TXT/@`);
  });

  it("etag 冲突（412）时重读再试一次，别人刚加的值也保留", async () => {
    const dns = azureDnsFake(
      { "_acme-challenge": { TTL: 60, TXTRecords: [{ value: [OTHER] }] } },
      {
        beforeWrite: (n, sets) => {
          if (n !== 1) return;
          const s = sets.get("_acme-challenge")!;
          s.properties.TXTRecords.push({ value: ["concurrent"] });
          s.etag = "etag-concurrent";
        },
      },
    );
    await azureDns.addTxt(ctx(dns.fetch), creds(), record());
    expect(dns.writes().map((w) => w.headers["if-match"])).toEqual(["etag-1", "etag-concurrent"]);
    expect(dns.sets.get("_acme-challenge")!.properties.TXTRecords).toEqual([{ value: [OTHER] }, { value: ["concurrent"] }, { value: [VALUE] }]);
  });

  it("新建时别人抢先建了同名记录集（If-None-Match 412）也重读重试", async () => {
    const dns = azureDnsFake({}, {
      beforeWrite: (n, sets) => void (n === 1 && sets.set("_acme-challenge", { etag: "etag-x", properties: { TTL: 60, TXTRecords: [{ value: [OTHER] }] } })),
    });
    await azureDns.addTxt(ctx(dns.fetch), creds(), record());
    expect(dns.writes().map((w) => [w.headers["if-none-match"], w.headers["if-match"]])).toEqual([["*", undefined], [undefined, "etag-x"]]);
    expect(dns.sets.get("_acme-challenge")!.properties.TXTRecords).toEqual([{ value: [OTHER] }, { value: [VALUE] }]);
  });

  it("连续冲突只重试一次，然后报错", async () => {
    const dns = azureDnsFake({ "_acme-challenge": { TTL: 60, TXTRecords: [{ value: [OTHER] }] } }, {
      beforeWrite: (n, sets) => void (sets.get("_acme-challenge")!.etag = `etag-c${n}`),
    });
    const err = await azureDns.addTxt(ctx(dns.fetch), creds(), record()).catch((e: unknown) => e);
    expect(err).toMatchObject({ provider: "azure", code: "PreconditionFailed", httpStatus: 412 });
    expect(dns.writes()).toHaveLength(2);
  });
});

describe("azure removeTxt", () => {
  const handle = `${ZONE_ID}/TXT/_acme-challenge`;

  it("同名还有其他值：去掉自己的值后带 If-Match 写回", async () => {
    const dns = azureDnsFake({ "_acme-challenge": { TTL: 60, metadata: { a: "b" }, TXTRecords: [{ value: [OTHER] }, { value: [VALUE] }] } });
    await azureDns.removeTxt(ctx(dns.fetch), creds(), record(), handle);
    const put = dns.writes()[0]!;
    expect(put.method).toBe("PUT");
    expect(put.headers["if-match"]).toBe("etag-1");
    expect(put.json).toEqual({ properties: { metadata: { a: "b" }, TTL: 60, TXTRecords: [{ value: [OTHER] }] } });
  });

  it("最后一个值：带 If-Match 删除整个记录集", async () => {
    const dns = azureDnsFake({ "_acme-challenge": { TTL: 60, TXTRecords: [{ value: [VALUE] }] } });
    await azureDns.removeTxt(ctx(dns.fetch), creds(), record(), handle);
    const del = dns.writes()[0]!;
    expect(del.method).toBe("DELETE");
    expect(del.headers["if-match"]).toBe("etag-1");
    expect(dns.sets.size).toBe(0);
  });

  it("记录集或值已不存在时视为成功，不写入", async () => {
    const cases: Record<string, Props>[] = [{}, { "_acme-challenge": { TTL: 60, TXTRecords: [{ value: [OTHER] }] } }];
    for (const initial of cases) {
      const dns = azureDnsFake(initial);
      await expect(azureDns.removeTxt(ctx(dns.fetch), creds(), record(), handle)).resolves.toBeUndefined();
      expect(dns.writes()).toEqual([]);
    }
  });

  it("删除时 etag 对不上（别人刚改过）则重读，别人加的值保留", async () => {
    const dns = azureDnsFake({ "_acme-challenge": { TTL: 60, TXTRecords: [{ value: [VALUE] }] } }, {
      beforeWrite: (n, sets) => {
        if (n !== 1) return;
        const s = sets.get("_acme-challenge")!;
        s.properties.TXTRecords.push({ value: ["concurrent"] });
        s.etag = "etag-concurrent";
      },
    });
    await azureDns.removeTxt(ctx(dns.fetch), creds(), record(), handle);
    expect(dns.writes().map((w) => w.method)).toEqual(["DELETE", "PUT"]);
    expect(dns.sets.get("_acme-challenge")!.properties.TXTRecords).toEqual([{ value: ["concurrent"] }]);
  });
});

describe("azure 错误映射", () => {
  const failing = (reply: FakeReply, times = Infinity) => {
    let n = 0;
    return fakeFetch((req) => (req.url.host === LOGIN_HOST ? TOKEN_REPLY : n++ < times ? reply : { body: { value: [] } }));
  };

  it("403 AuthorizationFailed：message 说明需要的角色，不重试", async () => {
    const fetch = failing(armErr(403, "AuthorizationFailed", "The client 'x' does not have authorization to perform action 'Microsoft.Network/dnszones/read'."));
    const err = await azureDns.listZones(ctx(fetch), creds()).catch((e: unknown) => e);
    expect(err).toMatchObject({ provider: "azure", code: "AuthorizationFailed", httpStatus: 403 });
    expect((err as Error).message).toMatch(/DNS Zone Contributor/);
    expect(isRetryable(err)).toBe(false);
    expect(armCalls(fetch)).toHaveLength(1);
  });

  it("429 / 5xx 可重试，重试后成功", async () => {
    for (const reply of [armErr(429, "TooManyRequests"), armErr(500, "InternalServerError"), { status: 502, body: "<html>Bad Gateway</html>" }]) {
      const fetch = failing(reply, 1);
      await expect(azureDns.listZones(ctx(fetch), creds())).resolves.toEqual([]);
      expect(armCalls(fetch)).toHaveLength(2);
    }
  });

  it("可重试错误的错误码", async () => {
    const codes: [FakeReply, string][] = [
      [armErr(429, "SubscriptionRequestsThrottled"), "SubscriptionRequestsThrottled"],
      [armErr(500, "InternalServerError"), "ServiceUnavailable.InternalServerError"],
      [armErr(503, "ServiceUnavailable"), "ServiceUnavailable"],
      [{ status: 502, body: "<html>Bad Gateway</html>" }, "ServiceUnavailable.HTTP502"],
    ];
    for (const [reply, code] of codes) {
      const err = await azureDns.listZones(ctx(failing(reply)), creds()).catch((e: unknown) => e);
      expect(err).toMatchObject({ code });
      expect(isRetryable(err)).toBe(true);
    }
  });
});
