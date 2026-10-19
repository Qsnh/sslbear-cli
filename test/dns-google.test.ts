import { generateKeyPairSync, verify } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { googleDns, type GoogleCredentials } from "../src/dns/google.js";
import type { DnsZone, TxtRecord } from "../src/dns/types.js";
import { CloudApiError, isRetryable, type Fetch, type QueryContext } from "../src/lib/http.js";
import { fakeFetch, type FakeReply, type FakeRequest } from "./helpers.js";

// 测试私钥现场生成，不在仓库里放任何像真实密钥的内容
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const PEM = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
const dir = mkdtempSync(join(tmpdir(), "sslbear-gdns-"));
let seq = 0;

/** 每个测试一个新的服务账号密钥文件（client_email 不同），进程内的令牌缓存互不影响 */
function keyFile(overrides: Record<string, unknown> = {}): { path: string; email: string } {
  const n = ++seq;
  const email = `dns-bot-${n}@demo-project.iam.gserviceaccount.com`;
  const path = join(dir, `sa-${n}.json`);
  const json = {
    type: "service_account",
    project_id: "demo-project",
    private_key_id: `kid-${n}`,
    private_key: PEM,
    client_email: email,
    token_uri: "https://oauth2.googleapis.com/token",
    ...overrides,
  };
  writeFileSync(path, JSON.stringify(json));
  return { path, email };
}

const creds = (overrides?: Record<string, unknown>, project?: string): GoogleCredentials => ({ keyFile: keyFile(overrides).path, ...(project && { project }) });

const ctx = (fetch: Fetch, sleep = async (_ms: number) => {}): QueryContext => ({ fetch, timeoutMs: 5000, now: new Date(), env: {}, sleep });

const TOKEN_HOST = "oauth2.googleapis.com";
const TOKEN_REPLY = { body: { access_token: "ya29.fake-access-token", expires_in: 3599, token_type: "Bearer" } };
const API_PREFIX = "/dns/v1/projects/demo-project/managedZones";
const gerr = (status: number, reason: string, message = reason, extra: Record<string, unknown> = {}) => ({
  status,
  body: { error: { code: status, message, errors: [{ message, domain: "global", reason }], ...extra } },
});

const ZONE: DnsZone = { name: "example.com", id: "example-com", extra: { project: "demo-project" } };
const FQDN = "_acme-challenge.example.com";
const VALUE = "x".repeat(43);
const OTHER = "y".repeat(43);
const record = (value = VALUE): TxtRecord => ({ zone: ZONE, fqdn: FQDN, value });

interface RRSet {
  kind?: string;
  name: string;
  type: string;
  ttl: number;
  rrdatas: string[];
}

/**
 * 内存版 Cloud DNS：GET rrsets 按 name + type 查，POST changes 与真实接口一样要求 deletions 与现有记录集完全一致（否则 412），
 * additions 撞上已存在的记录集为 409；beforeChange 可在提交前插入别人的改动，模拟并发冲突
 */
function cloudDns(initial: RRSet[] = [], opts: { beforeChange?: (n: number, sets: Map<string, RRSet>) => void; extra?: (req: FakeRequest) => FakeReply } = {}) {
  const sets = new Map(initial.map((r) => [r.name, structuredClone(r)]));
  const changes: { additions?: RRSet[]; deletions?: RRSet[] }[] = [];
  const fetch = fakeFetch((req) => {
    if (req.url.host === TOKEN_HOST) return TOKEN_REPLY;
    const extra = opts.extra?.(req);
    if (extra) return extra;
    if (req.url.pathname === `${API_PREFIX}/example-com/rrsets` && req.method === "GET") {
      const set = sets.get(req.url.searchParams.get("name") ?? "");
      return { body: { kind: "dns#resourceRecordSetsListResponse", rrsets: set && req.url.searchParams.get("type") === set.type ? [set] : [] } };
    }
    if (req.url.pathname === `${API_PREFIX}/example-com/changes` && req.method === "POST") {
      const change = req.json as { additions?: RRSet[]; deletions?: RRSet[] };
      changes.push(change);
      opts.beforeChange?.(changes.length, sets);
      for (const d of change.deletions ?? []) {
        if (JSON.stringify(sets.get(d.name)) !== JSON.stringify(d)) return gerr(412, "conditionNotMet", "Precondition not met for 'entity.change.deletions[0]'");
      }
      const deleted = new Set((change.deletions ?? []).map((d) => d.name));
      for (const a of change.additions ?? []) {
        if (sets.has(a.name) && !deleted.has(a.name)) return gerr(409, "alreadyExists", `The resource 'entity.change.additions[0]' named '${a.name} (TXT)' already exists`);
      }
      for (const name of deleted) sets.delete(name);
      for (const a of change.additions ?? []) sets.set(a.name, { kind: "dns#resourceRecordSet", ...a });
      return { body: { kind: "dns#change", ...change, id: String(changes.length), status: "done" } };
    }
    return undefined;
  });
  return { fetch, sets, changes };
}

const apiCalls = (fetch: { calls: FakeRequest[] }) => fetch.calls.filter((c) => c.url.host !== TOKEN_HOST);
const tokenCalls = (fetch: { calls: FakeRequest[] }) => fetch.calls.filter((c) => c.url.host === TOKEN_HOST);

afterEach(() => {
  vi.useRealTimers();
});

describe("google 凭证", () => {
  it("读取 GOOGLE_APPLICATION_CREDENTIALS 与可选的 GOOGLE_CLOUD_PROJECT", () => {
    expect(googleDns.readCredentials({})).toEqual({ state: "missing" });
    expect(googleDns.readCredentials({ GOOGLE_APPLICATION_CREDENTIALS: "/tmp/sa.json" })).toEqual({ state: "ok", credentials: { keyFile: "/tmp/sa.json" } });
    expect(googleDns.readCredentials({ GOOGLE_APPLICATION_CREDENTIALS: "/tmp/sa.json", GOOGLE_CLOUD_PROJECT: "p2" })).toEqual({
      state: "ok",
      credentials: { keyFile: "/tmp/sa.json", project: "p2" },
    });
  });

  it("NS 规则匹配 Cloud DNS 的权威服务器", () => {
    expect(googleDns.nameServerPattern.test("ns-cloud-a1.googledomains.com")).toBe(true);
    expect(googleDns.nameServerPattern.test("ns-cloud-e4.googledomains.com")).toBe(true);
    expect(googleDns.nameServerPattern.test("ns1.example.com")).toBe(false);
  });

  it("密钥文件读不了 / 不是 JSON / 不是服务账号密钥 / 没有项目时报 InvalidCredentials，不发请求、不泄露文件内容", async () => {
    const fetch = fakeFetch(() => undefined);
    const notJson = join(dir, "broken.json");
    writeFileSync(notJson, `{"private_key": "${PEM.slice(0, 80)}`);
    const cases: [GoogleCredentials, RegExp][] = [
      [{ keyFile: join(dir, "missing.json") }, /文件不存在/],
      [{ keyFile: notJson }, /不是合法的 JSON/],
      [creds({ type: "authorized_user" }), /不是服务账号密钥（type 为 authorized_user）/],
      [creds({ private_key: "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n" }), /不是有效的 PEM 私钥/],
      [creds({ project_id: undefined }), /GOOGLE_CLOUD_PROJECT/],
    ];
    for (const [c, msg] of cases) {
      const err = await googleDns.listZones(ctx(fetch), c).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(CloudApiError);
      expect(err).toMatchObject({ provider: "google", code: "InvalidCredentials" });
      expect((err as Error).message).toMatch(msg);
      expect((err as Error).message).not.toContain("BEGIN");
    }
    expect(fetch.calls).toHaveLength(0);
  });
});

describe("google 令牌", () => {
  it("签 RS256 JWT 换 access token：表单字段、声明与签名都符合服务账号文档", async () => {
    const { path, email } = keyFile();
    const fetch = fakeFetch((req) => (req.url.host === TOKEN_HOST ? TOKEN_REPLY : { body: { managedZones: [] } }));
    const before = Math.floor(Date.now() / 1000);
    await googleDns.listZones(ctx(fetch), { keyFile: path });

    const tokenReq = tokenCalls(fetch)[0]!;
    expect(tokenReq.method).toBe("POST");
    expect(tokenReq.url.href).toBe("https://oauth2.googleapis.com/token");
    expect(tokenReq.headers["content-type"]).toBe("application/x-www-form-urlencoded");
    const form = new URLSearchParams(tokenReq.body);
    expect([...form.keys()].sort()).toEqual(["assertion", "grant_type"]);
    expect(form.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");

    const [h, p, sig] = form.get("assertion")!.split(".");
    expect(JSON.parse(Buffer.from(h!, "base64url").toString())).toEqual({ alg: "RS256", typ: "JWT", kid: `kid-${seq}` });
    const claims = JSON.parse(Buffer.from(p!, "base64url").toString());
    expect(claims).toMatchObject({ iss: email, scope: "https://www.googleapis.com/auth/ndev.clouddns.readwrite", aud: "https://oauth2.googleapis.com/token" });
    expect(claims.iat).toBeGreaterThanOrEqual(before);
    expect(claims.exp - claims.iat).toBe(3600);
    expect(verify("sha256", Buffer.from(`${h}.${p}`), publicKey, Buffer.from(sig!, "base64url"))).toBe(true);

    const api = apiCalls(fetch)[0]!;
    expect(api.headers.authorization).toBe("Bearer ya29.fake-access-token");
  });

  it("令牌在同一进程内按凭证缓存，过期前 60 秒才重新换", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-10-18T00:00:00Z"));
    const c = creds();
    const fetch = fakeFetch((req) => (req.url.host === TOKEN_HOST ? TOKEN_REPLY : { body: { managedZones: [] } }));
    await googleDns.listZones(ctx(fetch), c);
    await googleDns.listZones(ctx(fetch), c);
    expect(tokenCalls(fetch)).toHaveLength(1);
    // expires_in 3599 秒：3538 秒时还能用，3540 秒时已进入 60 秒余量
    vi.setSystemTime(new Date(Date.parse("2026-10-18T00:00:00Z") + 3538_000));
    await googleDns.listZones(ctx(fetch), c);
    expect(tokenCalls(fetch)).toHaveLength(1);
    vi.setSystemTime(new Date(Date.parse("2026-10-18T00:00:00Z") + 3540_000));
    await googleDns.listZones(ctx(fetch), c);
    expect(tokenCalls(fetch)).toHaveLength(2);
    // 另一个服务账号单独换令牌
    await googleDns.listZones(ctx(fetch), creds());
    expect(tokenCalls(fetch)).toHaveLength(3);
  });

  it("令牌请求失败转成 CloudApiError，带原因与处理办法，不带私钥；失败不缓存", async () => {
    let fail = true;
    const fetch = fakeFetch((req) => {
      if (req.url.host !== TOKEN_HOST) return { body: { managedZones: [] } };
      return fail ? { status: 400, body: { error: "invalid_grant", error_description: "Invalid JWT Signature." } } : TOKEN_REPLY;
    });
    const c = creds();
    const err = await googleDns.listZones(ctx(fetch), c).catch((e: unknown) => e);
    expect(err).toMatchObject({ provider: "google", code: "invalid_grant", httpStatus: 400 });
    expect((err as Error).message).toMatch(/Invalid JWT Signature.*删除或停用/);
    expect((err as Error).message).not.toContain("PRIVATE KEY");
    expect(isRetryable(err)).toBe(false);
    fail = false;
    await expect(googleDns.listZones(ctx(fetch), c)).resolves.toEqual([]);
  });

  it("令牌端点 5xx 可重试", async () => {
    let n = 0;
    const fetch = fakeFetch((req) => {
      if (req.url.host !== TOKEN_HOST) return { body: { managedZones: [] } };
      return ++n === 1 ? { status: 503, body: "<html>unavailable</html>" } : TOKEN_REPLY;
    });
    await expect(googleDns.listZones(ctx(fetch), creds())).resolves.toEqual([]);
    expect(tokenCalls(fetch)).toHaveLength(2);
  });

  it("接口回 401 时丢掉缓存的令牌，下次重新换", async () => {
    let n = 0;
    const fetch = fakeFetch((req) => {
      if (req.url.host === TOKEN_HOST) return TOKEN_REPLY;
      return ++n === 1 ? gerr(401, "authError", "Request had invalid authentication credentials.", { status: "UNAUTHENTICATED" }) : { body: { managedZones: [] } };
    });
    const c = creds();
    const err = await googleDns.listZones(ctx(fetch), c).catch((e: unknown) => e);
    expect(err).toMatchObject({ code: "authError", httpStatus: 401 });
    await googleDns.listZones(ctx(fetch), c);
    expect(tokenCalls(fetch)).toHaveLength(2);
  });
});

describe("google listZones", () => {
  it("按 pageToken 翻页，只返回公网 zone，域名与 NS 规范化", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.host === TOKEN_HOST) return TOKEN_REPLY;
      if (req.url.pathname !== API_PREFIX) return undefined;
      if (!req.url.searchParams.get("pageToken")) {
        return {
          body: {
            managedZones: [
              { name: "example-com", dnsName: "Example.COM.", visibility: "public", nameServers: ["ns-cloud-a1.googledomains.com.", "ns-cloud-a2.googledomains.com."] },
              { name: "internal", dnsName: "corp.example.com.", visibility: "private", nameServers: ["ns-gcp-private.googledomains.com."] },
            ],
            nextPageToken: "page-2",
          },
        };
      }
      expect(req.url.searchParams.get("pageToken")).toBe("page-2");
      return { body: { managedZones: [{ name: "example-org", dnsName: "example.org." }] } };
    });
    const zones = await googleDns.listZones(ctx(fetch), creds());
    expect(zones).toEqual([
      { name: "example.com", id: "example-com", nameServers: ["ns-cloud-a1.googledomains.com", "ns-cloud-a2.googledomains.com"], extra: { project: "demo-project" } },
      { name: "example.org", id: "example-org", extra: { project: "demo-project" } },
    ]);
    expect(apiCalls(fetch).map((c) => c.url.search)).toEqual(["", "?pageToken=page-2"]);
  });

  it("GOOGLE_CLOUD_PROJECT 覆盖密钥文件里的 project_id", async () => {
    const fetch = fakeFetch((req) => (req.url.host === TOKEN_HOST ? TOKEN_REPLY : { body: {} }));
    const zones = await googleDns.listZones(ctx(fetch), creds({}, "other-project"));
    expect(zones).toEqual([]);
    expect(apiCalls(fetch)[0]!.url.pathname).toBe("/dns/v1/projects/other-project/managedZones");
  });
});

describe("google addTxt", () => {
  it("新建记录集：TTL 60，值带双引号", async () => {
    const dns = cloudDns();
    const handle = await googleDns.addTxt(ctx(dns.fetch), creds(), record());
    expect(handle).toBe("projects/demo-project/managedZones/example-com/rrsets/_acme-challenge.example.com./TXT");
    const get = apiCalls(dns.fetch)[0]!;
    expect(Object.fromEntries(get.url.searchParams)).toEqual({ name: "_acme-challenge.example.com.", type: "TXT" });
    expect(dns.changes).toEqual([{ additions: [{ name: "_acme-challenge.example.com.", type: "TXT", ttl: 60, rrdatas: [`"${VALUE}"`] }] }]);
    const post = apiCalls(dns.fetch)[1]!;
    expect(post.headers["content-type"]).toBe("application/json");
  });

  it("同名已有其他值：删除旧记录集（原样）+ 添加合并后的记录集，保留原 TTL", async () => {
    const existing: RRSet = { kind: "dns#resourceRecordSet", name: "_acme-challenge.example.com.", type: "TXT", ttl: 300, rrdatas: [`"${OTHER}"`] };
    const dns = cloudDns([existing]);
    await googleDns.addTxt(ctx(dns.fetch), creds(), record());
    expect(dns.changes).toEqual([
      { additions: [{ name: "_acme-challenge.example.com.", type: "TXT", ttl: 300, rrdatas: [`"${OTHER}"`, `"${VALUE}"`] }], deletions: [existing] },
    ]);
    expect(dns.sets.get("_acme-challenge.example.com.")!.rrdatas).toEqual([`"${OTHER}"`, `"${VALUE}"`]);
  });

  it("同名同值已存在（带不带引号都算）时不提交变更", async () => {
    for (const rr of [`"${VALUE}"`, VALUE]) {
      const dns = cloudDns([{ name: "_acme-challenge.example.com.", type: "TXT", ttl: 60, rrdatas: [`"${OTHER}"`, rr] }]);
      await expect(googleDns.addTxt(ctx(dns.fetch), creds(), record())).resolves.toMatch(/rrsets\/_acme-challenge\.example\.com\.\/TXT$/);
      expect(dns.changes).toEqual([]);
    }
  });

  it("并发冲突（412）时重读记录集再试一次，别人刚加的值也保留", async () => {
    const dns = cloudDns([{ name: "_acme-challenge.example.com.", type: "TXT", ttl: 60, rrdatas: [`"${OTHER}"`] }], {
      beforeChange: (n, sets) => {
        if (n === 1) sets.get("_acme-challenge.example.com.")!.rrdatas.push('"concurrent"');
      },
    });
    await googleDns.addTxt(ctx(dns.fetch), creds(), record());
    expect(dns.changes).toHaveLength(2);
    expect(dns.sets.get("_acme-challenge.example.com.")!.rrdatas).toEqual([`"${OTHER}"`, '"concurrent"', `"${VALUE}"`]);
  });

  it("新建时别人抢先建了同名记录集（409）也重读重试", async () => {
    const dns = cloudDns([], {
      beforeChange: (n, sets) => {
        if (n === 1) sets.set("_acme-challenge.example.com.", { name: "_acme-challenge.example.com.", type: "TXT", ttl: 60, rrdatas: [`"${OTHER}"`] });
      },
    });
    await googleDns.addTxt(ctx(dns.fetch), creds(), record());
    expect(dns.sets.get("_acme-challenge.example.com.")!.rrdatas).toEqual([`"${OTHER}"`, `"${VALUE}"`]);
  });

  it("连续冲突只重试一次，然后报错", async () => {
    const dns = cloudDns([{ name: "_acme-challenge.example.com.", type: "TXT", ttl: 60, rrdatas: [`"${OTHER}"`] }], {
      beforeChange: (n, sets) => void sets.get("_acme-challenge.example.com.")!.rrdatas.push(`"c${n}"`),
    });
    const err = await googleDns.addTxt(ctx(dns.fetch), creds(), record()).catch((e: unknown) => e);
    expect(err).toMatchObject({ provider: "google", code: "conditionNotMet", httpStatus: 412 });
    expect(dns.changes).toHaveLength(2);
  });

  it("变更为 pending 时轮询到 done 再返回", async () => {
    let polls = 0;
    const slept: number[] = [];
    const dns = cloudDns([], {
      extra: (req) => {
        if (req.method === "POST") return { body: { id: "42", status: "pending" } };
        if (req.url.pathname.endsWith("/changes/42")) return { body: { id: "42", status: ++polls < 3 ? "pending" : "done" } };
        return undefined;
      },
    });
    await googleDns.addTxt(ctx(dns.fetch, async (ms: number) => void slept.push(ms)), creds(), record());
    expect(polls).toBe(3);
    expect(slept).toEqual([2000, 2000, 2000]);
  });

  it("记录集配置了路由策略时不改动", async () => {
    const dns = cloudDns([{ name: "_acme-challenge.example.com.", type: "TXT", ttl: 60, routingPolicy: { geo: {} } } as unknown as RRSet]);
    await expect(googleDns.addTxt(ctx(dns.fetch), creds(), record())).rejects.toMatchObject({ code: "UnsupportedRecordSet" });
    expect(dns.changes).toEqual([]);
  });
});

describe("google removeTxt", () => {
  const handle = "projects/demo-project/managedZones/example-com/rrsets/_acme-challenge.example.com./TXT";

  it("同名还有其他值：去掉自己的值后写回", async () => {
    const existing: RRSet = { kind: "dns#resourceRecordSet", name: "_acme-challenge.example.com.", type: "TXT", ttl: 60, rrdatas: [`"${OTHER}"`, `"${VALUE}"`] };
    const dns = cloudDns([existing]);
    await googleDns.removeTxt(ctx(dns.fetch), creds(), record(), handle);
    expect(dns.changes).toEqual([{ deletions: [existing], additions: [{ name: "_acme-challenge.example.com.", type: "TXT", ttl: 60, rrdatas: [`"${OTHER}"`] }] }]);
    expect(dns.sets.get("_acme-challenge.example.com.")!.rrdatas).toEqual([`"${OTHER}"`]);
  });

  it("最后一个值：只做 deletion，整个记录集删除", async () => {
    const existing: RRSet = { kind: "dns#resourceRecordSet", name: "_acme-challenge.example.com.", type: "TXT", ttl: 60, rrdatas: [`"${VALUE}"`] };
    const dns = cloudDns([existing]);
    await googleDns.removeTxt(ctx(dns.fetch), creds(), record(), handle);
    expect(dns.changes).toEqual([{ deletions: [existing] }]);
    expect(dns.sets.size).toBe(0);
  });

  it("记录集或值已不存在时视为成功，不提交变更", async () => {
    for (const initial of [[], [{ name: "_acme-challenge.example.com.", type: "TXT", ttl: 60, rrdatas: [`"${OTHER}"`] }]]) {
      const dns = cloudDns(initial);
      await expect(googleDns.removeTxt(ctx(dns.fetch), creds(), record(), handle)).resolves.toBeUndefined();
      expect(dns.changes).toEqual([]);
    }
  });

  it("删除途中记录集被别人删掉（deletions 对不上）时重读，已不存在即成功", async () => {
    const dns = cloudDns([{ name: "_acme-challenge.example.com.", type: "TXT", ttl: 60, rrdatas: [`"${VALUE}"`] }], {
      beforeChange: (n, sets) => void (n === 1 && sets.clear()),
    });
    await expect(googleDns.removeTxt(ctx(dns.fetch), creds(), record(), handle)).resolves.toBeUndefined();
    expect(dns.changes).toHaveLength(1);
  });
});

describe("google 错误映射", () => {
  const failing = (reply: FakeReply, times = Infinity) => {
    let n = 0;
    return fakeFetch((req) => (req.url.host === TOKEN_HOST ? TOKEN_REPLY : n++ < times ? reply : { body: { managedZones: [] } }));
  };

  it("403 权限不足：错误码取 reason，message 说明需要的角色，不重试", async () => {
    const fetch = failing(gerr(403, "forbidden", "Forbidden", { status: "PERMISSION_DENIED" }));
    const err = await googleDns.listZones(ctx(fetch), creds()).catch((e: unknown) => e);
    expect(err).toMatchObject({ provider: "google", code: "forbidden", httpStatus: 403 });
    expect((err as Error).message).toMatch(/roles\/dns\.admin/);
    expect((err as Error).message).toMatch(/dns\.changes\.create/);
    expect(isRetryable(err)).toBe(false);
    expect(apiCalls(fetch)).toHaveLength(1);
  });

  it("Cloud DNS API 未启用时提示去启用", async () => {
    const fetch = failing(gerr(403, "accessNotConfigured", "Cloud DNS API has not been used in project 1 before or it is disabled."));
    const err = await googleDns.listZones(ctx(fetch), creds()).catch((e: unknown) => e);
    expect(err).toMatchObject({ code: "accessNotConfigured" });
    expect((err as Error).message).toMatch(/启用 dns\.googleapis\.com/);
  });

  it("429 / 403 rateLimitExceeded / 5xx 可重试，重试后成功", async () => {
    for (const reply of [
      gerr(429, "rateLimitExceeded", "Rate Limit Exceeded", { status: "RESOURCE_EXHAUSTED" }),
      gerr(403, "rateLimitExceeded", "Rate Limit Exceeded"),
      gerr(500, "backendError", "Internal Error"),
      { status: 502, body: "<html>Bad Gateway</html>" },
    ]) {
      const fetch = failing(reply, 1);
      await expect(googleDns.listZones(ctx(fetch), creds())).resolves.toEqual([]);
      expect(apiCalls(fetch)).toHaveLength(2);
    }
  });

  it("可重试错误的错误码", async () => {
    const codes: [FakeReply, string][] = [
      [gerr(403, "rateLimitExceeded"), "Throttling.rateLimitExceeded"],
      [gerr(500, "backendError"), "ServiceUnavailable.backendError"],
      [{ status: 502, body: "<html>Bad Gateway</html>" }, "ServiceUnavailable.HTTP502"],
    ];
    for (const [reply, code] of codes) {
      const err = await googleDns.listZones(ctx(failing(reply)), creds()).catch((e: unknown) => e);
      expect(err).toMatchObject({ code });
      expect(isRetryable(err)).toBe(true);
    }
  });
});
