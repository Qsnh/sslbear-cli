import { createHash, createPublicKey, generateKeyPairSync, verify, type JsonWebKey, type KeyObject } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import type { Fetch, QueryContext } from "../src/lib/http.js";
import { createAcmeClient } from "../src/issue/acme.js";
import { generateAccountKey } from "../src/issue/csr.js";
import { AcmeError } from "../src/issue/types.js";

const BASE = "https://ca.test";
const DIR_URL = `${BASE}/directory`;
const DIRECTORY = {
  newNonce: `${BASE}/new-nonce`,
  newAccount: `${BASE}/new-account`,
  newOrder: `${BASE}/new-order`,
  renewalInfo: `${BASE}/renewal-info`,
  revokeCert: `${BASE}/revoke-cert`,
  keyChange: `${BASE}/key-change`,
  meta: { termsOfService: `${BASE}/terms.pdf`, profiles: { classic: "经典配置", shortlived: "短期证书" }, caaIdentities: ["ca.test"] },
};
const PEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n";

interface CaRequest {
  method: string;
  url: string;
  path: string;
  headers: Record<string, string>;
  /** JWS protected 头 */
  header: Record<string, unknown>;
  /** POST-as-GET 为 ""，其余为解码后的 JSON */
  payload: unknown;
  /** 本次响应带回的 Replay-Nonce */
  replyNonce?: string;
}

interface CaReply {
  status?: number;
  body?: unknown;
  headers?: Record<string, string>;
  /** 不带 Replay-Nonce，客户端得自己去 newNonce 取 */
  noNonce?: boolean;
}

const json = (body: unknown, headers: Record<string, string> = {}, status = 200): CaReply => ({ status, body, headers });
const problem = (status: number, type: string, detail: string, extra: Record<string, unknown> = {}, headers: Record<string, string> = {}): CaReply => ({
  status,
  body: { type: `urn:ietf:params:acme:error:${type}`, detail, ...extra },
  headers: { "Content-Type": "application/problem+json", ...headers },
});

const decode = (s: string) => Buffer.from(s, "base64url").toString("utf8");

/**
 * 假 CA：按 RFC 8555 校验每个 JWS（protected 头字段、用 jwk / kid 对应的公钥验签、nonce 只能用一次、url 与请求 URL 一致），
 * 违规记进 violations 并回 400（不直接抛，免得被客户端转成网络错误而看不出原因）。
 * 目录、newNonce、newAccount 有默认实现，其余由 handle 按路径回应
 */
function fakeCa(handle: (req: CaRequest) => CaReply | undefined = () => undefined, directory: unknown = DIRECTORY) {
  const issued = new Set<string>();
  const used = new Set<string>();
  /** kid → 账号公钥 */
  const accounts = new Map<string, KeyObject>();
  const byJwk = new Map<string, string>();
  const violations: string[] = [];
  const requests: CaRequest[] = [];
  let heads = 0;
  let seq = 0;

  const respond = (r: CaReply, req?: CaRequest) => {
    const headers = new Headers(r.headers);
    if (!r.noNonce) {
      const n = `nonce-${++seq}`;
      issued.add(n);
      headers.set("Replay-Nonce", n);
      if (req) req.replyNonce = n;
    }
    const body = r.body === undefined ? null : typeof r.body === "string" ? r.body : JSON.stringify(r.body);
    if (body !== null && !headers.has("content-type")) headers.set("Content-Type", typeof r.body === "string" ? "text/plain" : "application/json");
    return new Response(body, { status: r.status ?? 200, headers });
  };

  const fetch = async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init?.headers ?? {}) as Record<string, string>)) headers[k.toLowerCase()] = v;
    const bad = (msg: string) => (violations.push(`${method} ${url}：${msg}`), respond(problem(400, "malformed", msg)));
    if (!/^sslbear-cli\/\d/.test(headers["user-agent"] ?? "")) violations.push(`${method} ${url}：缺少 User-Agent`);
    if (!(init?.signal instanceof AbortSignal)) violations.push(`${method} ${url}：没有超时 signal`);

    if (method === "GET" && url === DIR_URL) return respond({ body: directory, noNonce: true });
    if (method === "HEAD" && url === DIRECTORY.newNonce) {
      heads++;
      return respond({ status: 200 });
    }
    if (method === "GET") return respond({ status: 404, body: "Not Found", noNonce: true });
    if (method !== "POST") return bad(`不支持 ${method}`);
    if (headers["content-type"] !== "application/jose+json") return bad(`Content-Type 为 ${headers["content-type"]}`);

    const jws = JSON.parse(String(init?.body)) as Record<string, string>;
    if (Object.keys(jws).sort().join() !== "payload,protected,signature") return bad("JWS 不是扁平 JSON 序列化");
    const header = JSON.parse(decode(jws.protected!)) as Record<string, unknown>;
    if (header.alg !== "ES256") return bad(`alg 为 ${String(header.alg)}`);
    if (header.url !== url) return bad(`protected.url ${String(header.url)} 与请求 URL 不一致`);
    const nonce = String(header.nonce);
    if (!issued.has(nonce) || used.has(nonce)) return bad(`nonce ${nonce} 未签发或已用过`);
    used.add(nonce);

    const isNewAccount = url === DIRECTORY.newAccount;
    if ("jwk" in header === "kid" in header) return bad("jwk 与 kid 必须恰好有一个");
    if (isNewAccount !== "jwk" in header) return bad(isNewAccount ? "newAccount 必须用 jwk" : "newAccount 之外必须用 kid");
    let pub: KeyObject | undefined;
    if (isNewAccount) {
      const jwk = header.jwk as JsonWebKey;
      if (Object.keys(jwk).sort().join() !== "crv,kty,x,y") return bad(`jwk 成员不对（不能带私钥 d）：${Object.keys(jwk).join()}`);
      pub = createPublicKey({ key: jwk, format: "jwk" });
    } else {
      pub = accounts.get(String(header.kid));
      if (!pub) return bad(`未知账号 ${String(header.kid)}`);
    }
    const signed = Buffer.from(`${jws.protected}.${jws.payload}`);
    if (!verify("sha256", signed, { key: pub, dsaEncoding: "ieee-p1363" }, Buffer.from(jws.signature!, "base64url"))) return bad("签名验证失败");

    const req: CaRequest = { method, url, path: new URL(url).pathname, headers, header, payload: jws.payload === "" ? "" : JSON.parse(decode(jws.payload!)) };
    requests.push(req);
    const custom = handle(req);
    if (custom) return respond(custom, req);
    if (isNewAccount) {
      const jwk = header.jwk as JsonWebKey;
      const known = byJwk.get(`${jwk.x}.${jwk.y}`);
      if (known) return respond(json({ status: "valid" }, { Location: known }), req);
      const kid = `${BASE}/acct/${accounts.size + 1}`;
      accounts.set(kid, pub);
      byJwk.set(`${jwk.x}.${jwk.y}`, kid);
      return respond(json({ status: "valid" }, { Location: kid }, 201), req);
    }
    return respond(problem(404, "malformed", `没有这个资源：${url}`), req);
  };
  return { fetch: fetch as Fetch, violations, requests, heads: () => heads };
}

type Ca = ReturnType<typeof fakeCa>;
const cas: Ca[] = [];
afterEach(() => {
  for (const ca of cas.splice(0)) expect(ca.violations).toEqual([]);
});

function ctxOf(fetch: Fetch, sleeps: number[] = [], timeoutMs = 1000): QueryContext {
  return { env: {}, fetch, now: new Date("2026-10-18T00:00:00Z"), timeoutMs, sleep: async (ms) => void sleeps.push(ms) };
}

/** 建假 CA 与客户端，并注册好账号 */
async function setup(handle?: (req: CaRequest) => CaReply | undefined, opts: { register?: boolean } = {}) {
  const ca = fakeCa(handle);
  cas.push(ca);
  const sleeps: number[] = [];
  const accountKey = generateAccountKey();
  const client = await createAcmeClient(ctxOf(ca.fetch, sleeps), { directoryUrl: DIR_URL, accountKey });
  if (opts.register !== false) await client.ensureAccount();
  return { ca, client, sleeps, accountKey };
}

async function acmeError(p: Promise<unknown>): Promise<AcmeError> {
  const e = await p.then(
    () => undefined,
    (err: unknown) => err,
  );
  expect(e).toBeInstanceOf(AcmeError);
  return e as AcmeError;
}

const authz = (domain: string, status: string, extra: Record<string, unknown> = {}) => ({
  identifier: { type: "dns", value: domain },
  status,
  expires: "2026-10-25T00:00:00Z",
  challenges: [
    { type: "http-01", url: `${BASE}/chall/${domain}/http`, token: "tok-http", status: "pending" },
    { type: "dns-01", url: `${BASE}/chall/${domain}/dns`, token: `tok-${domain}`, status: status === "valid" ? "valid" : "pending" },
  ],
  ...extra,
});

describe("目录", () => {
  it("解析端点、配置文件、服务条款与 ARI", async () => {
    const { client } = await setup(undefined, { register: false });
    expect(client.directory).toEqual({
      url: DIR_URL,
      newNonce: DIRECTORY.newNonce,
      newAccount: DIRECTORY.newAccount,
      newOrder: DIRECTORY.newOrder,
      renewalInfo: DIRECTORY.renewalInfo,
      profiles: { classic: "经典配置", shortlived: "短期证书" },
      termsOfService: DIRECTORY.meta.termsOfService,
    });
  });

  it("CA 不支持配置文件与 ARI 时这两项缺省", async () => {
    const { meta: _meta, renewalInfo: _ri, ...plain } = DIRECTORY;
    const ca = fakeCa(undefined, plain);
    cas.push(ca);
    const client = await createAcmeClient(ctxOf(ca.fetch), { directoryUrl: DIR_URL, accountKey: generateAccountKey() });
    expect(client.directory.profiles).toBeUndefined();
    expect(client.directory.renewalInfo).toBeUndefined();
    expect(client.directory.termsOfService).toBeUndefined();
  });

  it("不是 ACME 目录、目录地址出错时报 AcmeError", async () => {
    const notDir = fakeCa(undefined, { hello: "world" });
    cas.push(notDir);
    const e = await acmeError(createAcmeClient(ctxOf(notDir.fetch), { directoryUrl: DIR_URL, accountKey: generateAccountKey() }));
    expect(e.type).toBe("badResponse");
    expect(e.detail).toMatch(/不是 ACME 目录/);
    const e404 = await acmeError(createAcmeClient(ctxOf(notDir.fetch), { directoryUrl: `${BASE}/nope`, accountKey: generateAccountKey() }));
    expect(e404).toMatchObject({ type: "badResponse", httpStatus: 404, detail: "HTTP 404：Not Found" });
  });

  it("账号私钥不是 P-256 时直接报错", async () => {
    const ca = fakeCa();
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
    await expect(createAcmeClient(ctxOf(ca.fetch), { directoryUrl: DIR_URL, accountKey: rsa })).rejects.toThrow(/P-256/);
  });
});

describe("账号与 JWS", () => {
  it("newAccount 用 jwk 签名、同意服务条款、带联系邮箱；之后的请求用 Location 作 kid；nonce 先 HEAD 取、之后用响应带回的", async () => {
    const { ca, client } = await setup(
      (req) => (req.path.startsWith("/authz/") ? json(authz("example.com", "pending")) : undefined),
      { register: false },
    );
    await client.ensureAccount("ops@example.com");
    const reg = ca.requests[0]!;
    expect(reg.payload).toEqual({ termsOfServiceAgreed: true, contact: ["mailto:ops@example.com"] });
    expect(reg.header.jwk).toMatchObject({ kty: "EC", crv: "P-256" });
    expect(reg.header.kid).toBeUndefined();

    await client.getAuthorization(`${BASE}/authz/1`);
    const next = ca.requests[1]!;
    expect(next.header.kid).toBe(`${BASE}/acct/1`);
    expect(next.header.jwk).toBeUndefined();
    expect(next.payload).toBe("");
    expect(next.header.nonce).toBe(reg.replyNonce);
    expect(ca.heads()).toBe(1);
  });

  it("同一把账号私钥再注册：CA 回 200 与原账号 URL；不给邮箱时不带 contact", async () => {
    const ca = fakeCa();
    cas.push(ca);
    const accountKey = generateAccountKey();
    for (let i = 0; i < 2; i++) {
      const client = await createAcmeClient(ctxOf(ca.fetch), { directoryUrl: DIR_URL, accountKey });
      await client.ensureAccount();
    }
    expect(ca.requests.map((r) => r.payload)).toEqual([{ termsOfServiceAgreed: true }, { termsOfServiceAgreed: true }]);
  });

  it("ensureAccount 之前调用其他方法报错，不发请求", async () => {
    const { ca, client } = await setup(undefined, { register: false });
    await expect(client.newOrder(["example.com"])).rejects.toThrow(/ensureAccount/);
    await expect(client.getAuthorization(`${BASE}/authz/1`)).rejects.toThrow(/ensureAccount/);
    expect(ca.requests).toHaveLength(0);
  });

  it("dnsTxtValue = base64url(SHA-256(token.账号公钥指纹))，指纹按 RFC 7638（crv, kty, x, y 字典序、无空白）", async () => {
    const { client, accountKey } = await setup(undefined, { register: false });
    const { x, y } = createPublicKey(accountKey).export({ format: "jwk" });
    const thumbprint = createHash("sha256").update(`{"crv":"P-256","kty":"EC","x":"${x}","y":"${y}"}`).digest("base64url");
    const expected = createHash("sha256").update(`tok-abc.${thumbprint}`).digest("base64url");
    expect(client.dnsTxtValue("tok-abc")).toBe(expected);
    expect(expected).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("响应没带 Replay-Nonce 时去 newNonce 补取；并发请求不复用同一个 nonce", async () => {
    let first = true;
    const { ca, client } = await setup((req) => {
      if (!req.path.startsWith("/authz/")) return undefined;
      const reply = { ...json(authz("example.com", "pending")), noNonce: first };
      first = false;
      return reply;
    });
    expect(ca.heads()).toBe(1);
    await client.getAuthorization(`${BASE}/authz/1`);
    await client.getAuthorization(`${BASE}/authz/2`);
    expect(ca.heads()).toBe(2);
    await Promise.all([1, 2, 3].map((i) => client.getAuthorization(`${BASE}/authz/${i}`)));
    const nonces = ca.requests.map((r) => r.header.nonce);
    expect(new Set(nonces).size).toBe(nonces.length);
  });
});

describe("badNonce", () => {
  it("用错误响应带回的新 nonce 重发", async () => {
    let rejects = 2;
    const { ca, client } = await setup((req) => {
      if (req.path !== "/authz/1") return undefined;
      if (rejects-- > 0) return problem(400, "badNonce", "JWS has an invalid anti-replay nonce");
      return json(authz("example.com", "pending"));
    });
    const a = await client.getAuthorization(`${BASE}/authz/1`);
    expect(a.domain).toBe("example.com");
    const tries = ca.requests.filter((r) => r.path === "/authz/1");
    expect(tries).toHaveLength(3);
    expect(tries[1]!.header.nonce).toBe(tries[0]!.replyNonce);
    expect(tries[2]!.header.nonce).toBe(tries[1]!.replyNonce);
  });

  it("重发 3 次仍是 badNonce 就放弃（可重试）", async () => {
    const { ca, client } = await setup((req) => (req.path === "/authz/1" ? problem(400, "badNonce", "bad nonce") : undefined));
    const e = await acmeError(client.getAuthorization(`${BASE}/authz/1`));
    expect(e.type).toBe("badNonce");
    expect(e.retryable).toBe(true);
    expect(ca.requests.filter((r) => r.path === "/authz/1")).toHaveLength(4);
  });
});

describe("下单与授权", () => {
  it("newOrder：identifiers、profile、replaces；Location 为订单 URL", async () => {
    const order = { status: "pending", authorizations: [`${BASE}/authz/1`, `${BASE}/authz/2`], finalize: `${BASE}/order/9/finalize`, identifiers: [] };
    const { ca, client } = await setup((req) => (req.path === "/new-order" ? json(order, { Location: `${BASE}/order/9` }, 201) : undefined));
    const o = await client.newOrder(["example.com", "*.example.com"], { profile: "classic", replaces: "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE" });
    expect(o).toEqual({ url: `${BASE}/order/9`, status: "pending", authorizations: order.authorizations, finalize: order.finalize });
    expect(ca.requests.at(-1)!.payload).toEqual({
      identifiers: [
        { type: "dns", value: "example.com" },
        { type: "dns", value: "*.example.com" },
      ],
      profile: "classic",
      replaces: "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE",
    });

    await client.newOrder(["example.com"]);
    expect(ca.requests.at(-1)!.payload).toEqual({ identifiers: [{ type: "dns", value: "example.com" }] });
  });

  it("下单响应缺 Location、订单格式不对时报 badResponse", async () => {
    const { client } = await setup((req) => (req.path === "/new-order" ? json({ status: "pending", authorizations: [], finalize: `${BASE}/f` }, {}, 201) : undefined));
    expect((await acmeError(client.newOrder(["example.com"]))).detail).toMatch(/Location/);
  });

  it("授权解析：普通域名、泛域名（identifier 去掉 *. 且 wildcard = true）、已 valid 的授权", async () => {
    const { client } = await setup((req) => {
      if (req.path === "/authz/plain") return json(authz("example.com", "pending"));
      if (req.path === "/authz/wild") {
        // 泛域名授权只提供 dns-01
        return json({ identifier: { type: "dns", value: "example.com" }, status: "pending", wildcard: true, challenges: [{ type: "dns-01", url: `${BASE}/chall/w`, token: "tok-w", status: "pending" }] });
      }
      if (req.path === "/authz/done") return json({ identifier: { type: "dns", value: "www.example.com" }, status: "valid", challenges: [] });
      return undefined;
    });
    expect(await client.getAuthorization(`${BASE}/authz/plain`)).toEqual({
      url: `${BASE}/authz/plain`,
      status: "pending",
      domain: "example.com",
      wildcard: false,
      challenge: { url: `${BASE}/chall/example.com/dns`, token: "tok-example.com", status: "pending" },
    });
    expect(await client.getAuthorization(`${BASE}/authz/wild`)).toMatchObject({ domain: "example.com", wildcard: true, challenge: { url: `${BASE}/chall/w`, token: "tok-w" } });
    const done = await client.getAuthorization(`${BASE}/authz/done`);
    expect(done).toEqual({ url: `${BASE}/authz/done`, status: "valid", domain: "www.example.com", wildcard: false });
  });

  it("应答质询：POST {}（不是 POST-as-GET）", async () => {
    const { ca, client } = await setup((req) => (req.path === "/chall/1" ? json({ type: "dns-01", status: "processing", token: "t", url: req.url }) : undefined));
    await client.answerChallenge(`${BASE}/chall/1`);
    expect(ca.requests.at(-1)!.payload).toEqual({});
  });
});

describe("错误", () => {
  it("限流：problem document 转成 AcmeError，带 httpStatus、Retry-After 秒数", async () => {
    const { client } = await setup((req) =>
      req.path === "/new-order"
        ? problem(429, "rateLimited", "too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s", {}, { "Retry-After": "3600" })
        : undefined,
    );
    const e = await acmeError(client.newOrder(["example.com"]));
    expect(e).toMatchObject({ type: "rateLimited", httpStatus: 429, retryAfter: 3600, retryable: true });
    expect(e.detail).toMatch(/too many certificates/);
    expect(e.message).toBe(e.detail);
  });

  it("Retry-After 为 HTTP 日期时以响应的 Date 头为基准换算成秒", async () => {
    const { client } = await setup((req) =>
      req.path === "/new-order" ? problem(429, "rateLimited", "slow down", {}, { "Retry-After": "Sun, 18 Oct 2026 10:30:00 GMT", Date: "Sun, 18 Oct 2026 10:00:00 GMT" }) : undefined,
    );
    expect((await acmeError(client.newOrder(["example.com"]))).retryAfter).toBe(1800);
  });

  it("subproblems 转成「域名：原因」", async () => {
    const { client } = await setup((req) =>
      req.path === "/new-order"
        ? problem(400, "rejectedIdentifier", "Some of the identifiers requested were rejected", {
            subproblems: [
              { type: "urn:ietf:params:acme:error:malformed", detail: 'Invalid underscore in DNS name "_example.org"', identifier: { type: "dns", value: "_example.org" } },
              { type: "urn:ietf:params:acme:error:rejectedIdentifier", detail: 'This CA will not issue for "example.net"', identifier: { type: "dns", value: "example.net" } },
            ],
          })
        : undefined,
    );
    const e = await acmeError(client.newOrder(["_example.org", "example.net"]));
    expect(e.type).toBe("rejectedIdentifier");
    expect(e.retryable).toBe(false);
    expect(e.subproblems).toEqual(['_example.org：Invalid underscore in DNS name "_example.org"', 'example.net：This CA will not issue for "example.net"']);
  });

  it("非 JSON 的错误响应：detail 为状态码加去掉标签的文字，按状态码归类", async () => {
    let status = 502;
    const { client } = await setup((req) =>
      req.path === "/new-order" ? { status, body: "<html><head><title>502 Bad Gateway</title></head><body><center>nginx</center></body></html>", headers: { "Content-Type": "text/html" } } : undefined,
    );
    const e = await acmeError(client.newOrder(["example.com"]));
    expect(e).toMatchObject({ type: "serverInternal", httpStatus: 502, retryable: true, detail: "HTTP 502：502 Bad Gateway nginx" });
    status = 429;
    expect((await acmeError(client.newOrder(["example.com"]))).type).toBe("rateLimited");
    status = 403;
    expect(await acmeError(client.newOrder(["example.com"]))).toMatchObject({ type: "badResponse", retryable: false });
  });

  it("网络错误 → network；超时 → timeout（都可重试）", async () => {
    const refused = (async () => {
      throw new TypeError("fetch failed", { cause: { code: "ECONNREFUSED" } });
    }) as Fetch;
    const e = await acmeError(createAcmeClient(ctxOf(refused), { directoryUrl: DIR_URL, accountKey: generateAccountKey() }));
    expect(e).toMatchObject({ type: "network", retryable: true });
    expect(e.detail).toBe("网络错误：ca.test ECONNREFUSED");

    // 真用 AbortSignal.timeout：请求挂起直到 signal 触发
    const hanging = ((_input: unknown, init?: RequestInit) =>
      new Promise((_resolve, reject) => init!.signal!.addEventListener("abort", () => reject(init!.signal!.reason)))) as Fetch;
    const t = await acmeError(createAcmeClient(ctxOf(hanging, [], 20), { directoryUrl: DIR_URL, accountKey: generateAccountKey() }));
    expect(t).toMatchObject({ type: "timeout", retryable: true });
    expect(t.detail).toBe("请求超时（20ms）：ca.test");
  });
});

describe("网络重试", () => {
  it("网络错误、超时自动重试（共 3 次，间隔 1、2 秒）；POST 原样重发同一个 nonce", async () => {
    const ca = fakeCa();
    cas.push(ca);
    const failOnce = new Set([DIR_URL, DIRECTORY.newAccount]);
    const flaky = (async (input: string | URL | Request, init?: RequestInit) => {
      // 目录与 newAccount 的第一次发送都在连上之前断开：CA 没收到，nonce 仍有效
      if (failOnce.delete(String(input))) throw new TypeError("fetch failed", { cause: { code: "ECONNRESET" } });
      return ca.fetch(input, init);
    }) as Fetch;
    const sleeps: number[] = [];
    const client = await createAcmeClient(ctxOf(flaky, sleeps), { directoryUrl: DIR_URL, accountKey: generateAccountKey() });
    await client.ensureAccount();
    expect(sleeps).toEqual([1000, 1000]);
    expect(ca.requests.map((r) => r.path)).toEqual(["/new-account"]);
  });

  it("连续 3 次网络错误才放弃", async () => {
    let calls = 0;
    const down = (async () => {
      calls++;
      throw new TypeError("fetch failed", { cause: { code: "ECONNRESET" } });
    }) as Fetch;
    const sleeps: number[] = [];
    expect(await acmeError(createAcmeClient(ctxOf(down, sleeps), { directoryUrl: DIR_URL, accountKey: generateAccountKey() }))).toMatchObject({ type: "network" });
    expect(calls).toBe(3);
    expect(sleeps).toEqual([1000, 2000]);
  });
});

describe("waitAuthorization", () => {
  it("pending → valid；轮询间隔遵守 Retry-After（上限 10 秒、下限 1 秒，缺省 2 秒）", async () => {
    const replies: Record<string, string>[] = [{ "Retry-After": "3" }, {}, { "Retry-After": "60" }, { "Retry-After": "0" }];
    let i = 0;
    const { client, sleeps } = await setup((req) => {
      if (req.path !== "/authz/1") return undefined;
      const h = replies[i++];
      return h ? json(authz("example.com", "pending"), h) : json(authz("example.com", "valid"));
    });
    await client.waitAuthorization(`${BASE}/authz/1`, 60_000);
    expect(sleeps).toEqual([3000, 2000, 10_000, 1000]);
  });

  it("invalid：原因取自 dns-01 质询的 error（含 subproblems），detail 带上泛域名", async () => {
    const { client } = await setup((req) =>
      req.path === "/authz/1"
        ? json({
            identifier: { type: "dns", value: "example.com" },
            status: "invalid",
            wildcard: true,
            challenges: [
              {
                type: "dns-01",
                url: `${BASE}/chall/1`,
                token: "t",
                status: "invalid",
                error: {
                  type: "urn:ietf:params:acme:error:unauthorized",
                  detail: "Incorrect TXT record found at _acme-challenge.example.com",
                  status: 403,
                  subproblems: [{ type: "urn:ietf:params:acme:error:dns", detail: "SERVFAIL", identifier: { type: "dns", value: "example.com" } }],
                },
              },
            ],
          })
        : undefined,
    );
    const e = await acmeError(client.waitAuthorization(`${BASE}/authz/1`, 60_000));
    expect(e.type).toBe("unauthorized");
    expect(e.detail).toBe("*.example.com：Incorrect TXT record found at _acme-challenge.example.com");
    expect(e.subproblems).toEqual(["example.com：SERVFAIL"]);
    expect(e.invalidAuthorization).toBe(true);
  });

  it("invalid 但 CA 没给原因、授权已过期时也报 AcmeError", async () => {
    const { client } = await setup((req) => {
      if (req.path === "/authz/bare") return json({ identifier: { type: "dns", value: "a.example.com" }, status: "invalid", challenges: [] });
      if (req.path === "/authz/old") return json(authz("b.example.com", "expired"));
      return undefined;
    });
    const bare = await acmeError(client.waitAuthorization(`${BASE}/authz/bare`, 1000));
    expect(bare).toMatchObject({ detail: "a.example.com：验证失败，CA 没有给出原因", invalidAuthorization: true });
    // 过期不是验证没通过：重跑会重新下单
    const old = await acmeError(client.waitAuthorization(`${BASE}/authz/old`, 1000));
    expect(old.detail).toMatch(/^b\.example\.com：授权已失效（expired）/);
    expect(old.invalidAuthorization).toBe(false);
  });

  it("按累计等待时间判超时：最后一次等待截到正好用完，再查一次后报 timeout", async () => {
    const { ca, client, sleeps } = await setup((req) => (req.path === "/authz/1" ? json(authz("example.com", "pending"), { "Retry-After": "5" }) : undefined));
    const e = await acmeError(client.waitAuthorization(`${BASE}/authz/1`, 12_000));
    expect(e).toMatchObject({ type: "timeout", retryable: true });
    expect(e.detail).toBe("example.com：等待 CA 验证超时（12 秒）");
    expect(sleeps).toEqual([5000, 5000, 2000]);
    expect(ca.requests.filter((r) => r.path === "/authz/1")).toHaveLength(4);
  });
});

describe("finalize 与下载", () => {
  const ORDER_URL = `${BASE}/order/1`;
  const FINALIZE_URL = `${BASE}/order/1/finalize`;
  const order = (status: string, extra: Record<string, unknown> = {}) => ({ status, authorizations: [`${BASE}/authz/1`], finalize: FINALIZE_URL, ...extra });
  const snapshot = { url: ORDER_URL, status: "pending" as const, authorizations: [`${BASE}/authz/1`], finalize: FINALIZE_URL };

  it("先查订单当前状态，ready 才提交 CSR；processing 按 Retry-After 继续等到 valid", async () => {
    const states = ["ready", "processing", "valid"];
    let i = 0;
    const { ca, client, sleeps } = await setup((req) => {
      if (req.path === "/order/1") {
        const s = states[i++]!;
        return json(order(s, s === "valid" ? { certificate: `${BASE}/cert/1` } : {}));
      }
      if (req.path === "/order/1/finalize") return json(order("processing"), { "Retry-After": "1" });
      return undefined;
    });
    const csr = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]);
    const done = await client.finalize(snapshot, csr, 60_000);
    expect(done).toEqual({ ...snapshot, status: "valid", certificate: `${BASE}/cert/1` });
    expect(ca.requests.filter((r) => r.path !== "/new-account").map((r) => [r.path, r.payload])).toEqual([
      ["/order/1", ""],
      ["/order/1/finalize", { csr: "MAMCAQA" }],
      ["/order/1", ""],
      ["/order/1", ""],
    ]);
    expect(sleeps).toEqual([1000, 2000]);
  });

  it("订单还是 pending（授权没完成）时报错，不提交 CSR", async () => {
    const { ca, client } = await setup((req) => (req.path === "/order/1" ? json(order("pending")) : undefined));
    const e = await acmeError(client.finalize(snapshot, Buffer.from([0x30, 0x00]), 60_000));
    expect(e.type).toBe("orderNotReady");
    expect(e.detail).toMatch(/授权/);
    expect(ca.requests.some((r) => r.path.endsWith("/finalize"))).toBe(false);
  });

  it("订单 invalid：用 order.error 报错", async () => {
    const { client } = await setup((req) => {
      if (req.path === "/order/1") return json(order("ready"));
      if (req.path === "/order/1/finalize") return json(order("invalid", { error: { type: "urn:ietf:params:acme:error:badCSR", detail: "CSR contains a public key of a known weak type" } }));
      return undefined;
    });
    const e = await acmeError(client.finalize(snapshot, Buffer.from([0x30, 0x00]), 60_000));
    expect(e).toMatchObject({ type: "badCSR", detail: "CSR contains a public key of a known weak type" });
  });

  it("CA 拒绝提交（如 badCSR problem）原样抛出", async () => {
    const { client } = await setup((req) => {
      if (req.path === "/order/1") return json(order("ready"));
      if (req.path === "/order/1/finalize") return problem(400, "badCSR", "Error finalizing order :: CSR is unacceptable");
      return undefined;
    });
    expect(await acmeError(client.finalize(snapshot, Buffer.from([0x30, 0x00]), 60_000))).toMatchObject({ type: "badCSR", httpStatus: 400 });
  });

  it("提交 CSR 报错但订单其实已在签发（网络重试导致重复提交）时接着等", async () => {
    const states = ["ready", "processing", "valid"];
    let i = 0;
    const { client } = await setup((req) => {
      if (req.path === "/order/1") {
        const s = states[i++]!;
        return json(order(s, s === "valid" ? { certificate: `${BASE}/cert/1` } : {}));
      }
      if (req.path === "/order/1/finalize") return problem(403, "orderNotReady", "Order's status (\"processing\") is not acceptable for finalization");
      return undefined;
    });
    const done = await client.finalize(snapshot, Buffer.from([0x30, 0x00]), 60_000);
    expect(done.certificate).toBe(`${BASE}/cert/1`);
  });

  it("一直 processing 时按累计等待时间超时", async () => {
    const { client, sleeps } = await setup((req) => {
      if (req.path === "/order/1") return json(order("processing"), { "Retry-After": "4" });
      return undefined;
    });
    const e = await acmeError(client.finalize(snapshot, Buffer.from([0x30, 0x00]), 10_000));
    expect(e).toMatchObject({ type: "timeout", detail: "等待 CA 签发证书超时（10 秒）" });
    expect(sleeps).toEqual([4000, 4000, 2000]);
  });

  it("下载证书：POST-as-GET，Accept: application/pem-certificate-chain，返回 PEM 原文", async () => {
    const { ca, client } = await setup((req) =>
      req.path === "/cert/1" ? { body: PEM, headers: { "Content-Type": "application/pem-certificate-chain" } } : req.path === "/cert/bad" ? json({ oops: true }) : undefined,
    );
    expect(await client.downloadCertificate(`${BASE}/cert/1`)).toBe(PEM);
    const req = ca.requests.at(-1)!;
    expect(req.payload).toBe("");
    expect(req.headers.accept).toBe("application/pem-certificate-chain");
    expect((await acmeError(client.downloadCertificate(`${BASE}/cert/bad`))).type).toBe("badResponse");
  });
});

describe("完整流程", () => {
  it("注册 → 下单 → 取授权 → 应答 → 等验证 → finalize → 下载", async () => {
    let answered = false;
    let finalized = false;
    const { ca, client } = await setup((req) => {
      switch (req.path) {
        case "/new-order":
          return json({ status: "pending", authorizations: [`${BASE}/authz/1`], finalize: `${BASE}/order/1/finalize` }, { Location: `${BASE}/order/1` }, 201);
        case "/authz/1":
          return json(authz("example.com", answered ? "valid" : "pending"));
        case "/chall/example.com/dns":
          answered = true;
          return json({ type: "dns-01", status: "processing" });
        case "/order/1":
          return json({ status: finalized ? "valid" : "ready", authorizations: [`${BASE}/authz/1`], finalize: `${BASE}/order/1/finalize`, ...(finalized && { certificate: `${BASE}/cert/1` }) });
        case "/order/1/finalize":
          finalized = true;
          return json({ status: "processing", authorizations: [`${BASE}/authz/1`], finalize: `${BASE}/order/1/finalize` });
        case "/cert/1":
          return { body: PEM };
      }
      return undefined;
    });
    const o = await client.newOrder(["example.com"], { profile: "classic" });
    const a = await client.getAuthorization(o.authorizations[0]!);
    expect(client.dnsTxtValue(a.challenge!.token)).toMatch(/^[A-Za-z0-9_-]{43}$/);
    await client.answerChallenge(a.challenge!.url);
    await client.waitAuthorization(a.url, 60_000);
    const done = await client.finalize(o, Buffer.from([0x30, 0x00]), 60_000);
    expect(await client.downloadCertificate(done.certificate!)).toBe(PEM);
    expect(ca.heads()).toBe(1);
  });
});
