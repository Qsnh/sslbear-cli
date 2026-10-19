import { createHash, createPublicKey, sign, type KeyObject } from "node:crypto";
import type { QueryContext } from "../lib/http.js";
import { VERSION } from "../version.js";
import { AcmeError, type AcmeAuthorization, type AcmeClient, type AcmeDirectory, type AcmeOrder } from "./types.js";

/** RFC 8555 第 6.1 节：客户端必须带 User-Agent */
const USER_AGENT = `sslbear-cli/${VERSION}`;
const ERROR_PREFIX = "urn:ietf:params:acme:error:";
/** badNonce 用错误响应带回的新 nonce 重发的次数上限 */
const MAX_BAD_NONCE_RETRIES = 3;
/** 轮询间隔：CA 没给 Retry-After 时 2 秒；给了也最多等 10 秒、至少 1 秒（Retry-After: 0 不能变成空转） */
const POLL_DEFAULT_MS = 2000;
const POLL_MIN_MS = 1000;
const POLL_MAX_MS = 10_000;
/** POST-as-GET（RFC 8555 第 6.3 节）的 payload 是空字符串，不是 JSON */
const POST_AS_GET = "";

const ORDER_STATUS: readonly string[] = ["pending", "ready", "processing", "valid", "invalid"];
const AUTHZ_STATUS: readonly string[] = ["pending", "valid", "invalid", "deactivated", "expired", "revoked"];

type Json = Record<string, unknown>;

interface AcmeResponse {
  status: number;
  headers: Headers;
  text: string;
}

const b64u = (b: Buffer | string) => Buffer.from(b).toString("base64url");
const str = (v: unknown) => (typeof v === "string" && v ? v : undefined);
const isObject = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

/**
 * 自己发请求而不用 lib/http.ts 的 send：ACME 要读 Replay-Nonce / Location / Retry-After 响应头。
 * 读响应体也在超时与网络错误处理范围内（响应头到了但响应体卡住同样算超时）
 */
async function request(ctx: QueryContext, url: string, init: { method: string; headers?: Record<string, string>; body?: string }): Promise<AcmeResponse> {
  try {
    const res = await ctx.fetch(url, { ...init, headers: { "User-Agent": USER_AGENT, ...init.headers }, signal: AbortSignal.timeout(ctx.timeoutMs) });
    return { status: res.status, headers: res.headers, text: await res.text() };
  } catch (e) {
    const err = e as Error;
    if (err.name === "TimeoutError" || err.name === "AbortError") throw new AcmeError("timeout", `请求超时（${ctx.timeoutMs}ms）：${hostOf(url)}`);
    const cause = (err as { cause?: { code?: string } }).cause?.code;
    throw new AcmeError("network", `网络错误：${hostOf(url)} ${cause ?? err.message}`);
  }
}

/** Retry-After（RFC 9110 第 10.2.3 节）是秒数或 HTTP 日期；日期以响应的 Date 头为基准，免受本机时钟偏差影响 */
function retryAfterOf(headers: Headers): number | undefined {
  const v = headers.get("retry-after")?.trim();
  if (!v) return undefined;
  if (/^\d+$/.test(v)) return Number(v);
  const at = Date.parse(v);
  if (Number.isNaN(at)) return undefined;
  const base = Date.parse(headers.get("date") ?? "");
  return Math.max(0, Math.ceil((at - (Number.isNaN(base) ? Date.now() : base)) / 1000));
}

const shortType = (t: unknown) => str(t)?.replace(ERROR_PREFIX, "");

/** 子问题（RFC 8555 第 6.7.1 节）各自带 identifier，转成「域名：原因」 */
function subproblemsOf(problem: Json): string[] | undefined {
  if (!Array.isArray(problem.subproblems) || problem.subproblems.length === 0) return undefined;
  return problem.subproblems.filter(isObject).map((s) => {
    const detail = str(s.detail) ?? shortType(s.type) ?? "未知错误";
    const id = isObject(s.identifier) ? str(s.identifier.value) : undefined;
    return id ? `${id}：${detail}` : detail;
  });
}

/** problem document（RFC 7807）→ AcmeError；prefix 用于在原因前标上域名 */
function problemError(problem: Json, fallbackType: string, opts: { httpStatus?: number; retryAfter?: number; prefix?: string } = {}): AcmeError {
  const type = shortType(problem.type) ?? fallbackType;
  const detail = str(problem.detail) ?? type;
  return new AcmeError(type, opts.prefix ? `${opts.prefix}：${detail}` : detail, opts.httpStatus, opts.retryAfter, subproblemsOf(problem));
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

function errorOf(res: AcmeResponse): AcmeError {
  const retryAfter = retryAfterOf(res.headers);
  const body = parseJson(res.text);
  // 不看 Content-Type 是否为 application/problem+json：有的反向代理会改写它，按内容判断更稳
  if (isObject(body) && (str(body.type) || str(body.detail))) return problemError(body, "badResponse", { httpStatus: res.status, retryAfter });
  // 不是 problem document（如网关返回的 HTML 错误页）：去掉标签只留文字；限流、服务端错误仍按状态码归类，retryable 才判断得对
  const text = res.text.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim().slice(0, 200);
  const type = res.status === 429 ? "rateLimited" : res.status >= 500 ? "serverInternal" : "badResponse";
  return new AcmeError(type, `HTTP ${res.status}${text ? `：${text}` : ""}`, res.status, retryAfter);
}

function jsonOf(res: AcmeResponse, url: string): Json {
  const body = parseJson(res.text);
  if (isObject(body)) return body;
  throw new AcmeError("badResponse", `响应不是合法 JSON（HTTP ${res.status}）：${hostOf(url)} ${res.text.slice(0, 200)}`, res.status);
}

function locationOf(res: AcmeResponse, url: string): string {
  const loc = res.headers.get("location");
  if (!loc) throw new AcmeError("badResponse", `CA 的响应缺少 Location 头：${url}`, res.status);
  return new URL(loc, url).href;
}

function pollDelayMs(retryAfter: number | undefined): number {
  return retryAfter === undefined ? POLL_DEFAULT_MS : Math.min(Math.max(retryAfter * 1000, POLL_MIN_MS), POLL_MAX_MS);
}

async function getDirectory(ctx: QueryContext, url: string): Promise<AcmeDirectory> {
  const res = await request(ctx, url, { method: "GET", headers: { Accept: "application/json" } });
  if (res.status >= 400) throw errorOf(res);
  const body = jsonOf(res, url);
  const newNonce = str(body.newNonce);
  const newAccount = str(body.newAccount);
  const newOrder = str(body.newOrder);
  if (!newNonce || !newAccount || !newOrder) throw new AcmeError("badResponse", `不是 ACME 目录（缺少 newNonce / newAccount / newOrder）：${url}`, res.status);
  const meta = isObject(body.meta) ? body.meta : {};
  // 配置文件说明在 Let's Encrypt 是文档链接；只关心有哪些名字，说明不是字符串时置空
  const profiles = isObject(meta.profiles) ? Object.fromEntries(Object.entries(meta.profiles).map(([k, v]) => [k, typeof v === "string" ? v : ""])) : {};
  const renewalInfo = str(body.renewalInfo);
  const termsOfService = str(meta.termsOfService);
  return {
    url,
    newNonce,
    newAccount,
    newOrder,
    ...(renewalInfo && { renewalInfo }),
    ...(Object.keys(profiles).length > 0 && { profiles }),
    ...(termsOfService && { termsOfService }),
  };
}

function parseOrder(body: Json, url: string): AcmeOrder {
  const status = str(body.status);
  const authorizations = Array.isArray(body.authorizations) ? body.authorizations : undefined;
  const finalize = str(body.finalize);
  if (!status || !ORDER_STATUS.includes(status) || !authorizations?.every((a) => typeof a === "string") || !finalize) {
    throw new AcmeError("badResponse", `CA 返回的订单格式不对：${url}`);
  }
  const certificate = str(body.certificate);
  return { url, status: status as AcmeOrder["status"], authorizations, finalize, ...(certificate && { certificate }) };
}

function parseAuthorization(body: Json, url: string): AcmeAuthorization {
  const status = str(body.status);
  const domain = isObject(body.identifier) ? str(body.identifier.value) : undefined;
  if (!status || !AUTHZ_STATUS.includes(status) || !domain) throw new AcmeError("badResponse", `CA 返回的授权格式不对：${url}`);
  const dns = (Array.isArray(body.challenges) ? body.challenges : []).filter(isObject).find((c) => c.type === "dns-01" && str(c.url) && str(c.token));
  return {
    url,
    status: status as AcmeAuthorization["status"],
    domain,
    wildcard: body.wildcard === true,
    ...(dns && { challenge: { url: String(dns.url), token: String(dns.token), status: str(dns.status) ?? "pending" } }),
  };
}

/** 授权 invalid：原因在失败质询的 error 里；只应答了 dns-01，优先取它的，没有再取任意一个带 error 的 */
function authorizationError(body: Json, name: string): AcmeError {
  const challenges = (Array.isArray(body.challenges) ? body.challenges : []).filter(isObject);
  const failed = challenges.find((c) => c.type === "dns-01" && isObject(c.error)) ?? challenges.find((c) => isObject(c.error));
  if (!failed) return new AcmeError("unauthorized", `${name}：验证失败，CA 没有给出原因`);
  return problemError(failed.error as Json, "unauthorized", { prefix: name });
}

/** 账号公钥 JWK：只含公开成员，按 RFC 7638 要求的字典序（crv, kty, x, y）排列，直接用于算指纹 */
function publicJwk(key: KeyObject): { crv: string; kty: string; x: string; y: string } {
  const { crv, kty, x, y } = createPublicKey(key).export({ format: "jwk" });
  return { crv: crv!, kty: kty!, x: x!, y: y! };
}

/**
 * ACME 客户端（RFC 8555）：读目录、管理 nonce、ES256 签名 JWS、把 problem document 转成 AcmeError。
 * 实例持有 nonce 与账号 URL（kid），可以并发调用：nonce 取出即清空，两个请求不会用同一个
 */
export async function createAcmeClient(ctx: QueryContext, opts: { directoryUrl: string; accountKey: KeyObject }): Promise<AcmeClient> {
  const { accountKey } = opts;
  if (accountKey.type !== "private" || accountKey.asymmetricKeyType !== "ec" || accountKey.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    throw new Error("ACME 账号私钥必须是 ECDSA P-256 私钥");
  }
  const directory = await getDirectory(ctx, opts.directoryUrl);
  const jwk = publicJwk(accountKey);
  const thumbprint = b64u(createHash("sha256").update(JSON.stringify(jwk)).digest());
  const sleep = ctx.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  /** 账号 URL：ensureAccount 之后才有，之后的请求都用它（kid）签名 */
  let kid: string | undefined;
  /** 上一个响应带回的 nonce，用一次就丢 */
  let spareNonce: string | undefined;

  async function takeNonce(): Promise<string> {
    const n = spareNonce;
    spareNonce = undefined;
    if (n) return n;
    const res = await request(ctx, directory.newNonce, { method: "HEAD" });
    if (res.status >= 400) throw errorOf(res);
    const fresh = res.headers.get("replay-nonce");
    if (!fresh) throw new AcmeError("badResponse", `CA 没有返回 Replay-Nonce：${directory.newNonce}`, res.status);
    return fresh;
  }

  /** 签名并发送；4xx / 5xx 抛 AcmeError。useJwk 只用于 newAccount（此时还没有账号 URL） */
  async function post(url: string, payload: unknown, opts: { useJwk?: boolean; accept?: string } = {}): Promise<AcmeResponse> {
    if (!opts.useJwk && !kid) throw new Error("ACME 账号未就绪：先调用 ensureAccount");
    const body = payload === POST_AS_GET ? "" : b64u(JSON.stringify(payload));
    let nonce = await takeNonce();
    for (let retry = 0; ; retry++) {
      const header = b64u(JSON.stringify({ alg: "ES256", nonce, url, ...(opts.useJwk ? { jwk } : { kid }) }));
      // ES256 的 JWS 签名是 r || s 各 32 字节（RFC 7518 第 3.4 节），不是 DER
      const signature = b64u(sign("sha256", Buffer.from(`${header}.${body}`), { key: accountKey, dsaEncoding: "ieee-p1363" }));
      const res = await request(ctx, url, {
        method: "POST",
        headers: { "Content-Type": "application/jose+json", ...(opts.accept && { Accept: opts.accept }) },
        body: JSON.stringify({ protected: header, payload: body, signature }),
      });
      const fresh = res.headers.get("replay-nonce") ?? undefined;
      const err = res.status >= 400 ? errorOf(res) : undefined;
      if (err?.type !== "badNonce" || retry >= MAX_BAD_NONCE_RETRIES) {
        // 没带新 nonce 时不清掉并发请求留下的
        if (fresh) spareNonce = fresh;
        if (err) throw err;
        return res;
      }
      // RFC 8555 第 6.5 节：重发必须用 badNonce 响应带回的 nonce；万一没带才去 newNonce 取
      nonce = fresh ?? (await takeNonce());
    }
  }

  async function readOrder(url: string): Promise<{ order: AcmeOrder; body: Json; retryAfter?: number }> {
    const res = await post(url, POST_AS_GET);
    const body = jsonOf(res, url);
    return { order: parseOrder(body, url), body, retryAfter: retryAfterOf(res.headers) };
  }

  /**
   * 轮询的等待：遵守 Retry-After；按累计等待时间判超时而不按墙钟，测试注入的 sleep 不真等也能走到超时分支。
   * 最后一次等待截到正好用完 timeoutMs，超时前总会再查一次状态
   */
  function waiter(timeoutMs: number) {
    let waited = 0;
    return async (retryAfter: number | undefined, timeoutDetail: string) => {
      if (waited >= timeoutMs) throw new AcmeError("timeout", timeoutDetail);
      const delay = Math.min(pollDelayMs(retryAfter), timeoutMs - waited);
      await sleep(delay);
      waited += delay;
    };
  }

  return {
    directory,

    async ensureAccount(email) {
      // 已用这个公钥注册过时 CA 返回 200 和原账号 URL，新注册返回 201，两者 Location 都是账号 URL
      const res = await post(directory.newAccount, { termsOfServiceAgreed: true, ...(email && { contact: [`mailto:${email}`] }) }, { useJwk: true });
      kid = locationOf(res, directory.newAccount);
    },

    async newOrder(domains, o = {}) {
      const payload = {
        identifiers: domains.map((value) => ({ type: "dns", value })),
        ...(o.profile && { profile: o.profile }),
        ...(o.replaces && { replaces: o.replaces }),
      };
      const res = await post(directory.newOrder, payload);
      const url = locationOf(res, directory.newOrder);
      return parseOrder(jsonOf(res, url), url);
    },

    async getAuthorization(url) {
      const res = await post(url, POST_AS_GET);
      return parseAuthorization(jsonOf(res, url), url);
    },

    dnsTxtValue(token) {
      // RFC 8555 第 8.1 / 8.4 节：key authorization = token "." 账号公钥指纹，TXT 记录为它的 SHA-256
      return b64u(createHash("sha256").update(`${token}.${thumbprint}`).digest());
    },

    async answerChallenge(url) {
      // 空对象 {} 表示「已就绪，请开始验证」；不能用 POST-as-GET，那只是查询
      await post(url, {});
    },

    async waitAuthorization(url, timeoutMs) {
      const wait = waiter(timeoutMs);
      for (;;) {
        const res = await post(url, POST_AS_GET);
        const body = jsonOf(res, url);
        const authz = parseAuthorization(body, url);
        // 泛域名的授权对象是去掉 *. 的域名，报错时还原成用户写的名字
        const name = authz.wildcard ? `*.${authz.domain}` : authz.domain;
        if (authz.status === "valid") return;
        if (authz.status === "invalid") throw authorizationError(body, name);
        if (authz.status !== "pending") throw new AcmeError("unauthorized", `${name}：授权已失效（${authz.status}），请重新下单`);
        await wait(retryAfterOf(res.headers), `${name}：等待 CA 验证超时（${Math.round(timeoutMs / 1000)} 秒）`);
      }
    },

    async finalize(order, csrDer, timeoutMs) {
      // 传入的是下单时的订单快照（通常还是 pending），以 CA 现在的状态为准
      let cur = await readOrder(order.url);
      if (cur.order.status === "ready") {
        const res = await post(cur.order.finalize, { csr: b64u(csrDer) });
        const body = jsonOf(res, cur.order.finalize);
        cur = { order: parseOrder(body, order.url), body, retryAfter: retryAfterOf(res.headers) };
      }
      const wait = waiter(timeoutMs);
      for (;;) {
        const { status, certificate } = cur.order;
        if (status === "valid") {
          if (!certificate) throw new AcmeError("badResponse", `订单已签发但没有证书地址：${order.url}`);
          return cur.order;
        }
        if (status === "invalid") {
          throw isObject(cur.body.error) ? problemError(cur.body.error, "orderInvalid") : new AcmeError("orderInvalid", `订单已失效，CA 没有给出原因：${order.url}`);
        }
        if (status === "pending") throw new AcmeError("orderNotReady", "订单还有授权没有通过验证，不能提交 CSR");
        // processing：CA 正在签发；ready：已提交 CSR 但 CA 还没开始处理。都继续等
        await wait(cur.retryAfter, `等待 CA 签发证书超时（${Math.round(timeoutMs / 1000)} 秒）`);
        cur = await readOrder(order.url);
      }
    },

    async downloadCertificate(url) {
      const res = await post(url, POST_AS_GET, { accept: "application/pem-certificate-chain" });
      if (!res.text.includes("-----BEGIN CERTIFICATE-----")) throw new AcmeError("badResponse", `下载到的证书不是 PEM 格式：${url}`, res.status);
      return res.text;
    },
  };
}
