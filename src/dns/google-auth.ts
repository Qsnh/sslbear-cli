import { createHash, createPrivateKey, sign, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { CloudApiError, isRetryableCode, send, type QueryContext } from "../lib/http.js";

/**
 * Google 服务账号鉴权（https://developers.google.com/identity/protocols/oauth2/service-account）：
 * 用密钥文件里的私钥签一个 RS256 JWT，POST 到 token_uri 换 access token。不用官方库，零依赖。
 */

/** Cloud DNS 读写的 OAuth 范围：discovery 文档里 changes.create 接受 cloud-platform 或它，取更窄的这个 */
export const DNS_SCOPE = "https://www.googleapis.com/auth/ndev.clouddns.readwrite";
const DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token";
/** 服务账号文档列出的令牌端点所在的主机 */
const TOKEN_HOST = "oauth2.googleapis.com";
const JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/** 文档规定 exp 最多比 iat 晚 1 小时 */
const ASSERTION_TTL_S = 3600;
/** 提前 60 秒换新令牌，免得请求途中过期 */
const REFRESH_MARGIN_MS = 60_000;

export interface ServiceAccountKey {
  clientEmail: string;
  privateKey: KeyObject;
  /** 写进 JWT 头的 kid（可选，帮 Google 直接定位是哪把密钥） */
  privateKeyId?: string;
  tokenUri: string;
  projectId?: string;
  /** 令牌缓存的键：服务账号 + 私钥指纹，不含私钥本身 */
  cacheKey: string;
}

type Json = Record<string, unknown>;
const str = (v: unknown) => (typeof v === "string" && v ? v : undefined);
const isObject = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);

/** 非 JSON 的响应（网关的 HTML 错误页等）返回 undefined，由调用方按 HTTP 状态报错 */
export function tryJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/** 5xx 加 ServiceUnavailable. 前缀交给 withRetry 重试（原始错误码保留在后面）；429 靠 httpStatus 识别，不用改 */
export function transientCode(code: string, status: number): string {
  return status >= 500 && !isRetryableCode(code) ? `ServiceUnavailable.${code}` : code;
}

const FS_ERRORS: Record<string, string> = { ENOENT: "文件不存在", EACCES: "没有读取权限", EPERM: "没有读取权限", EISDIR: "是一个目录" };

const keyFiles = new Map<string, ServiceAccountKey>();

/**
 * 读取并校验服务账号 JSON 密钥文件（同一路径只读一次）。
 * 出错信息只说哪里不对，不带文件内容：JSON.parse 的报错会引用原文片段，可能含私钥。
 */
export function loadServiceAccount(path: string): ServiceAccountKey {
  const hit = keyFiles.get(path);
  if (hit) return hit;
  const invalid = (why: string) => new CloudApiError("google", "InvalidCredentials", `GOOGLE_APPLICATION_CREDENTIALS（${path}）${why}`);
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code ?? "";
    throw invalid(`读取失败：${FS_ERRORS[code] ?? (code || "未知错误")}`);
  }
  const json = tryJson(text);
  if (!isObject(json)) throw invalid("不是合法的 JSON，应为服务账号的 JSON 密钥文件");
  if (json.type !== "service_account") {
    // gcloud auth application-default login 生成的是 authorized_user，工作负载身份联合是 external_account，都没有可签 JWT 的私钥
    throw invalid(`不是服务账号密钥（type 为 ${str(json.type) ?? "空"}）：只支持服务账号的 JSON 密钥（type 为 service_account）`);
  }
  const clientEmail = str(json.client_email);
  const pem = str(json.private_key);
  if (!clientEmail || !pem) throw invalid("缺少 client_email 或 private_key");
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey(pem);
  } catch {
    throw invalid("里的 private_key 不是有效的 PEM 私钥");
  }
  if (privateKey.asymmetricKeyType !== "rsa") throw invalid("里的 private_key 不是 RSA 私钥，无法签 RS256");
  const tokenUri = trustedTokenUri(str(json.token_uri));
  const fingerprint = createHash("sha256").update(privateKey.export({ type: "pkcs8", format: "der" })).digest("hex");
  const key: ServiceAccountKey = {
    clientEmail,
    privateKey,
    tokenUri,
    cacheKey: `${clientEmail}\n${fingerprint}\n${tokenUri}`,
    ...(str(json.private_key_id) && { privateKeyId: str(json.private_key_id) }),
    ...(str(json.project_id) && { projectId: str(json.project_id) }),
  };
  keyFiles.set(path, key);
  return key;
}

/**
 * 只信任 Google 官方令牌端点（https、主机名 oauth2.googleapis.com）：签好的 JWT 一小时内能换出 Cloud DNS 的读写令牌，
 * 密钥文件里的 token_uri 被改成别的地址（哪怕是 https）就等于把凭证交出去。缺省、写错或指向别处时一律用默认地址；
 * 老密钥文件里的 accounts.google.com/o/oauth2/token 等旧地址也换成默认地址，同样能换令牌（aud 跟着用实际发往的地址）
 */
function trustedTokenUri(uri: string | undefined): string {
  if (!uri) return DEFAULT_TOKEN_URI;
  try {
    const u = new URL(uri);
    return u.protocol === "https:" && u.hostname === TOKEN_HOST && !u.port && !u.username && !u.password ? u.href : DEFAULT_TOKEN_URI;
  } catch {
    return DEFAULT_TOKEN_URI;
  }
}

const b64u = (s: string) => Buffer.from(s).toString("base64url");

/** 换令牌用的 JWT 断言：RS256（SHA256withRSA），iss = 服务账号邮箱，aud = token_uri，有效期 1 小时 */
export function signAssertion(key: ServiceAccountKey, scope: string, nowMs: number): string {
  const header = { alg: "RS256", typ: "JWT", ...(key.privateKeyId && { kid: key.privateKeyId }) };
  const iat = Math.floor(nowMs / 1000);
  const claims = { iss: key.clientEmail, scope, aud: key.tokenUri, iat, exp: iat + ASSERTION_TTL_S };
  const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(claims))}`;
  return `${input}.${sign("sha256", Buffer.from(input), key.privateKey).toString("base64url")}`;
}

interface Token {
  token: string;
  expiresAt: number;
}

/** 进程内按服务账号 + 范围缓存令牌；存 Promise，同时到来的请求共用一次换取 */
const tokens = new Map<string, Promise<Token>>();

/** 取 access token：缓存里没过期（留 60 秒余量）就复用，否则重新换 */
export async function googleAccessToken(ctx: QueryContext, key: ServiceAccountKey, scope = DNS_SCOPE): Promise<string> {
  const cacheKey = `${key.cacheKey}\n${scope}`;
  const hit = tokens.get(cacheKey);
  if (hit) {
    const t = await hit.catch(() => undefined);
    if (t && Date.now() < t.expiresAt - REFRESH_MARGIN_MS) return t.token;
  }
  const p = requestToken(ctx, key, scope);
  tokens.set(cacheKey, p);
  // 失败的不留在缓存里，下次重新换
  p.catch(() => tokens.get(cacheKey) === p && tokens.delete(cacheKey));
  return (await p).token;
}

/** 接口回 401 时丢掉缓存的令牌（如服务账号密钥刚被停用），下次重新换 */
export function dropGoogleToken(key: ServiceAccountKey, scope = DNS_SCOPE): void {
  tokens.delete(`${key.cacheKey}\n${scope}`);
}

async function requestToken(ctx: QueryContext, key: ServiceAccountKey, scope: string): Promise<Token> {
  const body = new URLSearchParams({ grant_type: JWT_BEARER, assertion: signAssertion(key, scope, Date.now()) }).toString();
  const raw = await send(ctx, "google", key.tokenUri, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const parsed = tryJson(raw.text);
  const res = isObject(parsed) ? parsed : {};
  const token = str(res.access_token);
  if (raw.status >= 400 || !token) throw tokenError(raw.status, res);
  const expiresIn = Number(res.expires_in);
  return { token, expiresAt: Date.now() + (expiresIn > 0 ? expiresIn : 3600) * 1000 };
}

/** 令牌端点的错误体为 {error, error_description}（OAuth 2.0 标准格式），不带请求号 */
function tokenError(status: number, res: Json): CloudApiError {
  if (status < 400) return new CloudApiError("google", "InvalidResponse", `令牌响应里没有 access_token（HTTP ${status}）`, undefined, status);
  const error = str(res.error) ?? `HTTP${status}`;
  const desc = str(res.error_description);
  let hint = "";
  // 文档错误表里 invalid_grant 的几种原因：签名不对多半是密钥已在控制台删除 / 停用；时间不对是本机时钟偏差
  if (desc && /signature/i.test(desc)) hint = "：这把服务账号密钥可能已被删除或停用，请换一把有效的密钥";
  else if (desc && /timeframe|iat|exp/i.test(desc)) hint = "：本机时钟可能不准，请校准系统时间";
  else if (error === "invalid_grant" || error === "unauthorized_client") hint = "：请确认服务账号存在且未被停用";
  const message = `获取 Google 访问令牌失败（${error}${desc ? `: ${desc}` : ""}）${hint}`;
  return new CloudApiError("google", transientCode(error, status), message, undefined, status);
}
