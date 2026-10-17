import { createHash, createHmac } from "node:crypto";

export const sha256Hex = (s: string) => createHash("sha256").update(s).digest("hex");
const hmac = (key: string | Buffer, s: string) => createHmac("sha256", key).update(s).digest();

/** RFC 3986 编码：encodeURIComponent 之外再转义 !'()*，与 Go 的 url.QueryEscape（空格转 %20）一致 */
export function percentEncode(s: string): string {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

export function canonicalQuery(query: Record<string, string>): string {
  return Object.keys(query)
    .sort()
    .map((k) => `${percentEncode(k)}=${percentEncode(query[k] as string)}`)
    .join("&");
}

/** X-Date 格式：20250329T180937Z（UTC，精确到秒） */
export function volcDate(d: Date): string {
  return d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

export interface VolcSignInput {
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
  service: string;
  method: string;
  /** 火山引擎 OpenAPI 的路径均为 / */
  path?: string;
  query: Record<string, string>;
  /** 全部参与签名，需包含 host 与 x-date；名称大小写不限 */
  headers: Record<string, string>;
  body: string;
}

/**
 * 火山引擎 OpenAPI 签名（HMAC-SHA256），流程与 AWS SigV4 相同：
 * scope 为 {YYYYMMDD}/{region}/{service}/request，派生密钥的起点直接是 SK 原文（不加前缀）。
 */
export function volcAuthorization(input: VolcSignInput): string {
  const headers = Object.fromEntries(Object.entries(input.headers).map(([k, v]) => [k.toLowerCase(), v.trim()]));
  const datetime = headers["x-date"];
  if (!datetime) throw new Error("x-date header is required");
  const day = datetime.slice(0, 8);
  const names = Object.keys(headers).sort();
  const signedHeaders = names.join(";");
  const canonicalRequest = [
    input.method,
    input.path ?? "/",
    canonicalQuery(input.query),
    names.map((k) => `${k}:${headers[k]}\n`).join(""),
    signedHeaders,
    sha256Hex(input.body),
  ].join("\n");
  const scope = `${day}/${input.region}/${input.service}/request`;
  const stringToSign = ["HMAC-SHA256", datetime, scope, sha256Hex(canonicalRequest)].join("\n");
  let key = hmac(input.secretAccessKey, day);
  key = hmac(key, input.region);
  key = hmac(key, input.service);
  key = hmac(key, "request");
  const signature = createHmac("sha256", key).update(stringToSign).digest("hex");
  return `HMAC-SHA256 Credential=${input.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}

export interface TosSignInput {
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
  method: string;
  /** 虚拟主机风格下 bucket 不在路径里，查询 bucket 配置的路径均为 / */
  path?: string;
  /** 无值参数（如 customdomain）传空串，规范化后为 customdomain= */
  query: Record<string, string>;
  /** 需包含 host 与 x-tos-date；只有 content-type 与 x-tos-* 参与签名 */
  headers: Record<string, string>;
  /** 请求体 SHA256，缺省为空串的哈希（与 SDK 不带 x-tos-content-sha256 时一致） */
  payloadHash?: string;
}

/**
 * TOS V4 签名（TOS4-HMAC-SHA256），按 ve-tos-golang-sdk 的 sign_v4.go：
 * scope 为 {YYYYMMDD}/{region}/tos/request，派生密钥起点为 SK 原文；
 * header 值折叠连续空白；Authorization 各段之间只有逗号、没有空格。
 */
export function tosAuthorization(input: TosSignInput): string {
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(input.headers)) {
    const name = k.toLowerCase();
    if (name === "host" || name === "content-type" || name.startsWith("x-tos")) headers[name] = v.trim().split(/\s+/).join(" ");
  }
  const datetime = headers["x-tos-date"];
  if (!datetime) throw new Error("x-tos-date header is required");
  const day = datetime.slice(0, 8);
  const names = Object.keys(headers).sort();
  const signedHeaders = names.join(";");
  const canonicalRequest = [
    input.method,
    (input.path ?? "/").split("/").map(percentEncode).join("/"),
    canonicalQuery(input.query),
    names.map((k) => `${k}:${headers[k]}\n`).join(""),
    signedHeaders,
    input.payloadHash ?? sha256Hex(""),
  ].join("\n");
  const scope = `${day}/${input.region}/tos/request`;
  const stringToSign = ["TOS4-HMAC-SHA256", datetime, scope, sha256Hex(canonicalRequest)].join("\n");
  let key = hmac(input.secretAccessKey, day);
  key = hmac(key, input.region);
  key = hmac(key, "tos");
  key = hmac(key, "request");
  const signature = createHmac("sha256", key).update(stringToSign).digest("hex");
  return `TOS4-HMAC-SHA256 Credential=${input.accessKeyId}/${scope},SignedHeaders=${signedHeaders},Signature=${signature}`;
}
