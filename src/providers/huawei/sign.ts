import { createHash, createHmac } from "node:crypto";

const sha256Hex = (s: string) => createHash("sha256").update(s).digest("hex");

/** X-Sdk-Date 格式：20191115T033655Z（UTC） */
export function sdkDate(d: Date): string {
  return d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

/** API 网关签名的 URI 编码：只保留 A-Z a-z 0-9 - _ . ~，其余按 UTF-8 字节转为 %XX（大写），空格为 %20 */
export function hwEscape(s: string): string {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

/** 规范查询字符串：按参数名的字符编码升序，没有值的参数也要保留 "=" */
export function canonicalQuery(query: Record<string, string>): string {
  return Object.keys(query)
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
    .map((k) => `${hwEscape(k)}=${hwEscape(query[k] as string)}`)
    .join("&");
}

export interface ApigSignInput {
  accessKeyId: string;
  secretAccessKey: string;
  method: string;
  /** 不带查询串的请求路径，如 /v1.0/cdn/domains */
  path: string;
  query: Record<string, string>;
  /** 参与签名的请求头（必须含 X-Sdk-Date），名称不区分大小写 */
  headers: Record<string, string>;
  body?: string;
}

/** 规范请求：URI 每段单独编码，且签名时 URI 必须以 "/" 结尾（发请求时可以不带） */
export function apigCanonicalRequest(input: ApigSignInput): { canonicalRequest: string; signedHeaders: string } {
  const headers = Object.fromEntries(Object.entries(input.headers).map(([k, v]) => [k.toLowerCase(), v.trim()]));
  const names = Object.keys(headers).sort();
  let uri = input.path.split("/").map(hwEscape).join("/");
  if (!uri.endsWith("/")) uri += "/";
  const signedHeaders = names.join(";");
  const canonicalRequest = [
    input.method,
    uri,
    canonicalQuery(input.query),
    names.map((k) => `${k}:${headers[k]}\n`).join(""),
    signedHeaders,
    sha256Hex(input.body ?? ""),
  ].join("\n");
  return { canonicalRequest, signedHeaders };
}

/** 华为云 API 网关 AK/SK 签名（SDK-HMAC-SHA256），返回 Authorization 头的值 */
export function apigAuthorization(input: ApigSignInput): string {
  const date = Object.entries(input.headers).find(([k]) => k.toLowerCase() === "x-sdk-date")?.[1];
  if (!date) throw new Error("X-Sdk-Date header is required");
  const { canonicalRequest, signedHeaders } = apigCanonicalRequest(input);
  const stringToSign = ["SDK-HMAC-SHA256", date, sha256Hex(canonicalRequest)].join("\n");
  const signature = createHmac("sha256", input.secretAccessKey).update(stringToSign).digest("hex");
  return `SDK-HMAC-SHA256 Access=${input.accessKeyId}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}

/**
 * OBS 签名的 StringToSign：Verb、Content-MD5、Content-Type、Date 各占一行，再接 x-obs- 头和规范资源。
 * 带了 x-obs-date 时 Date 行置空（以 x-obs-date 为准）；resource 形如 "/" 或 "/bucket/?customdomain"。
 */
export function obsStringToSign(method: string, headers: Record<string, string>, resource: string): string {
  const h = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase().trim(), v.trim()]));
  const obsHeaders = Object.keys(h)
    .filter((k) => k.startsWith("x-obs-"))
    .sort()
    .map((k) => `${k}:${h[k]}\n`)
    .join("");
  const date = h["x-obs-date"] !== undefined ? "" : (h.date ?? "");
  return `${method}\n${h["content-md5"] ?? ""}\n${h["content-type"] ?? ""}\n${date}\n${obsHeaders}${resource}`;
}

/** OBS 签名（Header 中携带）：Authorization: OBS AK:Base64(HMAC-SHA1(SK, StringToSign)) */
export function obsAuthorization(accessKeyId: string, secretAccessKey: string, stringToSign: string): string {
  return `OBS ${accessKeyId}:${createHmac("sha1", secretAccessKey).update(stringToSign).digest("base64")}`;
}
