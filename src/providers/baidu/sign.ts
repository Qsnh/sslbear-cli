import { createHmac } from "node:crypto";

const hmacHex = (key: string, s: string) => createHmac("sha256", key).update(s).digest("hex");

/** RFC 3986 编码：只保留 A-Z a-z 0-9 - _ . ~，其余字节按 UTF-8 转 %XX（大写） */
export function uriEncode(s: string): string {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

/** CanonicalURI：路径按段编码、保留斜杠；请求 URL 也用同一结果，保证发出去的与签名的一致 */
export function canonicalPath(path: string): string {
  const p = path.startsWith("/") ? path : `/${path}`;
  return p.split("/").map(uriEncode).join("/");
}

/** 按「编码后的 key=value」整体排序（不是只按 key），值为空时保留 key= */
export function canonicalQuery(query: Record<string, string>): string {
  return Object.entries(query)
    .filter(([k]) => k.toLowerCase() !== "authorization")
    .map(([k, v]) => `${uriEncode(k)}=${uriEncode(v)}`)
    .sort()
    .join("&");
}

/** 认证字符串里的时间戳：UTC，精确到秒，如 2015-04-27T08:23:49Z */
export function bceTimestamp(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

// 官方推荐的签名头范围：这几个标准头 + 所有 x-bce- 开头的头
const DEFAULT_SIGNED = new Set(["host", "content-length", "content-type", "content-md5"]);

export interface BceSignInput {
  accessKeyId: string;
  secretAccessKey: string;
  method: string;
  path: string;
  query: Record<string, string>;
  /** 请求头（名称大小写不限），按官方推荐范围挑选参与签名的头，必须含 host */
  headers: Record<string, string>;
  timestamp: string;
  expirationSeconds?: number;
}

/**
 * 百度智能云 bce-auth-v1 签名：
 * SigningKey = HMAC-SHA256-HEX(SK, "bce-auth-v1/{ak}/{timestamp}/{expiration}")，
 * Signature = HMAC-SHA256-HEX(SigningKey, Method\nCanonicalURI\nCanonicalQueryString\nCanonicalHeaders)。
 * signedHeaders 总是显式写出（与 Go SDK 一致），留空时服务端按推荐范围取头，结果相同。
 */
export function bceAuthorization(input: BceSignInput): string {
  const prefix = `bce-auth-v1/${input.accessKeyId}/${input.timestamp}/${input.expirationSeconds ?? 1800}`;
  const signingKey = hmacHex(input.secretAccessKey, prefix);
  const picked: [string, string][] = [];
  for (const [k, v] of Object.entries(input.headers)) {
    const name = k.trim().toLowerCase();
    const value = v.trim();
    // 值为空的头不参与签名
    if (!value || !(DEFAULT_SIGNED.has(name) || name.startsWith("x-bce-"))) continue;
    picked.push([name, value]);
  }
  // CanonicalHeaders 按「name:value」整串排序，signedHeaders 只按名称排序，两者顺序可能不同
  const canonicalHeaders = picked
    .map(([k, v]) => `${uriEncode(k)}:${uriEncode(v)}`)
    .sort()
    .join("\n");
  const signedHeaders = picked
    .map(([k]) => k)
    .sort()
    .join(";");
  const canonicalRequest = [input.method.toUpperCase(), canonicalPath(input.path), canonicalQuery(input.query), canonicalHeaders].join("\n");
  return `${prefix}/${signedHeaders}/${hmacHex(signingKey, canonicalRequest)}`;
}
