import { createHmac } from "node:crypto";

/** 七牛的 URL 安全 Base64：+ / 换成 - _，保留尾部 = */
function sign(secretKey: string, data: string): string {
  return createHmac("sha1", secretKey).update(data).digest("base64").replace(/\+/g, "-").replace(/\//g, "_");
}

/** 与 Go 的 textproto.CanonicalMIMEHeaderKey 一致：x-qiniu-aaa → X-Qiniu-Aaa */
function canonicalHeaderKey(name: string): string {
  return name
    .split("-")
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1).toLowerCase())
    .join("-");
}

const QINIU_HEADER_PREFIX = "X-Qiniu-";

/** X-Qiniu-Date 格式：20260213T120000Z（UTC） */
export function qiniuDate(d: Date): string {
  return d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

export interface QiniuSignInput {
  accessKey: string;
  secretKey: string;
  method: string;
  host: string;
  /** 实际发送的路径 + query（原样，不再编码） */
  pathWithQuery: string;
  contentType: string;
  /** 只有 X-Qiniu-* 头参与签名，其余忽略 */
  headers?: Record<string, string>;
  body?: string;
}

/**
 * Qiniu 鉴权（新版管理凭证），返回 Authorization 头的值。
 * 签名串：`{Method} {PathWithQuery}\nHost: {Host}\nContent-Type: {CT}\n{X-Qiniu-* 按名排序逐行}\n{Body}`，
 * Body 仅在非 application/octet-stream 时参与（与 Python / Node.js SDK 一致）。
 */
export function qiniuAuthorization(input: QiniuSignInput): string {
  const xHeaders = Object.entries(input.headers ?? {})
    .map(([k, v]) => [canonicalHeaderKey(k), v] as const)
    .filter(([k]) => k.startsWith(QINIU_HEADER_PREFIX) && k.length > QINIU_HEADER_PREFIX.length)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  let data = `${input.method.toUpperCase()} ${input.pathWithQuery}\nHost: ${input.host}\nContent-Type: ${input.contentType}\n`;
  for (const [k, v] of xHeaders) data += `${k}: ${v}\n`;
  data += "\n";
  if (input.body && input.contentType !== "application/octet-stream") data += input.body;
  return `Qiniu ${input.accessKey}:${sign(input.secretKey, data)}`;
}

/**
 * QBox 鉴权（旧版管理凭证），返回 Authorization 头的值。
 * 签名串只有 `{PathWithQuery}\n`；仅表单请求体参与签名，JSON 等其他请求体不参与。
 */
export function qboxAuthorization(input: { accessKey: string; secretKey: string; pathWithQuery: string; formBody?: string }): string {
  return `QBox ${input.accessKey}:${sign(input.secretKey, `${input.pathWithQuery}\n${input.formBody ?? ""}`)}`;
}
