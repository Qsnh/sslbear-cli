import { createHash, createHmac } from "node:crypto";

const sha256Hex = (s: string) => createHash("sha256").update(s).digest("hex");
const hmac = (key: string | Buffer, s: string) => createHmac("sha256", key).update(s).digest();

export interface Tc3Input {
  secretId: string;
  secretKey: string;
  service: string;
  host: string;
  payload: string;
  /** Unix 秒 */
  timestamp: number;
  contentType?: string;
}

/** 腾讯云 API 3.0 签名 v3（TC3-HMAC-SHA256），POST + JSON，签名头为 content-type;host */
export function tc3Authorization(input: Tc3Input): string {
  const contentType = input.contentType ?? "application/json; charset=utf-8";
  const signedHeaders = "content-type;host";
  const canonicalRequest = [
    "POST",
    "/",
    "",
    `content-type:${contentType}\nhost:${input.host}\n`,
    signedHeaders,
    sha256Hex(input.payload),
  ].join("\n");
  const date = new Date(input.timestamp * 1000).toISOString().slice(0, 10);
  const scope = `${date}/${input.service}/tc3_request`;
  const stringToSign = ["TC3-HMAC-SHA256", String(input.timestamp), scope, sha256Hex(canonicalRequest)].join("\n");
  const kDate = hmac(`TC3${input.secretKey}`, date);
  const kService = hmac(kDate, input.service);
  const kSigning = hmac(kService, "tc3_request");
  const signature = createHmac("sha256", kSigning).update(stringToSign).digest("hex");
  return `TC3-HMAC-SHA256 Credential=${input.secretId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}

const sha1Hex = (s: string) => createHash("sha1").update(s).digest("hex");
const hmacSha1Hex = (key: string, s: string) => createHmac("sha1", key).update(s).digest("hex");

/** COS 的 UrlEncode：在 encodeURIComponent 基础上再编码 !'()* */
export function cosEncode(s: string): string {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

/** key 编码后转小写、value 编码，按 key 字典序拼成 [k1=v1&k2=v2, k1;k2] */
function cosFormat(o: Record<string, string>): [string, string] {
  const pairs = Object.entries(o)
    .map(([k, v]) => [cosEncode(k).toLowerCase(), cosEncode(v)] as const)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return [pairs.map(([k, v]) => `${k}=${v}`).join("&"), pairs.map(([k]) => k).join(";")];
}

export interface CosSignInput {
  secretId: string;
  secretKey: string;
  method: string;
  /** 未编码的请求路径，如 "/" */
  path: string;
  /** 请求参数，无值的子资源（如 ?domain）传空串 */
  query: Record<string, string>;
  /** 参与签名的请求头（应包含 host） */
  headers: Record<string, string>;
  /** 签名有效期起止，Unix 秒 */
  start: number;
  end: number;
}

/**
 * COS XML API 请求签名（q-sign-algorithm=sha1）。COS 的 XML 接口不走云 API 3.0，
 * 用的是这套独立的签名，官方各语言 SDK 都是这一实现。
 */
export function cosAuthorization(input: CosSignInput): string {
  const keyTime = `${input.start};${input.end}`;
  const signKey = hmacSha1Hex(input.secretKey, keyTime);
  const [httpParameters, urlParamList] = cosFormat(input.query);
  const [httpHeaders, headerList] = cosFormat(input.headers);
  const httpString = `${input.method.toLowerCase()}\n${input.path}\n${httpParameters}\n${httpHeaders}\n`;
  const stringToSign = `sha1\n${keyTime}\n${sha1Hex(httpString)}\n`;
  return [
    "q-sign-algorithm=sha1",
    `q-ak=${input.secretId}`,
    `q-sign-time=${keyTime}`,
    `q-key-time=${keyTime}`,
    `q-header-list=${headerList}`,
    `q-url-param-list=${urlParamList}`,
    `q-signature=${hmacSha1Hex(signKey, stringToSign)}`,
  ].join("&");
}
