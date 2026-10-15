import { createHash, createHmac } from "node:crypto";

/** RFC 3986 编码：encodeURIComponent 之外再转义 !'()*，与阿里云签名要求一致 */
export function percentEncode(s: string): string {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

export function canonicalQuery(params: Record<string, string>): string {
  return Object.keys(params)
    .sort()
    .map((k) => `${percentEncode(k)}=${percentEncode(params[k] as string)}`)
    .join("&");
}

/** RPC 风格 API 签名 V1（HMAC-SHA1），params 需已包含除 Signature 外的全部公共参数 */
export function rpcSignature(params: Record<string, string>, accessKeySecret: string, method = "GET"): string {
  const stringToSign = `${method}&${percentEncode("/")}&${percentEncode(canonicalQuery(params))}`;
  return createHmac("sha1", `${accessKeySecret}&`).update(stringToSign).digest("base64");
}

const sha256Hex = (s: string) => createHash("sha256").update(s).digest("hex");
const hmac256 = (key: string | Buffer, s: string) => createHmac("sha256", key).update(s).digest();

export interface OssV4Input {
  accessKeyId: string;
  accessKeySecret: string;
  /** 地域 ID，不带 oss- 前缀，如 cn-hangzhou */
  region: string;
  method: string;
  /** bucket 级操作填 bucket 名，服务级操作（ListBuckets）留空 */
  bucket?: string;
  /** 值为空串的参数按无值子资源处理，如 { cname: "" } */
  query: Record<string, string>;
  /** 需包含 x-oss-date、x-oss-content-sha256；STS 时含 x-oss-security-token */
  headers: Record<string, string>;
}

/** x-oss-date 格式：20231203T121212Z */
export function ossDate(d: Date): string {
  return d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

/** OSS 签名 V4（OSS4-HMAC-SHA256），payload 不参与签名（UNSIGNED-PAYLOAD） */
export function ossV4Authorization(input: OssV4Input): string {
  const headers = Object.fromEntries(Object.entries(input.headers).map(([k, v]) => [k.toLowerCase(), v.trim()]));
  const datetime = headers["x-oss-date"];
  if (!datetime) throw new Error("x-oss-date header is required");
  const day = datetime.slice(0, 8);
  const canonicalUri = input.bucket ? `/${percentEncode(input.bucket)}/` : "/";
  const canonicalQs = Object.keys(input.query)
    .sort()
    .map((k) => (input.query[k] ? `${percentEncode(k)}=${percentEncode(input.query[k] as string)}` : percentEncode(k)))
    .join("&");
  const canonicalHeaders = Object.keys(headers)
    .filter((k) => k.startsWith("x-oss-") || k === "content-type" || k === "content-md5")
    .sort()
    .map((k) => `${k}:${headers[k]}\n`)
    .join("");
  const canonicalRequest = [
    input.method,
    canonicalUri,
    canonicalQs,
    canonicalHeaders,
    "",
    headers["x-oss-content-sha256"] ?? "UNSIGNED-PAYLOAD",
  ].join("\n");
  const scope = `${day}/${input.region}/oss/aliyun_v4_request`;
  const stringToSign = ["OSS4-HMAC-SHA256", datetime, scope, sha256Hex(canonicalRequest)].join("\n");
  let key = hmac256(`aliyun_v4${input.accessKeySecret}`, day);
  key = hmac256(key, input.region);
  key = hmac256(key, "oss");
  key = hmac256(key, "aliyun_v4_request");
  const signature = createHmac("sha256", key).update(stringToSign).digest("hex");
  return `OSS4-HMAC-SHA256 Credential=${input.accessKeyId}/${scope},Signature=${signature}`;
}
