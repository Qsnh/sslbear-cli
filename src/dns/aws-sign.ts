import { createHash, createHmac } from "node:crypto";

/**
 * AWS Signature Version 4（AWS4-HMAC-SHA256），按 IAM 用户指南「Create a signed AWS API request」实现：
 * https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html
 * 与具体服务无关（region / service 由调用方给），以后接其他 AWS 服务可直接复用；用官方 SigV4 测试套件的向量验证。
 */

const sha256Hex = (s: string) => createHash("sha256").update(s).digest("hex");
const hmac = (key: string | Buffer, s: string) => createHmac("sha256", key).update(s).digest();

/** x-amz-date 格式：20150830T123600Z（UTC，不带毫秒） */
export function amzDate(d: Date): string {
  return d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

/**
 * 文档的 UriEncode：除 A-Z a-z 0-9 - . _ ~ 外的每个 UTF-8 字节都编码成大写 %XX，空格为 %20（不是 +）。
 * encodeURIComponent 不编码 !'()*，要补上。
 */
export function uriEncode(s: string): string {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

/**
 * 规范 URI：传入未编码的原始路径，逐段 UriEncode（保留分隔的 /）。
 * 不做 . / .. / 连续斜杠的规范化，也不做非 S3 服务要求的「已编码路径再编码一次」：
 * 两者只在路径含特殊字符时才有区别，Route 53 等 REST 接口的路径只有字母数字和 - . _，没有影响。
 */
export function canonicalUri(path: string): string {
  return path ? path.split("/").map(uriEncode).join("/") : "/";
}

/** 规范查询串：名、值分别 UriEncode 后按名排序（同名按值），没有值的参数保留 "="。发送时直接用它作 URL 的查询串，保证与签名一致 */
export function canonicalQueryString(query: Record<string, string>): string {
  return Object.entries(query)
    .map(([k, v]) => [uriEncode(k), uriEncode(v)] as const)
    .sort(([ka, va], [kb, vb]) => (ka < kb ? -1 : ka > kb ? 1 : va < vb ? -1 : va > vb ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join("&");
}

export interface SigV4Input {
  accessKeyId: string;
  secretAccessKey: string;
  /** STS 临时凭证的 session token：作为 x-amz-security-token 头发送并参与签名 */
  sessionToken?: string;
  region: string;
  service: string;
  method: string;
  /** Host 头：fetch 会自动带上（Host 是禁止手动设置的请求头），这里只参与签名，不出现在返回的 headers 里 */
  host: string;
  /** 未编码的原始路径，如 /2013-04-01/hostedzone */
  path: string;
  query?: Record<string, string>;
  /** 其余要发送的请求头，全部参与签名；名称大小写不限，同名多值传数组（按顺序以逗号拼接） */
  headers?: Record<string, string | readonly string[]>;
  body?: string;
  /** 签名时间（同时写进 x-amz-date） */
  date: Date;
  /** S3 等服务要求带 x-amz-content-sha256（请求体的 SHA256），Route 53 不需要 */
  contentSha256Header?: boolean;
}

export interface SignedRequest {
  /** 要发送的请求头：调用方给的 headers 加上 x-amz-date、x-amz-security-token、x-amz-content-sha256（按需）与 Authorization，不含 Host */
  headers: Record<string, string>;
  canonicalRequest: string;
  stringToSign: string;
  signature: string;
}

/** 派生签名密钥：kDate = HMAC("AWS4" + SK, YYYYMMDD) → region → service → "aws4_request" */
export function signingKey(secretAccessKey: string, day: string, region: string, service: string): Buffer {
  let key = hmac(`AWS4${secretAccessKey}`, day);
  key = hmac(key, region);
  key = hmac(key, service);
  return hmac(key, "aws4_request");
}

export function signV4(input: SigV4Input): SignedRequest {
  const datetime = amzDate(input.date);
  const day = datetime.slice(0, 8);
  const body = input.body ?? "";
  const payloadHash = sha256Hex(body);

  const send: Record<string, string> = {};
  // 参与签名的头：名称小写；值去掉首尾空白、连续空白折叠成一个空格，多值用逗号拼接（测试套件 get-header-value-trim / get-header-key-duplicate）
  const signed = new Map<string, string>([["host", input.host]]);
  const add = (name: string, value: string | readonly string[]) => {
    const values = typeof value === "string" ? [value] : value;
    send[name] = values.join(",");
    signed.set(name.toLowerCase(), values.map((v) => v.trim().replace(/\s+/g, " ")).join(","));
  };
  for (const [k, v] of Object.entries(input.headers ?? {})) add(k, v);
  add("X-Amz-Date", datetime);
  if (input.sessionToken) add("X-Amz-Security-Token", input.sessionToken);
  if (input.contentSha256Header) add("X-Amz-Content-Sha256", payloadHash);

  const names = [...signed.keys()].sort();
  const signedHeaders = names.join(";");
  const canonicalRequest = [
    input.method.toUpperCase(),
    canonicalUri(input.path),
    canonicalQueryString(input.query ?? {}),
    names.map((k) => `${k}:${signed.get(k)}\n`).join(""),
    signedHeaders,
    payloadHash,
  ].join("\n");
  const scope = `${day}/${input.region}/${input.service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", datetime, scope, sha256Hex(canonicalRequest)].join("\n");
  const signature = createHmac("sha256", signingKey(input.secretAccessKey, day, input.region, input.service)).update(stringToSign).digest("hex");
  // 算法与 Credential 之间是空格，其余各段之间是逗号（文档示例与测试套件都是「逗号 + 空格」）
  send.Authorization = `AWS4-HMAC-SHA256 Credential=${input.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { headers: send, canonicalRequest, stringToSign, signature };
}
