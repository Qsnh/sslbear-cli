import type { TencentCredentials } from "../../lib/env.js";
import { CloudApiError, send, withRetry, type QueryContext, type RawResponse } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import { xmlBlocks, xmlText } from "../../lib/xml.js";
import type { DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { cosAuthorization, cosEncode } from "./sign.js";
import { enrichFromSsl } from "./ssl.js";

/** GET Service 发到这个 host 返回账号下所有地域的 bucket */
const SERVICE_HOST = "service.cos.myqcloud.com";
/** GET Service 的 max-keys 上限 */
const BUCKET_PAGE = 2000;
/** 签名起点往前留一点余量，容忍本机时钟略快 */
const SIGN_SKEW_S = 60;
const SIGN_TTL_S = 900;

/**
 * COS 错误响应是 <Error><Code/><Message/><RequestId/></Error>。
 * 限流错误码 SlowDown（HTTP 503）记为 Throttling 让 withRetry 重试，原始错误码保留在 message 里。
 */
function cosError(raw: RawResponse): CloudApiError {
  const rawCode = xmlText(raw.text, "Code");
  const message = xmlText(raw.text, "Message") ?? (raw.text.slice(0, 200) || `HTTP ${raw.status}`);
  let code = rawCode ?? `HTTP${raw.status}`;
  if (rawCode === "SlowDown") code = "Throttling";
  else if (!rawCode && raw.status === 503) code = "ServiceUnavailable";
  const detail = rawCode && code !== rawCode ? `${message}（${rawCode}）` : message;
  return new CloudApiError("tencent", code, detail, xmlText(raw.text, "RequestId"), raw.status);
}

/** 以 GET 调用 COS XML 接口（路径固定为 /），返回响应 XML */
async function cosGet(ctx: QueryContext, creds: TencentCredentials, host: string, query: Record<string, string>): Promise<string> {
  return withRetry(ctx, async () => {
    const now = Math.floor(Date.now() / 1000);
    const headers: Record<string, string> = {};
    if (creds.sessionToken) headers["x-cos-security-token"] = creds.sessionToken;
    headers.Authorization = cosAuthorization({
      secretId: creds.secretId,
      secretKey: creds.secretKey,
      method: "GET",
      path: "/",
      query,
      headers: { host, ...headers },
      start: now - SIGN_SKEW_S,
      end: now + SIGN_TTL_S,
    });
    const qs = Object.entries(query)
      .map(([k, v]) => (v ? `${cosEncode(k)}=${cosEncode(v)}` : cosEncode(k)))
      .join("&");
    const raw = await send(ctx, "tencent", `https://${host}/${qs ? `?${qs}` : ""}`, { method: "GET", headers });
    if (raw.status >= 400) throw cosError(raw);
    return raw.text;
  });
}

/** 官方 Java SDK 对 GET Bucket domain / domain certificate 都把 404 视为「没有配置」 */
const isNotFound = (e: unknown) => e instanceof CloudApiError && e.httpStatus === 404;

interface Bucket {
  /** BucketName-APPID */
  name: string;
  region: string;
}

async function listBuckets(ctx: QueryContext, creds: TencentCredentials): Promise<Bucket[]> {
  const buckets: Bucket[] = [];
  let marker: string | undefined;
  for (let page = 0; page < 100; page++) {
    const xml = await cosGet(ctx, creds, SERVICE_HOST, { "max-keys": String(BUCKET_PAGE), ...(marker && { marker }) });
    for (const b of xmlBlocks(xml, "Bucket")) {
      const name = xmlText(b, "Name");
      const region = xmlText(b, "Location");
      if (name && region) buckets.push({ name, region });
    }
    marker = xmlText(xml, "IsTruncated") === "true" ? xmlText(xml, "NextMarker") : undefined;
    if (!marker) break;
  }
  return buckets;
}

const bucketHost = (b: Bucket) => `${b.name}.cos.${b.region}.myqcloud.com`;

interface CosDomain {
  bucket: Bucket;
  name: string;
  /** ENABLED / DISABLED */
  status?: string;
  /** 源站类型：REST / WEBSITE / ACCELERATE */
  type?: string;
}

async function listDomains(ctx: QueryContext, creds: TencentCredentials, bucket: Bucket): Promise<CosDomain[]> {
  let xml: string;
  try {
    xml = await cosGet(ctx, creds, bucketHost(bucket), { domain: "" });
  } catch (e) {
    // 没配置自定义域名时返回 404 DomainConfigNotFoundError
    if (isNotFound(e)) return [];
    throw e;
  }
  return xmlBlocks(xml, "DomainRule").flatMap((rule) => {
    const name = xmlText(rule, "Name");
    return name ? [{ bucket, name, status: xmlText(rule, "Status"), type: xmlText(rule, "Type") }] : [];
  });
}

interface DomainCert {
  /** Enabled / Disabled */
  status?: string;
  certId?: string;
  validityBegin?: string;
  validityExpire?: string;
}

async function getDomainCert(ctx: QueryContext, creds: TencentCredentials, d: CosDomain): Promise<DomainCert | undefined> {
  let xml: string;
  try {
    xml = await cosGet(ctx, creds, bucketHost(d.bucket), { domaincertificate: "", domainname: d.name });
  } catch (e) {
    if (isNotFound(e)) return undefined;
    throw e;
  }
  const info = xmlBlocks(xml, "CertificateInfo")[0];
  return {
    status: xmlText(xml.replace(/<CertificateInfo[\s\S]*<\/CertificateInfo>/, ""), "Status"),
    certId: info && xmlText(info, "CertId"),
    validityBegin: info && xmlText(info, "ValidityBegin"),
    validityExpire: info && xmlText(info, "ValidityExpire"),
  };
}

/** ValidityBegin / ValidityExpire 是 Unix 时间戳（SDK 里为 int64），0 或空表示没有 */
const timestampToIso = (v: string | undefined) => (v && /^\d+$/.test(v) && Number(v) > 0 ? toIso(Number(v)) : undefined);

/**
 * 对象存储 COS 的自定义源站域名：先列 bucket，再逐个 bucket 查自定义域名，最后逐个域名查证书配置（各阶段并发 5）。
 * HTTPS 以域名证书配置的 Status 为 Enabled 为准；只给了证书 ID 没给有效期的从 SSL 证书列表补。
 */
export const cos: DomainService<TencentCredentials> = {
  key: "cos",
  label: "对象存储 COS",
  async list(ctx: QueryContext, creds: TencentCredentials, warn: Warn): Promise<DomainRecord[]> {
    const buckets = await listBuckets(ctx, creds);
    const perBucket = await mapLimit(buckets, 5, (bucket) =>
      listDomains(ctx, creds, bucket).catch((e: unknown) => {
        warn(e, `bucket ${bucket.name}`);
        return [];
      }),
    );
    const records = await mapLimit(perBucket.flat(), 5, async (d) => {
      const cert = await getDomainCert(ctx, creds, d).catch((e: unknown) => {
        warn(e, `domain ${d.name}`);
        return undefined;
      });
      const https = cert?.status?.toLowerCase() === "enabled";
      return compact({
        provider: "tencent" as const,
        service: "cos",
        domain: d.name,
        status: d.status,
        https,
        cert:
          https && cert
            ? compact({
                id: cert.certId,
                notBefore: timestampToIso(cert.validityBegin),
                notAfter: timestampToIso(cert.validityExpire),
                status: cert.status,
              })
            : undefined,
        extra: compact({ bucket: d.bucket.name, region: d.bucket.region, type: d.type }),
      });
    });
    return enrichFromSsl(ctx, creds, warn, records);
  },
};
