import { createHash } from "node:crypto";
import type { TencentCredentials } from "../../lib/env.js";
import { CloudApiError, send, withRetry, type QueryContext, type RawResponse } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import { xmlBlocks, xmlText } from "../../lib/xml.js";
import type { DomainRecord } from "../../types.js";
import type { Deployer, DomainService, Warn } from "../registry.js";
import { permissionHint } from "./cam.js";
import { cosAuthorization, cosEncode } from "./sign.js";
import { enrichFromSsl, explainMissingCn } from "./ssl.js";

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
 * 无权限只有 AccessDenied「Access Denied.」，不说缺哪个权限（也可能来自 bucket 的访问策略），按接口名推断，措辞为「可能」。
 */
function cosError(raw: RawResponse, action: string): CloudApiError {
  const rawCode = xmlText(raw.text, "Code");
  const message = xmlText(raw.text, "Message") ?? (raw.text.slice(0, 200) || `HTTP ${raw.status}`);
  let code = rawCode ?? `HTTP${raw.status}`;
  if (rawCode === "SlowDown") code = "Throttling";
  else if (!rawCode && raw.status === 503) code = "ServiceUnavailable";
  let detail = rawCode && code !== rawCode ? `${message}（${rawCode}）` : message;
  if (code === "AccessDenied") detail += permissionHint(`cos:${action}`, true);
  return new CloudApiError("tencent", code, detail, xmlText(raw.text, "RequestId"), raw.status);
}

/**
 * 调用 COS XML 接口（路径固定为 /），返回响应 XML。带请求体时同时签 Content-MD5 与 Content-Type
 * （COS 的 PUT Bucket 子资源接口要求 Content-MD5）。action 是接口名，即 CAM Action 去掉 cos: 前缀（无权限时写进报错）。
 */
async function cosRequest(
  ctx: QueryContext,
  creds: TencentCredentials,
  action: string,
  method: "GET" | "PUT",
  host: string,
  query: Record<string, string>,
  body?: string,
): Promise<string> {
  return withRetry(ctx, async () => {
    const now = Math.floor(Date.now() / 1000);
    const headers: Record<string, string> = {};
    if (body !== undefined) {
      headers["content-md5"] = createHash("md5").update(body).digest("base64");
      headers["content-type"] = "application/xml";
    }
    if (creds.sessionToken) headers["x-cos-security-token"] = creds.sessionToken;
    headers.Authorization = cosAuthorization({
      secretId: creds.secretId,
      secretKey: creds.secretKey,
      method,
      path: "/",
      query,
      headers: { host, ...headers },
      start: now - SIGN_SKEW_S,
      end: now + SIGN_TTL_S,
    });
    const qs = Object.entries(query)
      .map(([k, v]) => (v ? `${cosEncode(k)}=${cosEncode(v)}` : cosEncode(k)))
      .join("&");
    const raw = await send(ctx, "tencent", `https://${host}/${qs ? `?${qs}` : ""}`, { method, headers, ...(body !== undefined && { body }) });
    if (raw.status >= 400) throw cosError(raw, action);
    return raw.text;
  });
}

const cosGet = (ctx: QueryContext, creds: TencentCredentials, action: string, host: string, query: Record<string, string>) =>
  cosRequest(ctx, creds, action, "GET", host, query);

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
    const xml = await cosGet(ctx, creds, "GetService", SERVICE_HOST, { "max-keys": String(BUCKET_PAGE), ...(marker && { marker }) });
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
    xml = await cosGet(ctx, creds, "GetBucketDomain", bucketHost(bucket), { domain: "" });
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
    xml = await cosGet(ctx, creds, "GetBucketDomainCertificate", bucketHost(d.bucket), { domaincertificate: "", domainname: d.name });
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

const xmlEscape = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/**
 * PUT Bucket domaincertificate：按 SSL 证书 ID 给自定义域名绑定证书，绑定后即开启 HTTPS（接口也收 PEM，
 * 统一走 SSL 证书服务便于复用）。该接口只管证书，不涉及自定义域名的其他配置，deploy / update 是同一个请求。
 */
const deployer: Deployer<TencentCredentials> = {
  // 实测 COS 不接受没有 CN 的证书
  requiresCommonName: true,
  async apply(ctx, creds, target, input) {
    const record = target.records[0]!;
    const bucket = record.extra?.bucket;
    const region = record.extra?.region;
    if (!bucket || !region) throw new CloudApiError("tencent", "MissingBucket", `COS 域名 ${record.domain} 缺少 bucket / region 信息`);
    const certId = await input.certId();
    const body =
      `<DomainCertificate><CertificateInfo><CertType>CustomCert</CertType><CustomCert><CertId>${xmlEscape(certId)}</CertId></CustomCert></CertificateInfo>` +
      `<DomainList><DomainName>${xmlEscape(record.domain)}</DomainName></DomainList></DomainCertificate>`;
    await explainMissingCn(input.cert, " COS ", ["InvalidDomainCertificate"], () =>
      cosRequest(ctx, creds, "PutBucketDomainCertificate", "PUT", bucketHost({ name: bucket, region }), { domaincertificate: "" }, body),
    );
    return { certId };
  },
};

/**
 * 对象存储 COS 的自定义源站域名：先列 bucket，再逐个 bucket 查自定义域名，最后逐个域名查证书配置（各阶段并发 5）。
 * HTTPS 以域名证书配置的 Status 为 Enabled 为准（404 表示从没配置过证书，即未开启；其他错误标记 httpsUnknown）；
 * 只给了证书 ID 没给有效期的从 SSL 证书列表补。
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
      let cert: DomainCert | undefined;
      // 证书配置查询失败（404 以外）时不知道是否开着 HTTPS：https 记为 false，同时标记 httpsUnknown，
      // 编排层据此不会把它当作未开启而直接部署覆盖线上证书
      let httpsUnknown: "true" | undefined;
      try {
        cert = await getDomainCert(ctx, creds, d);
      } catch (e) {
        warn(e, `domain ${d.name}`);
        httpsUnknown = "true";
      }
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
        extra: compact({ bucket: d.bucket.name, region: d.bucket.region, type: d.type, httpsUnknown }),
      });
    });
    return enrichFromSsl(ctx, creds, warn, records);
  },
  deployer,
};
