import { createHash } from "node:crypto";
import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, send, withRetry, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import { xmlBlocks, xmlText } from "../../lib/xml.js";
import type { CertInfo, DomainRecord } from "../../types.js";
import type { DeployInput, DeployOutcome, DeployTarget, DomainService, Warn } from "../registry.js";
import { certName, earliest, orderCerts } from "./common.js";
import { enrichFromScm } from "./scm.js";
import { obsAuthorization, obsStringToSign } from "./sign.js";

/** ListBuckets 不受 endpoint 限制，任一地域都返回所有地域的桶 */
const SERVICE_HOST = "obs.cn-north-4.myhuaweicloud.com";

// SlowDown 为 HTTP 503，不匹配 withRetry 的规则，加 Throttling. 前缀让它重试（TooManyRequests 为 429，已能识别）
const THROTTLE_CODES = new Set(["SlowDown"]);

interface ObsRequest {
  host: string;
  /** 缺省 GET */
  method?: "GET" | "PUT";
  /** 规范资源：服务级为 "/"，桶级为 "/<bucket>/"，签名的子资源（如 ?customdomain）要拼在后面 */
  resource: string;
  /** 实际发送的查询串（含 "?"），marker 之类的普通参数不参与签名 */
  search?: string;
  headers?: Record<string, string>;
  /** XML 请求体，带上 Content-MD5（参与签名） */
  body?: string;
}

/** OBS 协议签名（Authorization: OBS AK:Signature）；Date 是 fetch 规范里的禁止请求头，改用 x-obs-date，StringToSign 的 Date 行为空 */
async function obsSend(ctx: QueryContext, creds: AccessKeyCredentials, req: ObsRequest): Promise<string> {
  const method = req.method ?? "GET";
  return withRetry(ctx, async () => {
    const headers: Record<string, string> = { ...req.headers, "x-obs-date": new Date().toUTCString() };
    if (req.body !== undefined) {
      headers["Content-MD5"] = createHash("md5").update(req.body).digest("base64");
      headers["Content-Type"] = "application/xml";
    }
    if (creds.securityToken) headers["x-obs-security-token"] = creds.securityToken;
    headers.Authorization = obsAuthorization(creds.accessKeyId, creds.secretAccessKey, obsStringToSign(method, headers, req.resource));
    const raw = await send(ctx, "huawei", `https://${req.host}/${req.search ?? ""}`, { method, headers, ...(req.body !== undefined && { body: req.body }) });
    if (raw.status >= 400) {
      const code = xmlText(raw.text, "Code") ?? `HTTP${raw.status}`;
      throw new CloudApiError(
        "huawei",
        THROTTLE_CODES.has(code) ? `Throttling.${code}` : code,
        xmlText(raw.text, "Message") ?? `HTTP ${raw.status}`,
        xmlText(raw.text, "RequestId"),
        raw.status,
      );
    }
    return raw.text;
  });
}

interface Bucket {
  name: string;
  region: string;
}

async function listBuckets(ctx: QueryContext, creds: AccessKeyCredentials, warn: Warn): Promise<Bucket[]> {
  const buckets: Bucket[] = [];
  let marker: string | undefined;
  // 文档没写分页，SDK 支持 marker / IsTruncated，按截断标记兜底翻页
  for (let page = 0; page < 200; page++) {
    const xml = await obsSend(ctx, creds, {
      host: SERVICE_HOST,
      resource: "/",
      ...(marker && { search: `?marker=${encodeURIComponent(marker)}` }),
      // 只列对象桶，不含并行文件系统
      headers: { "x-obs-bucket-type": "OBJECT" },
    });
    for (const b of xmlBlocks(xml, "Bucket")) {
      const name = xmlText(b, "Name");
      const region = xmlText(b, "Location");
      if (!name) continue;
      if (region) buckets.push({ name, region });
      else warn(new CloudApiError("huawei", "UnknownLocation", "ListBuckets 未返回桶所在区域，无法确定访问域名"), `bucket ${name}`);
    }
    marker = xmlText(xml, "IsTruncated") === "true" ? xmlText(xml, "NextMarker") : undefined;
    if (!marker) break;
  }
  return buckets;
}

/** 有证书的才计入 HTTPS；客户端 CA 证书（client）不是服务端证书 */
const SERVER_CERT_TYPES = new Set(["server", "server_sm"]);

function parseCustomDomains(xml: string, bucket: Bucket): DomainRecord[] {
  const byDomain = new Map<string, (CertInfo & { type?: string })[]>();
  for (const block of xmlBlocks(xml, "Domains")) {
    const domain = xmlText(block, "DomainName");
    if (!domain) continue;
    const certs = byDomain.get(domain) ?? [];
    byDomain.set(domain, certs);
    const id = xmlText(block, "CertificateId");
    const type = xmlText(block, "CertificateType");
    if (!id || (type && !SERVER_CERT_TYPES.has(type))) continue;
    // ExpiredTime 为 UTC ISO 8601，如 2026-03-13T10:22:05.912Z；列表不给证书内容，国际证书的 RSA / ECC 无从得知
    const algorithm = type === "server_sm" ? ("SM2" as const) : undefined;
    certs.push(compact({ id, name: xmlText(block, "CertName"), notAfter: toIso(xmlText(block, "ExpiredTime")), algorithm, type }));
  }
  const withoutType = ({ type: _, ...cert }: CertInfo & { type?: string }): CertInfo => cert;
  return Array.from(byDomain, ([domain, certs]) => {
    const best = earliest(certs);
    return compact({
      provider: "huawei" as const,
      service: "obs",
      domain,
      // 自定义域名没有单独的 HTTPS 开关，绑定了服务端证书即支持 HTTPS
      https: !!best,
      cert: best && withoutType(best),
      certs: certs.length > 1 ? orderCerts(certs).map(withoutType) : undefined,
      extra: compact({ bucket: bucket.name, region: bucket.region, certType: best?.type }),
    });
  });
}

const xmlEscape = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/**
 * 设置桶的自定义域名（SetBucketCustomdomain）：证书按 CertificateType 分别设置，只设 server（国际服务端证书），
 * 国密（server_sm）与客户端 CA 证书（client）不动。带上 CCM 证书 ID（OBS 要求托管证书的 ID 必须是 CCM 上的）与 PEM。
 * 自定义域名没有单独的 HTTPS 开关，绑定服务端证书即支持 HTTPS，deploy 与 update 的请求相同。
 */
async function applyObs(ctx: QueryContext, creds: AccessKeyCredentials, target: DeployTarget, input: DeployInput): Promise<DeployOutcome> {
  let certId: string | undefined;
  for (const record of target.records) {
    const { bucket, region } = record.extra ?? {};
    if (!bucket || !region) throw new CloudApiError("huawei", "MissingBucket", `自定义域名 ${record.domain} 缺少所属 bucket / region`);
    certId ??= await input.certId();
    const body =
      `<CustomDomainConfiguration><Name>${xmlEscape(certName(input.cert))}</Name><CertificateId>${xmlEscape(certId)}</CertificateId>` +
      `<Certificate>${xmlEscape(input.cert.certPem)}</Certificate><PrivateKey>${xmlEscape(input.cert.keyPem)}</PrivateKey>` +
      `<CertificateType>server</CertificateType></CustomDomainConfiguration>`;
    const search = `?customdomain=${record.domain}`;
    await obsSend(ctx, creds, { host: `${bucket}.obs.${region}.myhuaweicloud.com`, method: "PUT", resource: `/${bucket}/${search}`, search, body });
  }
  return compact({ certId });
}

/** 对象存储 OBS 的自定义域名：先列桶，再逐个桶查自定义域名与绑定的证书（并发 5） */
export const obs: DomainService<AccessKeyCredentials> = {
  key: "obs",
  label: "对象存储 OBS",
  async list(ctx: QueryContext, creds: AccessKeyCredentials, warn: Warn): Promise<DomainRecord[]> {
    const buckets = await listBuckets(ctx, creds, warn);
    const perBucket = await mapLimit(buckets, 5, async (bucket) => {
      try {
        const xml = await obsSend(ctx, creds, {
          host: `${bucket.name}.obs.${bucket.region}.myhuaweicloud.com`,
          resource: `/${bucket.name}/?customdomain`,
          search: "?customdomain",
        });
        return parseCustomDomains(xml, bucket);
      } catch (e) {
        // 没配置自定义域名的桶报 NoSuchCustomDomain，等同空列表
        if (e instanceof CloudApiError && e.code === "NoSuchCustomDomain") return [];
        warn(e, `bucket ${bucket.name}`);
        return [];
      }
    });
    return enrichFromScm(ctx, creds, warn, perBucket.flat());
  },
  deployer: { apply: applyObs },
};
