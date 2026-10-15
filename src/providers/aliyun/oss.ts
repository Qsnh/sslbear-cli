import type { AliyunCredentials } from "../../lib/env.js";
import { CloudApiError, send, withRetry, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import { xmlBlocks, xmlText } from "../../lib/xml.js";
import type { DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { ossDate, ossV4Authorization, percentEncode } from "./sign.js";

/** ListBuckets 是服务级接口，任一地域的 endpoint 都返回全部 bucket */
const SERVICE_HOST = "oss-cn-hangzhou.aliyuncs.com";
const SERVICE_REGION = "cn-hangzhou";

interface OssRequest {
  host: string;
  region: string;
  bucket?: string;
  query: Record<string, string>;
}

/** OSS 签名 V1 已对新用户 / 新 bucket 停用，统一使用 V4 */
async function ossGet(ctx: QueryContext, creds: AliyunCredentials, req: OssRequest): Promise<string> {
  return withRetry(ctx, async () => {
    const headers: Record<string, string> = {
      "x-oss-date": ossDate(new Date()),
      "x-oss-content-sha256": "UNSIGNED-PAYLOAD",
    };
    if (creds.securityToken) headers["x-oss-security-token"] = creds.securityToken;
    headers.Authorization = ossV4Authorization({
      accessKeyId: creds.accessKeyId,
      accessKeySecret: creds.accessKeySecret,
      region: req.region,
      method: "GET",
      ...(req.bucket && { bucket: req.bucket }),
      query: req.query,
      headers,
    });
    const qs = Object.entries(req.query)
      .map(([k, v]) => (v ? `${percentEncode(k)}=${percentEncode(v)}` : percentEncode(k)))
      .join("&");
    const raw = await send(ctx, "aliyun", `https://${req.host}/${qs ? `?${qs}` : ""}`, { method: "GET", headers });
    if (raw.status >= 400) {
      throw new CloudApiError(
        "aliyun",
        xmlText(raw.text, "Code") ?? `HTTP${raw.status}`,
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
  endpoint: string;
}

async function listBuckets(ctx: QueryContext, creds: AliyunCredentials): Promise<Bucket[]> {
  const buckets: Bucket[] = [];
  let marker: string | undefined;
  for (let page = 0; page < 200; page++) {
    const xml = await ossGet(ctx, creds, {
      host: SERVICE_HOST,
      region: SERVICE_REGION,
      query: { "max-keys": "1000", ...(marker && { marker }) },
    });
    for (const b of xmlBlocks(xml, "Bucket")) {
      const name = xmlText(b, "Name");
      const location = xmlText(b, "Location");
      const region = xmlText(b, "Region") ?? location?.replace(/^oss-/, "");
      const endpoint = xmlText(b, "ExtranetEndpoint") ?? (location && `${location}.aliyuncs.com`);
      if (name && region && endpoint) buckets.push({ name, region, endpoint });
    }
    marker = xmlText(xml, "IsTruncated") === "true" ? xmlText(xml, "NextMarker") : undefined;
    if (!marker) break;
  }
  return buckets;
}

function parseCnames(xml: string, bucket: Bucket): DomainRecord[] {
  return xmlBlocks(xml, "Cname").flatMap((block) => {
    const domain = xmlText(block, "Domain");
    if (!domain) return [];
    const certXml = xmlBlocks(block, "Certificate")[0];
    const certStatus = certXml && xmlText(certXml, "Status");
    const https = !!certXml && certStatus !== "Disabled";
    return [
      compact({
        provider: "aliyun" as const,
        service: "oss",
        domain,
        status: xmlText(block, "Status"),
        https,
        cert: https
          ? compact({
              id: xmlText(certXml!, "CertId"),
              notBefore: toIso(xmlText(certXml!, "ValidStartDate")),
              notAfter: toIso(xmlText(certXml!, "ValidEndDate")),
              status: certStatus,
            })
          : undefined,
        extra: compact({ bucket: bucket.name, region: bucket.region, certType: certXml && xmlText(certXml, "Type") }),
      }),
    ];
  });
}

/** 对象存储 OSS 的自定义域名：先列 bucket，再逐个 bucket 查绑定的 CNAME 与证书（并发 5） */
export const oss: DomainService<AliyunCredentials> = {
  key: "oss",
  label: "对象存储 OSS",
  async list(ctx: QueryContext, creds: AliyunCredentials, warn: Warn): Promise<DomainRecord[]> {
    const buckets = await listBuckets(ctx, creds);
    const perBucket = await mapLimit(buckets, 5, async (bucket) => {
      try {
        const xml = await ossGet(ctx, creds, {
          host: `${bucket.name}.${bucket.endpoint}`,
          region: bucket.region,
          bucket: bucket.name,
          query: { cname: "" },
        });
        return parseCnames(xml, bucket);
      } catch (e) {
        warn(e, `bucket ${bucket.name}`);
        return [];
      }
    });
    return perBucket.flat();
  },
};
