import type { AliyunCredentials } from "../../lib/env.js";
import { CloudApiError, send, withRetry, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import { xmlBlocks, xmlText } from "../../lib/xml.js";
import type { DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { CAS_REGION } from "./cas.js";
import { permissionHint } from "./ram.js";
import { ossDate, ossV4Authorization, percentEncode } from "./sign.js";

/** ListBuckets 是服务级接口，任一地域的 endpoint 都返回全部 bucket */
const SERVICE_HOST = "oss-cn-hangzhou.aliyuncs.com";
const SERVICE_REGION = "cn-hangzhou";

interface OssRequest {
  /** 接口名，即 RAM Action 去掉 oss: 前缀（无权限时写进报错） */
  action: string;
  host: string;
  region: string;
  bucket?: string;
  query: Record<string, string>;
  /** 默认 GET；带 XML 请求体时为 POST */
  method?: "GET" | "POST";
  body?: string;
}

/** OSS 签名 V1 已对新用户 / 新 bucket 停用，统一使用 V4 */
async function ossRequest(ctx: QueryContext, creds: AliyunCredentials, req: OssRequest): Promise<string> {
  const method = req.method ?? "GET";
  return withRetry(ctx, async () => {
    const headers: Record<string, string> = {
      "x-oss-date": ossDate(new Date()),
      "x-oss-content-sha256": "UNSIGNED-PAYLOAD",
    };
    if (req.body !== undefined) headers["content-type"] = "application/xml";
    if (creds.securityToken) headers["x-oss-security-token"] = creds.securityToken;
    headers.Authorization = ossV4Authorization({
      accessKeyId: creds.accessKeyId,
      accessKeySecret: creds.accessKeySecret,
      region: req.region,
      method,
      ...(req.bucket && { bucket: req.bucket }),
      query: req.query,
      headers,
    });
    const qs = Object.entries(req.query)
      .map(([k, v]) => (v ? `${percentEncode(k)}=${percentEncode(v)}` : percentEncode(k)))
      .join("&");
    const raw = await send(ctx, "aliyun", `https://${req.host}/${qs ? `?${qs}` : ""}`, {
      method,
      headers,
      ...(req.body !== undefined && { body: req.body }),
    });
    if (raw.status >= 400) {
      const code = xmlText(raw.text, "Code") ?? `HTTP${raw.status}`;
      // 无权限时的原文不说缺哪个权限（自身接口只说 bucket 不属于你），AccessDeniedDetail 里有 AuthAction；
      // 没给 AuthAction 时 AccessDenied 也可能来自 bucket 策略，措辞为「可能」
      const authAction = xmlText(raw.text, "AuthAction");
      const hint =
        code === "AccessDenied"
          ? permissionHint({
              action: authAction ?? `oss:${req.action}`,
              explicit: xmlText(raw.text, "NoPermissionType") === "ExplicitDeny",
              uncertain: !authAction,
            })
          : "";
      throw new CloudApiError("aliyun", code, `${xmlText(raw.text, "Message") ?? `HTTP ${raw.status}`}${hint}`, xmlText(raw.text, "RequestId"), raw.status);
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
    const xml = await ossRequest(ctx, creds, {
      action: "ListBuckets",
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

const escapeXml = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/**
 * 对象存储 OSS 的自定义域名：先列 bucket，再逐个 bucket 查绑定的 CNAME 与证书（并发 5）。
 * 部署对已绑定的域名再调一次 PutCname，只带证书配置（证书服务里的证书 ID 加地域后缀），其他 CNAME 配置不受影响。
 * 用 Force 覆盖当前证书而不用 PreviousCertId 校验：超时重试时第一次可能已经换上新证书，校验会把成功误报为失败。
 */
export const oss: DomainService<AliyunCredentials> = {
  key: "oss",
  label: "对象存储 OSS",
  async list(ctx: QueryContext, creds: AliyunCredentials, warn: Warn): Promise<DomainRecord[]> {
    const buckets = await listBuckets(ctx, creds);
    const perBucket = await mapLimit(buckets, 5, async (bucket) => {
      try {
        const xml = await ossRequest(ctx, creds, {
          action: "ListCname",
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
  deployer: {
    // 实测 OSS 不接受没有 CN 的证书（MalformedCertificate）
    requiresCommonName: true,
    async apply(ctx, creds, target, input) {
      const certId = `${await input.certId()}-${CAS_REGION}`;
      for (const r of target.records) {
        const { bucket, region } = r.extra ?? {};
        if (!bucket || !region) throw new Error(`${r.domain} 缺少 bucket / region 信息`);
        await ossRequest(ctx, creds, {
          action: "PutCname",
          method: "POST",
          host: `${bucket}.oss-${region}.aliyuncs.com`,
          region,
          bucket,
          query: { cname: "", comp: "add" },
          body:
            `<BucketCnameConfiguration><Cname><Domain>${escapeXml(r.domain)}</Domain>` +
            `<CertificateConfiguration><CertId>${escapeXml(certId)}</CertId><Force>true</Force></CertificateConfiguration>` +
            "</Cname></BucketCnameConfiguration>",
        }).catch((e: unknown) => {
          // 实测 OSS 不接受 Subject 为空、只有 SAN 的证书（直接传 PEM 也一样），只回一句格式错误，补上原因
          if (e instanceof CloudApiError && e.code === "MalformedCertificate" && !input.cert.commonName) {
            e.message = `${e.message}（OSS 不接受没有通用名 CN、只有 SAN 的证书，如 Let's Encrypt 短期证书；请换用带通用名的证书）`;
          }
          throw e;
        });
      }
      return { certId };
    },
  },
};
