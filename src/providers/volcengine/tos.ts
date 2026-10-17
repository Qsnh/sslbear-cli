import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, send, withRetry, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { mapLimit } from "../../lib/pool.js";
import type { DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { enrichFromCertCenter } from "./certs.js";
import { canonicalQuery, tosAuthorization, volcDate } from "./sign.js";

/** ListBuckets 返回账号下所有地域的桶，任一地域的 endpoint 都可以 */
const SERVICE_HOST = "tos-cn-beijing.volces.com";
const SERVICE_REGION = "cn-beijing";

const NO_CUSTOM_DOMAIN_EC = "0016-00000008";

interface TosError {
  Code?: string;
  Message?: string;
  RequestId?: string;
  /** TOS 细分错误码，如 0003-00000003 账户未开通 TOS 服务 */
  EC?: string;
}

interface TosRequest {
  host: string;
  region: string;
  /** 无值参数（如 customdomain）传空串 */
  query: Record<string, string>;
}

/** TOS 的错误体是扁平 JSON {Code, Message, RequestId, EC}；EC 拼进 message，供 isInactive 判断未开通 */
async function tosGet<T>(ctx: QueryContext, creds: AccessKeyCredentials, req: TosRequest): Promise<Partial<T>> {
  return withRetry(ctx, async () => {
    const headers: Record<string, string> = { "X-Tos-Date": volcDate(new Date()) };
    if (creds.securityToken) headers["X-Tos-Security-Token"] = creds.securityToken;
    headers.Authorization = tosAuthorization({
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
      region: req.region,
      method: "GET",
      query: req.query,
      // Host 由 fetch 自动带上，只参与签名
      headers: { ...headers, Host: req.host },
    });
    const qs = Object.entries(req.query)
      .map(([k, v]) => (v ? canonicalQuery({ [k]: v }) : encodeURIComponent(k)))
      .join("&");
    const raw = await send(ctx, "volcengine", `https://${req.host}/${qs ? `?${qs}` : ""}`, { method: "GET", headers });
    let body: T & TosError;
    try {
      body = JSON.parse(raw.text);
    } catch {
      const code = raw.status >= 400 ? `HTTP${raw.status}` : "InvalidResponse";
      throw new CloudApiError("volcengine", code, `响应不是合法 JSON（HTTP ${raw.status}）：${raw.text.slice(0, 200)}`, undefined, raw.status);
    }
    // 桶未配置自定义域名：404 + EC 0016-00000008（Code 原文未查到，名称含 CustomDomain 的也认）；NoSuchBucket 等照常报错
    if (raw.status === 404 && (body.EC === NO_CUSTOM_DOMAIN_EC || /CustomDomain/i.test(body.Code ?? ""))) return {};
    if (raw.status >= 400) {
      // 503 SlowDown 为限流，换成能被 withRetry 识别的错误码；其余限流码（ExceedAccountQPSLimit 等）为 HTTP 429
      const code = body.Code === "SlowDown" ? "Throttling.SlowDown" : (body.Code ?? `HTTP${raw.status}`);
      const message = `${body.Message ?? `HTTP ${raw.status}`}${body.EC ? `（EC ${body.EC}）` : ""}`;
      throw new CloudApiError("volcengine", code, message, body.RequestId, raw.status);
    }
    return body;
  });
}

interface Bucket {
  Name: string;
  /** 地域，如 cn-beijing */
  Location?: string;
  /** 如 tos-cn-beijing.volces.com */
  ExtranetEndpoint?: string;
}

interface CustomDomainRule {
  Domain: string;
  Forbidden?: boolean;
  ForbiddenReason?: string;
  CertId?: string;
  /** CertBound / CertUnbound / CertExpired / CertNotExist / RoleNotExist / CertUnknown */
  CertStatus?: string;
}

/**
 * 对象存储 TOS 的自定义域名：ListBuckets（不分页，每账号最多 100 个桶）后逐个桶查 ?customdomain（并发 5）。
 * TOS 没有单独的 HTTPS 开关，绑定证书即可 HTTPS 访问、解绑后不能，所以以绑定了证书视为开启；
 * 接口只给证书 ID 与绑定状态，名称、有效期从证书中心按 ID 补全。
 */
export const tos: DomainService<AccessKeyCredentials> = {
  key: "tos",
  label: "对象存储 TOS",
  async list(ctx: QueryContext, creds: AccessKeyCredentials, warn: Warn): Promise<DomainRecord[]> {
    const body = await tosGet<{ Buckets: Bucket[] | null }>(ctx, creds, { host: SERVICE_HOST, region: SERVICE_REGION, query: {} });
    const buckets = (body.Buckets ?? []).filter((b) => b.Name && b.Location);
    const perBucket = await mapLimit(buckets, 5, async (bucket) => {
      try {
        const endpoint = bucket.ExtranetEndpoint || `tos-${bucket.Location}.volces.com`;
        // 必须走桶所在地域的 endpoint，走错地域会直接返回 NoSuchBucket
        const res = await tosGet<{ CustomDomainRules: CustomDomainRule[] | null }>(ctx, creds, {
          host: `${bucket.Name}.${endpoint}`,
          region: bucket.Location!,
          query: { customdomain: "" },
        });
        return (res.CustomDomainRules ?? []).map((rule) => ({ rule, bucket }));
      } catch (e) {
        warn(e, `bucket ${bucket.Name}`);
        return [];
      }
    });
    const records = perBucket.flat().map(({ rule, bucket }) => {
      const https = !!rule.CertId && rule.CertStatus !== "CertUnbound";
      return compact({
        provider: "volcengine" as const,
        service: "tos",
        domain: rule.Domain,
        status: rule.Forbidden ? "forbidden" : "normal",
        https,
        cert: https ? compact({ id: rule.CertId, status: rule.CertStatus }) : undefined,
        extra: compact({ bucket: bucket.Name, region: bucket.Location, forbiddenReason: rule.Forbidden ? rule.ForbiddenReason : undefined }),
      });
    });
    return enrichFromCertCenter(ctx, creds, warn, records);
  },
};
