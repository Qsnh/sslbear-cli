import { createHash } from "node:crypto";
import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, send, withRetry, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { mapLimit } from "../../lib/pool.js";
import type { DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { enrichFromCertCenter } from "./certs.js";
import { httpsAlreadyEnabled } from "./common.js";
import { canonicalQuery, sha256Hex, tosAuthorization, volcDate } from "./sign.js";

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
  method?: "GET" | "PUT";
  /** PUT 的 JSON 请求体 */
  body?: string;
}

/**
 * TOS 请求（虚拟主机风格）。PUT 带 JSON 体时加 Content-MD5 与 x-tos-content-sha256（后者参与签名）；成功的 PUT 没有响应体。
 * TOS 的错误体是扁平 JSON {Code, Message, RequestId, EC}；EC 拼进 message，供 isInactive 判断未开通。
 */
async function tosCall<T>(ctx: QueryContext, creds: AccessKeyCredentials, req: TosRequest): Promise<Partial<T>> {
  const method = req.method ?? "GET";
  return withRetry(ctx, async () => {
    const headers: Record<string, string> = { "X-Tos-Date": volcDate(new Date()) };
    if (creds.securityToken) headers["X-Tos-Security-Token"] = creds.securityToken;
    const payloadHash = req.body ? sha256Hex(req.body) : undefined;
    if (req.body) {
      headers["Content-Type"] = "application/json";
      headers["Content-MD5"] = createHash("md5").update(req.body).digest("base64");
      headers["X-Tos-Content-Sha256"] = payloadHash!;
    }
    headers.Authorization = tosAuthorization({
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
      region: req.region,
      method,
      query: req.query,
      // Host 由 fetch 自动带上，只参与签名
      headers: { ...headers, Host: req.host },
      ...(payloadHash && { payloadHash }),
    });
    const qs = Object.entries(req.query)
      .map(([k, v]) => (v ? canonicalQuery({ [k]: v }) : encodeURIComponent(k)))
      .join("&");
    const raw = await send(ctx, "volcengine", `https://${req.host}/${qs ? `?${qs}` : ""}`, { method, headers, ...(req.body && { body: req.body }) });
    if (raw.status < 300 && !raw.text.trim()) return {};
    let body: T & TosError;
    try {
      body = JSON.parse(raw.text);
    } catch {
      const code = raw.status >= 400 ? `HTTP${raw.status}` : "InvalidResponse";
      throw new CloudApiError("volcengine", code, `响应不是合法 JSON（HTTP ${raw.status}）：${raw.text.slice(0, 200)}`, undefined, raw.status);
    }
    // 桶未配置自定义域名：404 + EC 0016-00000008（实测 Code 为 NoSuchBucketCustomDomainConfiguration，名称含 CustomDomain 的也认）；NoSuchBucket 等照常报错
    if (method === "GET" && raw.status === 404 && (body.EC === NO_CUSTOM_DOMAIN_EC || /CustomDomain/i.test(body.Code ?? ""))) return {};
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
  /** tos / s3 */
  Protocol?: string;
  Forbidden?: boolean;
  ForbiddenReason?: string;
  CertId?: string;
  /**
   * CertBound 已绑定 / CertUnbound 未绑定 / CertExpired 已过期 / CertNotExist 证书已删除 /
   * RoleNotExist 跨服务授权失败（TOS 无法访问证书中心）/ CertUnknown 状态未知
   */
  CertStatus?: string;
}

/**
 * TOS 拿不到所绑证书的状态：实测 CertNotExist 的域名 TLS 握手下发的是默认的 *.tos-<region>.volces.com 证书
 * （即使证书中心里同 ID 的证书还在），自定义域名的 HTTPS 实际不可用；RoleNotExist 按文档同样无法使用。
 * 这两种视为未开启 HTTPS，证书 ID 与状态放在 extra 里提示。CertExpired / CertUnknown 仍按开启处理，照常给出证书。
 */
const CERT_UNAVAILABLE = new Set(["CertNotExist", "RoleNotExist"]);

const certUnavailable = (rule: CustomDomainRule) => !!rule.CertId && CERT_UNAVAILABLE.has(rule.CertStatus ?? "");

/** 绑了证书（且不是未绑定 / 不可用状态）即视为开启 HTTPS */
const ruleHttps = (rule: CustomDomainRule) => !!rule.CertId && rule.CertStatus !== "CertUnbound" && !certUnavailable(rule);

const bucketHost = (bucket: string, region: string) => `${bucket}.tos-${region}.volces.com`;

/**
 * 对象存储 TOS 的自定义域名：ListBuckets（不分页，每账号最多 100 个桶）后逐个桶查 ?customdomain（并发 5）。
 * TOS 没有单独的 HTTPS 开关，绑定证书即可 HTTPS 访问、解绑后不能，所以以绑定了证书视为开启（证书不可用的状态除外，见 CERT_UNAVAILABLE）；
 * 接口只给证书 ID 与绑定状态，名称、有效期从证书中心按 ID 补全。
 */
export const tos: DomainService<AccessKeyCredentials> = {
  key: "tos",
  label: "对象存储 TOS",
  async list(ctx: QueryContext, creds: AccessKeyCredentials, warn: Warn): Promise<DomainRecord[]> {
    const body = await tosCall<{ Buckets: Bucket[] | null }>(ctx, creds, { host: SERVICE_HOST, region: SERVICE_REGION, query: {} });
    const buckets = (body.Buckets ?? []).filter((b) => b.Name && b.Location);
    const perBucket = await mapLimit(buckets, 5, async (bucket) => {
      try {
        // 必须走桶所在地域的 endpoint，走错地域会直接返回 NoSuchBucket
        const res = await tosCall<{ CustomDomainRules: CustomDomainRule[] | null }>(ctx, creds, {
          host: bucket.ExtranetEndpoint ? `${bucket.Name}.${bucket.ExtranetEndpoint}` : bucketHost(bucket.Name, bucket.Location!),
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
      const unavailable = certUnavailable(rule);
      const https = ruleHttps(rule);
      return compact({
        provider: "volcengine" as const,
        service: "tos",
        domain: rule.Domain,
        status: rule.Forbidden ? "forbidden" : "normal",
        https,
        cert: https ? compact({ id: rule.CertId, status: rule.CertStatus }) : undefined,
        extra: compact({
          bucket: bucket.Name,
          region: bucket.Location,
          forbiddenReason: rule.Forbidden ? rule.ForbiddenReason : undefined,
          certId: unavailable ? rule.CertId : undefined,
          certStatus: unavailable ? rule.CertStatus : undefined,
        }),
      });
    });
    return enrichFromCertCenter(ctx, creds, warn, records);
  },
  deployer: {
    // 跨服务授权失败时 TOS 读不到证书中心，换绑的证书同样不会生效（实际下发默认证书）
    unsupported: (record) =>
      !record.extra?.bucket || !record.extra.region
        ? "缺少所在桶与地域信息"
        : record.extra.certStatus === "RoleNotExist"
          ? "TOS 没有访问证书中心的跨服务授权（证书状态 RoleNotExist），绑定的证书不会生效；请先在 TOS 控制台为自定义域名完成证书服务授权"
          : undefined,
    /**
     * PutBucketCustomDomain 按域名整条覆盖规则（不传 Protocol 会变回 tos），所以先读出该域名的规则，只换 CertId 再写回。
     * TOS 没有 HTTPS 开关，绑定证书即可 HTTPS 访问，部署与更新是同一个操作；部署时读到的规则已绑着可用的证书（HTTPS 其实已开启）则不写入。
     */
    async apply(ctx, creds, target, input) {
      const [record] = target.records;
      const { bucket, region } = record!.extra ?? {};
      const req = { host: bucketHost(bucket!, region!), region: region!, query: { customdomain: "" } };
      const res = await tosCall<{ CustomDomainRules: CustomDomainRule[] | null }>(ctx, creds, req);
      const rule = (res.CustomDomainRules ?? []).find((r) => r.Domain.toLowerCase() === record!.domain.toLowerCase());
      if (!rule) throw new CloudApiError("volcengine", "DomainNotFound", `桶 ${bucket} 上已没有自定义域名 ${record!.domain}`);
      if (target.mode === "deploy" && ruleHttps(rule)) throw httpsAlreadyEnabled();
      const certId = await input.certId();
      const body = JSON.stringify({ CustomDomainRule: compact({ Domain: rule.Domain, CertId: certId, Protocol: rule.Protocol }) });
      await tosCall(ctx, creds, { ...req, method: "PUT", body });
      return { certId };
    },
  },
};
