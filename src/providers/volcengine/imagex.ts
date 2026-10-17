import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import type { CertInfo, DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { enrichFromCertCenter } from "./certs.js";
import { callVolc } from "./client.js";

/** 每个地域有自己的 OpenAPI 域名，不支持跨地域调用；服务、域名都要到列出它的地域查 */
const REGIONS: Record<string, string> = {
  "cn-north-1": "imagex.volcengineapi.com",
  "ap-southeast-1": "imagex.ap-southeast-1.volcengineapi.com",
};
const MAIN_REGION = "cn-north-1";

interface ImageService {
  ServiceId: string;
  ServiceName?: string;
  /** cn / mya（柔佛） */
  ServiceRegion?: string;
  /** 中文：正常 / 未审核 / 审核未通过 / 禁用 */
  ServiceStatus?: string;
}

interface ServiceDomain {
  domain: string;
  /** 中文，如「正常」 */
  status?: string;
  is_default?: boolean;
}

interface DomainConfig {
  status?: string;
  https_config?: {
    enable_https?: boolean;
    /** HTTPS 关闭时可能残留，不能用来判断是否开启 */
    cert_id?: string;
    /** 文档未列出、仅 SDK 模型里有：{ id, common_name, not_after（Unix 秒） } */
    cert?: { id?: string; common_name?: string; not_after?: number } | null;
  } | null;
}

/** 2018-08-01 为 snake_case，SDK 用的 2023-05-01 为 PascalCase，两种都认 */
interface DomainCert {
  domain?: string;
  Domain?: string;
  cert_id?: string;
  CertID?: string;
  cert_name?: string;
  CertName?: string;
  cert_common_name?: string;
  CertCommonName?: string;
  /** Unix 秒 */
  cert_not_after?: number;
  CertNotAfter?: number;
  san?: string[] | null;
  San?: string[] | null;
}

// 服务查询时「未开通」与「服务没有可用域名」的 CodeN
const NOT_OPEN = /^(601001|600013|ERR_SUBSCRIPTION_NOTFOUND|ERR_INSTANCE_NOT_FOUND)$/;
const NO_DOMAIN = /^(601012|ERR_SERVICE_NO_AVAIL_DOMAIN)$/;

const seconds = (n?: number) => (n ? toIso(n) : undefined);
const asArray = <T>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);

/**
 * veImageX：逐地域列服务 → 每个服务 GetServiceDomains 列域名 → 逐域名 GetDomainConfig 读 HTTPS 开关与证书 ID。
 * 证书名称 / CN / SAN / 到期时间取自按地域一次返回的 GetImageAllDomainCert，缺到期时间时从证书中心按 ID 补全。
 * 接口均为 GET，字段为 snake_case。
 */
export const imagex: DomainService<AccessKeyCredentials> = {
  key: "imagex",
  label: "veImageX",
  async list(ctx: QueryContext, creds: AccessKeyCredentials, warn: Warn): Promise<DomainRecord[]> {
    const call = <T>(region: string, action: string, params: Record<string, string> = {}) =>
      callVolc<T>(ctx, creds, { host: REGIONS[region]!, service: "ImageX", region, version: "2018-08-01", action, method: "GET", params });

    const services: { service: ImageService; region: string }[] = [];
    const seen = new Set<string>();
    for (const region of Object.keys(REGIONS)) {
      let list: ImageService[];
      try {
        list = (await call<{ Services?: ImageService[] | null }>(region, "GetAllImageServices")).Services ?? [];
      } catch (e) {
        // 主地域失败即服务失败；柔佛未开通视为没有服务，其余错误记 issue
        if (region === MAIN_REGION) throw e;
        if (!(e instanceof CloudApiError && NOT_OPEN.test(e.code))) warn(e, `地域 ${region}`);
        continue;
      }
      for (const service of list) {
        if (seen.has(service.ServiceId)) continue;
        seen.add(service.ServiceId);
        services.push({ service, region });
      }
    }

    const perService = await mapLimit(services, 5, async ({ service, region }) => {
      try {
        const domains = asArray<ServiceDomain>(await call(region, "GetServiceDomains", { ServiceId: service.ServiceId }));
        return domains.map((d) => ({ d, service, region }));
      } catch (e) {
        if (!(e instanceof CloudApiError && NO_DOMAIN.test(e.code))) warn(e, `服务 ${service.ServiceName ?? service.ServiceId}`);
        return [];
      }
    });
    const domains = perService.flat();

    const configs = await mapLimit(domains, 5, async ({ d, service, region }) => {
      try {
        return await call<DomainConfig>(region, "GetDomainConfig", { ServiceId: service.ServiceId, DomainName: d.domain });
      } catch (e) {
        warn(e, `域名 ${d.domain}`);
        return undefined;
      }
    });

    // 只给开了 HTTPS 的域名所在地域拉证书详情
    const httpsRegions = new Set(domains.filter((_, i) => configs[i]?.https_config?.enable_https === true).map((x) => x.region));
    const certsByRegion = new Map<string, Map<string, DomainCert>>();
    for (const region of httpsRegions) {
      try {
        const list = asArray<DomainCert>(await call(region, "GetImageAllDomainCert"));
        certsByRegion.set(region, new Map(list.map((c) => [c.domain ?? c.Domain ?? "", c])));
      } catch (e) {
        warn(e, `地域 ${region} 的域名证书列表`);
      }
    }

    const records = domains.map(({ d, service, region }, i) => {
      const cfg = configs[i];
      const https = cfg?.https_config?.enable_https === true;
      let cert: CertInfo | undefined;
      if (https) {
        const configured = cfg?.https_config?.cert_id || cfg?.https_config?.cert?.id;
        const c = certsByRegion.get(region)?.get(d.domain);
        // 证书列表与域名配置的证书 ID 不一致时（如刚换证书）以域名配置为准
        const listed = c && (!configured || (c.cert_id ?? c.CertID) === configured) ? c : undefined;
        cert = compact({
          id: configured || listed?.cert_id || listed?.CertID,
          name: listed?.cert_name ?? listed?.CertName,
          commonName: listed?.cert_common_name ?? listed?.CertCommonName ?? cfg?.https_config?.cert?.common_name,
          sans: listed?.san ?? listed?.San ?? undefined,
          notAfter: seconds(listed?.cert_not_after ?? listed?.CertNotAfter ?? cfg?.https_config?.cert?.not_after),
        });
      }
      return compact({
        provider: "volcengine" as const,
        service: "imagex",
        domain: d.domain,
        status: cfg?.status ?? d.status,
        https,
        cert,
        extra: compact({ serviceId: service.ServiceId, serviceName: service.ServiceName, region }),
      });
    });
    return enrichFromCertCenter(ctx, creds, warn, records);
  },
};
