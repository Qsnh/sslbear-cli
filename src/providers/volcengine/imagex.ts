import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import type { CertInfo, DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { enrichFromCertCenter } from "./certs.js";
import { callVolc } from "./client.js";
import { HTTPS_UNKNOWN, httpsAlreadyEnabled } from "./common.js";

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

/** GetDomainConfig 的 HTTPS 配置；实测除开关外还返回 TLS 版本、QUIC、OCSP、强制跳转、HSTS，可整块读出再写回 */
interface HttpsConfig {
  enable_https?: boolean;
  enable_http2?: boolean;
  enable_quic?: boolean;
  enable_ocsp?: boolean;
  /** 未开启过 HTTPS 的域名为 null */
  tls_versions?: string[] | null;
  /** 是否强制跳转 HTTPS（旧字段，与 enable_force_redirect 同义） */
  force_https?: boolean;
  enable_force_redirect?: boolean;
  /** http2https / https2http */
  force_redirect_type?: string;
  /** 301 / 302 */
  force_redirect_code?: string;
  /** 读写字段名都是 enabled（SDK 模型里的 enable 实测写入不生效） */
  hsts?: { enabled?: boolean; subdomain?: string; ttl?: number } | null;
  /** HTTPS 关闭时可能残留，不能用来判断是否开启 */
  cert_id?: string;
  /** 文档未列出、仅 SDK 模型里有：{ id, common_name, not_after（Unix 秒） } */
  cert?: { id?: string; common_name?: string; not_after?: number } | null;
}

interface DomainConfig {
  status?: string;
  https_config?: HttpsConfig | null;
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

/** 读不到 TLS 版本（从未开过 HTTPS 的域名为 null）时 UpdateHttps 必填的默认值，取 CDN 文档的默认值 */
const DEFAULT_TLS_VERSIONS = ["tlsv1.1", "tlsv1.2", "tlsv1.3"];

/**
 * UpdateHttps 是整块覆盖：把读出的 https_config 原样转成写入的 https 块，只开启 HTTPS 并换成新证书。
 * 读不到的项按控制台开启 HTTPS 的默认行为（HTTP/2 开启、TLS 1.1–1.3），用了 TLS 默认值时返回提示。
 */
function httpsBlock(h: HttpsConfig, certId: string): { https: Record<string, unknown>; note?: string } {
  const tls = h.tls_versions?.length ? h.tls_versions : undefined;
  // 新字段 enable_force_redirect 优先；只有旧字段 force_https 时按 HTTP → HTTPS 301
  const redirect =
    h.enable_force_redirect !== undefined
      ? {
          enable_force_redirect: h.enable_force_redirect,
          ...(h.force_redirect_type && { force_redirect_type: h.force_redirect_type }),
          ...(h.force_redirect_code && { force_redirect_code: h.force_redirect_code }),
        }
      : h.force_https
        ? { enable_force_redirect: true, force_redirect_type: "http2https", force_redirect_code: "301" }
        : {};
  const https = {
    enable_https: true,
    cert_id: certId,
    enable_http2: h.enable_http2 ?? true,
    ...(h.enable_quic !== undefined && { enable_quic: h.enable_quic }),
    enable_ocsp: h.enable_ocsp ?? false,
    tls_versions: tls ?? DEFAULT_TLS_VERSIONS,
    ...redirect,
    ...(h.hsts && { hsts: compact({ enabled: h.hsts.enabled, subdomain: h.hsts.subdomain, ttl: h.hsts.ttl }) }),
  };
  return { https, ...(!tls && { note: "已开启 HTTPS；TLS 版本按默认 tlsv1.1–1.3，如需调整请到 veImageX 控制台" }) };
}

const write = <T>(ctx: QueryContext, creds: AccessKeyCredentials, region: string, action: string, body: Record<string, unknown>, query?: Record<string, string>) =>
  callVolc<T>(ctx, creds, { host: REGIONS[region]!, service: "ImageX", region, version: "2018-08-01", action, method: "POST", params: body, ...(query && { query }) });

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

    // 读配置失败的域名开关与证书都不明，打 httpsUnknown 标记
    const configFailed = new Set<number>();
    const configs = await mapLimit(domains, 5, async ({ d, service, region }, i) => {
      try {
        return await call<DomainConfig>(region, "GetDomainConfig", { ServiceId: service.ServiceId, DomainName: d.domain });
      } catch (e) {
        warn(e, `域名 ${d.domain}`);
        configFailed.add(i);
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
      // 域名配置没给证书 ID、证书列表又查询失败时，不知道绑的是哪张证书
      let unknown = configFailed.has(i);
      if (https) {
        const configured = cfg?.https_config?.cert_id || cfg?.https_config?.cert?.id;
        if (!configured && !certsByRegion.has(region)) unknown = true;
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
        extra: compact({ serviceId: service.ServiceId, serviceName: service.ServiceName, region, ...(unknown && HTTPS_UNKNOWN) }),
      });
    });
    return enrichFromCertCenter(ctx, creds, warn, records);
  },
  deployer: {
    requiresCommonName:
      "veImageX 实测会接受没有通用名（CN）的证书（如 Let's Encrypt 的短期证书），但边缘节点不会生效、仍下发原来的证书；未做修改，请改用带通用名的证书",
    unsupported: (record) =>
      !record.extra?.serviceId || !REGIONS[record.extra.region ?? ""] ? "缺少所属服务或地域信息" : undefined,
    /**
     * 部署与更新都用 UpdateHttps：先 GetDomainConfig 读出 https_config，整块写回、只开启 HTTPS 并换证书，
     * HTTP/2、QUIC、OCSP、TLS 版本、强制跳转、HSTS 原样带上。
     * 文档里的 UpdateImageBatchDomainCert（只关联证书）实测无论参数怎么传都返回 InvalidParameter（CodeN 600003），不用。
     * 读到的开关与查询时不同（部署时已开启、更新时已关闭）不写入，先核对再取证书 ID，核对不过不会上传证书。
     * 没有通用名（CN）的证书实测 UpdateHttps 照收、域名配置也显示新证书，但边缘节点一直下发旧证书（带 CN 的证书 2 分钟内生效），
     * 所以直接不处理（不读、不传、不写），以免报「已更新」而实际没有生效。
     */
    async apply(ctx, creds, target, input) {
      if (!input.cert.commonName) {
        throw new CloudApiError(
          "volcengine",
          "CertWithoutCommonName",
          "veImageX 实测会接受没有通用名（CN）的证书（如 Let's Encrypt 的短期证书），但边缘节点不会生效、仍下发原来的证书；未做修改，请改用带通用名的证书",
        );
      }
      const [record] = target.records;
      const { serviceId, region } = record!.extra as { serviceId: string; region: string };
      const cfg = await callVolc<DomainConfig>(ctx, creds, {
        host: REGIONS[region]!,
        service: "ImageX",
        region,
        version: "2018-08-01",
        action: "GetDomainConfig",
        method: "GET",
        params: { ServiceId: serviceId, DomainName: record!.domain },
      });
      const on = cfg.https_config?.enable_https === true;
      if (target.mode === "deploy" && on) throw httpsAlreadyEnabled();
      if (target.mode === "update" && !on) {
        throw new CloudApiError("volcengine", "HttpsDisabled", `域名 ${record!.domain} 的 HTTPS 已关闭（与查询时不同），未替换证书；如需部署并开启 HTTPS 请用 --domain 点名后重新执行`);
      }
      const certId = await input.certId();
      const { https, note } = httpsBlock(cfg.https_config ?? {}, certId);
      await write(ctx, creds, region, "UpdateHttps", { domain: record!.domain, https }, { ServiceId: serviceId });
      return { certId, ...(note && { note }) };
    },
  },
};
