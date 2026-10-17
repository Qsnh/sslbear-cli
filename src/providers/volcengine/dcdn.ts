import type { AccessKeyCredentials } from "../../lib/env.js";
import type { QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { enrichFromCertCenter } from "./certs.js";
import { callVolc } from "./client.js";

interface DcdnDomain {
  Domain: string;
  /** Started / Deploy / Stop */
  Status?: string;
  /** domestic / overseas / global */
  Scope?: string;
  ProjectName?: string;
  Https?: {
    /** 绑定证书时默认自动开启，可单独关闭 */
    EnableHttps?: boolean;
    CertBind?: {
      CertId?: string;
      CertName?: string;
      /** volc：证书中心；self：托管在 DCDN */
      CertSource?: string;
      /** Deployed / Waiting / Deploying */
      DeployStatus?: string;
      /** RFC 3339 UTC，如 2023-08-20T07:59:59Z */
      Expire?: string;
    } | null;
  } | null;
}

// 文档允许 PageSize < 10000，但每条都带完整域名配置，单页过大容易超时
const PAGE = 1000;

/**
 * 全站加速：ListDomainConfig 一次返回域名列表与各域名的 HTTPS 配置（含绑定证书与到期时间）。
 * 每个域名只绑一张服务器证书；到期时间缺失时从证书中心按 ID 补全。
 */
export const dcdn: DomainService<AccessKeyCredentials> = {
  key: "dcdn",
  label: "全站加速 DCDN",
  async list(ctx: QueryContext, creds: AccessKeyCredentials, warn: Warn): Promise<DomainRecord[]> {
    const domains = await paginate(PAGE, async (page) => {
      // 官方 SDK 与 API Explorer 的返回字段为 DomainList，API 文档示例写的是 DomainConfigs，两者都认
      const res = await callVolc<{ DomainList?: DcdnDomain[] | null; DomainConfigs?: DcdnDomain[] | null; Total?: number }>(ctx, creds, {
        host: "open.volcengineapi.com",
        service: "dcdn",
        region: "cn-north-1",
        version: "2021-04-01",
        action: "ListDomainConfig",
        method: "POST",
        params: { PageNumber: page, PageSize: PAGE },
      });
      return { items: res.DomainList ?? res.DomainConfigs ?? [], total: res.Total };
    });
    const records = domains.map((d) => {
      const bind = d.Https?.CertBind;
      // 没有开关字段时按文档的缺省行为：绑定了证书即开启
      const https = d.Https?.EnableHttps ?? !!bind?.CertId;
      return compact({
        provider: "volcengine" as const,
        service: "dcdn",
        domain: d.Domain,
        status: d.Status,
        https,
        cert: https && bind?.CertId ? compact({ id: bind.CertId, name: bind.CertName, notAfter: toIso(bind.Expire) }) : undefined,
        extra: compact({
          scope: d.Scope,
          project: d.ProjectName,
          certSource: https ? bind?.CertSource : undefined,
          certDeployStatus: https ? bind?.DeployStatus : undefined,
        }),
      });
    });
    return enrichFromCertCenter(ctx, creds, warn, records);
  },
};
