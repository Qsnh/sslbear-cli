import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, type QueryContext } from "../../lib/http.js";
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
      /** RFC 3339 UTC，如 2023-08-20T07:59:59Z（实测与证书真实到期时刻一致，不是标成 Z 的北京时间） */
      Expire?: string;
    } | null;
  } | null;
}

// 文档允许 PageSize < 10000，但每条都带完整域名配置，单页过大容易超时
const PAGE = 1000;

const call = <T>(ctx: QueryContext, creds: AccessKeyCredentials, action: string, params: Record<string, unknown>) =>
  callVolc<T>(ctx, creds, { host: "open.volcengineapi.com", service: "dcdn", region: "cn-north-1", version: "2021-04-01", action, method: "POST", params });

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
      const res = await call<{ DomainList?: DcdnDomain[] | null; DomainConfigs?: DcdnDomain[] | null; Total?: number }>(ctx, creds, "ListDomainConfig", {
        PageNumber: page,
        PageSize: PAGE,
      });
      return { items: res.DomainList ?? res.DomainConfigs ?? [], total: res.Total };
    });
    const records = domains.map((d) => {
      const bind = d.Https?.CertBind;
      // 没有开关字段时按文档的缺省行为：绑定了证书即开启。
      // 绑定证书但 EnableHttps=false 时按开关记为未开启（实测边缘节点仍用该证书完成 TLS 握手，HTTPS 请求照常回源）
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
  deployer: {
    /**
     * CreateCertBind 把证书中心的证书绑定到域名，替换原证书；文档说明绑定成功后同步开启该域名的 HTTPS，
     * 所以绑了证书但关闭 HTTPS 的域名（按关闭处理）点名部署时同样适用。HTTP/2、强制跳转、TLS 版本等不在此接口里，保持不变。
     */
    async apply(ctx, creds, target, input) {
      const [record] = target.records;
      const certId = await input.certId();
      const res = await call<{ Success?: boolean }>(ctx, creds, "CreateCertBind", { CertSource: "volc", CertId: certId, DomainNames: [record!.domain] });
      if (res.Success === false) throw new CloudApiError("volcengine", "CertBindFailed", "绑定证书失败（接口返回 Success=false）");
      return { certId };
    },
  },
};
