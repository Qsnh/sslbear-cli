import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { enrichFromCertCenter } from "./certs.js";
import { callVolc } from "./client.js";

interface CertBind {
  CertId?: string;
  CertName?: string;
  /** volc：证书中心；self：托管在 DCDN */
  CertSource?: string;
  /** Deployed / Waiting / Deploying */
  DeployStatus?: string;
  /** RFC 3339 UTC，如 2023-08-20T07:59:59Z（实测与证书真实到期时刻一致，不是标成 Z 的北京时间） */
  Expire?: string;
}

/** HTTPS 模块：除下面用到的字段外还有 Http2、Hsts、TlsVersions、ForceRedirect、QUICSwitch、OCSPStapling 等，写回时原样带上 */
type DcdnHttps = {
  /** 绑定证书时默认自动开启，可单独关闭 */
  EnableHttps?: boolean;
  CertBind?: CertBind | null;
} & Record<string, unknown>;

interface DcdnDomain {
  Domain: string;
  /** Started / Deploy / Stop */
  Status?: string;
  /** domestic / overseas / global */
  Scope?: string;
  ProjectName?: string;
  Https?: DcdnHttps | null;
}

// 文档允许 PageSize < 10000，但每条都带完整域名配置，单页过大容易超时
const PAGE = 1000;

const call = <T>(ctx: QueryContext, creds: AccessKeyCredentials, action: string, params: Record<string, unknown>, version = "2021-04-01") =>
  callVolc<T>(ctx, creds, { host: "open.volcengineapi.com", service: "dcdn", region: "cn-north-1", version, action, method: "POST", params });

/** 证书绑定里只读的状态字段，写回时不带 */
const READONLY_BIND = new Set(["DeployStatus", "CertStatus"]);

/** 读出的 HTTPS 模块写回前的整理：去掉 null（含嵌套），证书绑定去掉只读的部署状态，其余字段原样保留 */
function writable(v: unknown, inBind = false): unknown {
  if (Array.isArray(v)) return v.map((x) => writable(x));
  if (!v || typeof v !== "object") return v;
  return Object.fromEntries(
    Object.entries(v).flatMap(([k, x]) => (x === null || x === undefined || (inBind && READONLY_BIND.has(k)) ? [] : [[k, writable(x, k === "CertBind")]])),
  );
}

/** 读回单个域名的 HTTPS 模块（DescribeDomainDetail 按域名精确查询，不像 DescribeDomainConfig / ListDomainConfig 那样模糊匹配） */
async function readHttps(ctx: QueryContext, creds: AccessKeyCredentials, domain: string): Promise<DcdnHttps | undefined> {
  const res = await call<Partial<DcdnDomain>>(ctx, creds, "DescribeDomainDetail", { Domain: domain });
  if (res.Domain && res.Domain.toLowerCase() !== domain.toLowerCase()) return undefined;
  return res.Https ?? undefined;
}

const UNCONFIRMED_HINT = "请稍后用 domains 核对，或到全站加速控制台的 HTTPS 配置里查看";

/** 读回的配置里绑定的必须是新证书，否则无从确认部署结果 */
function assertBound(https: DcdnHttps | undefined, certId: string): void {
  const bound = https?.CertBind?.CertId;
  if (bound === certId) return;
  throw new CloudApiError(
    "volcengine",
    "CertBindUnconfirmed",
    `已提交绑定，但读回的域名配置里绑定的证书是 ${bound || "（空）"}，不是新证书 ${certId}，无法确认 HTTPS 已开启；${UNCONFIRMED_HINT}`,
  );
}

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
     * CreateCertBind 把证书中心的证书绑定到域名、替换原证书，HTTP/2、强制跳转、TLS 版本等不在此接口里，保持不变。
     * 更新：只换证书即可。
     * 部署：CreateCertBind 的文档没说会改 EnableHttps（绑了证书但关闭 HTTPS 的域名再绑同一张证书时可能什么都不变），
     * 所以绑定后用 DescribeDomainDetail 读回，确认绑的是新证书且 EnableHttps 为 true；HTTPS 没开时用 UpdateDomainConfig
     * 把读出的整个 Https 模块原样写回、只把 EnableHttps 改为 true（按模块整体覆盖，其他字段必须带上），再读回核对。
     * 仍然确认不了就报错，不算部署成功。
     */
    async apply(ctx, creds, target, input) {
      const domain = target.records[0]!.domain;
      const certId = await input.certId();
      const res = await call<{ Success?: boolean }>(ctx, creds, "CreateCertBind", { CertSource: "volc", CertId: certId, DomainNames: [domain] });
      if (res.Success === false) throw new CloudApiError("volcengine", "CertBindFailed", "绑定证书失败（接口返回 Success=false）");
      if (target.mode === "update") return { certId };

      const bound = await readHttps(ctx, creds, domain);
      assertBound(bound, certId);
      if (bound!.EnableHttps === true) return { certId };
      const Https = { ...(writable(bound) as DcdnHttps), EnableHttps: true };
      await call(ctx, creds, "UpdateDomainConfig", { Domain: domain, Https }, "2023-01-01");
      const after = await readHttps(ctx, creds, domain);
      assertBound(after, certId);
      if (after!.EnableHttps !== true) {
        throw new CloudApiError(
          "volcengine",
          "HttpsNotEnabled",
          `已绑定新证书并提交开启 HTTPS，但读回的配置显示 HTTPS 仍未开启（EnableHttps=${String(after!.EnableHttps)}）；${UNCONFIRMED_HINT}`,
        );
      }
      return { certId };
    },
  },
};
