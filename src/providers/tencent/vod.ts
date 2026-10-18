import type { TencentCredentials } from "../../lib/env.js";
import type { QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import type { DomainRecord } from "../../types.js";
import type { Deployer, DomainService, Warn } from "../registry.js";
import { callTencent } from "./client.js";
import { asPlatformDomain, isPlatformDomain } from "./platform.js";
import { enrichFromSsl } from "./ssl.js";

interface SubApp {
  SubAppId: number;
  SubAppIdName?: string;
  Status?: string;
}

interface VodDomain {
  Domain: string;
  DeployStatus?: string;
  Type?: string;
  HTTPSConfig?: { CloudCertId?: string; CertExpireTime?: string } | null;
}

const SUBAPP_PAGE = 200;
/** DescribeVodDomains 的 Limit 默认值 20（文档未写上限），按默认值翻页 */
const DOMAIN_PAGE = 20;
/** 防止接口异常时死循环：20 × 500 = 1 万个域名 */
const MAX_DOMAIN_PAGES = 500;

const call = <T>(ctx: QueryContext, creds: TencentCredentials, action: string, payload: Record<string, unknown>) =>
  callTencent<T>(ctx, creds, { service: "vod", version: "2018-07-17", action, payload });

/**
 * 查一个应用（或不带 SubAppId）下的全部域名。
 * DescribeVodDomains 先按 Offset/Limit 在服务端的完整列表上分页、再过滤掉不对外展示的域名，TotalCount 也把它们算在内：
 * 实测主应用 TotalCount=2 但只返回 1 个域名，Offset=0/Limit=1 返回空页，Offset=1 返回的正是第一页里那个域名。
 * 所以偏移量必须按页长递增（不能用已取到的条数，否则会把同一个域名再取一遍），并按域名去重兜底。
 */
async function listAppDomains(ctx: QueryContext, creds: TencentCredentials, app: SubApp | undefined): Promise<VodDomain[]> {
  const byName = new Map<string, VodDomain>();
  for (let page = 0; page < MAX_DOMAIN_PAGES; page++) {
    const offset = page * DOMAIN_PAGE;
    const res = await call<{ DomainSet?: VodDomain[] | null; TotalCount?: number }>(ctx, creds, "DescribeVodDomains", {
      Offset: offset,
      Limit: DOMAIN_PAGE,
      ...(app && { SubAppId: app.SubAppId }),
    });
    const items = res.DomainSet ?? [];
    for (const d of items) if (!byName.has(d.Domain)) byName.set(d.Domain, d);
    const done = res.TotalCount !== undefined ? offset + DOMAIN_PAGE >= res.TotalCount : items.length === 0;
    if (done) return [...byName.values()];
  }
  throw new Error(`点播域名分页超过 ${MAX_DOMAIN_PAGES} 页仍未取完，已中止（接口返回可能异常）`);
}

/**
 * SetVodDomainCertificate(Operation=Set) 按 SSL 证书 ID 设置证书，设置即开启 HTTPS，只涉及证书；
 * 2023-12-25 之后开通点播的账号必须带应用 ID（list 时已记在 extra.subAppId）。
 */
const deployer: Deployer<TencentCredentials> = {
  unsupported(record) {
    if (record.extra?.type === "EdgeOne") return "该域名由 EdgeOne 分发，证书需在 EdgeOne 上配置";
    if (record.status === "Locked") return "域名处于锁定状态（Locked），暂时无法变更配置";
    return undefined;
  },
  async apply(ctx, creds, target, input) {
    const record = target.records[0]!;
    const certId = await input.certId();
    const subAppId = record.extra?.subAppId;
    await call(ctx, creds, "SetVodDomainCertificate", {
      Domain: record.domain,
      Operation: "Set",
      CertID: certId,
      ...(subAppId && { SubAppId: Number(subAppId) }),
    });
    return { certId };
  },
};

/**
 * 2023-12-25 之后开通点播的账号必须按应用（SubAppId）查域名：先列应用再逐个查；
 * 未启用多应用的老账号应用列表为空，直接不带 SubAppId 查一次。
 */
export const vod: DomainService<TencentCredentials> = {
  key: "vod",
  label: "云点播",
  async list(ctx: QueryContext, creds: TencentCredentials, warn: Warn): Promise<DomainRecord[]> {
    // 应用列表查不到（老账号、接口异常）时退回不带 SubAppId 查询，真正的问题会在域名查询里暴露
    const apps = await paginate(SUBAPP_PAGE, async (_page, offset) => {
      const res = await call<{ SubAppIdInfoSet?: SubApp[] | null; TotalCount?: number }>(ctx, creds, "DescribeSubAppIds", {
        Offset: offset,
        Limit: SUBAPP_PAGE,
      });
      return { items: res.SubAppIdInfoSet ?? [], total: res.TotalCount };
    }).catch((): SubApp[] => []);
    const active = apps.filter((a) => a.Status !== "Destroyed" && a.Status !== "Destroying");
    const targets: (SubApp | undefined)[] = active.length ? active : [undefined];
    const perApp = await mapLimit(targets, 5, async (app) => {
      try {
        const domains = await listAppDomains(ctx, creds, app);
        return domains.map((d) => [d, app] as const);
      } catch (e) {
        // 只有一个查询目标时直接抛出，记为整个服务失败；多应用时单个应用失败不影响其他应用
        if (targets.length === 1) throw e;
        warn(e, `应用 ${app?.SubAppIdName ?? app?.SubAppId}`);
        return [];
      }
    });
    const records = perApp.flat().map(([d, app]) => {
      const certId = d.HTTPSConfig?.CloudCertId;
      const record = compact({
        provider: "tencent" as const,
        service: "vod",
        domain: d.Domain,
        status: d.DeployStatus,
        https: !!certId,
        cert: certId ? compact({ id: certId, notAfter: toIso(d.HTTPSConfig?.CertExpireTime) }) : undefined,
        extra: compact({ type: d.Type, subAppId: app ? String(app.SubAppId) : undefined, subApp: app?.SubAppIdName }),
      });
      // 默认分发域名（{appid}.vod2.myqcloud.com、{subappid}.vod-qcloud.com）由平台提供 HTTPS；
      // 它们的 HTTPSConfig 里 CloudCertId 为空、CertExpireTime 是平台早已过期的旧值，不能当作用户证书
      return isPlatformDomain(d.Domain) ? asPlatformDomain(record, true) : record;
    });
    return enrichFromSsl(ctx, creds, warn, records);
  },
  deployer,
};
