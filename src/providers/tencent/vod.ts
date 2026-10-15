import type { TencentCredentials } from "../../lib/env.js";
import type { QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import type { DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { callTencent } from "./client.js";
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
const DOMAIN_PAGE = 20;

const call = <T>(ctx: QueryContext, creds: TencentCredentials, action: string, payload: Record<string, unknown>) =>
  callTencent<T>(ctx, creds, { service: "vod", version: "2018-07-17", action, payload });

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
        const domains = await paginate(DOMAIN_PAGE, async (_page, offset) => {
          const res = await call<{ DomainSet?: VodDomain[] | null; TotalCount?: number }>(ctx, creds, "DescribeVodDomains", {
            Offset: offset,
            Limit: DOMAIN_PAGE,
            ...(app && { SubAppId: app.SubAppId }),
          });
          return { items: res.DomainSet ?? [], total: res.TotalCount };
        });
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
      return compact({
        provider: "tencent" as const,
        service: "vod",
        domain: d.Domain,
        status: d.DeployStatus,
        https: !!certId,
        cert: certId ? compact({ id: certId, notAfter: toIso(d.HTTPSConfig?.CertExpireTime) }) : undefined,
        extra: compact({ type: d.Type, subAppId: app ? String(app.SubAppId) : undefined, subApp: app?.SubAppIdName }),
      });
    });
    return enrichFromSsl(ctx, creds, warn, records);
  },
};
