import type { TencentCredentials } from "../../lib/env.js";
import type { QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { callTencent } from "./client.js";
import { enrichFromSsl } from "./ssl.js";

interface LiveDomain {
  Name: string;
  /** 0 推流域名，1 播放域名 */
  Type?: number;
  /** 0 停用，1 启用 */
  Status?: number;
}

interface CertBinding {
  DomainName: string;
  CertificateAlias?: string;
  /** 1 已开启 HTTPS，0 关闭 */
  Status?: number;
  CertExpireTime?: string;
  CloudCertId?: string;
}

const DOMAIN_PAGE = 100;
const BINDING_PAGE = 50;

const call = <T>(ctx: QueryContext, creds: TencentCredentials, action: string, payload: Record<string, unknown>) =>
  callTencent<T>(ctx, creds, { service: "live", version: "2018-08-01", action, payload });

/** 直播域名 + 域名证书绑定关系两次分页查询后按域名合并；绑定里缺到期时间的从 SSL 证书列表补 */
export const live: DomainService<TencentCredentials> = {
  key: "live",
  label: "云直播",
  async list(ctx: QueryContext, creds: TencentCredentials, warn: Warn): Promise<DomainRecord[]> {
    const [domains, bindings] = await Promise.all([
      paginate(DOMAIN_PAGE, async (page) => {
        const res = await call<{ DomainList?: LiveDomain[] | null; AllCount?: number }>(ctx, creds, "DescribeLiveDomains", {
          PageNum: page,
          PageSize: DOMAIN_PAGE,
        });
        return { items: res.DomainList ?? [], total: res.AllCount };
      }),
      paginate(BINDING_PAGE, async (_page, offset) => {
        const res = await call<{ LiveDomainCertBindings?: CertBinding[] | null; TotalNum?: number }>(
          ctx,
          creds,
          "DescribeLiveDomainCertBindings",
          { Offset: offset, Length: BINDING_PAGE },
        );
        return { items: res.LiveDomainCertBindings ?? [], total: res.TotalNum };
      }),
    ]);
    const bindingByDomain = new Map(bindings.map((b) => [b.DomainName, b]));
    const records = domains.map((d) => {
      const b = bindingByDomain.get(d.Name);
      const https = b?.Status === 1;
      return compact({
        provider: "tencent" as const,
        service: "live",
        domain: d.Name,
        status: d.Status === undefined ? undefined : d.Status === 1 ? "online" : "offline",
        https,
        // 绑了证书但未开启 HTTPS 的域名不对外提供证书，不计入到期统计
        cert: https && b ? compact({ id: b.CloudCertId, name: b.CertificateAlias, notAfter: toIso(b.CertExpireTime) }) : undefined,
        extra: d.Type === undefined ? undefined : { type: d.Type === 1 ? "play" : "push" },
      });
    });
    return enrichFromSsl(ctx, creds, warn, records);
  },
};
