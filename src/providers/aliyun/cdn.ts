import type { AliyunCredentials } from "../../lib/env.js";
import { CloudApiError, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { DomainRecord } from "../../types.js";
import type { DomainService } from "../registry.js";
import { callRpc } from "./client.js";

interface UserDomain {
  DomainName: string;
  DomainStatus?: string;
  /** 直播的域名状态字段名不同 */
  LiveDomainStatus?: string;
  /** CDN / 点播为 SslProtocol，DCDN 为 SSLProtocol */
  SslProtocol?: string;
  SSLProtocol?: string;
}

interface HttpsCertInfo {
  DomainName: string;
  CertName?: string;
  CertCommonName?: string;
  CertType?: string;
  CertStatus?: string;
  CertStartTime?: string;
  CertExpireTime?: string;
}

interface Product {
  service: string;
  label: string;
  endpoint: string;
  version: string;
  listAction: string;
  listPageSize: number;
  httpsAction: string;
  httpsPageSize: number;
}

/**
 * CDN / DCDN / 直播的接口结构相同：域名列表 + HTTPS 证书列表两次分页查询后按域名合并，
 * 避免逐个域名查证书。HTTPS 列表的时间为北京时间 "YYYY-MM-DD HH:mm:ss"。
 */
function cdnLike(p: Product): DomainService<AliyunCredentials> {
  return {
    key: p.service,
    label: p.label,
    async list(ctx: QueryContext, creds: AliyunCredentials): Promise<DomainRecord[]> {
      const call = <T>(action: string, params: Record<string, string | number>) =>
        callRpc<T>(ctx, creds, { endpoint: p.endpoint, version: p.version, action, params });
      const [domains, certs] = await Promise.all([
        paginate(p.listPageSize, async (page) => {
          const res = await call<{ Domains?: { PageData?: UserDomain[] }; TotalCount?: number }>(p.listAction, {
            PageNumber: page,
            PageSize: p.listPageSize,
          });
          return { items: res.Domains?.PageData ?? [], total: res.TotalCount };
        }),
        paginate(p.httpsPageSize, async (page) => {
          const res = await call<{ CertInfos?: { CertInfo?: HttpsCertInfo[] }; TotalCount?: number }>(p.httpsAction, {
            PageNumber: page,
            PageSize: p.httpsPageSize,
          });
          return { items: res.CertInfos?.CertInfo ?? [], total: res.TotalCount };
        }).catch((e: unknown) => {
          // 账号下没有任何 HTTPS 域名时接口报 NoHttpsDomain，等同空列表
          if (e instanceof CloudApiError && e.code === "NoHttpsDomain") return [];
          throw e;
        }),
      ]);
      const certByDomain = new Map(certs.map((c) => [c.DomainName, c]));
      return domains.map((d) => {
        const c = certByDomain.get(d.DomainName);
        return compact({
          provider: "aliyun" as const,
          service: p.service,
          domain: d.DomainName,
          status: d.DomainStatus ?? d.LiveDomainStatus,
          https: (d.SslProtocol ?? d.SSLProtocol) === "on" || !!c,
          cert: c
            ? compact({
                name: c.CertName,
                commonName: c.CertCommonName,
                notBefore: toIso(c.CertStartTime),
                notAfter: toIso(c.CertExpireTime),
                status: c.CertStatus,
              })
            : undefined,
          extra: c?.CertType ? { certType: c.CertType } : undefined,
        });
      });
    },
  };
}

// HTTPS 列表接口的 PageSize 上限：DCDN 文档为 500，CDN / 直播未注明，取保守值 100
export const cdn = cdnLike({
  service: "cdn",
  label: "CDN",
  endpoint: "cdn.aliyuncs.com",
  version: "2018-05-10",
  listAction: "DescribeUserDomains",
  listPageSize: 500,
  httpsAction: "DescribeCdnHttpsDomainList",
  httpsPageSize: 100,
});

export const dcdn = cdnLike({
  service: "dcdn",
  label: "全站加速 DCDN",
  endpoint: "dcdn.aliyuncs.com",
  version: "2018-01-15",
  listAction: "DescribeDcdnUserDomains",
  listPageSize: 500,
  httpsAction: "DescribeDcdnHttpsDomainList",
  httpsPageSize: 500,
});

export const live = cdnLike({
  service: "live",
  label: "视频直播",
  endpoint: "live.aliyuncs.com",
  version: "2016-11-01",
  listAction: "DescribeLiveUserDomains",
  listPageSize: 50,
  httpsAction: "DescribeLiveHttpsDomainList",
  httpsPageSize: 100,
});
