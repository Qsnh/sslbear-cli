import type { AliyunCredentials } from "../../lib/env.js";
import { CloudApiError, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { DomainRecord } from "../../types.js";
import type { Deployer, DomainService, Warn } from "../registry.js";
import { CAS_REGION, casCertName } from "./cas.js";
import { callRpc } from "./client.js";

interface UserDomain {
  DomainName: string;
  DomainStatus?: string;
  /** 直播的域名状态字段名不同 */
  LiveDomainStatus?: string;
  /** CDN / 点播为 SslProtocol，DCDN 为 SSLProtocol */
  SslProtocol?: string;
  SSLProtocol?: string;
  /** 直播的域名类型：liveVideo 播流域名，liveEdge 边缘推流域名 */
  LiveDomainType?: string;
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
  deployer: Deployer<AliyunCredentials>;
}

/** 域名列表里的 HTTPS 开关：CDN 为 SslProtocol，DCDN 为 SSLProtocol，直播没有该字段 */
const sslSwitch = (d: UserDomain) => d.SslProtocol ?? d.SSLProtocol;

/**
 * CDN / DCDN / 直播的接口结构相同：域名列表 + HTTPS 证书列表两次分页查询后按域名合并，
 * 避免逐个域名查证书。HTTPS 列表的时间文档写的是北京时间 "YYYY-MM-DD HH:mm:ss"，实测 CDN / DCDN / 直播都返回 ISO 8601 UTC，toIso 两种都能解析。
 * 证书列表只用于补全证书信息：没有开启 HTTPS 的域名时不查；查询失败（如无权限）只记一条 issue，
 * 域名照常输出，HTTPS 以域名列表里的开关为准。
 */
function cdnLike(p: Product): DomainService<AliyunCredentials> {
  return {
    key: p.service,
    label: p.label,
    async list(ctx: QueryContext, creds: AliyunCredentials, warn: Warn): Promise<DomainRecord[]> {
      const call = <T>(action: string, params: Record<string, string | number>) =>
        callRpc<T>(ctx, creds, { endpoint: p.endpoint, version: p.version, action, params });
      const domains = await paginate(p.listPageSize, async (page) => {
        const res = await call<{ Domains?: { PageData?: UserDomain[] }; TotalCount?: number }>(p.listAction, {
          PageNumber: page,
          PageSize: p.listPageSize,
        });
        return { items: res.Domains?.PageData ?? [], total: res.TotalCount };
      });
      // 没有开关字段（直播）时只能靠证书列表判断 HTTPS，有域名就要查
      const needCerts = domains.some((d) => sslSwitch(d) !== "off");
      let certs: HttpsCertInfo[] = [];
      if (needCerts) {
        try {
          certs = await paginate(p.httpsPageSize, async (page) => {
            const res = await call<{ CertInfos?: { CertInfo?: HttpsCertInfo[] }; TotalCount?: number }>(p.httpsAction, {
              PageNumber: page,
              PageSize: p.httpsPageSize,
            });
            return { items: res.CertInfos?.CertInfo ?? [], total: res.TotalCount };
          });
        } catch (e) {
          // 账号下没有任何 HTTPS 域名时接口报 NoHttpsDomain，等同空列表
          if (!(e instanceof CloudApiError && e.code === "NoHttpsDomain")) warn(e, "HTTPS 证书列表（用于补全证书信息）");
        }
      }
      const certByDomain = new Map(certs.map((c) => [c.DomainName, c]));
      return domains.map((d) => {
        // 域名列表里有 HTTPS 开关就以开关为准；没有该字段时以是否出现在 HTTPS 列表判断
        const ssl = sslSwitch(d);
        const https = ssl === undefined ? certByDomain.has(d.DomainName) : ssl === "on";
        const c = https ? certByDomain.get(d.DomainName) : undefined;
        return compact({
          provider: "aliyun" as const,
          service: p.service,
          domain: d.DomainName,
          status: d.DomainStatus ?? d.LiveDomainStatus,
          https,
          cert: c
            ? compact({
                name: c.CertName,
                commonName: c.CertCommonName,
                notBefore: toIso(c.CertStartTime),
                notAfter: toIso(c.CertExpireTime),
                status: c.CertStatus,
              })
            : undefined,
          extra: compact({ certType: c?.CertType, liveDomainType: d.LiveDomainType }),
        });
      });
    },
    deployer: p.deployer,
  };
}

/**
 * CDN / DCDN：Set*DomainSSLCertificate 按证书服务里的证书 ID 设置证书并打开 HTTPS 开关。
 * HTTP/2、强制跳转、TLS 版本、HSTS 等是各自独立的域名配置，不经过这个接口，换证书时保持原样，不需要先读后改。
 */
function sslCertDeployer(endpoint: string, version: string, action: string): Deployer<AliyunCredentials> {
  return {
    async apply(ctx, creds, target, input) {
      const certId = await input.certId();
      for (const r of target.records) {
        await callRpc(ctx, creds, {
          endpoint,
          version,
          action,
          method: "POST",
          params: { DomainName: r.domain, SSLProtocol: "on", CertType: "cas", CertId: certId, CertRegion: CAS_REGION },
        });
      }
      return { certId };
    },
  };
}

/** 直播：SetLiveDomainCertificate 没有证书 ID 参数，按证书名引用证书服务里的证书；推流域名不能配 HTTPS */
const liveDeployer: Deployer<AliyunCredentials> = {
  unsupported: (r) => (r.extra?.liveDomainType === "liveEdge" ? "直播推流域名不能配置 HTTPS 证书" : undefined),
  async apply(ctx, creds, target, input) {
    const certId = await input.certId();
    const certName = await casCertName(ctx, creds, certId);
    for (const r of target.records) {
      await callRpc(ctx, creds, {
        endpoint: "live.aliyuncs.com",
        version: "2016-11-01",
        action: "SetLiveDomainCertificate",
        method: "POST",
        params: { DomainName: r.domain, SSLProtocol: "on", CertType: "cas", CertName: certName },
      });
    }
    return { certId };
  },
};

// HTTPS 列表接口的 PageSize 上限：DCDN 文档为 500，CDN / 直播未注明上限，用文档默认值 20 以免超限报错
export const cdn = cdnLike({
  service: "cdn",
  label: "CDN",
  endpoint: "cdn.aliyuncs.com",
  version: "2018-05-10",
  listAction: "DescribeUserDomains",
  listPageSize: 500,
  httpsAction: "DescribeCdnHttpsDomainList",
  httpsPageSize: 20,
  deployer: sslCertDeployer("cdn.aliyuncs.com", "2018-05-10", "SetCdnDomainSSLCertificate"),
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
  deployer: sslCertDeployer("dcdn.aliyuncs.com", "2018-01-15", "SetDcdnDomainSSLCertificate"),
});

export const live = cdnLike({
  service: "live",
  label: "视频直播",
  endpoint: "live.aliyuncs.com",
  version: "2016-11-01",
  listAction: "DescribeLiveUserDomains",
  listPageSize: 50,
  httpsAction: "DescribeLiveHttpsDomainList",
  httpsPageSize: 20,
  deployer: liveDeployer,
});
