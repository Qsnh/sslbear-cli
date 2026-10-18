import type { AliyunCredentials } from "../../lib/env.js";
import type { QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import type { DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { CAS_REGION, casCertName } from "./cas.js";
import { callRpc } from "./client.js";

interface VodDomain {
  DomainName: string;
  DomainStatus?: string;
  SslProtocol?: string;
}

interface VodCertInfo {
  CertId?: string;
  CertName?: string;
  /** 文档称「证书匹配的域名」，实测为证书的全部 SAN，半角逗号分隔，不是通用名 */
  CertDomainName?: string;
  CertOrg?: string;
  CertType?: string;
  Status?: string;
  ServerCertificateStatus?: string;
  CertStartTime?: string;
  CertExpireTime?: string;
}

const ENDPOINT = "vod.cn-shanghai.aliyuncs.com";
const VERSION = "2017-03-21";
const PAGE = 50;

/**
 * 点播没有批量的 HTTPS 证书列表接口：只对开启了 HTTPS 的域名逐个查证书（并发 5）。
 * 部署用 SetVodDomainSSLCertificate 按证书服务里的证书设置证书并打开 HTTPS，与 CDN 一样不涉及其他 HTTPS 配置。
 */
export const vod: DomainService<AliyunCredentials> = {
  key: "vod",
  label: "视频点播",
  async list(ctx: QueryContext, creds: AliyunCredentials, warn: Warn): Promise<DomainRecord[]> {
    const call = <T>(action: string, params: Record<string, string | number>) =>
      callRpc<T>(ctx, creds, { endpoint: ENDPOINT, version: VERSION, action, params });
    const domains = await paginate(PAGE, async (page) => {
      const res = await call<{ Domains?: { PageData?: VodDomain[] }; TotalCount?: number }>("DescribeVodUserDomains", {
        PageNumber: page,
        PageSize: PAGE,
      });
      return { items: res.Domains?.PageData ?? [], total: res.TotalCount };
    });
    return mapLimit(domains, 5, async (d) => {
      const https = d.SslProtocol === "on";
      let c: VodCertInfo | undefined;
      if (https) {
        try {
          const res = await call<{ CertInfos?: { CertInfo?: VodCertInfo[] } }>("DescribeVodDomainCertificateInfo", {
            DomainName: d.DomainName,
          });
          c = res.CertInfos?.CertInfo?.[0];
        } catch (e) {
          warn(e, d.DomainName);
        }
      }
      return compact({
        provider: "aliyun" as const,
        service: "vod",
        domain: d.DomainName,
        status: d.DomainStatus,
        https,
        cert: c
          ? compact({
              id: c.CertId,
              name: c.CertName,
              sans: c.CertDomainName?.split(",").map((s) => s.trim()).filter(Boolean),
              issuer: c.CertOrg,
              notBefore: toIso(c.CertStartTime),
              notAfter: toIso(c.CertExpireTime),
              status: c.Status,
            })
          : undefined,
        extra: c?.CertType ? { certType: c.CertType } : undefined,
      });
    });
  },
  deployer: {
    async apply(ctx, creds, target, input) {
      const certId = await input.certId();
      // 证书 ID 与证书名一并传：测试环境里用真实账号调通的就是这组参数
      const certName = await casCertName(ctx, creds, certId);
      for (const r of target.records) {
        await callRpc(ctx, creds, {
          endpoint: ENDPOINT,
          version: VERSION,
          action: "SetVodDomainSSLCertificate",
          method: "POST",
          params: { DomainName: r.domain, SSLProtocol: "on", CertType: "cas", CertId: certId, CertName: certName, CertRegion: CAS_REGION },
        });
      }
      return { certId };
    },
  },
};
