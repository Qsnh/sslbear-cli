import type { AliyunCredentials } from "../../lib/env.js";
import type { QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import type { DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
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

/** 点播没有批量的 HTTPS 证书列表接口：只对开启了 HTTPS 的域名逐个查证书（并发 5） */
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
};
