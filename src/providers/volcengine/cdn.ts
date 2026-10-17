import type { AccessKeyCredentials } from "../../lib/env.js";
import type { QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { CertInfo, DomainRecord } from "../../types.js";
import type { DomainService } from "../registry.js";
import { callVolc } from "./client.js";
import { earliest, splitList } from "./common.js";

interface CdnDomain {
  Domain: string;
  Status?: string;
  /** 是否启用了 HTTPS 特性 */
  HTTPS?: boolean;
  ServiceType?: string;
  ServiceRegion?: string;
  Project?: string;
}

interface CdnCert {
  CertId?: string;
  /** 证书 CN */
  CertName?: string;
  /** SAN，逗号分隔 */
  DnsName?: string;
  /** running / expiring_soon / expired */
  Status?: string;
  /** Unix 秒 */
  EffectiveTime?: number;
  ExpireTime?: number;
  /** 已关联该证书的加速域名，逗号分隔 */
  ConfiguredDomain?: string | null;
  Desc?: string;
  Source?: string;
}

// 两个列表接口的 PageSize 上限都是 100
const PAGE = 100;

const call = <T>(ctx: QueryContext, creds: AccessKeyCredentials, action: string, params: Record<string, string | number>) =>
  callVolc<T>(ctx, creds, { host: "cdn.volcengineapi.com", service: "CDN", region: "cn-north-1", version: "2021-03-01", action, method: "POST", params });

function toCert(c: CdnCert): CertInfo {
  return compact({
    id: c.CertId,
    commonName: c.CertName,
    sans: splitList(c.DnsName),
    notBefore: toIso(c.EffectiveTime),
    notAfter: toIso(c.ExpireTime),
    status: c.Status,
  });
}

/**
 * CDN：域名列表（带 HTTPS 开关）+ 已关联加速域名的证书列表（ListCdnCertInfo 默认 Configured=true）按域名合并。
 * 双证书模式下一个域名出现在两张证书的 ConfiguredDomain 里，取先到期的那张。
 * 证书列表按 EncryType 过滤、缺省只返回 RSA/ECC（inter_cert），国密 SM2（sm_cert）需另查一次。
 */
export const cdn: DomainService<AccessKeyCredentials> = {
  key: "cdn",
  label: "CDN",
  async list(ctx: QueryContext, creds: AccessKeyCredentials): Promise<DomainRecord[]> {
    const listCerts = (encryType: string) =>
      paginate(PAGE, async (page) => {
        const res = await call<{ CertInfo?: CdnCert[] | null; Total?: number }>(ctx, creds, "ListCdnCertInfo", {
          PageNum: page,
          PageSize: PAGE,
          EncryType: encryType,
        });
        return { items: res.CertInfo ?? [], total: res.Total };
      });
    const [domains, interCerts, smCerts] = await Promise.all([
      paginate(PAGE, async (page) => {
        const res = await call<{ Data?: CdnDomain[] | null; Total?: number }>(ctx, creds, "ListCdnDomains", { PageNum: page, PageSize: PAGE });
        return { items: res.Data ?? [], total: res.Total };
      }),
      listCerts("inter_cert"),
      listCerts("sm_cert"),
    ]);
    const certsByDomain = new Map<string, CertInfo[]>();
    for (const c of [...interCerts, ...smCerts]) {
      for (const d of splitList(c.ConfiguredDomain)) {
        const list = certsByDomain.get(d) ?? [];
        list.push(toCert(c));
        certsByDomain.set(d, list);
      }
    }
    return domains.map((d) => {
      const https = d.HTTPS === true;
      return compact({
        provider: "volcengine" as const,
        service: "cdn",
        domain: d.Domain,
        status: d.Status,
        https,
        cert: https ? earliest(certsByDomain.get(d.Domain) ?? []) : undefined,
        extra: compact({ serviceType: d.ServiceType, serviceRegion: d.ServiceRegion, project: d.Project }),
      });
    });
  },
};
