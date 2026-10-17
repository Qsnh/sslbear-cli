import type { TencentCredentials } from "../../lib/env.js";
import type { QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { DomainRecord } from "../../types.js";
import type { DomainService } from "../registry.js";
import { callTencent } from "./client.js";
import { asPlatformDomain, isPlatformDomain } from "./platform.js";

interface CdnDomain {
  Domain: string;
  Status?: string;
  Area?: string;
  Https?: {
    Switch?: string;
    /** 实测 CertName 是证书的主域名（托管时自动生成），Message 才是证书备注（即 SSL 证书列表里的备注名） */
    CertInfo?: { CertId?: string; CertName?: string; Message?: string; ExpireTime?: string; DeployTime?: string; From?: string } | null;
  } | null;
}

/** DescribeDomainsConfig 的 Limit 上限为 100；一次调用覆盖境内与境外域名，用 Area 区分 */
const PAGE = 100;

export const cdn: DomainService<TencentCredentials> = {
  key: "cdn",
  label: "CDN",
  async list(ctx: QueryContext, creds: TencentCredentials): Promise<DomainRecord[]> {
    const domains = await paginate(PAGE, async (_page, offset) => {
      const res = await callTencent<{ Domains?: CdnDomain[] | null; TotalNumber?: number }>(ctx, creds, {
        service: "cdn",
        version: "2018-06-06",
        action: "DescribeDomainsConfig",
        payload: { Offset: offset, Limit: PAGE },
      });
      return { items: res.Domains ?? [], total: res.TotalNumber };
    });
    return domains.map((d) => {
      const cert = d.Https?.CertInfo;
      const https = d.Https?.Switch === "on";
      const record = compact({
        provider: "tencent" as const,
        service: "cdn",
        domain: d.Domain,
        status: d.Status,
        https,
        cert: https && cert ? compact({ id: cert.CertId, name: cert.Message || cert.CertName, notAfter: toIso(cert.ExpireTime) }) : undefined,
        extra: d.Area ? { area: d.Area } : undefined,
      });
      // 平台域名（如 *.video.myqcloud.com）有 HTTPS 开关但没有用户证书，HTTPS 以开关为准
      return isPlatformDomain(d.Domain) ? asPlatformDomain(record, https) : record;
    });
  },
};
