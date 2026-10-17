import type { TencentCredentials } from "../../lib/env.js";
import type { QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import type { DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { callTencent } from "./client.js";
import { sslCertsById } from "./ssl.js";

interface Zone {
  ZoneId: string;
  ZoneName?: string;
}

interface AccelerationDomain {
  DomainName: string;
  DomainStatus?: string;
  Certificate?: {
    /** disable 不配置服务端证书；eofreecert / eofreecert_manual 免费证书；sslcert SSL 托管证书 */
    Mode?: string;
    /** ExpireTime / DeployTime 为带时区的 ISO 8601 */
    List?: { CertId?: string; Alias?: string; ExpireTime?: string; DeployTime?: string; Status?: string; SignAlgo?: string }[] | null;
  } | null;
}

/** DescribeZones 的 Limit 上限 100，DescribeAccelerationDomains 的上限 200 */
const ZONE_PAGE = 100;
const DOMAIN_PAGE = 200;

const call = <T>(ctx: QueryContext, creds: TencentCredentials, action: string, payload: Record<string, unknown>) =>
  callTencent<T>(ctx, creds, { service: "teo", version: "2022-09-01", action, payload });

export const teo: DomainService<TencentCredentials> = {
  key: "teo",
  label: "EdgeOne",
  async list(ctx: QueryContext, creds: TencentCredentials, warn: Warn): Promise<DomainRecord[]> {
    const zones = await paginate(ZONE_PAGE, async (_page, offset) => {
      const res = await call<{ Zones?: Zone[] | null; TotalCount?: number }>(ctx, creds, "DescribeZones", {
        Offset: offset,
        Limit: ZONE_PAGE,
      });
      return { items: res.Zones ?? [], total: res.TotalCount };
    });
    const perZone = await mapLimit(zones, 5, async (zone) => {
      const domains = await paginate(DOMAIN_PAGE, async (_page, offset) => {
        const res = await call<{ AccelerationDomains?: AccelerationDomain[] | null; TotalCount?: number }>(
          ctx,
          creds,
          "DescribeAccelerationDomains",
          { ZoneId: zone.ZoneId, Offset: offset, Limit: DOMAIN_PAGE },
        );
        return { items: res.AccelerationDomains ?? [], total: res.TotalCount };
      }).catch((e: unknown) => {
        warn(e, `zone ${zone.ZoneName ?? zone.ZoneId}`);
        return [];
      });
      return domains.map((d) => [zone, d] as const);
    });
    const all = perZone.flat();
    const httpsOf = (d: AccelerationDomain) => !!d.Certificate?.Mode && d.Certificate.Mode !== "disable";
    // 证书列表的 ExpireTime 可能缺失（官方示例里 List 只有 CertId），缺了就按 ID 从 SSL 证书列表补，整个服务只拉一次
    const needSsl = all.some(([, d]) => httpsOf(d) && d.Certificate?.List?.some((c) => c.CertId && !c.ExpireTime));
    const ssl = needSsl ? await sslCertsById(ctx, creds, warn) : undefined;
    return all.map(([zone, d]) => {
      const mode = d.Certificate?.Mode;
      // 一个加速域名可挂多张证书（如 RSA + ECC），取最早到期的那张
      const certs = (d.Certificate?.List ?? [])
        .map((c) => {
          const s = c.CertId ? ssl?.get(c.CertId) : undefined;
          return { c, s, notAfter: toIso(c.ExpireTime) ?? s?.notAfter };
        })
        .sort((a, b) => (a.notAfter ?? "9999").localeCompare(b.notAfter ?? "9999"));
      const first = certs[0];
      const https = httpsOf(d);
      return compact({
        provider: "tencent" as const,
        service: "teo",
        domain: d.DomainName,
        status: d.DomainStatus,
        https,
        cert:
          https && first
            ? compact({
                id: first.c.CertId,
                name: first.c.Alias ?? first.s?.name,
                commonName: first.s?.commonName,
                sans: first.s?.sans,
                notBefore: first.s?.notBefore,
                notAfter: first.notAfter,
                status: first.c.Status,
              })
            : undefined,
        extra: compact({ zoneId: zone.ZoneId, zone: zone.ZoneName, certMode: mode }),
      });
    });
  },
};
