import type { TencentCredentials } from "../../lib/env.js";
import type { QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import type { DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { callTencent } from "./client.js";

interface Zone {
  ZoneId: string;
  ZoneName?: string;
}

interface AccelerationDomain {
  DomainName: string;
  DomainStatus?: string;
  Certificate?: {
    Mode?: string;
    List?: { CertId?: string; Alias?: string; ExpireTime?: string; DeployTime?: string; Status?: string; SignAlgo?: string }[] | null;
  } | null;
}

const ZONE_PAGE = 100;
const DOMAIN_PAGE = 200;

const call = <T>(ctx: QueryContext, creds: TencentCredentials, action: string, payload: Record<string, unknown>) =>
  callTencent<T>(ctx, creds, { service: "teo", version: "2022-09-01", action, payload });

export const teo: DomainService<TencentCredentials> = {
  key: "teo",
  label: "EdgeOne",
  async list(ctx: QueryContext, creds: TencentCredentials, warn: Warn): Promise<DomainRecord[]> {
    const zones = await paginate(ZONE_PAGE, async (page) => {
      const res = await call<{ Zones?: Zone[] | null; TotalCount?: number }>(ctx, creds, "DescribeZones", {
        Offset: (page - 1) * ZONE_PAGE,
        Limit: ZONE_PAGE,
      });
      return { items: res.Zones ?? [], total: res.TotalCount };
    });
    const perZone = await mapLimit(zones, 5, async (zone) => {
      const domains = await paginate(DOMAIN_PAGE, async (page) => {
        const res = await call<{ AccelerationDomains?: AccelerationDomain[] | null; TotalCount?: number }>(
          ctx,
          creds,
          "DescribeAccelerationDomains",
          { ZoneId: zone.ZoneId, Offset: (page - 1) * DOMAIN_PAGE, Limit: DOMAIN_PAGE },
        );
        return { items: res.AccelerationDomains ?? [], total: res.TotalCount };
      }).catch((e: unknown) => {
        warn(e, `zone ${zone.ZoneName ?? zone.ZoneId}`);
        return [];
      });
      return domains.map((d) => {
        const mode = d.Certificate?.Mode;
        // 一个加速域名可挂多张证书（如 RSA + ECC），取最早到期的那张
        const certs = (d.Certificate?.List ?? [])
          .map((c) => ({ c, notAfter: toIso(c.ExpireTime) }))
          .sort((a, b) => (a.notAfter ?? "9999").localeCompare(b.notAfter ?? "9999"));
        const first = certs[0];
        const https = !!mode && mode !== "disable";
        return compact({
          provider: "tencent" as const,
          service: "teo",
          domain: d.DomainName,
          status: d.DomainStatus,
          https,
          cert:
            https && first
              ? compact({ id: first.c.CertId, name: first.c.Alias, notAfter: first.notAfter, status: first.c.Status })
              : undefined,
          extra: compact({ zoneId: zone.ZoneId, zone: zone.ZoneName, certMode: mode }),
        });
      });
    });
    return perZone.flat();
  },
};
