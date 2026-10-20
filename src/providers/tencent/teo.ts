import { pickOldCert } from "../../deploy/plan.js";
import type { TencentCredentials } from "../../lib/env.js";
import { CloudApiError, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import type { CertInfo, DomainRecord } from "../../types.js";
import type { Deployer, DomainService, Warn } from "../registry.js";
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

/** SignAlgo 形如 "RSA 2048"、"ECC 256"，按关键字归一 */
function algorithmOf(signAlgo: string | undefined): CertInfo["algorithm"] {
  const s = signAlgo?.toUpperCase() ?? "";
  if (s.includes("SM2")) return "SM2";
  if (s.includes("RSA")) return "RSA";
  if (s.includes("EC")) return "ECC";
  return undefined;
}

const certsOf = (r: DomainRecord): CertInfo[] => r.certs ?? (r.cert ? [r.cert] : []);

/**
 * 域名还在部署上一次的变更时 ModifyHostsCertificate 报的错：实测（2026-10）新建的域名处于 process 时报
 * ResourceInUse「四层转发代理变更中，请等待变更完成后重试。」；ActionInProgress 文档写的是「操作频繁，请稍后重试」
 */
const BUSY = new Set(["ResourceInUse", "InvalidParameter.ActionInProgress"]);

/**
 * ModifyHostsCertificate 的 ServerCertInfo 是该域名的完整证书列表（RSA + ECC 可各挂一张）：
 * sslcert 模式下保留与新证书不同算法的那张（含国密），替换同算法的；免费证书模式下整体换成新证书。
 * ClientCertInfo / UpstreamCertInfo 不传即保持原有配置。域名还在部署上一次的变更时报 DomainBusy，编排层按可重试处理。
 */
const deployer: Deployer<TencentCredentials> = {
  unsupported(record, mode) {
    const certs = certsOf(record);
    if (mode === "update" && certs.length > 1 && certs.some((c) => !c.algorithm)) {
      return "该域名挂了多张证书，但查不到每张证书的算法，无法判断该替换哪一张；请在 EdgeOne 控制台手动更换";
    }
    return undefined;
  },
  async apply(ctx, creds, target, input) {
    const record = target.records[0]!;
    const zoneId = record.extra?.zoneId;
    if (!zoneId) throw new CloudApiError("tencent", "MissingZoneId", `EdgeOne 域名 ${record.domain} 缺少站点 ID`);
    const certId = await input.certId();
    const old = pickOldCert(record, input.cert.algorithm);
    const keep =
      target.mode === "update" && record.extra?.certMode === "sslcert"
        ? certsOf(record).filter((c) => c !== old && c.id && c.id !== certId && c.algorithm !== input.cert.algorithm)
        : [];
    await call(ctx, creds, "ModifyHostsCertificate", {
      ZoneId: zoneId,
      Hosts: [record.domain],
      Mode: "sslcert",
      ServerCertInfo: [...keep.map((c) => ({ CertId: c.id })), { CertId: certId }],
    }).catch((e: unknown) => {
      if (!(e instanceof CloudApiError) || !BUSY.has(e.code)) throw e;
      const message = `该域名上一次的配置变更还在部署中，未做修改；稍后重新执行即可（${e.message.replace(/[。.]$/, "")}，${e.code}）`;
      throw new CloudApiError(e.provider, "DomainBusy", message, e.requestId, e.httpStatus);
    });
    return { certId };
  },
};

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
    // 证书列表的 ExpireTime 可能缺失（官方示例里 List 只有 CertId），也没有 SAN、签发时间（部署时区分到期时间相近的另一张证书要用），
    // 按 ID 从 SSL 证书列表补，整个命令只拉一次
    const withCerts = all.filter(([, d]) => httpsOf(d) && d.Certificate?.List?.some((c) => c.CertId));
    const missingExpiry = withCerts.some(([, d]) => d.Certificate!.List!.some((c) => c.CertId && !c.ExpireTime));
    const ssl = withCerts.length ? await sslCertsById(ctx, creds, missingExpiry ? warn : undefined) : undefined;
    return all.map(([zone, d]) => {
      const mode = d.Certificate?.Mode;
      // 一个加速域名可挂多张证书（如 RSA + ECC）：cert 取最早到期的那张，certs 列出全部并标出算法
      const certs = (d.Certificate?.List ?? [])
        .map((c): CertInfo => {
          const s = c.CertId ? ssl?.get(c.CertId) : undefined;
          return compact({
            id: c.CertId,
            name: c.Alias ?? s?.name,
            commonName: s?.commonName,
            sans: s?.sans,
            notBefore: s?.notBefore,
            notAfter: toIso(c.ExpireTime) ?? s?.notAfter,
            status: c.Status,
            algorithm: algorithmOf(c.SignAlgo) ?? s?.algorithm,
          });
        })
        .sort((a, b) => (a.notAfter ?? "9999").localeCompare(b.notAfter ?? "9999"));
      const https = httpsOf(d);
      return compact({
        provider: "tencent" as const,
        service: "teo",
        domain: d.DomainName,
        status: d.DomainStatus,
        https,
        cert: https ? certs[0] : undefined,
        certs: https && certs.length > 1 ? certs : undefined,
        extra: compact({ zoneId: zone.ZoneId, zone: zone.ZoneName, certMode: mode }),
      });
    });
  },
  deployer,
};
