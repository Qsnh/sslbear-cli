import type { TencentCredentials } from "../../lib/env.js";
import type { QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { memo, paginate } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { CertificateRecord, DomainRecord } from "../../types.js";
import type { Warn } from "../registry.js";
import { callTencent } from "./client.js";

interface SslCertificate {
  CertificateId: string;
  Alias?: string;
  Domain?: string;
  SubjectAltName?: string[] | null;
  /** 北京时间 "YYYY-MM-DD HH:mm:ss" */
  CertBeginTime?: string;
  CertEndTime?: string;
  Status?: number;
  StatusName?: string;
  From?: string;
  ProductZhName?: string;
}

const PAGE = 1000;

async function fetchAll(ctx: QueryContext, creds: TencentCredentials): Promise<CertificateRecord[]> {
  const list = await paginate(PAGE, async (_page, offset) => {
    const res = await callTencent<{ Certificates?: SslCertificate[] | null; TotalCount?: number }>(ctx, creds, {
      service: "ssl",
      version: "2019-12-05",
      action: "DescribeCertificates",
      payload: { Offset: offset, Limit: PAGE, CertificateType: "SVR" },
    });
    return { items: res.Certificates ?? [], total: res.TotalCount };
  });
  return list.map((c) =>
    compact({
      provider: "tencent" as const,
      id: c.CertificateId,
      name: c.Alias,
      commonName: c.Domain,
      sans: c.SubjectAltName ?? undefined,
      issuer: c.ProductZhName,
      notBefore: toIso(c.CertBeginTime),
      notAfter: toIso(c.CertEndTime),
      status: c.StatusName ?? (c.Status === undefined ? undefined : String(c.Status)),
      source: c.From,
    }),
  );
}

const cached = memo<QueryContext, CertificateRecord[]>();

/** SSL 证书列表，同一次命令内（certs 与各服务补全）只拉一次 */
export function listSslCertificates(ctx: QueryContext, creds: TencentCredentials): Promise<CertificateRecord[]> {
  return cached(ctx, `ssl:${creds.secretId}`, () => fetchAll(ctx, creds));
}

/** 按 ID 索引的 SSL 证书；拉取失败（如没有 SSL 只读权限）只记一条 issue 并返回 undefined */
export async function sslCertsById(
  ctx: QueryContext,
  creds: TencentCredentials,
  warn: Warn,
): Promise<Map<string, CertificateRecord> | undefined> {
  try {
    const certs = await listSslCertificates(ctx, creds);
    return new Map(certs.map((c) => [c.id, c]));
  } catch (e) {
    warn(e, "SSL 证书列表（用于补全到期时间）");
    return undefined;
  }
}

const needsExpiry = (r: DomainRecord) => !!r.cert?.id && !r.cert.notAfter;
/** 点播、COS 的证书配置只有 ID（和到期时间），没有证书名，表格里只能显示 ID */
const needsName = (r: DomainRecord) => !!r.cert?.id && !r.cert.name;

/**
 * 有些服务只返回证书 ID 而缺到期时间、证书名等信息，用 SSL 证书列表按 ID 补全；服务给出的字段不覆盖。
 * 补全失败（如没有 SSL 只读权限）时，有域名缺到期时间才记一条 issue（只缺证书名不影响到期判断），域名本身照常返回。
 */
export async function enrichFromSsl(
  ctx: QueryContext,
  creds: TencentCredentials,
  warn: Warn,
  records: DomainRecord[],
): Promise<DomainRecord[]> {
  const pending = records.filter((r) => needsExpiry(r) || needsName(r));
  if (pending.length === 0) return records;
  let certs: CertificateRecord[];
  try {
    certs = await listSslCertificates(ctx, creds);
  } catch (e) {
    if (pending.some(needsExpiry)) warn(e, "SSL 证书列表（用于补全到期时间）");
    return records;
  }
  const byId = new Map(certs.map((c) => [c.id, c]));
  for (const r of pending) {
    const c = byId.get(r.cert!.id!);
    if (!c) continue;
    const cert = r.cert!;
    r.cert = compact({
      ...cert,
      name: cert.name ?? c.name,
      commonName: cert.commonName ?? c.commonName,
      sans: cert.sans ?? c.sans,
      notBefore: cert.notBefore ?? c.notBefore,
      notAfter: cert.notAfter ?? c.notAfter,
      status: cert.status ?? c.status,
    });
  }
  return records;
}
