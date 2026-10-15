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

/**
 * 有些服务只返回证书 ID 而缺到期时间等信息，用 SSL 证书列表按 ID 补全。
 * 补全失败（如没有 SSL 只读权限）只记一条 issue，域名本身照常返回。
 */
export async function enrichFromSsl(
  ctx: QueryContext,
  creds: TencentCredentials,
  warn: Warn,
  records: DomainRecord[],
): Promise<DomainRecord[]> {
  const pending = records.filter((r) => r.cert?.id && !r.cert.notAfter);
  if (pending.length === 0) return records;
  let certs: CertificateRecord[];
  try {
    certs = await listSslCertificates(ctx, creds);
  } catch (e) {
    warn(e, "SSL 证书列表（用于补全到期时间）");
    return records;
  }
  const byId = new Map(certs.map((c) => [c.id, c]));
  for (const r of pending) {
    const c = byId.get(r.cert!.id!);
    if (!c) continue;
    r.cert = compact({ ...r.cert, name: r.cert!.name ?? c.name, commonName: c.commonName, sans: c.sans, notBefore: c.notBefore, notAfter: c.notAfter, status: r.cert!.status ?? c.status });
  }
  return records;
}
