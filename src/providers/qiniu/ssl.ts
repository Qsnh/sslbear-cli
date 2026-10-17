import type { AccessKeyCredentials } from "../../lib/env.js";
import type { QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { memo } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { CertificateRecord, DomainRecord } from "../../types.js";
import type { Warn } from "../registry.js";
import { FUSION_HOST, listByMarker, qiniuGet } from "./client.js";

interface SslCert {
  certid: string;
  name?: string;
  common_name?: string;
  dnsnames?: string[] | null;
  /** Unix 秒 */
  not_before?: number;
  not_after?: number;
}

// 文档未写 limit 上限（默认 10）；取完以 marker 为准，不依赖 limit
const PAGE = 100;

const unixToIso = (v: number | undefined) => (v ? toIso(v) : undefined);

async function fetchAll(ctx: QueryContext, creds: AccessKeyCredentials): Promise<CertificateRecord[]> {
  const list = await listByMarker(PAGE, async (query) => {
    const res = await qiniuGet<{ certs?: SslCert[] | null; marker?: string }>(ctx, creds, FUSION_HOST, `/sslcert?${query}`);
    return { items: res.certs ?? [], marker: res.marker };
  });
  return list.map((c) =>
    compact({
      provider: "qiniu" as const,
      id: c.certid,
      name: c.name,
      commonName: c.common_name,
      sans: c.dnsnames ?? undefined,
      notBefore: unixToIso(c.not_before),
      notAfter: unixToIso(c.not_after),
    }),
  );
}

const cached = memo<QueryContext, CertificateRecord[]>();

/** SSL 证书列表（CDN 与 SSL 证书服务共用），同一次命令内（certs 与 CDN 补全）只拉一次 */
export function listSslCertificates(ctx: QueryContext, creds: AccessKeyCredentials): Promise<CertificateRecord[]> {
  return cached(ctx, `sslcert:${creds.accessKeyId}`, () => fetchAll(ctx, creds));
}

/**
 * 域名详情只给证书 ID，用证书列表按 ID 补全名称与有效期（不逐个查证书详情：详情接口会返回私钥）。
 * 补全失败只记一条 issue，域名本身照常返回。
 */
export async function enrichFromSsl(
  ctx: QueryContext,
  creds: AccessKeyCredentials,
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
    r.cert = compact({ ...r.cert, name: c.name, commonName: c.commonName, sans: c.sans, notBefore: c.notBefore, notAfter: c.notAfter });
  }
  return records;
}
