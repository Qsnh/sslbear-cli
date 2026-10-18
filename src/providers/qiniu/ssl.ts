import type { LocalCert } from "../../deploy/cert.js";
import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, withRetry, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { memo } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { CertificateRecord, DomainRecord } from "../../types.js";
import type { Warn } from "../registry.js";
import { FUSION_HOST, listByMarker, qiniuGet, qiniuRequest } from "./client.js";

/** 列表还有 uid、create_time、product_type（single / multiple_wildcard 等）、enable、state 等字段，未使用 */
interface SslCert {
  certid: string;
  name?: string;
  common_name?: string;
  dnsnames?: string[] | null;
  /** Unix 秒（UTC） */
  not_before?: number;
  not_after?: number;
  /** 密钥算法：RSA / ECDSA */
  encrypt?: string;
}

// 文档未写 limit 上限（默认 10）；marker 是偏移量，取完以空页为准，不依赖 limit
const PAGE = 100;

const unixToIso = (v: number | undefined) => (v ? toIso(v) : undefined);

function fetchRaw(ctx: QueryContext, creds: AccessKeyCredentials): Promise<SslCert[]> {
  return listByMarker(PAGE, async (query) => {
    const res = await qiniuGet<{ certs?: SslCert[] | null; marker?: string }>(ctx, creds, FUSION_HOST, `/sslcert?${query}`);
    return { items: res.certs ?? [], marker: res.marker };
  });
}

/** 证书列表的 encrypt：RSA / ECDSA（实测 ECC 证书为 ECDSA） */
const ALGORITHMS: Record<string, LocalCert["algorithm"]> = { RSA: "RSA", ECDSA: "ECC", ECC: "ECC", EC: "ECC" };

async function fetchAll(ctx: QueryContext, creds: AccessKeyCredentials): Promise<CertificateRecord[]> {
  const list = await fetchRaw(ctx, creds);
  return list.map((c) =>
    compact({
      provider: "qiniu" as const,
      id: c.certid,
      name: c.name,
      commonName: c.common_name,
      sans: c.dnsnames ?? undefined,
      notBefore: unixToIso(c.not_before),
      notAfter: unixToIso(c.not_after),
      algorithm: ALGORITHMS[(c.encrypt ?? "").toUpperCase()],
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
    r.cert = compact({ ...r.cert, name: c.name, commonName: c.commonName, sans: c.sans, notBefore: c.notBefore, notAfter: c.notAfter, algorithm: c.algorithm });
  }
  return records;
}

// 七牛文档没写证书名的长度上限，保守取 64
const NAME_MAX = 64;

/** 证书名 sslbear-<CN，* 换成 _>-<到期日 YYYYMMDD>，超长时截短 CN 部分；没有 CN 时用第一个 SAN */
function certName(cert: LocalCert): string {
  const suffix = `-${cert.notAfter.slice(0, 10).replace(/-/g, "")}`;
  const cn = (cert.commonName ?? cert.sans[0] ?? "cert").replace(/\*/g, "_");
  return `sslbear-${cn}`.slice(0, NAME_MAX - suffix.length) + suffix;
}

const toUnix = (iso: string) => Math.floor(Date.parse(iso) / 1000);

/**
 * 证书列表不给指纹 / 序列号，按「同算法 + 同起止时间（秒）+ 同 CN + 同 SAN」认定同一张证书。
 * 不用「到期时间相差 48 小时内」：同一批签发的 RSA / ECC 证书 CN、SAN 相同、到期只差几秒，放宽会复用到另一把私钥的证书。
 * 列表没给算法时不认作同一张（宁可多传一份）。
 */
function isSameCert(c: SslCert, cert: LocalCert): boolean {
  if (ALGORITHMS[(c.encrypt ?? "").toUpperCase()] !== cert.algorithm) return false;
  if (c.not_before !== toUnix(cert.notBefore) || c.not_after !== toUnix(cert.notAfter)) return false;
  const cn = c.common_name?.toLowerCase();
  if (cert.commonName && cn !== cert.commonName.toLowerCase()) return false;
  // 没有 SAN 的证书七牛可能不给 dnsnames，这时按 CN 比
  const names = new Set((c.dnsnames?.length ? c.dnsnames : cn ? [cn] : []).map((n) => n.toLowerCase()));
  const local = new Set(cert.sans);
  return names.size === local.size && [...local].every((n) => names.has(n));
}

/**
 * 上传证书到七牛 SSL 证书服务（POST fusion /sslcert，QBox 鉴权，私钥与证书链放在 JSON 请求体里）。
 * 上传接口非幂等：超时等可重试的错误整体重来，每次都重新拉证书列表查重（不用缓存），
 * 上一次其实已传成功时直接复用，不会传出两份。
 */
export function uploadSslCertificate(ctx: QueryContext, creds: AccessKeyCredentials, cert: LocalCert): Promise<{ id: string; reused: boolean }> {
  return withRetry(ctx, async () => {
    const same = (await fetchRaw(ctx, creds)).find((c) => isSameCert(c, cert));
    if (same) return { id: same.certid, reused: true };
    const res = await qiniuRequest<{ certID?: string; certid?: string }>(ctx, creds, FUSION_HOST, "/sslcert", {
      method: "POST",
      body: { name: certName(cert), common_name: cert.commonName ?? cert.sans[0], pri: cert.keyPem, ca: cert.certPem },
      retry: false,
    });
    const id = res.certID ?? res.certid;
    if (!id) throw new CloudApiError("qiniu", "InvalidResponse", "上传证书的响应里没有证书 ID（certID）");
    return { id, reused: false };
  });
}
