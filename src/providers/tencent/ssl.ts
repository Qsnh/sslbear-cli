import type { LocalCert } from "../../deploy/cert.js";
import type { TencentCredentials } from "../../lib/env.js";
import { CloudApiError, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { memo, paginate } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { CertInfo, CertificateRecord, DomainRecord } from "../../types.js";
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
  /** 如 "RSA 2048"、"ECC 256" */
  EncryptAlgorithm?: string;
  IsSM?: boolean;
}

const ALGORITHMS: Record<string, CertInfo["algorithm"]> = { RSA: "RSA", ECC: "ECC", EC: "ECC", ECDSA: "ECC", SM2: "SM2" };

function algorithmOf(c: SslCertificate): CertInfo["algorithm"] {
  if (c.IsSM) return "SM2";
  return ALGORITHMS[(c.EncryptAlgorithm ?? "").trim().split(/\s+/)[0]!.toUpperCase()];
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
      algorithm: algorithmOf(c),
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
 * 按 ID 索引的 SSL 证书；拉取失败（如没有 SSL 只读权限）返回 undefined，给了 warn 时（有证书缺到期时间要靠它补）记一条 issue
 */
export async function sslCertsById(
  ctx: QueryContext,
  creds: TencentCredentials,
  warn?: Warn,
): Promise<Map<string, CertificateRecord> | undefined> {
  try {
    const certs = await listSslCertificates(ctx, creds);
    return new Map(certs.map((c) => [c.id, c]));
  } catch (e) {
    warn?.(e, "SSL 证书列表（用于补全到期时间）");
    return undefined;
  }
}

const needsExpiry = (r: DomainRecord) => !!r.cert?.id && !r.cert.notAfter;

/**
 * 各服务的证书配置只给证书 ID 和部分信息（点播、COS 没有证书名，CDN、直播没有 SAN、签发时间和算法），用 SSL 证书列表
 * 按 ID 补全；服务给出的字段不覆盖（preferSslName 时证书名以 SSL 列表为准）。SAN、签发时间、算法是部署时区分
 * 「到期时间相近的另一张证书」要用的，所以有证书 ID 的都补。
 * 补全失败（如没有 SSL 只读权限）时，有域名缺到期时间才记一条 issue（其他字段不影响到期判断），域名本身照常返回。
 */
export async function enrichFromSsl(
  ctx: QueryContext,
  creds: TencentCredentials,
  warn: Warn,
  records: DomainRecord[],
  opts: { preferSslName?: boolean } = {},
): Promise<DomainRecord[]> {
  const pending = records.filter((r) => !!r.cert?.id);
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
      name: opts.preferSslName ? (c.name ?? cert.name) : (cert.name ?? c.name),
      commonName: cert.commonName ?? c.commonName,
      sans: cert.sans ?? c.sans,
      notBefore: cert.notBefore ?? c.notBefore,
      notAfter: cert.notAfter ?? c.notAfter,
      status: cert.status ?? c.status,
      algorithm: cert.algorithm ?? c.algorithm,
    });
  }
  return records;
}

/**
 * 实测（2026-10）腾讯云 CDN、COS、点播不接受没有通用名（CN）的证书（如 Let's Encrypt 短期证书，subject 为空、只有 SAN），
 * 报错却不直说：CDN 报 FailedOperation.CdnConfigError「Https证书内容非法」，COS 报 InvalidDomainCertificate，
 * 点播只报 FailedOperation。证书没有 CN 且报的是这几种错误时在报错里补上原因（错误码、RequestId 不变）。直播照常接受。
 */
export async function explainMissingCn<T>(cert: LocalCert, product: string, codes: readonly string[], fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    if (cert.commonName || !(e instanceof CloudApiError) || !codes.includes(e.code)) throw e;
    const hint = `该证书没有通用名 CN，实测腾讯云${product}不接受这类证书（如 Let's Encrypt 短期证书），请改用带 CN 的证书`;
    throw new CloudApiError(e.provider, e.code, `${e.message}（${hint}）`, e.requestId, e.httpStatus);
  }
}

/** 上传后在 SSL 证书列表里的备注名：sslbear-<CN，* 换成 _>-<到期日 YYYYMMDD（UTC）> */
export function certAlias(cert: LocalCert): string {
  const name = (cert.commonName ?? cert.sans[0] ?? "cert").replace(/\*/g, "_");
  return `sslbear-${name}-${cert.notAfter.slice(0, 10).replace(/-/g, "")}`;
}

/**
 * 上传证书到 SSL 证书服务。Repeatable=false 时服务端按指纹查重：已有同一张证书则不新建，直接返回已有证书的 ID，
 * 查重以指纹为准，只会复用确定的同一张证书；callTencent 超时 / 限流后原样重发也不会重复建证书。
 * 文档说重复时 ID 放在 RepeatCertId，实测（2026-10）RepeatCertId 为空、CertificateId 直接就是已有证书的 ID，
 * 所以是否复用按上传前的证书列表判断（查询阶段补全证书信息时多半已拉过，同一次命令内只拉一次）；
 * 列表拉取失败（如没有 SSL 只读权限）时无法判断，按新上传报告。
 */
export async function uploadSslCertificate(
  ctx: QueryContext,
  creds: TencentCredentials,
  cert: LocalCert,
): Promise<{ id: string; reused: boolean }> {
  const existing = await listSslCertificates(ctx, creds).then(
    (certs) => new Set(certs.map((c) => c.id)),
    () => undefined,
  );
  const res = await callTencent<{ CertificateId?: string | null; RepeatCertId?: string | null; RequestId?: string }>(ctx, creds, {
    service: "ssl",
    version: "2019-12-05",
    action: "UploadCertificate",
    payload: {
      CertificatePublicKey: cert.certPem,
      CertificatePrivateKey: cert.keyPem,
      CertificateType: "SVR",
      Alias: certAlias(cert),
      Repeatable: false,
    },
  });
  if (res.RepeatCertId) return { id: res.RepeatCertId, reused: true };
  if (res.CertificateId) return { id: res.CertificateId, reused: existing?.has(res.CertificateId) ?? false };
  throw new CloudApiError("tencent", "InvalidResponse", "上传证书的响应里没有证书 ID", res.RequestId);
}
