import { createHash, X509Certificate } from "node:crypto";
import type { LocalCert } from "../../deploy/cert.js";
import { SAME_CERT_TOLERANCE_MS } from "../../deploy/plan.js";
import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { memo } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { CertificateRecord, CertInfo, DomainRecord } from "../../types.js";
import type { Warn } from "../registry.js";
import { callBce } from "./client.js";

const HOST = "certificate.baidubce.com";

interface CertDetail {
  certId: string;
  certName?: string;
  certCommonName?: string;
  /** 英文逗号分隔 */
  certDNSNames?: string;
  /** UTC，如 2014-06-01T23:00:10Z */
  certStartTime?: string;
  certStopTime?: string;
  /** 1 服务端证书，2 客户端证书（双向认证用的 CA） */
  certType?: number;
  /** UNUSED / IN_USE */
  status?: string;
  expired?: boolean;
}

/** 接口偶尔用一串 "-" 占位，不是真实域名 */
function splitNames(s: string | undefined): string[] | undefined {
  const names = (s ?? "")
    .split(",")
    .map((x) => x.trim())
    .filter((x) => x && !/^-+$/.test(x));
  return names.length ? names : undefined;
}

/**
 * 证书管理的证书列表详情（比 /v1/certificate 多了域名与使用状态），接口不分页、一次返回全部。
 * 只保留服务端证书：客户端证书是双向认证用的 CA，不涉及网站证书续期。
 */
async function fetchAll(ctx: QueryContext, creds: AccessKeyCredentials): Promise<CertificateRecord[]> {
  const res = await callBce<{ certs?: CertDetail[] | null }>(ctx, creds, { host: HOST, path: "/v1/certificate/detail" });
  return (res.certs ?? [])
    .filter((c) => c.certType !== 2)
    .map((c) =>
      compact({
        provider: "baidu" as const,
        id: c.certId,
        name: c.certName,
        commonName: c.certCommonName,
        sans: splitNames(c.certDNSNames),
        notBefore: toIso(c.certStartTime),
        notAfter: toIso(c.certStopTime),
        status: c.status,
      }),
    );
}

const cached = memo<QueryContext, CertificateRecord[]>();

/** 证书管理的证书列表，同一次命令内（certs 与 CDN 补全）只拉一次 */
export function listBaiduCertificates(ctx: QueryContext, creds: AccessKeyCredentials): Promise<CertificateRecord[]> {
  return cached(ctx, `cert:${creds.accessKeyId}`, () => fetchAll(ctx, creds));
}

/** CDN 的 BOS 默认域名等场景用平台通用证书，证书管理里查不到，无需补全 */
const COMMON_CERT_ID = "cert-common";

const lookup = (c: CertInfo | undefined) => !!c?.id && c.id !== COMMON_CERT_ID;
const missingExpiry = (c: CertInfo) => lookup(c) && !c.notAfter;
/** CDN 的 HTTPS 域名列表不给通用名与 SAN */
const missingNames = (c: CertInfo) => lookup(c) && !c.commonName;
/** 域名上的全部证书（certs 已包含 cert） */
const certsOf = (r: DomainRecord): CertInfo[] => r.certs ?? (r.cert ? [r.cert] : []);
const needsExpiry = (r: DomainRecord) => certsOf(r).some(missingExpiry);
const needsNames = (r: DomainRecord) => certsOf(r).some(missingNames);

/**
 * 域名接口缺到期时间或通用名 / SAN 时，用证书管理的列表按证书 ID 补全（cert 与 certs 里的每一张）；域名接口给出的有效期不覆盖。
 * 补全失败（如没有证书管理只读权限）时，有域名缺到期时间才记一条 issue，域名本身照常返回。
 */
export async function enrichFromCertService(
  ctx: QueryContext,
  creds: AccessKeyCredentials,
  warn: Warn,
  records: DomainRecord[],
): Promise<DomainRecord[]> {
  const pending = records.filter((r) => needsExpiry(r) || needsNames(r));
  if (pending.length === 0) return records;
  let certs: CertificateRecord[];
  try {
    certs = await listBaiduCertificates(ctx, creds);
  } catch (e) {
    if (pending.some(needsExpiry)) warn(e, "证书管理列表（用于补全到期时间）");
    return records;
  }
  const byId = new Map(certs.map((c) => [c.id, c]));
  const fill = (cert: CertInfo): CertInfo => {
    const c = byId.get(cert.id!);
    if (!lookup(cert) || !c) return cert;
    return compact({
      ...cert,
      name: cert.name ?? c.name,
      commonName: cert.commonName ?? c.commonName,
      sans: cert.sans ?? c.sans,
      notBefore: cert.notBefore ?? c.notBefore,
      notAfter: cert.notAfter ?? c.notAfter,
    });
  };
  for (const r of pending) {
    if (r.cert) r.cert = fill(r.cert);
    if (r.certs) r.certs = r.certs.map(fill);
  }
  return records;
}

const PEM_CERT = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;

/** 证书名限制：以字母开头，只允许字母、数字和 - / _ .，长度 1-65 */
const NAME_MAX = 65;

/** sslbear-<通用名，* 及不允许的字符换成 _>-<到期日 YYYYMMDD>，超长时截断通用名 */
export function baiduCertName(cert: LocalCert): string {
  const date = cert.notAfter.slice(0, 10).replace(/-/g, "");
  const cn = (cert.commonName ?? cert.sans[0] ?? "cert").replace(/[^A-Za-z0-9\-/_.]/g, "_");
  const room = NAME_MAX - "sslbear-".length - 1 - date.length;
  return `sslbear-${cn.slice(0, room)}-${date}`;
}

const sameNames = (a: string[], b: string[]) => {
  const x = new Set(a.map((n) => n.toLowerCase()));
  const y = new Set(b.map((n) => n.toLowerCase()));
  return x.size === y.size && [...x].every((n) => y.has(n));
};

/**
 * 证书管理的 certFingerprint 格式文档没有写明：认得出的十六进制摘要（SHA-1 / SHA-256，可带冒号）才比对叶子证书 DER，
 * 认不出或没有时返回 undefined。
 */
function fingerprintMatches(remote: unknown, leafPem: string): boolean | undefined {
  if (typeof remote !== "string") return undefined;
  const hex = remote.replace(/[:\s]/g, "").toLowerCase();
  const algorithm = /^[0-9a-f]{40}$/.test(hex) ? "sha1" : /^[0-9a-f]{64}$/.test(hex) ? "sha256" : undefined;
  if (!algorithm) return undefined;
  return createHash(algorithm).update(new X509Certificate(leafPem).raw).digest("hex") === hex;
}

/**
 * 证书管理里的同一张证书：列表不给指纹，先按「同通用名 + 同 SAN + 到期时间相差 48 小时内」筛出候选，
 * 再逐个查证书信息里的指纹确认（同一时刻签发的 RSA / ECC 两张证书前三项完全相同，要靠指纹区分）；
 * 指纹一致的优先，指纹认不出的候选次之，指纹明确不一致的不算。
 */
async function findUploaded(ctx: QueryContext, creds: AccessKeyCredentials, cert: LocalCert, leafPem: string): Promise<string | undefined> {
  const newMs = Date.parse(cert.notAfter);
  const cn = (cert.commonName ?? "").toLowerCase();
  const candidates = (await listBaiduCertificates(ctx, creds)).filter(
    (c) =>
      (c.commonName ?? "").toLowerCase() === cn &&
      Math.abs(Date.parse(c.notAfter ?? "") - newMs) <= SAME_CERT_TOLERANCE_MS &&
      sameNames(c.sans ?? (c.commonName ? [c.commonName] : []), cert.sans),
  );
  let unverified: string | undefined;
  for (const c of candidates) {
    const meta = await callBce<{ certFingerprint?: unknown }>(ctx, creds, { host: HOST, path: `/v1/certificate/${c.id}` });
    const same = fingerprintMatches(meta.certFingerprint, leafPem);
    if (same) return c.id;
    if (same === undefined) unverified ??= c.id;
  }
  return unverified;
}

/** 上传到证书管理（POST /v1/certificate），叶子证书与中间证书链分开传；已有同一张证书时复用 */
export async function uploadBaiduCertificate(ctx: QueryContext, creds: AccessKeyCredentials, cert: LocalCert): Promise<{ id: string; reused: boolean }> {
  const [leaf, ...chain] = cert.certPem.match(PEM_CERT) ?? [];
  if (!leaf) throw new CloudApiError("baidu", "InvalidCertificate", "证书内容为空");
  const existing = await findUploaded(ctx, creds, cert, leaf);
  if (existing) return { id: existing, reused: true };
  const res = await callBce<{ certId?: string }>(ctx, creds, {
    host: HOST,
    path: "/v1/certificate",
    method: "POST",
    body: {
      certName: baiduCertName(cert),
      certServerData: leaf,
      certPrivateData: cert.keyPem.trim(),
      ...(chain.length > 0 && { certLinkData: chain.join("\n") }),
      certType: 1,
    },
  });
  if (!res.certId) throw new CloudApiError("baidu", "InvalidResponse", "上传证书成功但响应里没有证书 ID");
  return { id: res.certId, reused: false };
}
