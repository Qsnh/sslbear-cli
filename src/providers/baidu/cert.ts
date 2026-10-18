import { createHash, X509Certificate } from "node:crypto";
import type { LocalCert } from "../../deploy/cert.js";
import { SAME_CERT_TOLERANCE_MS } from "../../deploy/plan.js";
import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, withRetry, type QueryContext } from "../../lib/http.js";
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
  /**
   * 证书指纹，文档未写明格式。实测：GET /v1/certificate/{certId} 返回叶子证书 DER 的 SHA-1（40 位小写 hex、无冒号），
   * /v1/certificate/detail 列表里没有该字段（官方 Go SDK 的列表详情声明了它，仍兼容列表自带的情况）
   */
  certFingerprint?: unknown;
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
async function fetchRaw(ctx: QueryContext, creds: AccessKeyCredentials): Promise<CertDetail[]> {
  const res = await callBce<{ certs?: CertDetail[] | null }>(ctx, creds, { host: HOST, path: "/v1/certificate/detail" });
  return (res.certs ?? []).filter((c) => c.certType !== 2);
}

const toRecord = (c: CertDetail): CertificateRecord =>
  compact({
    provider: "baidu" as const,
    id: c.certId,
    name: c.certName,
    commonName: c.certCommonName,
    sans: splitNames(c.certDNSNames),
    notBefore: toIso(c.certStartTime),
    notAfter: toIso(c.certStopTime),
    status: c.status,
  });

const cached = memo<QueryContext, CertificateRecord[]>();

/** 证书管理的证书列表，同一次命令内（certs 与 CDN 补全）只拉一次 */
export function listBaiduCertificates(ctx: QueryContext, creds: AccessKeyCredentials): Promise<CertificateRecord[]> {
  return cached(ctx, `cert:${creds.accessKeyId}`, async () => (await fetchRaw(ctx, creds)).map(toRecord));
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

/** sslbear-<通用名，* 及不允许的字符换成 _>-<到期日 YYYYMMDD>[-<后缀>]，超长时截断通用名 */
export function baiduCertName(cert: LocalCert, suffix?: string): string {
  const tail = `-${cert.notAfter.slice(0, 10).replace(/-/g, "")}${suffix ? `-${suffix}` : ""}`;
  const cn = (cert.commonName ?? cert.sans[0] ?? "cert").replace(/[^A-Za-z0-9\-/_.]/g, "_");
  return `sslbear-${cn.slice(0, NAME_MAX - "sslbear-".length - tail.length)}${tail}`;
}

/** 证书名可能要求唯一（ResourceNameDuplicated）：依次用默认名、加指纹前 8 位、再加序号，取第一个没被占用的 */
function freeName(cert: LocalCert, taken: ReadonlySet<string>): string {
  const fp = cert.fingerprint.slice(0, 8);
  for (let i = 0; ; i++) {
    const name = baiduCertName(cert, i === 0 ? undefined : i === 1 ? fp : `${fp}-${i}`);
    if (!taken.has(name)) return name;
  }
}

const sameNames = (a: string[], b: string[]) => {
  const x = new Set(a.map((n) => n.toLowerCase()));
  const y = new Set(b.map((n) => n.toLowerCase()));
  return x.size === y.size && [...x].every((n) => y.has(n));
};

/** 十六进制摘要的长度 → 算法 */
const DIGESTS: Record<number, string> = { 32: "md5", 40: "sha1", 64: "sha256" };

/**
 * certFingerprint 的格式文档没有写明：认得出的十六进制摘要（MD5 / SHA-1 / SHA-256，可带冒号、不分大小写）才与叶子证书 DER 的同种摘要比对，
 * 没有或认不出时返回 undefined
 */
function fingerprintMatches(remote: unknown, leafDer: Buffer): boolean | undefined {
  if (typeof remote !== "string") return undefined;
  const hex = remote.replace(/[:\s]/g, "").toLowerCase();
  const algorithm = /^[0-9a-f]+$/.test(hex) ? DIGESTS[hex.length] : undefined;
  if (!algorithm) return undefined;
  return createHash(algorithm).update(leafDer).digest("hex") === hex;
}

/**
 * 证书管理里的同一张证书：只认指纹明确一致的（同一时刻签发的 RSA / ECC 两张证书通用名、SAN、有效期都可能相同，只能靠指纹区分），
 * 拿不到指纹或格式认不出时不算同一张（宁可多传一份）。
 * 列表自带指纹时直接比对；没带的先按「同通用名 + 同 SAN + 到期时间相差 48 小时内」筛出候选，再逐个查证书信息里的指纹。
 */
async function findUploaded(
  ctx: QueryContext,
  creds: AccessKeyCredentials,
  certs: CertDetail[],
  cert: LocalCert,
  leafDer: Buffer,
): Promise<string | undefined> {
  const listed = certs.find((c) => fingerprintMatches(c.certFingerprint, leafDer));
  if (listed) return listed.certId;
  const newMs = Date.parse(cert.notAfter);
  const cn = (cert.commonName ?? "").toLowerCase();
  const candidates = certs.filter(
    (c) =>
      fingerprintMatches(c.certFingerprint, leafDer) === undefined &&
      (c.certCommonName ?? "").toLowerCase() === cn &&
      Math.abs(Date.parse(toIso(c.certStopTime) ?? "") - newMs) <= SAME_CERT_TOLERANCE_MS &&
      sameNames(splitNames(c.certDNSNames) ?? (c.certCommonName ? [c.certCommonName] : []), cert.sans),
  );
  for (const c of candidates) {
    const meta = await callBce<{ certFingerprint?: unknown }>(ctx, creds, { host: HOST, path: `/v1/certificate/${c.certId}` });
    if (fingerprintMatches(meta.certFingerprint, leafDer)) return c.certId;
  }
  return undefined;
}

/** 上传时报重名后换名重传的次数上限（报重名说明证书没建出来，换名重传是安全的） */
const NAME_ATTEMPTS = 3;

/**
 * 上传到证书管理（POST /v1/certificate），叶子证书与中间证书链分开传；已有同一张证书时复用。
 * 上传不幂等，POST 本身只发一次、不自动重试：遇到超时、限流等可重试的错误时整轮重来，先重新拉证书列表（不走缓存）查重，
 * 上一次其实已传成功、且凭指纹认得出时直接复用，认不出就再传一份；总共最多 3 轮。
 * 列表里已有同名证书、或上传时报重名（ResourceNameDuplicated）时，换带指纹后缀的名字。
 * 证书管理解析不了没有通用名的证书（实测 400 CertificateParameterInvalid「Index 0 out of bounds」），这时在错误信息里说明原因。
 */
export async function uploadBaiduCertificate(ctx: QueryContext, creds: AccessKeyCredentials, cert: LocalCert): Promise<{ id: string; reused: boolean }> {
  const [leaf, ...chain] = cert.certPem.match(PEM_CERT) ?? [];
  if (!leaf) throw new CloudApiError("baidu", "InvalidCertificate", "证书内容为空");
  const leafDer = new X509Certificate(leaf).raw;
  return withRetry(ctx, async () => {
    const certs = await fetchRaw(ctx, creds);
    const existing = await findUploaded(ctx, creds, certs, cert, leafDer);
    if (existing) return { id: existing, reused: true };
    const taken = new Set(certs.map((c) => c.certName ?? ""));
    for (let attempt = 1; ; attempt++) {
      const certName = freeName(cert, taken);
      let res: { certId?: string };
      try {
        res = await callBce<{ certId?: string }>(ctx, creds, {
          host: HOST,
          path: "/v1/certificate",
          method: "POST",
          body: {
            certName,
            certServerData: leaf,
            certPrivateData: cert.keyPem.trim(),
            ...(chain.length > 0 && { certLinkData: chain.join("\n") }),
            certType: 1,
          },
          retry: false,
        });
      } catch (e) {
        if (e instanceof CloudApiError && e.code === "CertificateParameterInvalid" && !cert.commonName) {
          throw new CloudApiError(
            "baidu",
            e.code,
            `百度智能云证书管理不接受没有通用名（CN）的证书（如 Let's Encrypt 的短期证书），请改用带通用名的证书；原始信息：${e.message}`,
            e.requestId,
            e.httpStatus,
          );
        }
        if (!(e instanceof CloudApiError && e.code === "ResourceNameDuplicated") || attempt >= NAME_ATTEMPTS) throw e;
        taken.add(certName);
        continue;
      }
      if (!res.certId) throw new CloudApiError("baidu", "InvalidResponse", "上传证书成功但响应里没有证书 ID");
      return { id: res.certId, reused: false };
    }
  });
}
