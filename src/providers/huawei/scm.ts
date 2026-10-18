import { X509Certificate } from "node:crypto";
import type { LocalCert } from "../../deploy/cert.js";
import { SAME_CERT_TOLERANCE_MS } from "../../deploy/plan.js";
import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { memo, paginate } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { CertInfo, CertificateRecord, DomainRecord } from "../../types.js";
import type { Warn } from "../registry.js";
import { callHuawei } from "./client.js";
import { certName } from "./common.js";

/** 云证书管理服务 CCM（原 SCM）的 SSL 证书接口是全局服务，中国站统一走北京四 */
const SCM_HOST = "scm.cn-north-4.myhuaweicloud.com";
/** limit 只能取 10 / 20 / 50 */
const PAGE = 50;

interface ScmCertificate {
  id: string;
  name?: string;
  domain?: string;
  /** 附加域名（不含 domain），分号分隔，如 "a.example.com;b.example.com"；没有时为 null */
  sans?: string;
  type?: string;
  brand?: string;
  /** "2021-05-27 16:46:25.0"，不带时区，实测为北京时间（证书 notAfter 13:09:53Z 返回 "21:09:53.0"） */
  expire_time?: string;
  /** ISSUED / EXPIRED / UPLOAD（上传托管的证书）等 */
  status?: string;
}

// 文档未注明时区，实测为北京时间；toIso 不认小数秒，先去掉
const scmTime = (s: string | undefined) => toIso(s?.replace(/\.\d+$/, ""));

async function fetchAll(ctx: QueryContext, creds: AccessKeyCredentials): Promise<CertificateRecord[]> {
  const list = await paginate(PAGE, async (_page, offset) => {
    const res = await callHuawei<{ certificates?: ScmCertificate[] | null; total_count?: number }>(ctx, creds, {
      host: SCM_HOST,
      path: "/v3/scm/certificates",
      // offset 为条目偏移（同服务 ListCertificatesByTag 文档写明「从 offset 指定的下一条数据开始」）；
      // expired_days_since 按文档是「有效期内及最多过期 xx 天」、缺省 0，取最大值 1095，让已过期但仍绑定着的证书也能列出和补全
      query: { limit: PAGE, offset, expired_days_since: 1095 },
    });
    return { items: res.certificates ?? [], total: res.total_count };
  });
  return list.map((c) =>
    compact({
      provider: "huawei" as const,
      id: c.id,
      name: c.name,
      commonName: c.domain,
      // sans 只是「附加域名」，不含主域名；与证书本身的 SAN 扩展（及其它厂商的输出）保持一致，把主域名放在最前面
      sans: [...new Set([c.domain ?? "", ...(c.sans ?? "").split(/[;,]/)].map((s) => s.trim()).filter(Boolean))],
      issuer: c.brand,
      notAfter: scmTime(c.expire_time),
      status: c.status,
      source: c.status === "UPLOAD" ? "upload" : c.type,
    }),
  );
}

const cached = memo<QueryContext, CertificateRecord[]>();

/** SSL 证书列表，同一次命令内（certs 与各服务补全）只拉一次 */
export function listScmCertificates(ctx: QueryContext, creds: AccessKeyCredentials): Promise<CertificateRecord[]> {
  return cached(ctx, `scm:${creds.accessKeyId}`, () => fetchAll(ctx, creds));
}

const needsExpiry = (c: CertInfo | undefined) => !!c?.id && !c.notAfter;
/** 绑定的是 CCM 证书（ID 形如 scs1765868588104；OBS 自有证书自动生成的是 32 位十六进制 ID）但缺通用名，如 OBS 自定义域名 */
const needsNames = (c: CertInfo | undefined) => !!c?.id && /^scs\d+$/.test(c.id) && !c.commonName;
const certsOf = (r: DomainRecord) => [r.cert, ...(r.certs ?? [])];

/**
 * 域名接口只给了证书 ID、缺到期时间（或缺 CN / SAN）时，用 SSL 证书列表按 ID 补全（cert 与 certs 里的每一张）；已有的字段不覆盖。
 * 补全失败（如没有 SCM 只读权限）时，有域名缺到期时间才记一条 issue，域名本身照常返回。
 */
export async function enrichFromScm(
  ctx: QueryContext,
  creds: AccessKeyCredentials,
  warn: Warn,
  records: DomainRecord[],
): Promise<DomainRecord[]> {
  const pending = records.filter((r) => certsOf(r).some((c) => needsExpiry(c) || needsNames(c)));
  if (pending.length === 0) return records;
  let certs: CertificateRecord[];
  try {
    certs = await listScmCertificates(ctx, creds);
  } catch (e) {
    if (pending.some((r) => certsOf(r).some(needsExpiry))) warn(e, "SSL 证书列表（用于补全到期时间）");
    return records;
  }
  const byId = new Map(certs.map((c) => [c.id, c]));
  const fill = (cert: CertInfo): CertInfo => {
    const c = cert.id ? byId.get(cert.id) : undefined;
    if (!c) return cert;
    return compact({
      ...cert,
      name: cert.name ?? c.name,
      commonName: cert.commonName ?? c.commonName,
      sans: cert.sans ?? c.sans,
      issuer: cert.issuer ?? c.issuer,
      notAfter: cert.notAfter ?? c.notAfter,
      status: cert.status ?? c.status,
    });
  };
  for (const r of pending) {
    if (r.cert) r.cert = fill(r.cert);
    if (r.certs) r.certs = r.certs.map(fill);
  }
  return records;
}

const PEM_CERT = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;

const nameSet = (names: (string | undefined)[]) => [...new Set(names.filter((n): n is string => !!n).map((n) => n.toLowerCase()))].sort().join(",");

/** 列表不给指纹 / 序列号，先按 CN + 全部域名 + 到期时间（容差同决策表）筛出候选 */
function isCandidate(c: CertificateRecord, cert: LocalCert): boolean {
  if (cert.commonName && c.commonName?.toLowerCase() !== cert.commonName.toLowerCase()) return false;
  if (nameSet(c.sans ?? [c.commonName]) !== nameSet([cert.commonName, ...cert.sans])) return false;
  const at = Date.parse(c.notAfter ?? "");
  return Number.isFinite(at) && Math.abs(at - Date.parse(cert.notAfter)) <= SAME_CERT_TOLERANCE_MS;
}

/**
 * 上传到云证书管理服务（ImportCertificate）。先查重：列表里 CN、域名、到期时间都相同的候选，
 * 再用证书详情（ShowCertificate）的 SHA-1 指纹确认是同一张；详情不给指纹时按候选条件复用。
 * certificate 字段上限 4096 字符，叶子 + 中间证书容易超出，所以证书链单独放 certificate_chain（上限 8192）。
 */
export async function uploadScmCertificate(ctx: QueryContext, creds: AccessKeyCredentials, cert: LocalCert): Promise<{ id: string; reused: boolean }> {
  const [leaf, ...chain] = cert.certPem.match(PEM_CERT) ?? [];
  const sha1 = new X509Certificate(leaf!).fingerprint.replace(/:/g, "").toLowerCase();
  const listed = await listScmCertificates(ctx, creds);
  for (const c of listed.filter((x) => isCandidate(x, cert))) {
    const detail = await callHuawei<{ fingerprint?: string | null }>(ctx, creds, { host: SCM_HOST, path: `/v3/scm/certificates/${c.id}` });
    const fingerprint = detail.fingerprint?.replace(/:/g, "").toLowerCase();
    if (!fingerprint || fingerprint === sha1) return { id: c.id, reused: true };
  }
  const res = await callHuawei<{ certificate_id?: string }>(ctx, creds, {
    host: SCM_HOST,
    path: "/v3/scm/certificates/import",
    method: "POST",
    body: {
      name: certName(cert),
      certificate: `${leaf}\n`,
      ...(chain.length > 0 && { certificate_chain: `${chain.join("\n")}\n` }),
      private_key: cert.keyPem,
      // 已自行查重；交给服务端查重的话，重复时的报错码文档没写
      duplicate_check: false,
    },
  });
  if (!res.certificate_id) throw new CloudApiError("huawei", "InvalidResponse", "导入证书成功但未返回证书 ID");
  return { id: res.certificate_id, reused: false };
}
