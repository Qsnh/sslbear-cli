import type { LocalCert } from "../../deploy/cert.js";
import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { memo, paginate } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { CertInfo, CertificateRecord, DomainRecord } from "../../types.js";
import type { Warn } from "../registry.js";
import { callVolc } from "./client.js";
import { certName, keyAlgorithm } from "./common.js";

interface CertInstance {
  InstanceId: string;
  /** 证书备注，未填时为「未命名证书」 */
  Tag?: string;
  CommonName?: string;
  San?: string[] | null;
  Issuer?: string;
  /** 北京时间 "YYYY-MM-DD HH:mm:ss"；尚未签发的订单为空 */
  NotBefore?: string;
  NotAfter?: string;
  /** NotSubmitted / Pending / Issued / Revoked / Canceled / Failed 等 */
  Status?: string;
  /** Free / Test / Paid / Imported */
  InstanceType?: string;
  /** 如 "RSA 2048" */
  CertificateKeyAlgorithm?: string;
  IsCertificateSm?: boolean;
}

const PAGE = 100;

const call = <T>(ctx: QueryContext, creds: AccessKeyCredentials, action: string, params: Record<string, unknown>) =>
  callVolc<T>(ctx, creds, {
    host: "certificate-service.volcengineapi.com",
    service: "certificate_service",
    region: "cn-beijing",
    version: "2024-10-01",
    action,
    method: "POST",
    params,
  });

async function fetchAll(ctx: QueryContext, creds: AccessKeyCredentials): Promise<CertificateRecord[]> {
  const list = await paginate(PAGE, async (page) => {
    const res = await call<{ Instances?: CertInstance[] | null; TotalCount?: number }>(ctx, creds, "CertificateGetInstanceList", {
      PageNumber: page,
      PageSize: PAGE,
    });
    return { items: res.Instances ?? [], total: res.TotalCount };
  });
  // 待提交 / 验证中 / 申请失败的订单还没有证书，不列出
  return list
    .filter((c) => c.NotAfter)
    .map((c) =>
      compact({
        provider: "volcengine" as const,
        id: c.InstanceId,
        name: c.Tag,
        commonName: c.CommonName,
        sans: c.San ?? undefined,
        issuer: c.Issuer,
        notBefore: toIso(c.NotBefore),
        notAfter: toIso(c.NotAfter),
        status: c.Status,
        source: c.InstanceType,
        algorithm: c.IsCertificateSm ? ("SM2" as const) : keyAlgorithm(c.CertificateKeyAlgorithm),
      }),
    );
}

const cached = memo<QueryContext, CertificateRecord[]>();

/** 证书中心的 SSL 证书列表，同一次命令内（certs 与各服务补全）只拉一次 */
export function listCertCenter(ctx: QueryContext, creds: AccessKeyCredentials): Promise<CertificateRecord[]> {
  return cached(ctx, `cert:${creds.accessKeyId}`, () => fetchAll(ctx, creds));
}

/**
 * 只返回证书 ID 的服务，用证书中心列表按 ID 补全 CN / SAN / 有效期（只补缺到期时间的证书，顺序不变）。
 * 补全失败（如没有证书中心只读权限）只记一条 issue，证书原样返回。
 */
export async function completeCerts(ctx: QueryContext, creds: AccessKeyCredentials, warn: Warn, certs: CertInfo[]): Promise<CertInfo[]> {
  if (!certs.some((c) => c.id && !c.notAfter)) return certs;
  let list: CertificateRecord[];
  try {
    list = await listCertCenter(ctx, creds);
  } catch (e) {
    warn(e, "证书中心证书列表（用于补全到期时间）");
    return certs;
  }
  const byId = new Map(list.map((c) => [c.id, c]));
  return certs.map((cert) => {
    const c = cert.id && !cert.notAfter ? byId.get(cert.id) : undefined;
    if (!c) return cert;
    return compact({
      ...cert,
      name: cert.name ?? c.name,
      commonName: cert.commonName ?? c.commonName,
      sans: cert.sans ?? c.sans,
      issuer: cert.issuer ?? c.issuer,
      notBefore: c.notBefore,
      notAfter: c.notAfter,
      status: cert.status ?? c.status,
    });
  });
}

/** 按域名记录补全，域名本身照常返回 */
export async function enrichFromCertCenter(
  ctx: QueryContext,
  creds: AccessKeyCredentials,
  warn: Warn,
  records: DomainRecord[],
): Promise<DomainRecord[]> {
  const withCert = records.filter((r) => r.cert);
  const filled = await completeCerts(ctx, creds, warn, withCert.map((r) => r.cert!));
  withCert.forEach((r, i) => (r.cert = filled[i]));
  return records;
}

/**
 * 双证书服务（CDN、点播）的域名证书接口不区分 RSA / ECC，按 ID 从证书中心查算法。
 * 查询失败只记一条 issue，返回空表（这些域名会因算法不明而不处理）。
 */
async function certAlgorithms(ctx: QueryContext, creds: AccessKeyCredentials, warn: Warn): Promise<Map<string, NonNullable<CertInfo["algorithm"]>>> {
  try {
    const list = await listCertCenter(ctx, creds);
    return new Map(list.flatMap((c) => (c.algorithm ? [[c.id, c.algorithm] as const] : [])));
  } catch (e) {
    warn(e, "证书中心证书列表（用于识别双证书的算法）");
    return new Map();
  }
}

/** 给缺算法的证书按 ID 补上算法（只在域名绑了两张以上国际证书时需要） */
export async function fillDualAlgorithms(ctx: QueryContext, creds: AccessKeyCredentials, warn: Warn, groups: CertInfo[][]): Promise<CertInfo[][]> {
  const needs = (certs: CertInfo[]) => certs.filter((c) => c.algorithm !== "SM2").length > 1 && certs.some((c) => c.id && !c.algorithm);
  if (!groups.some(needs)) return groups;
  const algorithms = await certAlgorithms(ctx, creds, warn);
  return groups.map((certs) =>
    needs(certs) ? certs.map((c) => (c.algorithm || !c.id || !algorithms.has(c.id) ? c : { ...c, algorithm: algorithms.get(c.id) })) : certs,
  );
}

/**
 * 上传到证书中心（ImportCertificate）。不允许重复上传（Repeatable=false）：证书中心按指纹查重，
 * 已有同一张证书时不再上传、返回最早那张的 ID（RepeatId），记为复用。
 */
export async function uploadToCertCenter(ctx: QueryContext, creds: AccessKeyCredentials, cert: LocalCert): Promise<{ id: string; reused: boolean }> {
  const res = await call<{ InstanceId?: string; RepeatId?: string }>(ctx, creds, "ImportCertificate", {
    Tag: certName(cert),
    Repeatable: false,
    CertificateInfo: { CertificateChain: cert.certPem.trim(), PrivateKey: cert.keyPem.trim() },
  });
  if (res.RepeatId) return { id: res.RepeatId, reused: true };
  if (res.InstanceId) return { id: res.InstanceId, reused: false };
  throw new CloudApiError("volcengine", "InvalidResponse", "上传证书后证书中心没有返回证书 ID");
}
