import { X509Certificate } from "node:crypto";
import type { LocalCert } from "../../deploy/cert.js";
import { compact } from "../../lib/compact.js";
import type { CertInfo, DomainRecord } from "../../types.js";

/** 一个域名挂多张证书（国际 + 国密等）时取最早到期的那张，没有到期时间的排最后 */
export function earliest<T extends CertInfo>(certs: readonly T[]): T | undefined {
  const at = (c: CertInfo) => (c.notAfter ? Date.parse(c.notAfter) : Number.POSITIVE_INFINITY);
  return certs.reduce<T | undefined>((best, c) => (!best || at(c) < at(best) ? c : best), undefined);
}

/** 国际证书（已知 RSA / ECC 的在前，算法未知的其次）排在国密证书前，部署时按同算法、再按第一张国际证书选要替换的那张 */
const rank = (c: CertInfo) => (c.algorithm === "SM2" ? 2 : c.algorithm ? 0 : 1);
export function orderCerts<T extends CertInfo>(certs: readonly T[]): T[] {
  return [...certs].sort((a, b) => rank(a) - rank(b));
}

/** 证书来源只用于填 extra，不放进证书信息里 */
export function withoutSource({ source: _, ...cert }: CertInfo & { source?: string }): CertInfo {
  return cert;
}

/** 国密证书私钥读不回来：整体覆盖式的证书接口无法在保留自有上传的国密证书的同时替换国际证书 */
export const SM_CERT_LOCKED =
  "该域名同时配置了自有上传的国密证书，接口读不到它的私钥，替换国际证书会把国密证书一并删掉；请在控制台更换，或先把国密证书改为云证书管理服务（CCM）托管";

/** 查询时已知国密证书不是 CCM 托管的（extra.smCertSource），部署时无法保留它 */
export function smCertLocked(record: DomainRecord): string | undefined {
  const source = record.extra?.smCertSource;
  return source && source !== "scm" ? SM_CERT_LOCKED : undefined;
}

/** 证书名：sslbear-<CN，不允许的字符换成 _>-<到期日 YYYYMMDD>；CCM、OBS 限 3~63 位英文字母、数字、下划线、中划线、英文句点，CDN 限 3~64 位 */
const NAME_MAX = 63;
export function certName(cert: Pick<LocalCert, "commonName" | "sans" | "notAfter">): string {
  const head = "sslbear-";
  const tail = `-${cert.notAfter.slice(0, 10).replace(/-/g, "")}`;
  const host = (cert.commonName ?? cert.sans[0] ?? "cert").replace(/[^A-Za-z0-9_.-]/g, "_");
  return `${head}${host.slice(0, NAME_MAX - head.length - tail.length)}${tail}`;
}

/** 国密（SM2）证书的公钥类型 Node 识别不了，返回 undefined，由调用方按接口给的证书类型标注 */
function algorithmOf(x: X509Certificate): CertInfo["algorithm"] {
  const type = x.publicKey.asymmetricKeyType;
  return type === "rsa" || type === "rsa-pss" ? "RSA" : type === "ec" ? "ECC" : undefined;
}

const cn = (dn: string) => /^CN=(.*)$/m.exec(dn)?.[1];

/**
 * 解析接口返回的 PEM 证书内容（证书链取第一张，即服务端证书），拿到 CN / SAN / 签发者 / 有效期 / 密钥算法。
 * 内容为空、被打码或格式不对时返回 undefined，由调用方退回接口给的字段。
 */
export function parsePem(pem: string | null | undefined): CertInfo | undefined {
  if (!pem || !pem.includes("-----BEGIN CERTIFICATE-----")) return undefined;
  try {
    const x = new X509Certificate(pem);
    const sans = (x.subjectAltName ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.startsWith("DNS:"))
      .map((s) => s.slice(4));
    return compact({
      commonName: cn(x.subject),
      sans,
      issuer: cn(x.issuer) ?? x.issuer.replace(/\n/g, ", "),
      notBefore: new Date(x.validFrom).toISOString(),
      notAfter: new Date(x.validTo).toISOString(),
      algorithm: algorithmOf(x),
    });
  } catch {
    return undefined;
  }
}
