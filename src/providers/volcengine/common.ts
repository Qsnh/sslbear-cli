import { X509Certificate } from "node:crypto";
import type { LocalCert } from "../../deploy/cert.js";
import { pickOldCert } from "../../deploy/plan.js";
import type { CertInfo, DomainRecord } from "../../types.js";

/** 逗号分隔的域名列表（接口里常带空格） */
export function splitList(s: string | null | undefined): string[] {
  return (s ?? "").split(",").map((x) => x.trim()).filter(Boolean);
}

/** 一个域名挂多张证书（RSA + ECC 双证书）时取最早到期的那张，没有到期时间的排最后 */
export function earliest<T extends CertInfo>(certs: readonly T[]): T | undefined {
  const at = (c: CertInfo) => (c.notAfter ? Date.parse(c.notAfter) : Number.POSITIVE_INFINITY);
  return certs.reduce<T | undefined>((best, c) => (!best || at(c) < at(best) ? c : best), undefined);
}

type Algorithm = NonNullable<CertInfo["algorithm"]>;

/** 证书中心的 CertificateKeyAlgorithm（文档示例为 "RSA 2048"）换算成 RSA / ECC / SM2 */
export function keyAlgorithm(s: string | undefined): Algorithm | undefined {
  const v = (s ?? "").trim().toUpperCase();
  if (v.startsWith("RSA")) return "RSA";
  if (v.startsWith("SM2")) return "SM2";
  if (v.startsWith("EC")) return "ECC";
  return undefined;
}

const PEM_CERT = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;

/** 证书 PEM（取第一张，即叶子证书）的公钥算法；国密证书由调用方按 EncryType 判断 */
export function pemAlgorithm(pem: string | null | undefined): "RSA" | "ECC" | undefined {
  const block = pem?.match(PEM_CERT)?.[0];
  if (!block) return undefined;
  try {
    const type = new X509Certificate(block).publicKey.asymmetricKeyType;
    return type === "rsa" || type === "rsa-pss" ? "RSA" : type === "ec" ? "ECC" : undefined;
  } catch {
    return undefined;
  }
}

/** PEM 里每张证书 DER 的 SHA-256（小写 hex、无冒号），与 LocalCert.fingerprint 同格式 */
export function pemFingerprints(pem: string): string[] {
  return (pem.match(new RegExp(PEM_CERT.source, "g")) ?? []).flatMap((b) => {
    try {
      return [new X509Certificate(b).fingerprint256.replace(/:/g, "").toLowerCase()];
    } catch {
      return [];
    }
  });
}

/** 上传到证书服务时的证书名：sslbear-<CN，* 换成 _>-<到期日 YYYYMMDD>；超出 max 时截断 CN 部分 */
export function certName(cert: LocalCert, max = Number.POSITIVE_INFINITY): string {
  const cn = (cert.commonName ?? cert.sans[0] ?? "cert").replace(/\*/g, "_");
  const date = cert.notAfter.slice(0, 10).replace(/-/g, "");
  const room = max - "sslbear-".length - date.length - 1;
  return `sslbear-${cn.slice(0, Math.max(room, 1))}-${date}`;
}

const allCerts = (record: DomainRecord): CertInfo[] => (record.certs?.length ? record.certs : record.cert ? [record.cert] : []);

/** 双证书（两张以上国际证书）里有查不到算法的，无法确定该替换哪一张 */
export function ambiguousDual(record: DomainRecord): boolean {
  const intl = allCerts(record).filter((c) => c.algorithm !== "SM2");
  return intl.length > 1 && intl.some((c) => !c.algorithm);
}

export const AMBIGUOUS_DUAL = "该域名绑了两张证书但查不到各自的算法（RSA / ECC），无法确定替换哪一张";

/** 更新双证书域名时要原样保留的证书：除被替换的那张（同算法）以外的全部，含国密证书 */
export function certsToKeep(record: DomainRecord, algorithm: LocalCert["algorithm"]): CertInfo[] {
  const old = pickOldCert(record, algorithm);
  return allCerts(record).filter((c) => c.id && c.id !== old?.id);
}
