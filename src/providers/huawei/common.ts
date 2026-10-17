import { X509Certificate } from "node:crypto";
import { compact } from "../../lib/compact.js";
import type { CertInfo } from "../../types.js";

/** 一个域名挂多张证书（国际 + 国密等）时取最早到期的那张，没有到期时间的排最后 */
export function earliest<T extends CertInfo>(certs: readonly T[]): T | undefined {
  const at = (c: CertInfo) => (c.notAfter ? Date.parse(c.notAfter) : Number.POSITIVE_INFINITY);
  return certs.reduce<T | undefined>((best, c) => (!best || at(c) < at(best) ? c : best), undefined);
}

const cn = (dn: string) => /^CN=(.*)$/m.exec(dn)?.[1];

/**
 * 解析接口返回的 PEM 证书内容（证书链取第一张，即服务端证书），拿到 CN / SAN / 签发者 / 有效期。
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
    });
  } catch {
    return undefined;
  }
}
