import { X509Certificate, createPrivateKey, type KeyObject } from "node:crypto";
import { UsageError } from "../query.js";

/** 要部署的本地证书：已校验私钥匹配、证书链齐全、在有效期内 */
export interface LocalCert {
  /** 叶子在前、中间证书在后，\n 换行并以 \n 结尾 */
  certPem: string;
  keyPem: string;
  commonName?: string;
  /** 证书覆盖的域名（小写）；没有 SAN 时为 CN */
  sans: string[];
  notBefore: string;
  notAfter: string;
  algorithm: "RSA" | "ECC";
  /** 叶子证书 DER 的 SHA-256，小写 hex、无冒号 */
  fingerprint: string;
  /** 大写 hex */
  serialNumber: string;
  issuer?: string;
}

const PEM_CERT = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;

/** X509Certificate.subject / issuer 是多行 "K=V"，取 CN */
function cnOf(dn: string): string | undefined {
  return dn
    .split("\n")
    .map((l) => /^CN=(.*)$/.exec(l.trim())?.[1])
    .find((v) => v !== undefined);
}

function sansOf(cert: X509Certificate): string[] {
  return (cert.subjectAltName ?? "")
    .split(/,\s*/)
    .filter((s) => s.startsWith("DNS:"))
    .map((s) => normalizeDomain(s.slice(4)));
}

function parseKey(keyPem: string): KeyObject {
  if (/ENCRYPTED/.test(keyPem)) throw new UsageError("私钥是加密的，请先解密（如 openssl pkey -in key.pem -out key-plain.pem）");
  if (!/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(keyPem)) throw new UsageError("--key 不是 PEM 格式的私钥");
  try {
    return createPrivateKey(keyPem);
  } catch {
    // 不带原始错误：openssl 的错误信息可能夹带私钥片段
    throw new UsageError("私钥无法解析，请确认是未加密的 PEM 格式 RSA / ECC 私钥");
  }
}

export function loadLocalCert(certText: string, keyText: string, now: Date): LocalCert {
  const certPemText = certText.replace(/^﻿/, "").replace(/\r\n?/g, "\n");
  const keyPem = `${keyText.replace(/^﻿/, "").replace(/\r\n?/g, "\n").trim()}\n`;
  const blocks = certPemText.match(PEM_CERT) ?? [];
  if (blocks.length === 0) throw new UsageError("--cert 里没有 PEM 格式的证书（-----BEGIN CERTIFICATE-----）");
  let certs: X509Certificate[];
  try {
    certs = blocks.map((b) => new X509Certificate(b));
  } catch {
    throw new UsageError("--cert 里有无法解析的证书");
  }
  const key = parseKey(keyPem);
  const leafIndex = certs.findIndex((c) => {
    try {
      return c.checkPrivateKey(key);
    } catch {
      return false;
    }
  });
  if (leafIndex < 0) throw new UsageError("私钥与证书不匹配：--cert 里没有与 --key 对应的证书");
  const leaf = certs[leafIndex]!;
  const chain = certs.filter((_, i) => i !== leafIndex);
  const selfSigned = leaf.issuer === leaf.subject;
  if (!selfSigned && !chain.some((c) => leaf.checkIssued(c))) {
    throw new UsageError("证书文件缺少中间证书链：请使用包含中间证书的 fullchain 文件（叶子证书 + 中间证书）");
  }
  const notBefore = new Date(Date.parse(leaf.validFrom)).toISOString();
  const notAfter = new Date(Date.parse(leaf.validTo)).toISOString();
  if (now.getTime() < Date.parse(notBefore) || now.getTime() > Date.parse(notAfter)) {
    throw new UsageError(`证书不在有效期内（有效期 ${notBefore} 至 ${notAfter}）`);
  }
  const type = leaf.publicKey.asymmetricKeyType;
  const algorithm = type === "rsa" || type === "rsa-pss" ? "RSA" : type === "ec" ? "ECC" : undefined;
  if (!algorithm) throw new UsageError(`不支持的证书密钥类型：${type}（仅支持 RSA、ECC）`);
  const commonName = cnOf(leaf.subject);
  const sans = sansOf(leaf);
  if (sans.length === 0 && commonName) sans.push(normalizeDomain(commonName));
  const ordered = [blocks[leafIndex]!, ...blocks.filter((_, i) => i !== leafIndex)];
  return {
    certPem: `${ordered.join("\n")}\n`,
    keyPem,
    ...(commonName && { commonName }),
    sans,
    notBefore,
    notAfter,
    algorithm,
    fingerprint: leaf.fingerprint256.replace(/:/g, "").toLowerCase(),
    serialNumber: leaf.serialNumber.toUpperCase(),
    ...(cnOf(leaf.issuer) && { issuer: cnOf(leaf.issuer) }),
  };
}

/** 小写、去首尾空白与结尾点；七牛的泛域名写作 ".example.com"，统一为 "*.example.com" */
export function normalizeDomain(domain: string): string {
  const d = domain.trim().toLowerCase().replace(/\.$/, "");
  return d.startsWith(".") ? `*${d}` : d;
}

/** 浏览器的匹配规则：精确匹配，或 *.example.com 覆盖一级子域（不含根域、不含多级）；云上的泛域名只能由同样的泛域名覆盖 */
export function certCovers(sans: readonly string[], domain: string): boolean {
  const d = normalizeDomain(domain);
  return sans.some((raw) => {
    const s = normalizeDomain(raw);
    if (s === d) return true;
    if (!s.startsWith("*.") || d.startsWith("*.")) return false;
    const suffix = s.slice(1);
    const label = d.slice(0, -suffix.length);
    return d.endsWith(suffix) && label.length > 0 && !label.includes(".");
  });
}
