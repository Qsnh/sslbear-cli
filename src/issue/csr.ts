import { createPublicKey, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { bitString, children, contextTag, ia5String, integer, nullValue, octetString, oid, readTlv, sequence, set, utf8String, type Tlv } from "./asn1.js";
import type { KeyType } from "./types.js";

/** 证书私钥：rsa = RSA 2048，ecc = ECDSA P-256 */
export function generateCertKey(type: KeyType): KeyObject {
  return type === "rsa"
    ? generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey
    : generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
}

/** ACME 账号私钥：ECDSA P-256（JWS 用 ES256） */
export function generateAccountKey(): KeyObject {
  return generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
}

const OID = {
  commonName: "2.5.4.3",
  extensionRequest: "1.2.840.113549.1.9.14",
  subjectAltName: "2.5.29.17",
  authorityKeyIdentifier: "2.5.29.35",
  sha256WithRSAEncryption: "1.2.840.113549.1.1.11",
  ecdsaWithSHA256: "1.2.840.10045.4.3.2",
};

/** X.520 ub-common-name：CN 最长 64 个字符，更长的域名只能放进 SAN */
const MAX_CN = 64;

/**
 * PKCS#10 CSR（RFC 2986，DER）：CN 为第一个域名（超过 64 个字符则 subject 为空），SAN 为全部域名，SHA-256 签名。
 * CA 以 SAN 为准签发，CN 仍然带上：国内多数云服务拒收没有 CN 的证书。
 * domains 须已规范化为 ASCII（IDN 已转 punycode），dNSName 是 IA5String
 */
export function buildCsr(key: KeyObject, domains: readonly string[]): Buffer {
  if (domains.length === 0) throw new Error("CSR 至少要有一个域名");
  const bad = domains.find((d) => !/^[\x21-\x7e]+$/.test(d));
  if (bad !== undefined) throw new Error(`CSR 的域名必须是 ASCII（IDN 先转 punycode）：${bad}`);
  const type = key.asymmetricKeyType;
  if (type !== "rsa" && type !== "ec") throw new Error(`不支持的证书密钥类型：${type}`);

  const cn = domains[0]!;
  const subject = cn.length > MAX_CN ? sequence() : sequence(set(sequence(oid(OID.commonName), utf8String(cn))));
  const spki = createPublicKey(key).export({ type: "spki", format: "der" });
  const san = sequence(...domains.map((d) => contextTag(2, Buffer.from(d, "ascii"), false)));
  const extensionRequest = sequence(oid(OID.extensionRequest), set(sequence(sequence(oid(OID.subjectAltName), octetString(san)))));
  const info = sequence(integer(0), subject, spki, contextTag(0, extensionRequest));

  // RSA 的算法标识按 RFC 4055 带 NULL 参数；ECDSA 按 RFC 5758 不带参数，签名为 DER 编码的 (r, s)
  const algorithm = type === "rsa" ? sequence(oid(OID.sha256WithRSAEncryption), nullValue()) : sequence(oid(OID.ecdsaWithSHA256));
  const signature = type === "rsa" ? sign("sha256", info, key) : sign("sha256", info, { key, dsaEncoding: "der" });
  return sequence(info, algorithm, bitString(signature));
}

const PEM_CERT = /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/;

/** 取证书扩展 extnValue（OCTET STRING）的内容；扩展在 tbsCertificate 的 [3] EXPLICIT 里，没有扩展的证书返回 undefined */
function extensionValue(tbs: Tlv, extnOid: string): Buffer | undefined {
  const exts = children(tbs).find((t) => t.tag === 0xa3);
  if (!exts) return undefined;
  const target = oid(extnOid);
  for (const ext of children(readTlv(exts.content))) {
    const [id, ...rest] = children(ext);
    // Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }：critical 可能省略，取最后一个
    if (id?.raw.equals(target)) return rest.at(-1)?.content;
  }
  return undefined;
}

/**
 * RFC 9773 第 4.1 节的 ARI 证书标识：base64url(AKI keyIdentifier) + "." + base64url(序列号 DER 内容字节)。
 * 序列号取 INTEGER 的内容字节原样编码（含为保证正数补的前导 0x00），不能用 X509Certificate.serialNumber 的十六进制转换。
 * 输入为 fullchain 时取第一张（叶子）。证书没有 AKI（或 AKI 里没有 keyIdentifier）、解析不了时返回 undefined：
 * replaces 只是续签的附加信息，算不出来就不带，不应让签发失败
 */
export function ariCertId(certPem: string): string | undefined {
  const b64 = PEM_CERT.exec(certPem)?.[1];
  if (!b64) return undefined;
  try {
    const cert = readTlv(Buffer.from(b64.replace(/\s+/g, ""), "base64"));
    const tbs = children(cert)[0];
    if (!tbs) return undefined;
    // TBSCertificate ::= SEQUENCE { version [0] EXPLICIT（可省略）, serialNumber INTEGER, ... }：第一个直接子 INTEGER 即序列号
    const serial = children(tbs).find((t) => t.tag === 0x02);
    const aki = extensionValue(tbs, OID.authorityKeyIdentifier);
    if (!serial || !aki) return undefined;
    // AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING OPTIONAL, ... }
    const keyId = children(readTlv(aki)).find((t) => t.tag === 0x80);
    if (!keyId) return undefined;
    return `${keyId.content.toString("base64url")}.${serial.content.toString("base64url")}`;
  } catch {
    return undefined;
  }
}
