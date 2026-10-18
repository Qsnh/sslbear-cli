import { generateKeyPairSync, type KeyObject } from "node:crypto";
import type { KeyType } from "./types.js";

// 占位：待实现（generateCertKey 已可用）

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

/** PKCS#10 CSR（DER）：CN 为第一个域名（超过 64 个字符则不设 CN），SAN 为全部域名，SHA-256 签名 */
export function buildCsr(_key: KeyObject, _domains: readonly string[]): Buffer {
  throw new Error("未实现");
}

/** RFC 9773 ARI 证书标识：base64url(AKI keyIdentifier) + "." + base64url(序列号 DER 内容字节)；证书没有 AKI 时返回 undefined */
export function ariCertId(_certPem: string): string | undefined {
  throw new Error("未实现");
}
