import type { CertInfo } from "../../types.js";

/** 逗号分隔的域名列表（接口里常带空格） */
export function splitList(s: string | null | undefined): string[] {
  return (s ?? "").split(",").map((x) => x.trim()).filter(Boolean);
}

/** 一个域名挂多张证书（RSA + ECC 双证书）时取最早到期的那张，没有到期时间的排最后 */
export function earliest<T extends CertInfo>(certs: readonly T[]): T | undefined {
  const at = (c: CertInfo) => (c.notAfter ? Date.parse(c.notAfter) : Number.POSITIVE_INFINITY);
  return certs.reduce<T | undefined>((best, c) => (!best || at(c) < at(best) ? c : best), undefined);
}
