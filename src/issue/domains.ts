import { isIP } from "node:net";
import { domainToASCII } from "node:url";
import { UsageError } from "../query.js";
import type { KeyType } from "./types.js";

/** 一张证书最多覆盖的域名数（Let's Encrypt 的上限） */
export const MAX_DOMAINS = 100;

/** 一个 label：字母、数字、连字符，不以连字符开头或结尾，1~63 个字符；Let's Encrypt 不接受下划线 */
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * 规范化一个要签发的域名：小写、去掉结尾点、IDN 转 punycode；泛域名只允许最左侧一个 "*."。
 * 不合法时抛 UsageError，message 带上原始输入，方便调用方对照修正
 */
export function normalizeIssueDomain(input: string): string {
  const bad = (why: string) => new UsageError(`域名 "${input}" 不合法：${why}`);
  const raw = input.trim().toLowerCase().replace(/\.$/, "");
  const wildcard = raw.startsWith("*.");
  const base = wildcard ? raw.slice(2) : raw;
  if (base.includes("*")) throw bad("泛域名只能在最左侧写一个 *.（如 *.example.com）");
  // domainToASCII 会把 0x7f.1 这类写法解析成 IPv4，所以转换前后都要排除 IP
  if (isIP(base.replace(/^\[(.*)\]$/, "$1"))) throw bad("不支持 IP 证书");
  const ascii = domainToASCII(base).replace(/\.$/, "");
  if (!ascii) throw bad("不是合法的域名（含空格、非法字符，或无法转换为 punycode）");
  if (isIP(ascii)) throw bad("不支持 IP 证书");
  const labels = ascii.split(".");
  if (labels.length < 2) throw bad("至少要有两级（如 example.com）");
  const wrong = labels.find((l) => !LABEL.test(l));
  if (wrong !== undefined) {
    throw bad(wrong ? `"${wrong}" 含不允许的字符或超过 63 个字符（只能是字母、数字、连字符，且不以连字符开头或结尾）` : "有空的一级");
  }
  // 最后一级是纯数字的不是域名（也防住 domainToASCII 没识别出来的 IP 写法）
  if (/^\d+$/.test(labels.at(-1)!)) throw bad("顶级域不能是纯数字");
  const domain = wildcard ? `*.${ascii}` : ascii;
  if (domain.length > 253) throw bad("总长度超过 253 个字符");
  return domain;
}

/** 主域名的排序：层级少的在前（泛域名按去掉 *. 后算），同级时非泛域名在前，再按字母序 */
function primaryOrder(a: string, b: string): number {
  const depth = (d: string) => d.replace(/^\*\./, "").split(".").length;
  return depth(a) - depth(b) || Number(a.startsWith("*.")) - Number(b.startsWith("*.")) || (a < b ? -1 : a > b ? 1 : 0);
}

/**
 * -d 给的全部域名：逐个规范化、去重、不超过 100 个。主域名（见 primaryOrder）排第一，决定 CN 与保存目录名，
 * 其余保持首次出现的顺序：-d 写的顺序不同也落到同一个目录，重复执行才能复用
 */
export function parseDomains(inputs: readonly string[]): string[] {
  if (inputs.length === 0) throw new UsageError("--domain 不能为空");
  const domains = [...new Set(inputs.map(normalizeIssueDomain))];
  if (domains.length > MAX_DOMAINS) throw new UsageError(`一张证书最多 ${MAX_DOMAINS} 个域名，去重后收到 ${domains.length} 个`);
  const primary = [...domains].sort(primaryOrder)[0]!;
  return [primary, ...domains.filter((d) => d !== primary)];
}

/**
 * 默认保存目录名：主域名（"*" 换成 "_"）+ 算法，测试环境再加 _staging。
 * 算法、环境都进目录名：RSA / ECC 两张证书可以并存，--staging 的测试证书不会覆盖正式证书
 */
export function certDirName(primary: string, keyType: KeyType, staging: boolean): string {
  return `${primary.replace("*", "_")}_${keyType}${staging ? "_staging" : ""}`;
}

/** 验证记录所在的名字：泛域名去掉 "*."，与根域名共用同一个 _acme-challenge 名 */
export function challengeName(domain: string): string {
  return `_acme-challenge.${domain.replace(/^\*\./, "")}`;
}
