import { daysUntil } from "../lib/time.js";
import type { CertInfo, DomainRecord } from "../types.js";
import { normalizeDomain, type LocalCert } from "./cert.js";

/** 用户定的更新窗口：当前证书 30 天内到期才直接替换，超过需用户二次确认（--force） */
export const RENEW_WITHIN_DAYS = 30;

/** 两张证书到期（及签发）时间相差在此范围内视为同一张：有的服务只精确到天，华为证书列表的时间还差 8 小时 */
export const SAME_CERT_TOLERANCE_MS = 48 * 3_600_000;

const DAY_MS = 86_400_000;

export type SkipReason =
  | "platform_managed"
  | "unsupported"
  | "https_off"
  | "already_current"
  | "unknown_expiry"
  | "newer_current"
  | "not_due"
  | "same_expiry"
  | "shared_cert_blocked";

/** 这几类跳过需要用户二次确认后加 --force 才执行 */
export const NEEDS_CONFIRM: ReadonlySet<SkipReason> = new Set<SkipReason>(["unknown_expiry", "newer_current", "not_due", "same_expiry"]);

export const CONFIRM_HINT = "确需提前更换请向用户确认后加 --force 重新执行（可配合 -d 只针对这些域名）";

export interface Decision {
  kind: "deploy" | "update" | "skip";
  reason?: SkipReason;
  message?: string;
  needsConfirm?: boolean;
  /** 将被替换的旧证书 */
  oldCert?: CertInfo;
  oldDaysLeft?: number;
}

export interface DecideOptions {
  /** 被 --domain 点名 */
  named: boolean;
  force: boolean;
  now: Date;
  /** 服务或记录不支持部署的原因 */
  unsupported?: string;
}

/** 新证书要替换的那张：双证书时取同算法的，没有同算法的取另一张国际证书；国密证书不参与 */
export function pickOldCert(record: DomainRecord, algorithm: LocalCert["algorithm"]): CertInfo | undefined {
  const all = record.certs?.length ? record.certs : record.cert ? [record.cert] : [];
  const intl = all.filter((c) => c.algorithm !== "SM2");
  return intl.find((c) => c.algorithm === algorithm) ?? intl[0];
}

const day = (iso: string) => iso.slice(0, 10);

/** 设计文档的决策表，按顺序第一条命中即定 */
export function decide(record: DomainRecord, cert: LocalCert, o: DecideOptions): Decision {
  const skip = (reason: SkipReason, message: string): Decision => ({ kind: "skip", reason, message });
  if (record.extra?.managed === "platform") return skip("platform_managed", "平台默认域名，由云厂商提供证书");
  if (o.unsupported) return skip("unsupported", o.unsupported);
  if (!record.https) {
    return o.named ? { kind: "deploy" } : skip("https_off", "未开启 HTTPS；如需部署请用 --domain 点名该域名");
  }

  const oldCert = pickOldCert(record, cert.algorithm);
  const oldDaysLeft = daysUntil(oldCert?.notAfter, o.now);
  const base = { ...(oldCert && { oldCert }), ...(oldDaysLeft !== undefined && { oldDaysLeft }) };
  const oldMs = Date.parse(oldCert?.notAfter ?? "");
  const newMs = Date.parse(cert.notAfter);
  const near = (a: number, b: number) => Math.abs(a - b) <= SAME_CERT_TOLERANCE_MS;

  let confirm: [SkipReason, string] | undefined;
  if (Number.isFinite(oldMs) && near(oldMs, newMs)) {
    // 到期时间相同还要看签发时间与算法：同一天到期的重签证书、同时签发的 RSA / ECC 两张都不是同一张。
    // 查不到签发时间只能按到期时间判断；查不到算法时无法区分同时签发的两张，按同一张跳过，
    // 但用户点名并坚持（-d + --force）就换；只加 --force 不波及它们（它们不在需确认清单里，用户没被问过）
    const oldStart = Date.parse(oldCert?.notBefore ?? "");
    const startNear = !Number.isFinite(oldStart) || near(oldStart, Date.parse(cert.notBefore));
    // 两天内重签（如 issue --force、改了域名再签）的证书时间也相近：当前证书的 SAN 有新证书没有的域名就肯定不是同一张。
    // 只看「多出来的」：有的服务返回的 SAN 不全，少了不能说明是另一张。不看 commonName：有的服务填的其实是证书名
    // （火山引擎点播的 CertName 可能是 sslbear 上传时起的名字），拿来比会让重复执行不再跳过
    const extraSan = oldCert?.sans?.map(normalizeDomain).find((d) => !cert.sans.includes(d));
    const oldAlg = oldCert?.algorithm;
    if (extraSan) {
      confirm = ["same_expiry", `当前证书与新证书到期时间相近，但当前证书还覆盖 ${extraSan}，不是同一张`];
    } else if (startNear && (!oldAlg || oldAlg === cert.algorithm)) {
      if (oldAlg) return { ...skip("already_current", "已是该证书（到期时间相同）"), ...base };
      if (!(o.force && o.named)) {
        return {
          ...skip(
            "already_current",
            "已是该证书（到期时间相同）；若其实是同期签发的另一张证书（如 RSA / ECC 各一张），向用户确认后用 -d 点名该域名并加 --force 可强制替换",
          ),
          ...base,
        };
      }
    } else {
      confirm = [
        "same_expiry",
        startNear
          ? `当前证书（${oldAlg}）与新证书（${cert.algorithm}）到期时间相同但算法不同`
          : "当前证书与新证书到期时间相同但签发时间不同（可能是重签的证书）",
      ];
    }
  } else if (!Number.isFinite(oldMs)) confirm = ["unknown_expiry", "查不到当前证书的到期时间"];
  else if (oldMs - newMs > SAME_CERT_TOLERANCE_MS) {
    confirm = ["newer_current", `当前证书 ${day(oldCert!.notAfter!)} 到期，比新证书（${day(cert.notAfter)}）还晚`];
  } else if (oldMs - o.now.getTime() > RENEW_WITHIN_DAYS * DAY_MS) {
    // 按毫秒比较：剩 30 天 23 小时也算未到更新时间，展示的天数仍向下取整
    confirm = ["not_due", `当前证书还剩 ${oldDaysLeft} 天，未到更新时间`];
  }

  if (confirm && !o.force) {
    return { kind: "skip", reason: confirm[0], message: `${confirm[1]}；${CONFIRM_HINT}`, needsConfirm: true, ...base };
  }
  return { kind: "update", ...base };
}
