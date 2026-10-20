const DAY_MS = 86_400_000;

// 个位数的月日时分秒也接受：腾讯云官方示例里出现过 "2024-11-06 08:00:0"
const LOCAL_DATETIME = /^(\d{4})-(\d{1,2})-(\d{1,2})(?:[ T](\d{1,2}):(\d{1,2})(?::(\d{1,2}))?)?$/;

/**
 * 把云厂商返回的各种时间格式统一成 ISO 8601 (UTC)。
 * 不带时区的 "YYYY-MM-DD HH:mm:ss" 按北京时间理解：国内云厂商接口返回的本地时间均为 UTC+8。
 * 纯数字按 Unix 时间戳处理（< 1e12 视为秒，否则为毫秒）。
 * Unix 纪元（1970-01-01T00:00:00Z）及以前的时间视为占位的零值、返回 undefined：如 EdgeOne 免费证书申请中时 ExpireTime 为 "0001-01-01T00:00:00Z"（实测），
 * 当真会被算成早已过期。
 */
export function toIso(value: unknown): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  let ms: number;
  if (typeof value === "number") {
    ms = value < 1e12 ? value * 1000 : value;
  } else if (typeof value === "string") {
    const s = value.trim();
    const m = LOCAL_DATETIME.exec(s);
    if (/^\d{10,13}$/.test(s)) {
      return toIso(Number(s));
    } else if (m) {
      const [y, mo, d, h, mi, sec] = m.slice(1).map((x) => (x ?? "0").padStart(2, "0"));
      ms = Date.parse(`${y}-${mo}-${d}T${h}:${mi}:${sec}+08:00`);
    } else {
      ms = Date.parse(s);
    }
  } else {
    return undefined;
  }
  return Number.isFinite(ms) && ms > 0 ? new Date(ms).toISOString() : undefined;
}

/** 剩余天数向下取整：还剩 0.5 天记为 0，已过期为负数 */
export function daysUntil(iso: string | undefined, now: Date): number | undefined {
  if (!iso) return undefined;
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? Math.floor((ms - now.getTime()) / DAY_MS) : undefined;
}

/** 表格展示用：本地时区 YYYY-MM-DD */
export function formatDate(iso: string | undefined): string {
  if (!iso) return "-";
  const d = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}
