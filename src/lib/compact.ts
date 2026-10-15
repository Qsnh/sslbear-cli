type Defined<T> = { [K in keyof T]: Exclude<T[K], null> };

/** 去掉 undefined / null / 空串 / 空数组 / 空对象字段，让输出的 JSON 只保留有值的字段 */
export function compact<T extends object>(o: T): Defined<T> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o)) {
    if (v === undefined || v === null || v === "") continue;
    if (typeof v === "object" && Object.keys(v).length === 0) continue;
    out[k] = v;
  }
  return out as Defined<T>;
}
