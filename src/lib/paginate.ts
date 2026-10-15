/** 防止接口异常（如忽略页码一直返回同一页）时死循环 */
const MAX_PAGES = 1000;

export interface Page<T> {
  items: T[];
  total?: number;
}

/**
 * 逐页拉取直到取完。接口返回 total 时以 total 为准（遇到空页也停），
 * 这样即使接口悄悄把 pageSize 截小也不会漏数据；没有 total 时以不足一页为结束。
 * 页码分页的接口用 page（从 1 开始）；偏移量分页的接口用 offset（已取到的条数），
 * 不要用 (page - 1) * pageSize 换算，否则接口截小 pageSize 时会跳过中间的数据。
 */
export async function paginate<T>(pageSize: number, fetchPage: (page: number, offset: number) => Promise<Page<T>>): Promise<T[]> {
  const all: T[] = [];
  for (let page = 1; page <= MAX_PAGES; page++) {
    const { items, total } = await fetchPage(page, all.length);
    all.push(...items);
    const done = total !== undefined ? all.length >= total || items.length === 0 : items.length < pageSize;
    if (done) return all;
  }
  throw new Error(`分页超过 ${MAX_PAGES} 页仍未取完，已中止（接口返回可能异常）`);
}

/** 同一次命令里多个服务共享的查询结果（如证书列表），按 key 缓存 Promise */
export function memo<K extends object, V>(): (owner: K, key: string, load: () => Promise<V>) => Promise<V> {
  const cache = new WeakMap<K, Map<string, Promise<V>>>();
  return (owner, key, load) => {
    let m = cache.get(owner);
    if (!m) cache.set(owner, (m = new Map()));
    let p = m.get(key);
    if (!p) m.set(key, (p = load()));
    return p;
  };
}
