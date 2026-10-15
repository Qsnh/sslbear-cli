/** 防止接口异常时死循环：单个服务最多翻 200 页 */
const MAX_PAGES = 200;

export interface Page<T> {
  items: T[];
  total?: number;
}

/**
 * 逐页拉取直到取完：返回条数不足一页，或累计条数达到 total 即停止。
 * page 从 1 开始；偏移量分页的接口自行换算 offset = (page - 1) * pageSize。
 */
export async function paginate<T>(pageSize: number, fetchPage: (page: number) => Promise<Page<T>>): Promise<T[]> {
  const all: T[] = [];
  for (let page = 1; page <= MAX_PAGES; page++) {
    const { items, total } = await fetchPage(page);
    all.push(...items);
    if (items.length < pageSize || (total !== undefined && all.length >= total)) break;
  }
  return all;
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
