import { CloudApiError, send, withRetry, type QueryContext } from "../lib/http.js";
import { paginate } from "../lib/paginate.js";
import { varsEnv } from "./env.js";
import { defineDns, normalizeName, relativeName, type TxtRecord } from "./types.js";

export interface DigitalOceanCredentials { token: string }

/**
 * DigitalOcean API v2 的 Domains / Domain Records（https://docs.digitalocean.com/reference/api/，
 * 字段以 GitHub digitalocean/openapi 为准）。每个 TXT 值是一条有独立 ID 的记录。
 */
const API = "https://api.digitalocean.com/v2";
/** 文档（DNS Limits）：所有记录的 TTL 最小 30 秒 */
const TTL = 30;
/** per_page 上限 */
const PAGE = 200;
/** OpenAPI 的 security：列记录要 domain:read，新增记录要 domain:create 或 domain:update，删除记录要 domain:delete 或 domain:update */
const PERMISSION_HINT =
  "DIGITALOCEAN_TOKEN 无效或权限不足：需要 Full Access 令牌，或带 domain:read 与 domain:update（也可以是 domain:create + domain:delete）权限的自定义令牌；" +
  "Read Only 令牌不能增删记录";

/** 4xx / 5xx 的错误体：id 是与 HTTP 状态对应的短标识（如 not_found、unauthorized），request_id 部分接口才有 */
interface DoError {
  id?: string;
  message?: string;
  request_id?: string;
}

interface DoRecord {
  id: number;
  type?: string;
  name?: string;
  data?: string;
  ttl?: number;
}

interface DoRequest {
  method?: "GET" | "POST" | "DELETE";
  body?: unknown;
  /** 默认对限流、5xx、超时自动重试；addTxt 自己在外层重试（每次先查重），里面的请求传 false */
  retry?: boolean;
}

const enc = encodeURIComponent;

function toError(status: number, body: DoError | undefined, text: string): CloudApiError {
  const raw = body?.id;
  const message = body?.message || text.slice(0, 200) || `HTTP ${status}`;
  const requestId = body?.request_id;
  // 每小时 5000 次、每分钟 250 次，超了返回 429；5xx 记为 ServiceUnavailable，交给 withRetry 重试
  if (status === 429) return new CloudApiError("digitalocean", "Throttling", `${message}（${raw ?? "HTTP 429"}）`, requestId, status);
  if (status >= 500) return new CloudApiError("digitalocean", "ServiceUnavailable", `${message}（${raw ?? `HTTP ${status}`}）`, requestId, status);
  const code = raw ?? `HTTP${status}`;
  if (status === 401 || status === 403) return new CloudApiError("digitalocean", code, `${message}。${PERMISSION_HINT}`, requestId, status);
  return new CloudApiError("digitalocean", code, message, requestId, status);
}

/** 调用 DigitalOcean API v2，返回解析后的 JSON；DELETE 成功时是 204 无响应体，返回空对象 */
async function doRequest<T>(ctx: QueryContext, creds: DigitalOceanCredentials, path: string, req: DoRequest = {}): Promise<T> {
  const method = req.method ?? "GET";
  const body = req.body === undefined ? undefined : JSON.stringify(req.body);
  const once = async (): Promise<T> => {
    const headers: Record<string, string> = { Authorization: `Bearer ${creds.token}`, Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const raw = await send(ctx, "digitalocean", `${API}${path}`, { method, headers, ...(body !== undefined && { body }) });
    // 查询接口没有响应体按非法响应处理，免得把异常当成空列表
    if (method !== "GET" && raw.status < 400 && raw.text.trim() === "") return {} as T;
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw.text);
    } catch {
      if (raw.status >= 400) throw toError(raw.status, undefined, raw.text);
      throw new CloudApiError("digitalocean", "InvalidResponse", `响应不是合法 JSON（HTTP ${raw.status}）：${raw.text.slice(0, 200)}`, undefined, raw.status);
    }
    if (raw.status >= 400) throw toError(raw.status, (parsed ?? undefined) as DoError | undefined, raw.text);
    return parsed as T;
  };
  return req.retry === false ? once() : withRetry(ctx, once);
}

/** 防御性去掉一层引号：DigitalOcean 返回的 data 不带引号，但用户在控制台手动加的记录可能带 */
const unquote = (s = "") => (s.length >= 2 && s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1) : s);

/** 该名字下值为 record.value 的 TXT 记录 */
async function findTxt(ctx: QueryContext, creds: DigitalOceanCredentials, record: TxtRecord, retry: boolean): Promise<DoRecord[]> {
  const rel = relativeName(record.fqdn, record.zone.name);
  // 文档：name 过滤参数必须是完整记录名
  const query = new URLSearchParams({ type: "TXT", name: record.fqdn, per_page: String(PAGE) });
  const items = await paginate(PAGE, async (page) => {
    const res = await doRequest<{ domain_records?: DoRecord[]; meta?: { total?: number } }>(
      ctx,
      creds,
      `/domains/${enc(record.zone.id)}/records?${query}&page=${page}`,
      { retry },
    );
    return { items: res.domain_records ?? [], total: res.meta?.total };
  });
  // 返回的 name 是相对名（根为 @）；本地再按类型、名字、值过滤一遍，即使过滤参数没生效也不会认错记录
  return items.filter((r) => {
    const name = normalizeName(r.name ?? "");
    return r.type === "TXT" && (name === rel || name === record.fqdn) && unquote(r.data) === record.value;
  });
}

async function deleteRecord(ctx: QueryContext, creds: DigitalOceanCredentials, record: TxtRecord, id: string): Promise<void> {
  try {
    await doRequest(ctx, creds, `/domains/${enc(record.zone.id)}/records/${enc(id)}`, { method: "DELETE" });
  } catch (e) {
    // 已经不存在视为成功
    if (e instanceof CloudApiError && e.httpStatus === 404) return;
    throw e;
  }
}

export const digitaloceanDns = defineDns<DigitalOceanCredentials>({
  vendor: "digitalocean",
  label: "DigitalOcean",
  ...varsEnv<DigitalOceanCredentials>([{ name: "DIGITALOCEAN_TOKEN", aliases: ["DIGITALOCEAN_ACCESS_TOKEN"], required: true, secret: true }], (v) => ({ token: v.DIGITALOCEAN_TOKEN! })),
  nameServerPattern: /^ns[1-3]\.digitalocean\.com$/,

  async listZones(ctx, creds) {
    const domains = await paginate(PAGE, async (page) => {
      const res = await doRequest<{ domains?: { name: string }[]; meta?: { total?: number } }>(ctx, creds, `/domains?page=${page}&per_page=${PAGE}`);
      return { items: res.domains ?? [], total: res.meta?.total };
    });
    // DigitalOcean 的域名没有「待接入 / 未激活」状态，也不返回 NS（固定为 ns1~3.digitalocean.com，按 nameServerPattern 判定）。
    // 接口按域名寻址，id 即域名
    return domains.map((d) => {
      const name = normalizeName(d.name);
      return { name, id: name };
    });
  },

  async addTxt(ctx, creds, record) {
    const rel = relativeName(record.fqdn, record.zone.name);
    // 新增不是幂等的，文档也没说同名同值会不会被拒：每次尝试（含自动重试）都先查同名同值的记录，有就直接用，免得超时重发后多出一条
    return withRetry(ctx, async () => {
      const existing = (await findTxt(ctx, creds, record, false))[0];
      if (existing) return String(existing.id);
      try {
        const res = await doRequest<{ domain_record?: DoRecord }>(ctx, creds, `/domains/${enc(record.zone.id)}/records`, {
          method: "POST",
          body: { type: "TXT", name: rel, data: record.value, ttl: TTL },
          retry: false,
        });
        if (typeof res.domain_record?.id !== "number") throw new CloudApiError("digitalocean", "InvalidResponse", "新增记录的响应里没有记录 ID");
        return String(res.domain_record.id);
      } catch (e) {
        // 被判为重复（422）时再查一次，已有就按同名同值已存在处理；422 也可能是别的校验错误（如同名 CNAME 冲突），查不到就照原样报
        if (e instanceof CloudApiError && e.httpStatus === 422) {
          const again = (await findTxt(ctx, creds, record, false))[0];
          if (again) return String(again.id);
        }
        throw e;
      }
    });
  },

  async removeTxt(ctx, creds, record, handle) {
    // 先按句柄（记录 ID）删；再把同名同值的其他记录一并删掉：DigitalOcean 若不拒绝重复记录，超时重发可能多加了一条。
    // 只删值等于本次验证值的记录，同名下的其他值不动
    await deleteRecord(ctx, creds, record, handle);
    let rest: DoRecord[];
    try {
      rest = await findTxt(ctx, creds, record, true);
    } catch (e) {
      // 域名已经不在账号里，记录自然也不在了
      if (e instanceof CloudApiError && e.httpStatus === 404) return;
      throw e;
    }
    for (const r of rest) if (String(r.id) !== handle) await deleteRecord(ctx, creds, record, String(r.id));
  },
});
