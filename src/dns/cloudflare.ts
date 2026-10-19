import { CloudApiError, send, withRetry, type QueryContext } from "../lib/http.js";
import { paginate } from "../lib/paginate.js";
import { varsEnv } from "./env.js";
import { defineDns, normalizeName, type DnsZone, type TxtRecord } from "./types.js";

export interface CloudflareCredentials { apiToken: string }

/**
 * Cloudflare API v4（https://developers.cloudflare.com/api/，字段以 GitHub cloudflare/api-schemas 的 OpenAPI 为准）。
 * 每个 TXT 值是一条有独立 ID 的记录，增删一条不影响同名下的其他值。
 */
const API = "https://api.cloudflare.com/client/v4";
/** 文档：DNS only 记录的 TTL 非企业版最小 60、企业版 30；1 表示「自动」，实际是 300 秒 */
const TTL = 60;
/** GET /zones 的 per_page 上限 */
const ZONE_PAGE = 50;
const RECORD_PAGE = 100;
/** 已有完全相同的记录：81057 是旧错误码，现在返回 81058「An identical record already exists.」 */
const DUPLICATE_CODES = new Set(["81057", "81058"]);
/** 81044：记录不存在 */
const NOT_FOUND_CODE = "81044";
/** 6111 Authorization 头格式不对、9109 令牌无效或无权访问该资源、10000 Authentication error（多为缺权限） */
const AUTH_CODES = new Set([6111, 9109, 10000]);
const PERMISSION_HINT =
  "CLOUDFLARE_API_TOKEN 无效或权限不足：令牌需要 Zone → Zone → Read（列出 zone）与 Zone → DNS → Edit（增删 TXT 记录）权限" +
  "（新版权限名为 Zone Read、DNS Write），Zone Resources 要包含该域名所在的 zone";

interface CfMessage {
  code?: number;
  message?: string;
  error_chain?: CfMessage[];
}

interface CfEnvelope<T> {
  success?: boolean;
  errors?: CfMessage[];
  result?: T;
  result_info?: { total_count?: number };
}

interface CfZone {
  id: string;
  name: string;
  status?: string;
  type?: string;
  name_servers?: string[];
  vanity_name_servers?: string[];
}

interface CfRecord {
  id: string;
  type?: string;
  name?: string;
  content?: string;
}

interface CfRequest {
  method?: "GET" | "POST" | "DELETE";
  body?: unknown;
  /** 默认对限流、5xx、超时自动重试；addTxt 自己在外层重试（每次先查重），里面的请求传 false */
  retry?: boolean;
}

const enc = encodeURIComponent;
/** 错误体里的全部错误码（含 error_chain 里的下层原因） */
const codesOf = (errors: CfMessage[] = []): number[] =>
  errors.flatMap((e) => [...(typeof e.code === "number" ? [e.code] : []), ...codesOf(e.error_chain)]);

function toError(status: number, body: CfEnvelope<unknown> | undefined, text: string): CloudApiError {
  const errors = body?.errors ?? [];
  const detail = errors.map((e) => `${e.code}: ${e.message}`).join("；") || text.slice(0, 200) || `HTTP ${status}`;
  const code = errors[0]?.code !== undefined ? String(errors[0].code) : `HTTP${status}`;
  // 429 后 5 分钟内的请求都会被拒（文档 Rate limits）；5xx 记为 ServiceUnavailable，交给 withRetry 重试
  if (status === 429) return new CloudApiError("cloudflare", "Throttling", `请求过于频繁（${detail}）`, undefined, status);
  if (status >= 500) return new CloudApiError("cloudflare", "ServiceUnavailable", `${detail}（HTTP ${status}）`, undefined, status);
  if (status === 401 || status === 403 || codesOf(errors).some((c) => AUTH_CODES.has(c))) {
    return new CloudApiError("cloudflare", code, `${detail}。${PERMISSION_HINT}`, undefined, status);
  }
  return new CloudApiError("cloudflare", code, detail, undefined, status);
}

/** 调用 Cloudflare API v4，返回解析后的响应信封；失败（HTTP 4xx/5xx 或 success: false）抛 CloudApiError */
async function cfRequest<T>(ctx: QueryContext, creds: CloudflareCredentials, path: string, req: CfRequest = {}): Promise<CfEnvelope<T>> {
  const method = req.method ?? "GET";
  const body = req.body === undefined ? undefined : JSON.stringify(req.body);
  const once = async (): Promise<CfEnvelope<T>> => {
    const headers: Record<string, string> = { Authorization: `Bearer ${creds.apiToken}`, Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const raw = await send(ctx, "cloudflare", `${API}${path}`, { method, headers, ...(body !== undefined && { body }) });
    let parsed: CfEnvelope<T> | undefined;
    try {
      parsed = JSON.parse(raw.text) as CfEnvelope<T>;
    } catch {
      // 网关层的错误（502、限流页等）可能是 HTML
      if (raw.status >= 400) throw toError(raw.status, undefined, raw.text);
      throw new CloudApiError("cloudflare", "InvalidResponse", `响应不是合法 JSON（HTTP ${raw.status}）：${raw.text.slice(0, 200)}`, undefined, raw.status);
    }
    if (raw.status >= 400 || !parsed || parsed.success === false) throw toError(raw.status, parsed ?? undefined, raw.text);
    return parsed;
  };
  return req.retry === false ? once() : withRetry(ctx, once);
}

/** 接口返回的 TXT content 可能带引号（新记录会被自动加上），比较时去掉一层引号 */
const unquote = (s = "") => (s.length >= 2 && s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1) : s);

function toZone(z: CfZone): DnsZone {
  // 自定义 NS（vanity，Business / Enterprise 套餐）也是这个 zone 的权威 NS，域名实际可能委派给它们
  const ns = [...new Set([...(z.name_servers ?? []), ...(z.vanity_name_servers ?? [])].map(normalizeName))].filter(Boolean);
  return { name: normalizeName(z.name), id: z.id, ...(ns.length > 0 && { nameServers: ns }) };
}

/** 该名字下值为 record.value 的 TXT 记录（正常只有一条：Cloudflare 拒绝重复记录） */
async function findTxt(ctx: QueryContext, creds: CloudflareCredentials, record: TxtRecord, retry: boolean): Promise<CfRecord[]> {
  const query = new URLSearchParams({ type: "TXT", "name.exact": record.fqdn, per_page: String(RECORD_PAGE) });
  const items = await paginate(RECORD_PAGE, async (page) => {
    const res = await cfRequest<CfRecord[]>(ctx, creds, `/zones/${enc(record.zone.id)}/dns_records?${query}&page=${page}`, { retry });
    return { items: res.result ?? [], total: res.result_info?.total_count };
  });
  // 本地再按类型、名字、值过滤一遍：即使过滤参数没生效，也不会认错记录
  return items.filter((r) => r.id && r.type === "TXT" && normalizeName(r.name ?? "") === record.fqdn && unquote(r.content) === record.value);
}

export const cloudflareDns = defineDns<CloudflareCredentials>({
  vendor: "cloudflare",
  label: "Cloudflare",
  ...varsEnv<CloudflareCredentials>([{ name: "CLOUDFLARE_API_TOKEN", required: true, secret: true }], (v) => ({ apiToken: v.CLOUDFLARE_API_TOKEN! })),
  nameServerPattern: /\.ns\.cloudflare\.com$/,

  async listZones(ctx, creds) {
    const zones = await paginate(ZONE_PAGE, async (page) => {
      const res = await cfRequest<CfZone[]>(ctx, creds, `/zones?page=${page}&per_page=${ZONE_PAGE}`);
      return { items: res.result ?? [], total: res.result_info?.total_count };
    });
    // 只要 status=active：initializing / pending 是 NS 还没改到 Cloudflare（待接入），moved 是 NS 已经改走，这些 zone 里的记录不会被解析到。
    // 只要 type=full（缺省即 full）：partial（CNAME 接入）的权威 DNS 在别家；secondary 的记录从主 DNS 同步过来，不能用接口改
    return zones.filter((z) => z.status === "active" && (z.type ?? "full") === "full").map(toZone);
  },

  async addTxt(ctx, creds, record) {
    // 新增不是幂等的：每次尝试（含自动重试）都先查同名同值的记录，有就直接用，免得超时重发后报「已存在」或误判失败
    return withRetry(ctx, async () => {
      const existing = (await findTxt(ctx, creds, record, false))[0];
      if (existing) return existing.id;
      try {
        // content 按 RFC 1035 的字符串形式带上引号（OpenAPI 的要求；不带引号时 Cloudflare 也会自动加上）
        const res = await cfRequest<CfRecord>(ctx, creds, `/zones/${enc(record.zone.id)}/dns_records`, {
          method: "POST",
          body: { type: "TXT", name: record.fqdn, content: `"${record.value}"`, ttl: TTL },
          retry: false,
        });
        if (!res.result?.id) throw new CloudApiError("cloudflare", "InvalidResponse", "新增记录的响应里没有记录 ID");
        return res.result.id;
      } catch (e) {
        // 查完到提交之间同一条已被加上（比如上一次提交其实成功了）：按同名同值已存在处理
        if (e instanceof CloudApiError && DUPLICATE_CODES.has(e.code)) {
          const again = (await findTxt(ctx, creds, record, false))[0];
          if (again) return again.id;
        }
        throw e;
      }
    });
  },

  async removeTxt(ctx, creds, record, handle) {
    // 句柄是记录 ID，只删这一条；同名下的其他值是别的记录，不受影响
    try {
      await cfRequest(ctx, creds, `/zones/${enc(record.zone.id)}/dns_records/${enc(handle)}`, { method: "DELETE" });
    } catch (e) {
      if (e instanceof CloudApiError && (e.httpStatus === 404 || e.code === NOT_FOUND_CODE)) return;
      throw e;
    }
  },
});
