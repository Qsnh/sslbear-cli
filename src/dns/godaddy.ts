import { CloudApiError, send, withRetry, type QueryContext } from "../lib/http.js";
import { varsEnv } from "./env.js";
import { defineDns, normalizeName, relativeName, type DnsZone, type TxtRecord } from "./types.js";

export interface GoDaddyCredentials { apiKey: string; apiSecret: string }

/**
 * GoDaddy Domains API v1（https://developer.godaddy.com/docs/references/rest/domains/v1，
 * 字段以 https://developer.godaddy.com/openapi/domains-v1.json 为准），用 Classic Developer Key（sso-key）鉴权。
 * v1 的记录没有 ID，同类型同名的全部值是一组：新增用 PATCH 追加；删除时读出这一组、去掉本次的值后用 PUT 整组写回，
 * 去掉后为空才 DELETE 这一组。注意 PUT /v1/domains/{domain}/records（不带类型和名字）会替换整个 zone，绝不能用。
 */
const API = "https://api.godaddy.com";
/** 文档（DNSRecord schema）：TTL 最小 600、最大 86400 */
const TTL = 600;
/** GET /v1/domains 的 limit 上限 */
const DOMAIN_PAGE = 1000;
const MAX_PAGES = 1000;
/** GoDaddy 托管 DNS 的权威 NS（nsXX.domaincontrol.com） */
const NS_PATTERN = /\.domaincontrol\.com$/;
const AUTH_HINT =
  "GoDaddy 鉴权失败：请确认 GODADDY_API_KEY / GODADDY_API_SECRET 是同一对 Production（生产环境）密钥（OTE 测试环境的密钥不能用于 api.godaddy.com）。" +
  "GoDaddy 已计划停用 Domains 接口的 Classic Developer Key（sso-key），停用后需改用 Personal Access Token";
const FORBIDDEN_HINT =
  "GoDaddy 拒绝访问：域名管理与 DNS 接口只对符合条件的账号开放（现行文档要求账号在 GoDaddy 至少持有 1 个域名，或有开通管理权限的套餐；" +
  "2024-05 至 2026-04 曾要求 10 个以上域名或 Discount Domain Club 会员），不符合时所有请求都返回 403；也请确认域名属于这对密钥所在的账号";

/** 错误体：code 是稳定的错误码（如 UNABLE_TO_AUTHENTICATE、ACCESS_DENIED、INVALID_BODY），fields 是逐字段的校验错误 */
interface GdError {
  code?: string;
  message?: string;
  fields?: { path?: string; code?: string; message?: string }[];
}

interface GdDomain {
  domain: string;
  status?: string;
  nameServers?: string[] | null;
}

interface GdRecord {
  type?: string;
  name?: string;
  data?: string;
  ttl?: number;
}

interface GdRequest {
  method?: "GET" | "PATCH" | "PUT" | "DELETE";
  body?: unknown;
  /** 默认对限流、5xx、超时自动重试；addTxt 自己在外层重试（每次先查重），里面的请求传 false */
  retry?: boolean;
}

const enc = encodeURIComponent;
/** 记录名做路径段：@（根）原样保留，其余按 URI 组件编码 */
const encName = (name: string) => enc(name).replace(/%40/g, "@");

function toError(status: number, body: GdError | undefined, text: string): CloudApiError {
  const raw = body?.code;
  const fields = (body?.fields ?? []).map((f) => `${f.path ?? ""} ${f.code ?? ""} ${f.message ?? ""}`.trim()).filter(Boolean);
  const message = [body?.message || text.slice(0, 200) || `HTTP ${status}`, ...fields].join("；");
  // 限流时可能没有响应体（文档 Rate limits）；5xx 记为 ServiceUnavailable，交给 withRetry 重试
  if (status === 429) return new CloudApiError("godaddy", "Throttling", `${message}（${raw ?? "HTTP 429"}）`, undefined, status);
  if (status >= 500) return new CloudApiError("godaddy", "ServiceUnavailable", `${message}（${raw ?? `HTTP ${status}`}）`, undefined, status);
  const code = raw ?? `HTTP${status}`;
  if (status === 401) return new CloudApiError("godaddy", code, `${message}。${AUTH_HINT}`, undefined, status);
  if (status === 403) return new CloudApiError("godaddy", code, `${message}。${FORBIDDEN_HINT}`, undefined, status);
  return new CloudApiError("godaddy", code, message, undefined, status);
}

/** 调用 GoDaddy API，返回解析后的 JSON；写接口成功时（200 / 204）没有响应体，返回 undefined */
async function gdRequest<T>(ctx: QueryContext, creds: GoDaddyCredentials, path: string, req: GdRequest = {}): Promise<T | undefined> {
  const method = req.method ?? "GET";
  const body = req.body === undefined ? undefined : JSON.stringify(req.body);
  const once = async (): Promise<T | undefined> => {
    // 不带 Accept 时部分接口可能按 XML 返回
    const headers: Record<string, string> = { Authorization: `sso-key ${creds.apiKey}:${creds.apiSecret}`, Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const raw = await send(ctx, "godaddy", `${API}${path}`, { method, headers, ...(body !== undefined && { body }) });
    // 查询接口没有响应体按非法响应处理，免得把异常当成空列表（删除时据此整组写回，会误删别人的值）
    if (method !== "GET" && raw.status < 400 && raw.text.trim() === "") return undefined;
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw.text);
    } catch {
      if (raw.status >= 400) throw toError(raw.status, undefined, raw.text);
      throw new CloudApiError("godaddy", "InvalidResponse", `响应不是合法 JSON（HTTP ${raw.status}）：${raw.text.slice(0, 200)}`, undefined, raw.status);
    }
    if (raw.status >= 400) throw toError(raw.status, (parsed ?? undefined) as GdError | undefined, raw.text);
    return parsed as T;
  };
  return req.retry === false ? once() : withRetry(ctx, once);
}

/** 防御性去掉一层引号：GoDaddy 返回的 data 不带引号，但用户手动加的记录可能带 */
const unquote = (s = "") => (s.length >= 2 && s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1) : s);

const recordsPath = (record: TxtRecord) => `/v1/domains/${enc(record.zone.id)}/records/TXT/${encName(relativeName(record.fqdn, record.zone.name))}`;

/** 该名字下的全部 TXT 记录（原样返回，删除时要整组写回） */
async function listTxt(ctx: QueryContext, creds: GoDaddyCredentials, record: TxtRecord, retry: boolean): Promise<GdRecord[]> {
  let res: GdRecord[] | undefined;
  try {
    res = await gdRequest<GdRecord[]>(ctx, creds, recordsPath(record), { retry });
  } catch (e) {
    // 名字下没有记录或域名不存在：当作空（域名真不存在时，随后的 PATCH 会报出来）
    if (e instanceof CloudApiError && e.httpStatus === 404) return [];
    throw e;
  }
  if (!Array.isArray(res)) throw new CloudApiError("godaddy", "InvalidResponse", "查询 TXT 记录的响应不是数组");
  return res;
}

/**
 * 只要 DNS 由 GoDaddy 托管的域名：注册局 NS（includes=nameServers）里有 *.domaincontrol.com 才列出，nameServers 只填这些。
 * NS 全在别家（如改到了 Cloudflare）时 GoDaddy 的解析记录不生效，等同其他服务商的「未接入」，不返回；
 * 不能把别家的 NS 填进 nameServers：编排层按 nameServers 判定哪家在解析，填了会让 GoDaddy 也被当成在解析。
 * 接口没返回 NS 时照常列出，按 nameServerPattern 判定。
 */
function toZone(d: GdDomain): DnsZone | undefined {
  const name = normalizeName(d.domain);
  const ns = (d.nameServers ?? []).map(normalizeName).filter(Boolean);
  const own = ns.filter((h) => NS_PATTERN.test(h));
  if (ns.length > 0 && own.length === 0) return undefined;
  // 接口按域名寻址，id 即域名
  return { name, id: name, ...(own.length > 0 && { nameServers: own }) };
}

export const godaddyDns = defineDns<GoDaddyCredentials>({
  vendor: "godaddy",
  label: "GoDaddy",
  ...varsEnv<GoDaddyCredentials>([
    { name: "GODADDY_API_KEY", required: true, secret: false },
    { name: "GODADDY_API_SECRET", required: true, secret: true },
  ], (v) => ({ apiKey: v.GODADDY_API_KEY!, apiSecret: v.GODADDY_API_SECRET! })),
  nameServerPattern: NS_PATTERN,

  async listZones(ctx, creds) {
    const all = new Map<string, GdDomain>();
    let marker = "";
    for (let page = 0; ; page++) {
      if (page >= MAX_PAGES) throw new Error(`分页超过 ${MAX_PAGES} 页仍未取完，已中止（接口返回可能异常）`);
      // 只要 ACTIVE：过期、转入 / 转出中、待验证、冻结等状态的域名改不了解析或解析不生效
      const query = new URLSearchParams({ statuses: "ACTIVE", includes: "nameServers", limit: String(DOMAIN_PAGE) });
      if (marker) query.set("marker", marker);
      const items = await gdRequest<GdDomain[]>(ctx, creds, `/v1/domains?${query}`);
      if (!Array.isArray(items)) throw new CloudApiError("godaddy", "InvalidResponse", "域名列表的响应不是数组");
      const before = all.size;
      for (const d of items) if (d.domain) all.set(normalizeName(d.domain), d);
      // marker 是上一页最后一个域名。不按「不足一页」判断结束（接口悄悄截小 limit 时会漏），取到空页、或没有新域名（接口忽略 marker）为止
      const last = items[items.length - 1]?.domain;
      if (!last || all.size === before) break;
      marker = last;
    }
    return [...all.values()]
      .filter((d) => d.status === "ACTIVE")
      .map(toZone)
      .filter((z): z is DnsZone => z !== undefined);
  },

  async addTxt(ctx, creds, record) {
    const name = relativeName(record.fqdn, record.zone.name);
    // GoDaddy 没有记录 ID，句柄只用于展示与排查；删除时按名字和值定位
    const handle = `TXT:${name}:${record.value}`;
    const has = (records: GdRecord[]) => records.some((r) => unquote(r.data) === record.value);
    // PATCH 追加不是幂等的（文档：重复调用会加出重复记录）：每次尝试（含自动重试）都先查，已有同名同值就直接用
    return withRetry(ctx, async () => {
      if (has(await listTxt(ctx, creds, record, false))) return handle;
      try {
        // PATCH 只追加，同名下已有的其他 TXT 值保留
        await gdRequest(ctx, creds, `/v1/domains/${enc(record.zone.id)}/records`, {
          method: "PATCH",
          body: [{ type: "TXT", name, data: record.value, ttl: TTL }],
          retry: false,
        });
        return handle;
      } catch (e) {
        // 文档没写同名同值时 PATCH 是报错还是重复添加；报 409 / 422 时再查一次，已有就按已存在处理
        if (e instanceof CloudApiError && (e.httpStatus === 409 || e.httpStatus === 422) && has(await listTxt(ctx, creds, record, false))) return handle;
        throw e;
      }
    });
  },

  async removeTxt(ctx, creds, record) {
    const records = await listTxt(ctx, creds, record, true);
    // 去掉本次的值（重复添加出的多条一并去掉），其余原样保留（含各自的 TTL）
    const keep = records.filter((r) => unquote(r.data) !== record.value);
    if (keep.length === records.length) return;
    if (keep.length === 0) {
      try {
        await gdRequest(ctx, creds, recordsPath(record), { method: "DELETE" });
      } catch (e) {
        if (e instanceof CloudApiError && e.httpStatus === 404) return;
        throw e;
      }
      return;
    }
    // PUT /records/TXT/{name} 只替换这个名字下的 TXT，别的名字、别的类型不受影响
    await gdRequest(ctx, creds, recordsPath(record), { method: "PUT", body: keep.map((r) => ({ data: r.data ?? "", ttl: r.ttl ?? TTL })) });
  },
});
