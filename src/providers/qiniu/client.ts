import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, send, withRetry, type QueryContext } from "../../lib/http.js";
import { qboxAuthorization, qiniuAuthorization, qiniuDate } from "./sign.js";

/** 域名管理 / 域名配置接口，官方要求 Qiniu 鉴权 */
export const API_HOST = "api.qiniu.com";
/** 证书管理、用量统计等接口，官方要求 QBox 鉴权 */
export const FUSION_HOST = "fusion.qiniuapi.com";

// 单用户 QPS 上限：api 10、fusion 5-10，超限报 403024。逐域名并发查详情时按最小间隔发出请求
const MIN_INTERVAL_MS = 125;
const nextSlot = new WeakMap<QueryContext, number>();

async function pace(ctx: QueryContext): Promise<void> {
  const now = Date.now();
  const slot = Math.max(now, nextSlot.get(ctx) ?? 0);
  nextSlot.set(ctx, slot + MIN_INTERVAL_MS);
  if (slot > now) await (ctx.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms))))(slot - now);
}

interface QiniuError {
  /**
   * 业务码。失败时为 6 位错误码（如 400401），HTTP 状态码同时为 4xx / 5xx；
   * 成功时各接口不统一：证书列表 GET /sslcert（api 与 fusion 两个 host 都一样）为 0，
   * 上传证书 POST /sslcert、刷新预取等写接口为 200，域名接口不带 code。
   */
  code?: number;
  error?: string;
  /** 网关鉴权失败时返回，如 BadToken */
  error_code?: string;
}

/** 成功响应的业务码：0、200 或缺省；HTTP 2xx 但带其他业务码也按失败处理 */
const isSuccessCode = (code: unknown) => typeof code !== "number" || code === 0 || code === 200;

/**
 * 把七牛的错误响应转成 CloudApiError。限流（HTTP 429 / 573、业务码 403024）统一记为 Throttling、
 * 503 记为 ServiceUnavailable，让 withRetry 识别重试；原始错误码保留在 message 里。
 */
function toError(status: number, body: QiniuError | undefined, text: string): CloudApiError {
  const raw = body?.error_code ?? (typeof body?.code === "number" ? String(body.code) : undefined);
  const message = body?.error || text.slice(0, 200) || `HTTP ${status}`;
  const throttled = status === 429 || status === 573 || raw === "403024";
  if (throttled || (status === 503 && !raw)) {
    const code = throttled ? "Throttling" : "ServiceUnavailable";
    return new CloudApiError("qiniu", code, `${message}（${raw ?? `HTTP ${status}`}）`, undefined, status);
  }
  return new CloudApiError("qiniu", raw ?? `HTTP${status}`, message, undefined, status);
}

export interface QiniuRequest {
  method?: "GET" | "POST" | "PUT";
  /** 按 JSON 发送的请求体（私钥、证书等只放在请求体里，不上 URL） */
  body?: unknown;
  /** 默认对限流、超时等自动重试；非幂等的写接口（上传证书）传 false，由调用方查重后自行重试 */
  retry?: boolean;
}

/**
 * 调用七牛管理接口：api.qiniu.com 用 Qiniu 鉴权（签 X-Qiniu-Date 防重放，JSON 请求体参与签名），
 * fusion.qiniuapi.com 用 QBox 鉴权（只签路径 + query，JSON 请求体不参与）。
 * pathWithQuery 需已编码，签名与实际请求用同一个串。
 */
export async function qiniuRequest<T>(
  ctx: QueryContext,
  creds: AccessKeyCredentials,
  host: string,
  pathWithQuery: string,
  req: QiniuRequest = {},
): Promise<T> {
  const method = req.method ?? "GET";
  const body = req.body === undefined ? undefined : JSON.stringify(req.body);
  const once = async () => {
    await pace(ctx);
    const keys = { accessKey: creds.accessKeyId, secretKey: creds.secretAccessKey };
    const headers: Record<string, string> = {};
    if (host === FUSION_HOST) {
      if (body !== undefined) headers["Content-Type"] = "application/json";
      headers.Authorization = qboxAuthorization({ ...keys, pathWithQuery });
    } else {
      // 与官方 SDK 一致：GET 也显式带上表单 Content-Type 并参与签名
      const contentType = body === undefined ? "application/x-www-form-urlencoded" : "application/json";
      Object.assign(headers, { "Content-Type": contentType, "X-Qiniu-Date": qiniuDate(new Date()) });
      headers.Authorization = qiniuAuthorization({ ...keys, method, host, pathWithQuery, contentType, headers, ...(body !== undefined && { body }) });
    }
    const raw = await send(ctx, "qiniu", `https://${host}${pathWithQuery}`, { method, headers, ...(body !== undefined && { body }) });
    // 写接口成功时可能不带响应体（查询接口仍按非法响应处理，免得把异常当成空列表）
    if (method !== "GET" && raw.status < 400 && raw.text.trim() === "") return {} as T;
    let parsed: (QiniuError & T) | undefined;
    try {
      parsed = JSON.parse(raw.text);
    } catch {
      // 路径不存在等网关错误返回纯文本
      if (raw.status >= 400) throw toError(raw.status, undefined, raw.text);
      throw new CloudApiError("qiniu", "InvalidResponse", `响应不是合法 JSON（HTTP ${raw.status}）：${raw.text.slice(0, 200)}`, undefined, raw.status);
    }
    if (raw.status >= 400 || !isSuccessCode(parsed?.code)) throw toError(raw.status, parsed, raw.text);
    return parsed as T;
  };
  return req.retry === false ? once() : withRetry(ctx, once);
}

/** 以 GET 调用七牛管理接口，见 qiniuRequest */
export function qiniuGet<T>(ctx: QueryContext, creds: AccessKeyCredentials, host: string, pathWithQuery: string): Promise<T> {
  return qiniuRequest<T>(ctx, creds, host, pathWithQuery);
}

const MAX_PAGES = 1000;

/**
 * marker 分页：返回的 marker 为空（或与上次相同、或本页为空）即取完。
 * 七牛的列表接口都不返回总数，接口悄悄截小 limit 时也会按 marker 继续取。实测两种 marker：
 * 域名列表是游标，最后一页仍带 marker，再取一页才返回空列表与空 marker；
 * 证书列表是偏移量（非空页返回 offset + limit），从不为空，取完后下一页返回空列表与原 marker。
 */
export async function listByMarker<T>(
  limit: number,
  fetchPage: (query: string) => Promise<{ items: T[]; marker?: string }>,
): Promise<T[]> {
  const all: T[] = [];
  let marker = "";
  for (let page = 0; page < MAX_PAGES; page++) {
    const { items, marker: next } = await fetchPage(`marker=${encodeURIComponent(marker)}&limit=${limit}`);
    all.push(...items);
    if (!next || next === marker || items.length === 0) return all;
    marker = next;
  }
  throw new Error(`分页超过 ${MAX_PAGES} 页仍未取完，已中止（接口返回可能异常）`);
}
