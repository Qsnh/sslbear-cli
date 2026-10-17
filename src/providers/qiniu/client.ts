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

/**
 * 以 GET 调用七牛管理接口：api.qiniu.com 用 Qiniu 鉴权（签 X-Qiniu-Date 防重放），
 * fusion.qiniuapi.com 用 QBox 鉴权。pathWithQuery 需已编码，签名与实际请求用同一个串。
 */
export async function qiniuGet<T>(ctx: QueryContext, creds: AccessKeyCredentials, host: string, pathWithQuery: string): Promise<T> {
  return withRetry(ctx, async () => {
    await pace(ctx);
    const keys = { accessKey: creds.accessKeyId, secretKey: creds.secretAccessKey };
    let headers: Record<string, string>;
    if (host === FUSION_HOST) {
      headers = { Authorization: qboxAuthorization({ ...keys, pathWithQuery }) };
    } else {
      // 与官方 SDK 一致：GET 也显式带上表单 Content-Type 并参与签名
      headers = { "Content-Type": "application/x-www-form-urlencoded", "X-Qiniu-Date": qiniuDate(new Date()) };
      headers.Authorization = qiniuAuthorization({ ...keys, method: "GET", host, pathWithQuery, contentType: headers["Content-Type"]!, headers });
    }
    const raw = await send(ctx, "qiniu", `https://${host}${pathWithQuery}`, { method: "GET", headers });
    let body: (QiniuError & T) | undefined;
    try {
      body = JSON.parse(raw.text);
    } catch {
      // 路径不存在等网关错误返回纯文本
      if (raw.status >= 400) throw toError(raw.status, undefined, raw.text);
      throw new CloudApiError("qiniu", "InvalidResponse", `响应不是合法 JSON（HTTP ${raw.status}）：${raw.text.slice(0, 200)}`, undefined, raw.status);
    }
    if (raw.status >= 400 || !isSuccessCode(body?.code)) throw toError(raw.status, body, raw.text);
    return body as T;
  });
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
