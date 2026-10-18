import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, send, withRetry, type QueryContext } from "../../lib/http.js";
import { canonicalQuery, sha256Hex, volcAuthorization, volcDate } from "./sign.js";

export interface VolcRequest {
  host: string;
  /** 签名用的服务名，大小写以各产品文档为准（如 CDN、vod） */
  service: string;
  region: string;
  version: string;
  action: string;
  /** GET 的参数放 query（只能是标量）；POST 的参数为 JSON body，可嵌套 */
  method: "GET" | "POST";
  params?: Record<string, unknown>;
  /** POST 时额外放在 query 上的参数（如 veImageX 写接口的 ServiceId） */
  query?: Record<string, string>;
}

interface VolcEnvelope {
  ResponseMetadata?: {
    RequestId?: string;
    Error?: { Code?: string; CodeN?: number; Message?: string };
  };
  Result?: unknown;
}

// 产品自定义的限流错误码（DCDN 为 HTTP 400，veImageX 可能是 HTTP 200），不匹配通用重试规则，加上 Throttling. 前缀交给 withRetry 重试；
// 网关层限流 FlowLimitExceeded 为 HTTP 429，ServiceUnavailableTemp 匹配 ServiceUnavailable，无需处理
const THROTTLE_CODES = new Set(["ErrTooManyRequests", "ERR_TOO_MANY_REQUESTS", "600014"]);
// 服务端暂时繁忙 / 内部超时，加上 ServiceUnavailable. 前缀交给 withRetry 重试（编排层的 isRetryable 也据此把失败标为可重试）：
// 实测视频直播偶发 InternalServiceTimeout，重试即成功；证书中心的 SystemBusy、DCDN 的 DomainIsBusy（域名配置变更中）同为暂时状态
const TRANSIENT_CODES = new Set(["InternalServiceTimeout", "SystemBusy", "DomainIsBusy"]);

/**
 * 调用火山引擎 OpenAPI（HMAC-SHA256 签名），返回 Result；限流、超时等可重试的错误自动重试。
 * 业务错误可能是 HTTP 200 也可能是 4xx/5xx（实测鉴权失败在 CDN 为 200、在 DCDN 为 401），一律以 ResponseMetadata.Error 为准。
 */
export function callVolc<T>(ctx: QueryContext, creds: AccessKeyCredentials, req: VolcRequest): Promise<T> {
  return withRetry(ctx, () => callVolcOnce<T>(ctx, creds, req));
}

/** 只发一次、不自动重试：不幂等的写接口（如视频直播 CreateCert）由调用方先查重再决定是否重发 */
export async function callVolcOnce<T>(ctx: QueryContext, creds: AccessKeyCredentials, req: VolcRequest): Promise<T> {
  const params = Object.fromEntries(Object.entries(req.params ?? {}).filter(([, v]) => v !== undefined && v !== ""));
  const query: Record<string, string> = { Action: req.action, Version: req.version, ...req.query };
  let body = "";
  if (req.method === "GET") {
    for (const [k, v] of Object.entries(params)) query[k] = String(v);
  } else {
    body = JSON.stringify(params);
  }
  const headers: Record<string, string> = {
    "X-Date": volcDate(new Date()),
    "X-Content-Sha256": sha256Hex(body),
  };
  if (req.method === "POST") headers["Content-Type"] = "application/json";
  if (creds.securityToken) headers["X-Security-Token"] = creds.securityToken;
  headers.Authorization = volcAuthorization({
    accessKeyId: creds.accessKeyId,
    secretAccessKey: creds.secretAccessKey,
    region: req.region,
    service: req.service,
    method: req.method,
    query,
    // Host 由 fetch 自动带上，只参与签名
    headers: { ...headers, Host: req.host },
    body,
  });
  const raw = await send(ctx, "volcengine", `https://${req.host}/?${canonicalQuery(query)}`, {
    method: req.method,
    headers,
    ...(req.method === "POST" && { body }),
  });
  let parsed: VolcEnvelope;
  try {
    parsed = JSON.parse(raw.text);
  } catch {
    const code = raw.status >= 400 ? `HTTP${raw.status}` : "InvalidResponse";
    throw new CloudApiError("volcengine", code, `响应不是合法 JSON（HTTP ${raw.status}）：${raw.text.slice(0, 200)}`, undefined, raw.status);
  }
  const meta = parsed.ResponseMetadata;
  const err = meta?.Error;
  // veImageX 的业务错误可能是 HTTP 200 + 空 Code + 非零 CodeN（如未开通 601001），没有 Code 时用 CodeN
  if (err && (err.Code || err.CodeN)) {
    const errCode = err.Code || String(err.CodeN);
    const code =
      THROTTLE_CODES.has(errCode) || THROTTLE_CODES.has(String(err.CodeN))
        ? `Throttling.${errCode}`
        : TRANSIENT_CODES.has(errCode)
          ? `ServiceUnavailable.${errCode}`
          : errCode;
    throw new CloudApiError("volcengine", code, err.Message || errCode, meta!.RequestId, raw.status);
  }
  if (raw.status >= 400) {
    // 兜底：错误响应不带 ResponseMetadata.Error 时按 HTTP 状态报错
    throw new CloudApiError("volcengine", `HTTP${raw.status}`, raw.text.slice(0, 200), meta?.RequestId, raw.status);
  }
  // 部分接口的 Result 直接是数组（ListSpace、GetServiceDomains），调用方自行判断
  return (parsed.Result ?? {}) as T;
}
