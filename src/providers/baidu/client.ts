import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, send, withRetry, type QueryContext } from "../../lib/http.js";
import { explainDenied } from "./iam.js";
import { bceAuthorization, bceTimestamp, canonicalPath, uriEncode } from "./sign.js";

export interface BceRequest {
  host: string;
  path: string;
  query?: Record<string, string>;
  /** 默认 GET；DELETE 没有请求体，不带 Content-Type */
  method?: "GET" | "PUT" | "POST" | "DELETE";
  /** JSON 请求体（证书、私钥只能放在这里，不能放在 URL 上） */
  body?: unknown;
  /** 默认对限流、超时等自动重试；非幂等的写接口（上传证书）传 false，由调用方查重后自行重试 */
  retry?: boolean;
}

interface BceErrorBody {
  code?: string;
  message?: string;
  requestId?: string;
}

// 百度智能云没有公开统一的限流错误码；withRetry 认不出的限流类名称换成 Throttling 交给它重试，原始码保留在 message 里
const THROTTLE = /RateLimit|TooManyRequests/i;

/**
 * 调用百度智能云 REST API（bce-auth-v1 签名），返回解析后的 JSON。
 * 有请求体时以 JSON 发送，Content-Type 参与签名。
 * 错误以 HTTP 状态码表示，响应体为 {code, message, requestId}。
 */
export async function callBce<T>(ctx: QueryContext, creds: AccessKeyCredentials, req: BceRequest): Promise<T> {
  const once = async (): Promise<T> => {
    const query = req.query ?? {};
    const method = req.method ?? "GET";
    const timestamp = bceTimestamp(new Date());
    const headers: Record<string, string> = { "x-bce-date": timestamp };
    if (creds.securityToken) headers["x-bce-security-token"] = creds.securityToken;
    const payload = req.body === undefined ? undefined : JSON.stringify(req.body);
    // 与 sslbear-e2e 实测通过的写法一致
    if (payload !== undefined) headers["Content-Type"] = "application/json;charset=utf-8";
    headers.Authorization = bceAuthorization({
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
      method,
      path: req.path,
      query,
      // Host 由 fetch 自动带上，只参与签名
      headers: { ...headers, host: req.host },
      timestamp,
    });
    // 值为空的参数在 URL 里只写参数名（如 config?https，与官方 SDK 一致），签名里仍按规范写成 https=
    const qs = Object.entries(query)
      .map(([k, v]) => (v === "" ? uriEncode(k) : `${uriEncode(k)}=${uriEncode(v)}`))
      .join("&");
    const raw = await send(ctx, "baidu", `https://${req.host}${canonicalPath(req.path)}${qs ? `?${qs}` : ""}`, {
      method,
      headers,
      ...(payload !== undefined && { body: payload }),
    });
    let body: unknown;
    try {
      body = raw.text.trim() ? JSON.parse(raw.text) : {};
    } catch {
      if (raw.status < 400) {
        throw new CloudApiError("baidu", "InvalidResponse", `响应不是合法 JSON（HTTP ${raw.status}）：${raw.text.slice(0, 200)}`, undefined, raw.status);
      }
      // 网关层错误页（非 JSON）：503 按服务不可用重试
      const code = raw.status === 503 ? "ServiceUnavailable" : `HTTP${raw.status}`;
      throw new CloudApiError("baidu", code, `HTTP ${raw.status}：${raw.text.slice(0, 200)}`, undefined, raw.status);
    }
    if (raw.status >= 400) {
      const err = (body ?? {}) as BceErrorBody;
      const code = err.code || `HTTP${raw.status}`;
      const message = err.message || `HTTP ${raw.status}${raw.text.trim() ? "" : "（响应体为空）"}`;
      if (THROTTLE.test(code)) {
        throw new CloudApiError("baidu", "Throttling", `${code}: ${message}`, err.requestId, raw.status);
      }
      throw new CloudApiError("baidu", code, explainDenied(req.host, method, code, message), err.requestId, raw.status);
    }
    return body as T;
  };
  return req.retry === false ? once() : withRetry(ctx, once);
}
