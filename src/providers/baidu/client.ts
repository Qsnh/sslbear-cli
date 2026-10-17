import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, send, withRetry, type QueryContext } from "../../lib/http.js";
import { bceAuthorization, bceTimestamp, canonicalPath, canonicalQuery } from "./sign.js";

export interface BceRequest {
  host: string;
  path: string;
  query?: Record<string, string>;
}

interface BceErrorBody {
  code?: string;
  message?: string;
  requestId?: string;
}

// 百度智能云没有公开统一的限流错误码；withRetry 认不出的限流类名称换成 Throttling 交给它重试，原始码保留在 message 里
const THROTTLE = /RateLimit|TooManyRequests/i;

/**
 * 调用百度智能云 REST API（GET + bce-auth-v1 签名），返回解析后的 JSON。
 * 错误以 HTTP 状态码表示，响应体为 {code, message, requestId}。
 */
export async function callBce<T>(ctx: QueryContext, creds: AccessKeyCredentials, req: BceRequest): Promise<T> {
  return withRetry(ctx, async () => {
    const query = req.query ?? {};
    const timestamp = bceTimestamp(new Date());
    const headers: Record<string, string> = { "x-bce-date": timestamp };
    if (creds.securityToken) headers["x-bce-security-token"] = creds.securityToken;
    headers.Authorization = bceAuthorization({
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
      method: "GET",
      path: req.path,
      query,
      // Host 由 fetch 自动带上，只参与签名
      headers: { ...headers, host: req.host },
      timestamp,
    });
    const qs = canonicalQuery(query);
    const raw = await send(ctx, "baidu", `https://${req.host}${canonicalPath(req.path)}${qs ? `?${qs}` : ""}`, { method: "GET", headers });
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
      const message = err.message || `HTTP ${raw.status}`;
      if (THROTTLE.test(code)) {
        throw new CloudApiError("baidu", "Throttling", `${code}: ${message}`, err.requestId, raw.status);
      }
      throw new CloudApiError("baidu", code, message, err.requestId, raw.status);
    }
    return body as T;
  });
}
