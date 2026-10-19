import type { TencentCredentials } from "../../lib/env.js";
import { CloudApiError, parseJson, send, withRetry, type QueryContext } from "../../lib/http.js";
import { tc3Authorization } from "./sign.js";

export interface TencentRequest {
  service: string;
  version: string;
  action: string;
  region?: string;
  payload?: Record<string, unknown>;
}

interface TencentEnvelope {
  Response?: {
    Error?: { Code?: string; Message?: string };
    RequestId?: string;
  };
}

/** 调用腾讯云 API 3.0（POST JSON + TC3-HMAC-SHA256），返回 Response 内的业务数据 */
export async function callTencent<T>(ctx: QueryContext, creds: TencentCredentials, req: TencentRequest): Promise<T> {
  return withRetry(ctx, () => callTencentOnce<T>(ctx, creds, req));
}

/**
 * 只发一次、不自动重试：不幂等的写接口（如添加解析记录）由调用方先查重再决定是否重发；
 * 服务自定义的限流错误码也可以先换成 withRetry 认得的码再由调用方重试
 */
export async function callTencentOnce<T>(ctx: QueryContext, creds: TencentCredentials, req: TencentRequest): Promise<T> {
  const host = `${req.service}.tencentcloudapi.com`;
  const payload = JSON.stringify(req.payload ?? {});
  const timestamp = Math.floor(Date.now() / 1000);
  const headers: Record<string, string> = {
    Authorization: tc3Authorization({
      secretId: creds.secretId,
      secretKey: creds.secretKey,
      service: req.service,
      host,
      payload,
      timestamp,
    }),
    "Content-Type": "application/json; charset=utf-8",
    "X-TC-Action": req.action,
    "X-TC-Version": req.version,
    "X-TC-Timestamp": String(timestamp),
    "X-TC-Language": "zh-CN",
  };
  if (req.region) headers["X-TC-Region"] = req.region;
  if (creds.sessionToken) headers["X-TC-Token"] = creds.sessionToken;
  const raw = await send(ctx, "tencent", `https://${host}/`, { method: "POST", headers, body: payload });
  const body = parseJson("tencent", raw) as TencentEnvelope;
  const res = body.Response;
  if (!res) {
    throw new CloudApiError("tencent", `HTTP${raw.status}`, `响应缺少 Response 字段：${raw.text.slice(0, 200)}`, undefined, raw.status);
  }
  if (res.Error) {
    throw new CloudApiError("tencent", res.Error.Code ?? "Unknown", res.Error.Message ?? "未知错误", res.RequestId, raw.status);
  }
  return res as T;
}
