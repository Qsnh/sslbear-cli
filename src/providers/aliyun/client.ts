import { randomUUID } from "node:crypto";
import type { AliyunCredentials } from "../../lib/env.js";
import { CloudApiError, parseJson, send, withRetry, type QueryContext } from "../../lib/http.js";
import { canonicalQuery, rpcSignature } from "./sign.js";

export interface RpcRequest {
  endpoint: string;
  version: string;
  action: string;
  params?: Record<string, string | number | undefined>;
  /**
   * 写接口用 POST：业务参数放在表单体里（证书 PEM、私钥不出现在 URL 上），公共参数与签名仍在 URL 上；
   * 签名覆盖两处的全部参数，与官方 SDK 的做法一致
   */
  method?: "GET" | "POST";
}

interface RpcErrorBody {
  Code?: string;
  Message?: string;
  RequestId?: string;
}

/** 调用阿里云 RPC 风格 API（签名 V1），可重试的错误自动重试 */
export function callRpc<T>(ctx: QueryContext, creds: AliyunCredentials, req: RpcRequest): Promise<T> {
  return withRetry(ctx, () => callRpcOnce<T>(ctx, creds, req));
}

/** 只发一次、不自动重试：不幂等的写接口（如上传证书）由调用方先查重再决定是否重试 */
export async function callRpcOnce<T>(ctx: QueryContext, creds: AliyunCredentials, req: RpcRequest): Promise<T> {
  const common: Record<string, string> = {
    Format: "JSON",
    Version: req.version,
    Action: req.action,
    AccessKeyId: creds.accessKeyId,
    SignatureMethod: "HMAC-SHA1",
    SignatureVersion: "1.0",
    SignatureNonce: randomUUID(),
    Timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
  };
  if (creds.securityToken) common.SecurityToken = creds.securityToken;
  const api: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.params ?? {})) {
    if (v !== undefined && v !== "") api[k] = String(v);
  }
  const post = req.method === "POST";
  const query = post ? { ...common } : { ...common, ...api };
  query.Signature = rpcSignature({ ...common, ...api }, creds.accessKeySecret, post ? "POST" : "GET");
  const url = `https://${req.endpoint}/?${canonicalQuery(query)}`;
  const raw = await send(
    ctx,
    "aliyun",
    url,
    post
      ? { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: canonicalQuery(api) }
      : { method: "GET" },
  );
  const body = parseJson("aliyun", raw) as T & RpcErrorBody;
  if (raw.status >= 400) {
    throw new CloudApiError(
      "aliyun",
      body.Code ?? `HTTP${raw.status}`,
      body.Message ?? `HTTP ${raw.status}`,
      body.RequestId,
      raw.status,
    );
  }
  return body;
}
