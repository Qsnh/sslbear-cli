import { randomUUID } from "node:crypto";
import type { AliyunCredentials } from "../../lib/env.js";
import { CloudApiError, parseJson, send, withRetry, type QueryContext } from "../../lib/http.js";
import { canonicalQuery, rpcSignature } from "./sign.js";

export interface RpcRequest {
  endpoint: string;
  version: string;
  action: string;
  params?: Record<string, string | number | undefined>;
}

interface RpcErrorBody {
  Code?: string;
  Message?: string;
  RequestId?: string;
}

/** 调用阿里云 RPC 风格 API（GET + 签名 V1） */
export async function callRpc<T>(ctx: QueryContext, creds: AliyunCredentials, req: RpcRequest): Promise<T> {
  return withRetry(ctx, async () => {
    const params: Record<string, string> = {
      Format: "JSON",
      Version: req.version,
      Action: req.action,
      AccessKeyId: creds.accessKeyId,
      SignatureMethod: "HMAC-SHA1",
      SignatureVersion: "1.0",
      SignatureNonce: randomUUID(),
      Timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    };
    if (creds.securityToken) params.SecurityToken = creds.securityToken;
    for (const [k, v] of Object.entries(req.params ?? {})) {
      if (v !== undefined && v !== "") params[k] = String(v);
    }
    params.Signature = rpcSignature(params, creds.accessKeySecret);
    const raw = await send(ctx, "aliyun", `https://${req.endpoint}/?${canonicalQuery(params)}`, { method: "GET" });
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
  });
}
