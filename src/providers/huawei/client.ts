import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, send, withRetry, type QueryContext } from "../../lib/http.js";
import { memo } from "../../lib/paginate.js";
import { apigAuthorization, canonicalQuery, hwEscape, sdkDate } from "./sign.js";

export interface HuaweiRequest {
  host: string;
  path: string;
  /** 缺省 GET */
  method?: "GET" | "POST" | "PUT";
  query?: Record<string, string | number | undefined>;
  /** JSON 请求体，参与签名；证书私钥等敏感内容只能放在这里，不能放在 query 上 */
  body?: unknown;
  /** 区域级服务（如视频直播）用 AK/SK 认证时必须带 X-Project-Id */
  projectId?: string;
  /** 默认对限流、超时等自动重试；非幂等的写接口（导入证书）传 false 只发一次，由调用方查重后自行重试 */
  retry?: boolean;
}

interface ErrorFields {
  error_code?: unknown;
  error_msg?: unknown;
  code?: unknown;
  message?: unknown;
  title?: unknown;
  request_id?: unknown;
}

const str = (v: unknown) => (typeof v === "string" && v ? v : undefined);

// 服务自定义的限流错误码不是 HTTP 429（网关层 APIGW.0308 为 429，withRetry 已能识别），加 Throttling. 前缀交给 withRetry 重试
const THROTTLE_CODES = new Set(["LIVE.100011007"]);

/**
 * 错误体有三种形态：API 网关与多数服务为顶层 {error_code, error_msg, request_id}；
 * CDN 部分接口为 {error: {error_code, error_msg}}；IAM（Keystone）为 {error: {code: 401, title, message}}。
 * CDN 的业务错误可能以 HTTP 200 返回，所以 200 也要检查；顶层 code/message 只在 4xx/5xx 时才当作错误，以免误判正常数据。
 */
function findError(body: unknown, status: number): { code: string; message: string; requestId?: string } | undefined {
  if (!body || typeof body !== "object") return undefined;
  const b = body as ErrorFields & { error?: unknown };
  const requestId = str(b.request_id);
  const top = str(b.error_code);
  if (top) return { code: top, message: str(b.error_msg) ?? top, requestId };
  if (b.error && typeof b.error === "object") {
    const e = b.error as ErrorFields;
    const code = str(e.error_code) ?? str(e.code) ?? str(e.title) ?? (status >= 400 ? `HTTP${status}` : undefined);
    if (code) return { code, message: str(e.error_msg) ?? str(e.message) ?? code, requestId: requestId ?? str(e.request_id) };
  }
  if (status >= 400) {
    const code = str(b.code) ?? `HTTP${status}`;
    return { code, message: str(b.message) ?? `HTTP ${status}`, requestId };
  }
  return undefined;
}

/**
 * 调用华为云 API 网关下的 REST 接口（SDK-HMAC-SHA256，请求体参与签名），返回解析后的 JSON；
 * 写接口成功时可能没有响应体（如 CDN 修改配置返回 204），此时返回空对象。
 * RequestId 只在 X-Request-Id 响应头里稳定出现，send() 拿不到响应头，这里取错误体中的 request_id（网关错误都带）。
 */
export async function callHuawei<T>(ctx: QueryContext, creds: AccessKeyCredentials, req: HuaweiRequest): Promise<T> {
  const once = async (): Promise<T> => {
    const query = Object.fromEntries(
      Object.entries(req.query ?? {})
        .filter(([, v]) => v !== undefined && v !== "")
        .map(([k, v]) => [k, String(v)]),
    );
    const method = req.method ?? "GET";
    const body = req.body === undefined ? undefined : JSON.stringify(req.body);
    const signed: Record<string, string> = { "X-Sdk-Date": sdkDate(new Date()) };
    if (req.projectId) signed["X-Project-Id"] = req.projectId;
    if (creds.securityToken) signed["X-Security-Token"] = creds.securityToken;
    const authorization = apigAuthorization({
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
      method,
      path: req.path,
      query,
      // Host 由 fetch 自动带上，只参与签名
      headers: { ...signed, Host: req.host },
      body,
    });
    // 与官方 SDK 一致：Content-Type 照常发送但不参与签名
    const headers = { ...signed, "Content-Type": "application/json", Authorization: authorization };
    const qs = canonicalQuery(query);
    // 路径段与签名时一样逐段编码（如泛域名 *.example.com 里的 *），与官方 SDK 发出的 URL 一致
    const path = req.path.split("/").map(hwEscape).join("/");
    const raw = await send(ctx, "huawei", `https://${req.host}${path}${qs ? `?${qs}` : ""}`, { method, headers, ...(body !== undefined && { body }) });
    if (method !== "GET" && raw.status < 400 && raw.text.trim() === "") return {} as T;
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw.text);
    } catch {
      const code = raw.status >= 400 ? `HTTP${raw.status}` : "InvalidResponse";
      throw new CloudApiError("huawei", code, `响应不是合法 JSON（HTTP ${raw.status}）：${raw.text.slice(0, 200)}`, undefined, raw.status);
    }
    const err = findError(parsed, raw.status);
    if (err) {
      const code = THROTTLE_CODES.has(err.code) ? `Throttling.${err.code}` : err.code;
      throw new CloudApiError("huawei", code, err.message, err.requestId, raw.status);
    }
    return parsed as T;
  };
  return req.retry === false ? once() : withRetry(ctx, once);
}

/** 全局 IAM endpoint，查询项目不区分地域 */
const IAM_HOST = "iam.myhuaweicloud.com";

interface KeystoneProject {
  id: string;
  /** 地域的系统项目名即地域 ID（如 cn-north-4）；子项目为 "<地域>_<名称>"；MOS 为 OBS 内置项目 */
  name: string;
  enabled?: boolean;
}

const cachedProjects = memo<QueryContext, Map<string, string>>();

/**
 * 地域 ID → 项目 ID（只取各地域的系统项目，不含子项目）。
 * 用 KeystoneListAuthProjects（GET /v3/auth/projects）：IAM 文档注明「当前API调用无需策略权限」，
 * 比官方 SDK 自动获取 project_id 用的 KeystoneListProjects 少要求一项 iam:projects:listProjects 权限。
 */
export function listProjects(ctx: QueryContext, creds: AccessKeyCredentials): Promise<Map<string, string>> {
  return cachedProjects(ctx, `iam:${creds.accessKeyId}`, async () => {
    const res = await callHuawei<{ projects?: KeystoneProject[] }>(ctx, creds, { host: IAM_HOST, path: "/v3/auth/projects" });
    return new Map((res.projects ?? []).filter((p) => p.enabled !== false && p.id && p.name).map((p) => [p.name, p.id]));
  });
}
