import { createHash } from "node:crypto";
import { CloudApiError, isRetryableCode, send, withRetry, type QueryContext } from "../lib/http.js";
import { varsEnv } from "./env.js";
import { defineDns, normalizeName, relativeName, type DnsZone, type TxtRecord } from "./types.js";

export interface AzureCredentials { tenantId: string; clientId: string; clientSecret: string; subscriptionId: string }

/**
 * Azure DNS（ARM，https://learn.microsoft.com/rest/api/dns/）。只支持全球版 Azure（management.azure.com）和服务主体 + 客户端密码。
 * 记录集模型：同名的全部 TXT 值是一个记录集，PUT 整体替换，所以先 GET 出现有记录集、改好后带 If-Match: etag 写回，防止覆盖并发改动。
 */
const ARM = "https://management.azure.com";
const LOGIN = "https://login.microsoftonline.com";
/** Microsoft.Network/dnsZones 最新的稳定版（azure-rest-api-specs 的 stable 目录；之后只有 2023-07-01-preview） */
const API_VERSION = "2018-05-01";
const SCOPE = "https://management.azure.com/.default";
const TTL = 60;
const MAX_PAGES = 1000;
/** 提前 60 秒换新令牌，免得请求途中过期 */
const REFRESH_MARGIN_MS = 60_000;
const PERMISSION_HINT =
  "服务主体缺少 Azure DNS 权限：请给它分配「DNS 区域参与者」（DNS Zone Contributor）角色，或包含 Microsoft.Network/dnsZones/read、" +
  "Microsoft.Network/dnsZones/TXT/* 的自定义角色；列出区域用的是订阅级接口，建议把角色分配在订阅上";

interface Zone {
  id?: string;
  name?: string;
  properties?: { zoneType?: string; nameServers?: string[] };
}

interface TxtRecordSet {
  id?: string;
  etag?: string;
  properties?: { TTL?: number; metadata?: Record<string, string>; TXTRecords?: { value?: string[] }[] };
}

type Json = Record<string, unknown>;
const str = (v: unknown) => (typeof v === "string" && v ? v : undefined);
const isObject = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);

function tryJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/** 5xx 加 ServiceUnavailable. 前缀交给 withRetry 重试（原始错误码保留在后面）；429 靠 httpStatus 识别 */
const transientCode = (code: string, status: number) => (status >= 500 && !isRetryableCode(code) ? `ServiceUnavailable.${code}` : code);

// ---- 令牌：OAuth 2.0 客户端凭据流（https://learn.microsoft.com/entra/identity-platform/v2-oauth2-client-creds-grant-flow）----

interface Token {
  token: string;
  expiresAt: number;
}

/** 进程内按凭证缓存令牌；键里只放密码的哈希，存 Promise 让同时到来的请求共用一次换取 */
const tokens = new Map<string, Promise<Token>>();
const tokenKey = (c: AzureCredentials) => `${c.tenantId}\n${c.clientId}\n${createHash("sha256").update(c.clientSecret).digest("hex")}`;

/** 常见 AADSTS 错误码对应的处理办法；错误描述本身是英文，补一句中文说明该改哪个变量 */
const AADSTS_HINTS: Record<number, string> = {
  7000215: "AZURE_CLIENT_SECRET 不对：要填客户端密码的「值」，不是「机密 ID」",
  7000222: "客户端密码已过期，请在应用注册里新建一个",
  700016: "该租户下找不到这个应用，请检查 AZURE_CLIENT_ID 与 AZURE_TENANT_ID",
  90002: "找不到该租户，请检查 AZURE_TENANT_ID",
  900023: "AZURE_TENANT_ID 格式不对（应为目录 ID 或租户域名）",
};

/** 错误体为 {error, error_description, error_codes, trace_id, correlation_id}；描述的第一行是「AADSTSxxxx: 原因」，后面几行是追踪号与时间 */
function tokenError(status: number, res: Json): CloudApiError {
  if (status < 400) return new CloudApiError("azure", "InvalidResponse", `令牌响应里没有 access_token（HTTP ${status}）`, undefined, status);
  const error = str(res.error) ?? `HTTP${status}`;
  const reason = str(res.error_description)?.split(/\r?\n/)[0]?.trim();
  const codes = Array.isArray(res.error_codes) ? (res.error_codes as unknown[]) : [];
  const hint = codes.map((c) => AADSTS_HINTS[Number(c)]).find(Boolean) ?? "请检查 AZURE_TENANT_ID、AZURE_CLIENT_ID、AZURE_CLIENT_SECRET";
  const message = `获取 Azure 访问令牌失败（${error}${reason ? `: ${reason}` : ""}）：${hint}`;
  return new CloudApiError("azure", transientCode(error, status), message, str(res.trace_id), status);
}

async function requestToken(ctx: QueryContext, c: AzureCredentials): Promise<Token> {
  // URLSearchParams 会对密码做 URL 编码（文档要求）
  const body = new URLSearchParams({ client_id: c.clientId, scope: SCOPE, client_secret: c.clientSecret, grant_type: "client_credentials" }).toString();
  const raw = await send(ctx, "azure", `${LOGIN}/${encodeURIComponent(c.tenantId)}/oauth2/v2.0/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const parsed = tryJson(raw.text);
  const res = isObject(parsed) ? parsed : {};
  const token = str(res.access_token);
  if (raw.status >= 400 || !token) throw tokenError(raw.status, res);
  const expiresIn = Number(res.expires_in);
  return { token, expiresAt: Date.now() + (expiresIn > 0 ? expiresIn : 3599) * 1000 };
}

async function accessToken(ctx: QueryContext, c: AzureCredentials): Promise<string> {
  const key = tokenKey(c);
  const hit = tokens.get(key);
  if (hit) {
    const t = await hit.catch(() => undefined);
    if (t && Date.now() < t.expiresAt - REFRESH_MARGIN_MS) return t.token;
  }
  const p = requestToken(ctx, c);
  tokens.set(key, p);
  // 失败的不留在缓存里，下次重新换
  p.catch(() => tokens.get(key) === p && tokens.delete(key));
  return (await p).token;
}

// ---- ARM 请求 ----

/** ARM 错误体为 {error: {code, message}}；个别网关错误没有 error 外层。请求号只在 x-ms-request-id 响应头里，send() 拿不到 */
function armError(status: number, body: unknown, text: string): CloudApiError {
  const e = isObject(body) ? (isObject(body.error) ? body.error : body) : undefined;
  const raw = str(e?.code) ?? `HTTP${status}`;
  let message = str(e?.message) ?? (text.slice(0, 200) || `HTTP ${status}`);
  if (raw === "AuthorizationFailed" || raw === "LinkedAuthorizationFailed") message += `（${PERMISSION_HINT}）`;
  else if (raw === "InvalidAuthenticationTokenTenant") message += "（AZURE_SUBSCRIPTION_ID 不属于 AZURE_TENANT_ID 指定的租户）";
  else if (raw === "SubscriptionNotFound") message += "（请检查 AZURE_SUBSCRIPTION_ID）";
  return new CloudApiError("azure", transientCode(raw, status), message, undefined, status);
}

const armUrl = (path: string) => `${ARM}${path}${path.includes("?") ? "&" : "?"}api-version=${API_VERSION}`;

/** 调用 ARM 接口，返回解析后的 JSON（DELETE 等没有响应体时为 undefined）；令牌请求在重试范围内，限流、5xx、超时自动重试 */
function callArm<T>(ctx: QueryContext, c: AzureCredentials, req: { method?: "GET" | "PUT" | "DELETE"; url: string; headers?: Record<string, string>; body?: unknown }): Promise<T | undefined> {
  return withRetry(ctx, async () => {
    const token = await accessToken(ctx, c);
    const raw = await send(ctx, "azure", req.url, {
      method: req.method ?? "GET",
      headers: { Authorization: `Bearer ${token}`, ...(req.body !== undefined && { "Content-Type": "application/json" }), ...req.headers },
      ...(req.body !== undefined && { body: JSON.stringify(req.body) }),
    });
    const parsed = raw.text.trim() ? tryJson(raw.text) : undefined;
    if (raw.status >= 400) {
      // 令牌被提前吊销（如服务主体被删、密码被重置）时丢掉缓存，下次重新换
      if (raw.status === 401) tokens.delete(tokenKey(c));
      throw armError(raw.status, parsed, raw.text);
    }
    if (raw.text.trim() && parsed === undefined) {
      throw new CloudApiError("azure", "InvalidResponse", `响应不是合法 JSON（HTTP ${raw.status}）：${raw.text.slice(0, 200)}`, undefined, raw.status);
    }
    return parsed as T | undefined;
  });
}

/** nextLink 是完整 URL：只跟随指向 ARM 的链接，免得把令牌发到别处 */
function nextUrl(link: string): string {
  let u: URL;
  try {
    u = new URL(link);
  } catch {
    throw new CloudApiError("azure", "InvalidResponse", `分页链接不是合法 URL：${link.slice(0, 200)}`);
  }
  if (u.protocol !== "https:" || u.hostname !== new URL(ARM).hostname) {
    throw new CloudApiError("azure", "InvalidResponse", `分页链接指向了意外的地址：${u.host}`);
  }
  if (!u.searchParams.has("api-version")) u.searchParams.set("api-version", API_VERSION);
  return u.toString();
}

// ---- 记录集 ----

/** 相对名里只有字母、数字、-、_、.；zone 顶点的 @ 不转义（RFC 3986 允许 @ 出现在路径段里） */
const recordSetPath = (record: TxtRecord) =>
  `${encodeURI(record.zone.id)}/TXT/${encodeURIComponent(relativeName(record.fqdn, record.zone.name)).replace(/%40/g, "@")}`;

/** 一条 TXT 记录的 value 是字符串数组（超过 255 字节时拆成多段），拼起来才是完整的值 */
const joined = (r: { value?: string[] }) => (r.value ?? []).join("");

async function getTxtSet(ctx: QueryContext, c: AzureCredentials, path: string): Promise<TxtRecordSet | undefined> {
  try {
    return await callArm<TxtRecordSet>(ctx, c, { url: armUrl(path) });
  } catch (e) {
    if (e instanceof CloudApiError && e.httpStatus === 404) return undefined;
    throw e;
  }
}

/** 写回记录集：保留原有的 TTL 与 metadata（PUT 整体替换，不带上就会被清掉） */
const putBody = (existing: TxtRecordSet | undefined, records: { value?: string[] }[]) => ({
  properties: {
    ...(existing?.properties?.metadata && { metadata: existing.properties.metadata }),
    TTL: existing?.properties?.TTL ?? TTL,
    TXTRecords: records,
  },
});

/**
 * 有 etag 时带 If-Match，别人在我们读和写之间改过就返回 412；新建时带 If-None-Match: *，同时有人建了同名记录集也返回 412。
 * etag 取自响应体的 etag 字段（send() 不返回响应头）
 */
const condition = (existing: TxtRecordSet | undefined): Record<string, string> =>
  existing ? (existing.etag ? { "If-Match": existing.etag } : {}) : { "If-None-Match": "*" };

/** 读出现有记录集交给 step 改写；并发冲突（412 前提条件不满足、409 冲突）时重读重试一次 */
async function readModifyWrite<T>(ctx: QueryContext, c: AzureCredentials, path: string, step: (existing: TxtRecordSet | undefined) => Promise<T>): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    const existing = await getTxtSet(ctx, c, path);
    try {
      return await step(existing);
    } catch (e) {
      if (attempt >= 2 || !(e instanceof CloudApiError) || ![409, 412].includes(e.httpStatus ?? 0)) throw e;
    }
  }
}

export const azureDns = defineDns<AzureCredentials>({
  vendor: "azure",
  label: "Azure DNS",
  ...varsEnv<AzureCredentials>([
    { name: "AZURE_TENANT_ID", required: true, secret: false },
    { name: "AZURE_CLIENT_ID", required: true, secret: false },
    { name: "AZURE_CLIENT_SECRET", required: true, secret: true },
    { name: "AZURE_SUBSCRIPTION_ID", required: true, secret: false },
  ], (v) => ({
    tenantId: v.AZURE_TENANT_ID!,
    clientId: v.AZURE_CLIENT_ID!,
    clientSecret: v.AZURE_CLIENT_SECRET!,
    subscriptionId: v.AZURE_SUBSCRIPTION_ID!,
  })),
  // 全球版 Azure DNS 的权威 NS 为 ns1-xx.azure-dns.com、ns2-xx.azure-dns.net、ns3-xx.azure-dns.org、ns4-xx.azure-dns.info
  nameServerPattern: /(^|\.)azure-dns\.(com|net|org|info)$/,

  async listZones(ctx, creds) {
    const zones: DnsZone[] = [];
    let url: string | undefined = armUrl(`/subscriptions/${encodeURIComponent(creds.subscriptionId)}/providers/Microsoft.Network/dnszones`);
    const seen = new Set<string>();
    while (url) {
      // 防止接口异常（如 nextLink 一直指向同一页）时死循环
      if (seen.has(url) || seen.size >= MAX_PAGES) throw new Error(`分页超过 ${MAX_PAGES} 页或分页链接重复，已中止（接口返回可能异常）`);
      seen.add(url);
      let page: { value?: Zone[]; nextLink?: string } | undefined;
      try {
        page = await callArm<{ value?: Zone[]; nextLink?: string }>(ctx, creds, { url });
      } catch (e) {
        // 订阅没注册 Microsoft.Network 资源提供程序时不可能有 DNS 区域（有资源时也注销不了），按没有 zone 处理
        if (e instanceof CloudApiError && e.code === "MissingSubscriptionRegistration") return zones;
        throw e;
      }
      for (const z of page?.value ?? []) {
        // 旧版私有区域（zoneType = Private）只对虚拟网络可见；现行的私有 DNS 区域是另一种资源（privateDnsZones），不会出现在这里
        if (!z.id || !z.name || z.properties?.zoneType === "Private") continue;
        const nameServers = (z.properties?.nameServers ?? []).map(normalizeName).filter(Boolean);
        // 记录集接口按 zone 的资源 ID（含订阅和资源组）寻址
        const resourceGroup = /\/resourceGroups\/([^/]+)\//i.exec(z.id)?.[1];
        zones.push({
          name: normalizeName(z.name),
          id: z.id,
          ...(nameServers.length > 0 && { nameServers }),
          ...(resourceGroup && { extra: { resourceGroup } }),
        });
      }
      url = page?.nextLink ? nextUrl(page.nextLink) : undefined;
    }
    return zones;
  },

  async addTxt(ctx, creds, record) {
    const path = recordSetPath(record);
    const id = await readModifyWrite(ctx, creds, path, async (existing) => {
      const records = existing?.properties?.TXTRecords ?? [];
      if (records.some((r) => joined(r) === record.value)) return existing?.id;
      const res = await callArm<TxtRecordSet>(ctx, creds, {
        method: "PUT",
        url: armUrl(path),
        headers: condition(existing),
        body: putBody(existing, [...records, { value: [record.value] }]),
      });
      return res?.id;
    });
    // 记录集模型没有单条记录的 ID：句柄是记录集的资源 ID，删除时按 record 重新读取记录集，只去掉这个值
    return id ?? path;
  },

  async removeTxt(ctx, creds, record) {
    const path = recordSetPath(record);
    await readModifyWrite(ctx, creds, path, async (existing) => {
      const records = existing?.properties?.TXTRecords ?? [];
      const rest = records.filter((r) => joined(r) !== record.value);
      if (!existing || rest.length === records.length) return;
      const headers = condition(existing);
      // 只剩我们的值时删掉整个记录集（空记录集在 Azure 里仍是一个资源，留着会在控制台里多出一条空记录）
      if (rest.length === 0) await deleteSet(ctx, creds, path, headers);
      else await callArm(ctx, creds, { method: "PUT", url: armUrl(path), headers, body: putBody(existing, rest) });
    });
  },
});

/** 删除记录集；已经不存在（404）视为成功 */
async function deleteSet(ctx: QueryContext, c: AzureCredentials, path: string, headers: Record<string, string>): Promise<void> {
  try {
    await callArm(ctx, c, { method: "DELETE", url: armUrl(path), headers });
  } catch (e) {
    if (e instanceof CloudApiError && e.httpStatus === 404) return;
    throw e;
  }
}
