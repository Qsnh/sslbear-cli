import { CloudApiError, send, withRetry, type QueryContext } from "../lib/http.js";
import { varsEnv } from "./env.js";
import { dropGoogleToken, googleAccessToken, loadServiceAccount, transientCode, tryJson, type ServiceAccountKey } from "./google-auth.js";
import { defineDns, normalizeName, type DnsZone, type TxtRecord } from "./types.js";

export interface GoogleCredentials { keyFile: string; project?: string }

/**
 * Cloud DNS API v1（https://cloud.google.com/dns/docs/reference/rest/v1，字段以 discovery 文档为准）。
 * 记录集模型：同名同类型的全部 TXT 值是一个 ResourceRecordSet，改动只能通过 changes.create 提交
 * 「删除旧记录集 + 添加新记录集」，deletions 必须与现有数据完全一致，所以每次都先读出现有记录集原样放进 deletions。
 */
const API = "https://dns.googleapis.com/dns/v1";
const TTL = 60;
const MAX_PAGES = 1000;
/** changes.create 返回 pending 时轮询到 done 再返回（lego、acme.sh 也这样做），免得紧接着的读改写读到旧记录集 */
const CHANGE_POLL_MS = 2000;
const CHANGE_POLLS = 15;
/** 老式 Google API 的限流可能是 403 + 这两个 reason，不是 429 */
const THROTTLE_REASONS = new Set(["rateLimitExceeded", "userRateLimitExceeded"]);
const PERMISSION_HINT =
  "服务账号缺少 Cloud DNS 权限：需要 DNS Administrator（roles/dns.admin）角色，或包含 dns.managedZones.list、dns.resourceRecordSets.list、" +
  "dns.changes.create、dns.changes.get、dns.resourceRecordSets.create / update / delete 的自定义角色；也请确认项目 ID 正确";

interface ManagedZone {
  name?: string;
  dnsName?: string;
  visibility?: string;
  nameServers?: string[];
}

interface RRSet {
  name: string;
  type: string;
  ttl?: number;
  rrdatas?: string[];
  routingPolicy?: unknown;
}

interface Change {
  id?: string;
  status?: string;
  additions?: RRSet[];
  deletions?: RRSet[];
}

interface Session {
  key: ServiceAccountKey;
  project: string;
}

type Json = Record<string, unknown>;
const str = (v: unknown) => (typeof v === "string" && v ? v : undefined);
const isObject = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);
const enc = encodeURIComponent;

/** 第一次调用时才读密钥文件；GOOGLE_CLOUD_PROJECT 覆盖密钥里的 project_id */
function session(creds: GoogleCredentials): Session {
  const key = loadServiceAccount(creds.keyFile);
  const project = creds.project ?? key.projectId;
  if (!project) {
    throw new CloudApiError("google", "InvalidCredentials", "服务账号密钥里没有 project_id，请用 GOOGLE_CLOUD_PROJECT 指定 Cloud DNS 所在的项目");
  }
  return { key, project };
}

/**
 * 错误体为 {error: {code, message, status, errors: [{reason, message}]}}；错误码优先取 errors[].reason
 * （Cloud DNS 错误文档按 reason 列举：alreadyExists、preconditionFailed、notFound 等），没有时取 status
 */
function apiError(status: number, body: unknown, text: string): CloudApiError {
  const e = isObject(body) && isObject(body.error) ? body.error : undefined;
  const first = Array.isArray(e?.errors) ? (e.errors as unknown[]).find(isObject) : undefined;
  const raw = str(first?.reason) ?? str(e?.status) ?? `HTTP${status}`;
  let message = str(e?.message) ?? (text.slice(0, 200) || `HTTP ${status}`);
  if (raw === "accessNotConfigured" || raw === "SERVICE_DISABLED") message += "（项目没有启用 Cloud DNS API，请在控制台「API 和服务」里启用 dns.googleapis.com）";
  else if (status === 403 && !THROTTLE_REASONS.has(raw)) message += `（${PERMISSION_HINT}）`;
  else if (status === 401) message += "（访问令牌无效，请确认服务账号密钥有效）";
  const code = THROTTLE_REASONS.has(raw) ? `Throttling.${raw}` : transientCode(raw, status);
  return new CloudApiError("google", code, message, undefined, status);
}

/** 调用 Cloud DNS 接口（路径相对 /projects/{project}）；令牌请求在重试范围内，限流、5xx、超时自动重试 */
function callDns<T>(ctx: QueryContext, s: Session, req: { method?: "GET" | "POST"; path: string; query?: Record<string, string | undefined>; body?: unknown }): Promise<T> {
  return withRetry(ctx, async () => {
    const token = await googleAccessToken(ctx, s.key);
    const query = Object.entries(req.query ?? {}).filter((e): e is [string, string] => !!e[1]);
    const qs = new URLSearchParams(query).toString();
    const raw = await send(ctx, "google", `${API}/projects/${enc(s.project)}${req.path}${qs ? `?${qs}` : ""}`, {
      method: req.method ?? "GET",
      headers: { Authorization: `Bearer ${token}`, ...(req.body !== undefined && { "Content-Type": "application/json" }) },
      ...(req.body !== undefined && { body: JSON.stringify(req.body) }),
    });
    const parsed = tryJson(raw.text);
    if (raw.status >= 400) {
      if (raw.status === 401) dropGoogleToken(s.key);
      throw apiError(raw.status, parsed, raw.text);
    }
    if (parsed === undefined) {
      throw new CloudApiError("google", "InvalidResponse", `响应不是合法 JSON（HTTP ${raw.status}）：${raw.text.slice(0, 200)}`, undefined, raw.status);
    }
    return parsed as T;
  });
}

/** TXT 的 rrdata 是带引号的字符串，超过 255 字节时拆成多段（"a" "b"），读的时候拼起来比较；不带引号的按原文 */
function txtValue(rrdata: string): string {
  const parts = [...rrdata.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]!.replace(/\\(.)/g, "$1"));
  return parts.length > 0 ? parts.join("") : rrdata.trim();
}

const quote = (value: string) => `"${value.replace(/["\\]/g, "\\$&")}"`;

async function getTxtSet(ctx: QueryContext, s: Session, zone: string, name: string): Promise<RRSet | undefined> {
  const res = await callDns<{ rrsets?: RRSet[] }>(ctx, s, { path: `/managedZones/${enc(zone)}/rrsets`, query: { name, type: "TXT" } });
  return res.rrsets?.find((r) => r.type === "TXT" && normalizeName(r.name) === normalizeName(name));
}

/**
 * 提交变更并等它变为 done。查询状态只是为了让下一次读改写读到新记录集：
 * 查询失败（如自定义角色没给 dns.changes.get）或超时仍 pending 都不算失败，变更已被受理，是否生效由编排层查权威 DNS 确认。
 */
async function applyChange(ctx: QueryContext, s: Session, zone: string, change: Change): Promise<void> {
  const res = await callDns<Change>(ctx, s, { method: "POST", path: `/managedZones/${enc(zone)}/changes`, body: change });
  if (res.status !== "pending" || !res.id) return;
  const sleep = ctx.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  for (let i = 0; i < CHANGE_POLLS; i++) {
    await sleep(CHANGE_POLL_MS);
    const current = await callDns<Change>(ctx, s, { path: `/managedZones/${enc(zone)}/changes/${enc(res.id)}` }).catch(() => undefined);
    if (current?.status !== "pending") return;
  }
}

/**
 * 并发冲突：别人在我们读和写之间改了这个记录集——deletions 对不上（412 conditionNotMet / preconditionFailed）、
 * 要添加的记录集已存在（409 alreadyExists）、要删除的已被删掉（404 notFound），重读一次再试。
 * 错误文档只列了 reason 没写 HTTP 状态，状态码取自社区报告（external-dns、lego），两者任一对上都算
 */
const CONFLICT_REASONS = new Set(["conditionNotMet", "preconditionFailed", "alreadyExists", "notFound"]);
const isConflict = (e: unknown) => e instanceof CloudApiError && ([404, 409, 412].includes(e.httpStatus ?? 0) || CONFLICT_REASONS.has(e.code));

/** 读改写，冲突时重读重试一次；step 返回 undefined 表示无需改动 */
async function readModifyWrite(ctx: QueryContext, s: Session, record: TxtRecord, step: (existing: RRSet | undefined, name: string) => Change | undefined): Promise<void> {
  const name = `${record.fqdn}.`;
  for (let attempt = 1; ; attempt++) {
    const existing = await getTxtSet(ctx, s, record.zone.id, name);
    if (existing?.routingPolicy) {
      throw new CloudApiError("google", "UnsupportedRecordSet", `${record.fqdn} 的 TXT 记录集配置了路由策略（routingPolicy），不能自动改动，请在控制台处理`);
    }
    const change = step(existing, name);
    if (!change) return;
    try {
      return await applyChange(ctx, s, record.zone.id, change);
    } catch (e) {
      if (attempt >= 2 || !isConflict(e)) throw e;
    }
  }
}

export const googleDns = defineDns<GoogleCredentials>({
  vendor: "google",
  label: "Google Cloud DNS",
  ...varsEnv<GoogleCredentials>([
    { name: "GOOGLE_APPLICATION_CREDENTIALS", required: true, secret: false },
    { name: "GOOGLE_CLOUD_PROJECT", required: false, secret: false },
  ], (v) => ({ keyFile: v.GOOGLE_APPLICATION_CREDENTIALS!, ...(v.GOOGLE_CLOUD_PROJECT && { project: v.GOOGLE_CLOUD_PROJECT }) })),
  // Cloud DNS 的权威 NS 为 ns-cloud-{a..e}{1..4}.googledomains.com
  nameServerPattern: /^ns-cloud-[a-z]\d+\.googledomains\.com$/,

  async listZones(ctx, creds) {
    const s = session(creds);
    const zones: DnsZone[] = [];
    let pageToken: string | undefined;
    for (let page = 0; page < MAX_PAGES; page++) {
      const res = await callDns<{ managedZones?: ManagedZone[]; nextPageToken?: string }>(ctx, s, { path: "/managedZones", query: { pageToken } });
      for (const z of res.managedZones ?? []) {
        // 私有 zone 只对 VPC 可见，公网验证用不上；visibility 缺省是 public（创建时的默认值）
        if ((z.visibility ?? "public") !== "public" || !z.name || !z.dnsName) continue;
        const nameServers = (z.nameServers ?? []).map(normalizeName).filter(Boolean);
        // 接口按 managed zone 的名称寻址（如 example-com），不是域名
        zones.push({ name: normalizeName(z.dnsName), id: z.name, ...(nameServers.length > 0 && { nameServers }), extra: { project: s.project } });
      }
      if (!res.nextPageToken || res.nextPageToken === pageToken) return zones;
      pageToken = res.nextPageToken;
    }
    throw new Error(`分页超过 ${MAX_PAGES} 页仍未取完，已中止（接口返回可能异常）`);
  },

  async addTxt(ctx, creds, record) {
    const s = session(creds);
    await readModifyWrite(ctx, s, record, (existing, name) => {
      if (existing?.rrdatas?.some((r) => txtValue(r) === record.value)) return undefined;
      // 已有记录集时保留它的其他值和 TTL（TTL 是整个记录集的属性，不替别人改），只追加我们的值
      const addition: RRSet = { name, type: "TXT", ttl: existing?.ttl ?? TTL, rrdatas: [...(existing?.rrdatas ?? []), quote(record.value)] };
      return { additions: [addition], ...(existing && { deletions: [existing] }) };
    });
    // 记录集模型没有单条记录的 ID：句柄是记录集的资源路径，删除时按 record 重新读取记录集，只去掉这个值
    return `projects/${s.project}/managedZones/${record.zone.id}/rrsets/${record.fqdn}./TXT`;
  },

  async removeTxt(ctx, creds, record) {
    const s = session(creds);
    await readModifyWrite(ctx, s, record, (existing) => {
      const rrdatas = existing?.rrdatas ?? [];
      const rest = rrdatas.filter((r) => txtValue(r) !== record.value);
      if (!existing || rest.length === rrdatas.length) return undefined;
      // 其他值原样写回；只剩我们的值时只做 deletion，整个记录集删掉
      return { deletions: [existing], ...(rest.length > 0 && { additions: [{ name: existing.name, type: "TXT", ttl: existing.ttl ?? TTL, rrdatas: rest }] }) };
    });
  },
});
