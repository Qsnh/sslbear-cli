import { CloudApiError, isRetryableCode, send, withRetry, type QueryContext, type RawResponse } from "../lib/http.js";
import { xmlBlocks, xmlText } from "../lib/xml.js";
import { canonicalQueryString, signV4 } from "./aws-sign.js";
import { varsEnv } from "./env.js";
import { defineDns, normalizeName, type DnsZone, type TxtRecord } from "./types.js";

export interface AwsCredentials { accessKeyId: string; secretAccessKey: string; sessionToken?: string }

/**
 * Route 53 是全局服务：中国区以外一律走 route53.amazonaws.com，签名 region 固定 us-east-1
 * （docs.aws.amazon.com/general/latest/gr/r53.html）。中国区（route53.amazonaws.com.cn，cn-northwest-1）暂不支持。
 */
const HOST = "route53.amazonaws.com";
const REGION = "us-east-1";
const SERVICE = "route53";
const API = "/2013-04-01";
const XMLNS = "https://route53.amazonaws.com/doc/2013-04-01/";
/** ListHostedZones 每页最多 100 个 */
const PAGE_SIZE = 100;
/** 防止接口异常（如一直返回同一个 NextMarker）时死循环 */
const MAX_PAGES = 1000;
/** Route 53 允许 0–2147483647；验证记录用完即删，TTL 只决定递归解析器缓存多久，取与其他服务商一致的 60 秒 */
const TTL = 60;

// PriorRequestNotComplete（HTTP 400）：同一 hosted zone 的上一个变更还没处理完，文档建议退避后重试；
// 根域名与泛域名的验证值先后写进同一个 zone 时容易碰到。不匹配通用重试规则，加 Throttling. 前缀交给 withRetry
const THROTTLE_CODES = new Set(["PriorRequestNotComplete"]);
// REST-XML 接口实际返回 AccessDenied，通用错误列表里写的是 AccessDeniedException，两个都认
const ACCESS_DENIED = new Set(["AccessDenied", "AccessDeniedException"]);
const PERMISSIONS = "route53:ListHostedZones、route53:ListResourceRecordSets、route53:ChangeResourceRecordSets";

interface R53Request {
  /** 接口名，只用于错误提示 */
  action: string;
  method: "GET" | "POST";
  path: string;
  query?: Record<string, string>;
  /** POST 的 XML 请求体 */
  body?: string;
  /** 成功响应的根元素：200 但内容不对（如被代理 / 网关页面替换）时报错，免得被当成「没有 zone / 没有记录」 */
  root: string;
}

/** 调用 Route 53 REST 接口（SigV4 签名），返回响应 XML；限流、5xx 等可重试的错误自动重试 */
function call(ctx: QueryContext, creds: AwsCredentials, req: R53Request): Promise<string> {
  return withRetry(ctx, async () => {
    const signed = signV4({
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
      ...(creds.sessionToken && { sessionToken: creds.sessionToken }),
      region: REGION,
      service: SERVICE,
      method: req.method,
      host: HOST,
      path: req.path,
      query: req.query ?? {},
      headers: req.body !== undefined ? { "Content-Type": "application/xml" } : {},
      body: req.body ?? "",
      // 每次重试重新签名：签名带时间，ctx.now 是命令开始的时间，不能用
      date: new Date(),
    });
    const qs = canonicalQueryString(req.query ?? {});
    const raw = await send(ctx, "aws", `https://${HOST}${req.path}${qs ? `?${qs}` : ""}`, {
      method: req.method,
      headers: signed.headers,
      ...(req.body !== undefined && { body: req.body }),
    });
    if (raw.status >= 400) throw toError(raw, req.action);
    if (!new RegExp(`<${req.root}[\\s>]`).test(raw.text)) {
      throw new CloudApiError("aws", "InvalidResponse", `${req.action} 响应不是预期的 XML（HTTP ${raw.status}）：${raw.text.slice(0, 200)}`, undefined, raw.status);
    }
    return raw.text;
  });
}

/** 同名标签的全部文本（已反转义 XML 实体）；xmlText 只取第一个，这里给每一块套回标签再取 */
const xmlTexts = (xml: string, tag: string) => xmlBlocks(xml, tag).map((b) => xmlText(`<${tag}>${b}</${tag}>`, tag) ?? "");

/**
 * 错误响应有两种（aws-sdk-go route53/unmarshal_error.go 同样按根元素区分）：
 * - 通用：<ErrorResponse><Error><Type/><Code/><Message/></Error><RequestId/></ErrorResponse>
 * - ChangeResourceRecordSets 的校验失败：<InvalidChangeBatch><Messages><Message/>…</Messages><RequestId/></InvalidChangeBatch>
 */
function toError(raw: RawResponse, action: string): CloudApiError {
  const requestId = xmlText(raw.text, "RequestId");
  let code: string;
  let message: string;
  if (/<InvalidChangeBatch[\s>]/.test(raw.text)) {
    code = "InvalidChangeBatch";
    message = xmlTexts(xmlBlocks(raw.text, "Messages")[0] ?? "", "Message").join("；") || xmlText(raw.text, "Message") || "变更校验失败";
  } else {
    const err = xmlBlocks(raw.text, "Error")[0];
    // 网关层错误可能不是 XML（如 502 的 HTML 页面），按 HTTP 状态报
    code = (err && xmlText(err, "Code")) || `HTTP${raw.status}`;
    message = (err && xmlText(err, "Message")) || raw.text.slice(0, 200) || `HTTP ${raw.status}`;
  }
  if (ACCESS_DENIED.has(code)) {
    message = `${message}（${action} 被拒绝：DNS 验证需要 IAM 权限 ${PERMISSIONS}，见 docs/permissions.md）`;
  } else if (code === "InvalidChangeBatch" && /CNAME/.test(message)) {
    // 设计约定：_acme-challenge 已 CNAME 到别处（DNS 别名模式）不支持，报错里说明原因
    message = `${message}（该名字已有 CNAME 记录，不能再加 TXT；_acme-challenge 用 CNAME 委托到别处的方式暂不支持）`;
  } else if (code === "InvalidClientTokenId") {
    message = `${message}（AWS_ACCESS_KEY_ID 无效；AWS 中国区的密钥不能用于全球区的 Route 53，中国区暂不支持）`;
  }
  // 5xx（InternalFailure、网关错误等）是服务端暂时故障，加 ServiceUnavailable. 前缀交给 withRetry 重试；
  // 写操作重试是安全的：变更批次里带着精确的旧记录集，上一次其实已生效时重复提交会对不上、整批被拒（InvalidChangeBatch），
  // 由 addTxt / removeTxt 重新读取后判定
  const mapped = THROTTLE_CODES.has(code)
    ? `Throttling.${code}`
    : raw.status >= 500 && !isRetryableCode(code)
      ? `ServiceUnavailable.${code}`
      : code;
  return new CloudApiError("aws", mapped, message, requestId, raw.status);
}

/**
 * Route 53 返回的名字里，a-z 0-9 - _ 以外的字符一律是 \ 加三位八进制（如 * 为 \052），比较前先还原
 * （docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html）
 */
export function unescapeName(name: string): string {
  return name.replace(/\\([0-7]{3})/g, (_, oct: string) => String.fromCharCode(parseInt(oct, 8)));
}

const zoneId = (id: string) => id.replace(/^\/hostedzone\//, "");

async function listPublicZones(ctx: QueryContext, creds: AwsCredentials): Promise<DnsZone[]> {
  const zones: DnsZone[] = [];
  let marker: string | undefined;
  for (let page = 1; ; page++) {
    if (page > MAX_PAGES) throw new Error(`ListHostedZones 分页超过 ${MAX_PAGES} 页仍未取完，已中止（接口返回可能异常）`);
    const xml = await call(ctx, creds, {
      action: "ListHostedZones",
      method: "GET",
      path: `${API}/hostedzone`,
      query: { maxitems: String(PAGE_SIZE), ...(marker && { marker }) },
      root: "ListHostedZonesResponse",
    });
    for (const b of xmlBlocks(xml, "HostedZone")) {
      const id = xmlText(b, "Id");
      const name = xmlText(b, "Name");
      if (!id || !name) continue;
      // 私有 zone（只在 VPC 内解析）不能用于公网验证；没建 Config 的 zone 不返回 Config，按公网处理
      if (xmlText(b, "PrivateZone") === "true") continue;
      zones.push({ name: normalizeName(unescapeName(name)), id: zoneId(id) });
    }
    // 文档：NextMarker 只在 IsTruncated 为 true 时出现，是下一页第一个 zone 的 ID
    if (xmlText(xml, "IsTruncated") !== "true") return zones;
    marker = xmlText(xml, "NextMarker");
    if (!marker) throw new CloudApiError("aws", "InvalidResponse", "ListHostedZones 返回 IsTruncated=true 但没有 NextMarker，无法继续翻页");
  }
}

/**
 * 同一账号可以建多个同名的公网 zone（常见于重建 zone 后旧的没删），只有注册商那里登记了 NS 的那个真正生效。
 * ListHostedZones 不返回 NS，NS 主机名规则又分不出同是 Route 53 的两个 zone，所以只对同名的 zone 逐个 GetHostedZone 取 NS，
 * 交给编排层按域名实际的 NS 判定。尽力而为：取不到（如没给 route53:GetHostedZone 权限）就不带 NS，由编排层报 ZoneAmbiguous。
 */
async function fillDuplicateNameServers(ctx: QueryContext, creds: AwsCredentials, zones: DnsZone[]): Promise<void> {
  const count = new Map<string, number>();
  for (const z of zones) count.set(z.name, (count.get(z.name) ?? 0) + 1);
  for (const z of zones) {
    if (count.get(z.name)! < 2) continue;
    try {
      const xml = await call(ctx, creds, { action: "GetHostedZone", method: "GET", path: `${API}/hostedzone/${z.id}`, root: "GetHostedZoneResponse" });
      const ns = xmlTexts(xmlBlocks(xml, "DelegationSet")[0] ?? "", "NameServer").map(normalizeName).filter(Boolean);
      if (ns.length > 0) z.nameServers = ns;
    } catch {
      // 见函数注释：不影响其他 zone，也不让整个 listZones 失败
    }
  }
}

/** 一个名字下的 TXT 记录集；values 为接口原样返回的值（带双引号，可能含 \" 等转义），写回时原样保留 */
interface TxtSet {
  ttl: number;
  values: string[];
}

/** 接口返回的值与验证值是否为同一条：Route 53 的 TXT 值带双引号，验证值是 base64url，不含需要转义的字符 */
const isValue = (raw: string, value: string) => raw === `"${value}"` || raw === value;

/**
 * 读出 fqdn 的 TXT 记录集。ListResourceRecordSets 没有精确查询，name + type 只是起始位置
 * （返回第一个 名字 ≥ name 且类型 ≥ type 的记录集），所以 maxitems=1 取一条后还要核对名字和类型正好是它。
 */
async function readTxtSet(ctx: QueryContext, creds: AwsCredentials, record: TxtRecord): Promise<TxtSet | undefined> {
  const xml = await call(ctx, creds, {
    action: "ListResourceRecordSets",
    method: "GET",
    path: `${API}/hostedzone/${record.zone.id}/rrset`,
    query: { name: `${record.fqdn}.`, type: "TXT", maxitems: "1" },
    root: "ListResourceRecordSetsResponse",
  });
  const set = xmlBlocks(xml, "ResourceRecordSet")[0];
  if (!set || xmlText(set, "Type") !== "TXT" || normalizeName(unescapeName(xmlText(set, "Name") ?? "")) !== record.fqdn) return undefined;
  // 别名、加权 / 地理等非简单路由（带 SetIdentifier）、流量策略生成的记录集不能按「读出来追加再写回」处理：
  // 写成简单记录集会改掉用户的路由配置，或者被 Route 53 拒绝。不动它，让用户手动处理
  if (/<(AliasTarget|SetIdentifier|TrafficPolicyInstanceId)[\s>]/.test(set)) {
    throw new CloudApiError(
      "aws",
      "UnsupportedRecordSet",
      `${record.fqdn} 已有别名记录或非简单路由策略的 TXT 记录集，无法安全地追加验证值，请在 Route 53 控制台改为简单路由后重试`,
    );
  }
  const ttl = Number(xmlText(set, "TTL"));
  const values = xmlBlocks(set, "ResourceRecord")
    .map((r) => xmlText(r, "Value"))
    .filter((v): v is string => !!v);
  return { ttl: Number.isFinite(ttl) ? ttl : TTL, values };
}

const escapeXml = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/** 变更批次里的一项：DELETE 必须与现有记录集完全一致（TTL 与全部值），CREATE 要求记录集不存在 */
export interface TxtChange {
  action: "CREATE" | "DELETE";
  set: TxtSet;
}

/** 元素顺序必须与文档的 Basic Syntax 一致（Name、Type、TTL、ResourceRecords），否则 Route 53 拒收 */
export function changeBatchXml(fqdn: string, changes: TxtChange[]): string {
  const change = ({ action, set }: TxtChange) => {
    const records = set.values.map((v) => `<ResourceRecord><Value>${escapeXml(v)}</Value></ResourceRecord>`).join("");
    return (
      `<Change><Action>${action}</Action>` +
      `<ResourceRecordSet><Name>${escapeXml(fqdn)}.</Name><Type>TXT</Type><TTL>${set.ttl}</TTL><ResourceRecords>${records}</ResourceRecords></ResourceRecordSet>` +
      `</Change>`
    );
  };
  return (
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<ChangeResourceRecordSetsRequest xmlns="${XMLNS}"><ChangeBatch><Changes>${changes.map(change).join("")}</Changes></ChangeBatch></ChangeResourceRecordSetsRequest>`
  );
}

/**
 * 不用 UPSERT：读改写之间别人（如同时运行的另一个 issue）改了记录集时，UPSERT 会用旧内容覆盖、把别人刚加的值丢掉。
 * 改为在同一个变更批次里「DELETE 读到的旧记录集 + CREATE 新记录集」（原来没有记录集时只 CREATE）：批次是事务，全部生效或全部不生效
 * （API_ChangeResourceRecordSets），旧记录集对不上（被改过）或要新建的已存在时整批被拒（InvalidChangeBatch），相当于比较后写入
 */
async function changeTxt(ctx: QueryContext, creds: AwsCredentials, record: TxtRecord, changes: TxtChange[]): Promise<void> {
  // 提交即返回，不轮询 GetChange 等 INSYNC：编排层会直接向权威 DNS 查询确认生效，省一项权限
  await call(ctx, creds, {
    action: "ChangeResourceRecordSets",
    method: "POST",
    path: `${API}/hostedzone/${record.zone.id}/rrset/`,
    body: changeBatchXml(record.fqdn, changes),
    root: "ChangeResourceRecordSetsResponse",
  });
}

/** 把记录集从 before 换成 after：before 为空时只 CREATE，after 为空时只 DELETE */
const replaceSet = (before: TxtSet | undefined, after: TxtSet | undefined): TxtChange[] => [
  ...(before ? [{ action: "DELETE" as const, set: before }] : []),
  ...(after ? [{ action: "CREATE" as const, set: after }] : []),
];

/**
 * 读 → 算出新记录集 → 比较后写入；冲突（读完之后记录集被改了，或上一次提交其实已生效但响应丢失、被重试）时 Route 53 报 InvalidChangeBatch，
 * 重读后再试一次。plan 返回 undefined 表示不用改
 */
async function readModifyWrite(
  ctx: QueryContext,
  creds: AwsCredentials,
  record: TxtRecord,
  plan: (set: TxtSet | undefined) => TxtChange[] | undefined,
): Promise<void> {
  for (let attempt = 1; ; attempt++) {
    const changes = plan(await readTxtSet(ctx, creds, record));
    if (!changes) return;
    try {
      await changeTxt(ctx, creds, record, changes);
      return;
    } catch (e) {
      if (attempt >= 2 || !isCode(e, "InvalidChangeBatch")) throw e;
    }
  }
}

const isCode = (e: unknown, code: string) => e instanceof CloudApiError && e.code === code;

/** Route 53 没有单条记录的 ID（记录集由 zone + 名字 + 类型确定），句柄只是定位信息，删除时按 record 里的值从记录集里去掉 */
const handleOf = (record: TxtRecord) => `${record.zone.id}/${record.fqdn}`;

export const awsDns = defineDns<AwsCredentials>({
  vendor: "aws",
  label: "AWS Route 53",
  ...varsEnv<AwsCredentials>([
    { name: "AWS_ACCESS_KEY_ID", required: true, secret: false },
    { name: "AWS_SECRET_ACCESS_KEY", required: true, secret: true },
    { name: "AWS_SESSION_TOKEN", required: false, secret: true },
  ], (v) => ({
    accessKeyId: v.AWS_ACCESS_KEY_ID!,
    secretAccessKey: v.AWS_SECRET_ACCESS_KEY!,
    ...(v.AWS_SESSION_TOKEN && { sessionToken: v.AWS_SESSION_TOKEN }),
  })),
  // 默认分配的 NS 形如 ns-2048.awsdns-64.com / .net / .org / .co.uk（GetHostedZone 文档示例）；白标 NS（自定义名字的可重用委托集）匹配不上
  nameServerPattern: /^ns-\d+\.awsdns-\d+\.(com|net|org|co\.uk)$/,
  async listZones(ctx, creds) {
    const zones = await listPublicZones(ctx, creds);
    await fillDuplicateNameServers(ctx, creds, zones);
    return zones;
  },
  async addTxt(ctx, creds, record) {
    // 记录集模型：同名的其他值（另一个域名的验证值、用户自己的 TXT）原样带上一起写回。
    // 已有记录集时沿用它的 TTL，不改动用户原有记录的属性；新建时用 60 秒。值已经在了（含上一次提交其实已生效）就不改
    await readModifyWrite(ctx, creds, record, (set) =>
      set?.values.some((v) => isValue(v, record.value))
        ? undefined
        : replaceSet(set, { ttl: set?.ttl ?? TTL, values: [...(set?.values ?? []), `"${record.value}"`] }),
    );
    return handleOf(record);
  },
  async removeTxt(ctx, creds, record) {
    try {
      // 去掉这次的值，剩余值写回（DELETE 旧 + CREATE 新）；只剩这一个值时只 DELETE 旧记录集。记录集或值已经不在了视为成功
      await readModifyWrite(ctx, creds, record, (set) => {
        const rest = set?.values.filter((v) => !isValue(v, record.value)) ?? [];
        if (!set || rest.length === set.values.length) return undefined;
        return replaceSet(set, rest.length > 0 ? { ttl: set.ttl, values: rest } : undefined);
      });
    } catch (e) {
      // zone 已被删除，记录自然也不在了
      if (isCode(e, "NoSuchHostedZone")) return;
      throw e;
    }
  },
});
