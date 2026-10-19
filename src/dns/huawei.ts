import { domainToASCII } from "node:url";
import { ENV_FAMILIES, readAccessKey, type AccessKeyCredentials } from "../lib/env.js";
import { CloudApiError, isRetryable, withRetry, type QueryContext } from "../lib/http.js";
import { paginate } from "../lib/paginate.js";
import { callHuawei, listProjects, type HuaweiRequest } from "../providers/huawei/client.js";
import { familyEnv } from "./env.js";
import { defineDns, normalizeName, relativeName, type DnsZone, type TxtRecord } from "./types.js";

/**
 * 公网域名是全局资源，文档要求在华北-北京四调用（ListPublicZones https://support.huaweicloud.com/api-dns/dns_api_62003.html），
 * 没有全局的 dns.myhuaweicloud.com 接入点。只适配中国站（国际站的文档要求 ap-southeast-3）
 */
const REGION = "cn-north-4";
const HOST = `dns.${REGION}.myhuaweicloud.com`;
// limit 取值 0~500，缺省 500
const PAGE_SIZE = 500;
/** TTL 取值 1~2147483647（创建记录集 https://support.huaweicloud.com/api-dns/dns_api_64001.html），公网解析没有按版本区分的下限 */
const TTL = 1;
/**
 * 全网默认线路的 ID（「获取线路 ID」https://support.huaweicloud.com/api-dns/zh-cn_topic_0085546214.html）。
 * 用 v2.1 接口：同名同类型不同线路是不同的记录集，v2 接口看不到线路，可能把运营商线路的记录集当成默认线路的改掉
 */
const DEFAULT_LINE = "default_view";

// 正常、更新中的域名照常解析；创建中、删除中、冻结、违规 / 公安冻结、暂停（DISABLE）、失败的不返回。云解析不检查 NS 是否已指向华为云，没有「未接入」状态
const LIVE_ZONE = new Set(["ACTIVE", "PENDING_UPDATE"]);

// 暂时性错误码（错误码页 https://support.huaweicloud.com/api-dns/ErrorCode.html）：获取锁失败 DNS.0021 可能以 HTTP 500 返回，按限流处理；
// 系统繁忙、域名 / 记录集处于中间状态（如刚创建的记录集还在 PENDING_CREATE）按服务暂不可用处理，都交给 withRetry 重试
const THROTTLE_CODES = new Set(["DNS.0021"]);
const TRANSIENT_CODES = new Set(["DNS.0000", "DNS.0003", "DNS.0209", "DNS.0314", "DNS.0334"]);
// 记录集已存在：文档没写重复创建具体报哪个，记录集名称已存在 / 存在重复记录集 / 资源记录已存在或冲突都可能
const DUPLICATE_CODES = new Set(["DNS.0312", "DNS.0335", "DNS.0016"]);
// 记录集已不存在
const GONE_CODES = new Set(["DNS.0313", "DNS.0004"]);

/** 记录集在创建 / 修改 / 删除中（PENDING_*）时不能再改，等它稳定：每 2 秒查一次，最多 30 秒 */
const PENDING = /^PENDING_/;
const STEADY_POLLS = 15;
const STEADY_INTERVAL_MS = 2000;

interface HwZone {
  id?: string;
  /** 带结尾点，如 example.com. */
  name?: string;
  status?: string;
}

interface HwRecordSet {
  id?: string;
  name?: string;
  type?: string;
  /** TXT 的每个值带双引号 */
  records?: string[] | null;
  status?: string;
  line?: string;
}

type RecordSet = HwRecordSet & { id: string };

const ascii = (name: string) => normalizeName(domainToASCII(normalizeName(name)) || name);

/** TXT 记录值要用半角双引号包裹（「添加公网域名解析记录」https://support.huaweicloud.com/usermanual-dns/dns_usermanual_0006.html），比较时去掉 */
const quote = (v: string) => `"${v}"`;
const unquote = (v: string) => (v.length >= 2 && v.startsWith('"') && v.endsWith('"') ? v.slice(1, -1) : v);

/**
 * 调一次云解析接口（不自动重试，由各操作在外层整体重试）。
 * 多项目的账号用 AK/SK 调用时必须带 X-Project-Id（「构造请求」https://support.huaweicloud.com/api-dns/zh-cn_topic_0037134406.html），
 * 官方 SDK 也总是自动查出项目 ID 带上；查项目用的 IAM 接口不需要额外权限，结果在一次命令内缓存
 */
async function call<T>(ctx: QueryContext, creds: AccessKeyCredentials, req: Omit<HuaweiRequest, "host" | "projectId" | "retry">): Promise<T> {
  const projectId = (await listProjects(ctx, creds)).get(REGION);
  try {
    return await callHuawei<T>(ctx, creds, { ...req, host: HOST, retry: false, ...(projectId && { projectId }) });
  } catch (e) {
    if (e instanceof CloudApiError && (THROTTLE_CODES.has(e.code) || TRANSIENT_CODES.has(e.code))) {
      const prefix = THROTTLE_CODES.has(e.code) ? "Throttling" : "ServiceUnavailable";
      throw new CloudApiError("huawei", `${prefix}.${e.code}`, e.message, e.requestId, e.httpStatus);
    }
    throw e;
  }
}

/**
 * 接口里的记录集名（FQDN，带结尾点）。中文域名的 zone 名在 issue 这边是 punycode，接口要求记录集名「后缀以 zone name 结束」，
 * 换回接口里的原名（listZones 放在 extra.apiName）
 */
function apiName(record: TxtRecord): string {
  const zone = record.zone.extra?.apiName ?? record.zone.name;
  const rel = relativeName(record.fqdn, record.zone.name);
  return `${rel === "@" ? zone : `${rel}.${zone}`}.`;
}

const setsPath = (record: TxtRecord) => `/v2.1/zones/${record.zone.id}/recordsets`;

/**
 * 默认线路上同名的 TXT 记录集。name 是模糊匹配（「包含」），带不带结尾点文档没写：不带结尾点查（存的名字带不带点都包含它），
 * 再在本地按名字、类型、线路精确比对
 */
async function findSet(ctx: QueryContext, creds: AccessKeyCredentials, record: TxtRecord): Promise<RecordSet | undefined> {
  const name = apiName(record).slice(0, -1);
  const sets = await paginate<HwRecordSet>(PAGE_SIZE, async (_page, offset) => {
    const res = await call<{ recordsets?: HwRecordSet[] | null; metadata?: { total_count?: number } }>(ctx, creds, {
      path: setsPath(record),
      query: { type: "TXT", name, limit: PAGE_SIZE, offset },
    });
    return { items: res.recordsets ?? [], total: res.metadata?.total_count };
  });
  return sets.find(
    (s): s is RecordSet =>
      !!s.id && s.type?.toUpperCase() === "TXT" && ascii(s.name ?? "") === record.fqdn && (s.line || DEFAULT_LINE) === DEFAULT_LINE,
  );
}

/** 等记录集离开 PENDING_* 状态，返回最新的记录集；等待期间被删掉了返回 undefined */
async function steady(ctx: QueryContext, creds: AccessKeyCredentials, record: TxtRecord, set: RecordSet | undefined): Promise<RecordSet | undefined> {
  const sleep = ctx.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  for (let i = 0; set && PENDING.test(set.status ?? ""); i++) {
    if (i === STEADY_POLLS) {
      throw new CloudApiError(
        "huawei",
        "RecordSetNotSteady",
        `记录集 ${record.fqdn} 一直处于 ${set.status} 状态（已等待 ${(STEADY_POLLS * STEADY_INTERVAL_MS) / 1000} 秒），暂时不能修改，请稍后重试`,
      );
    }
    await sleep(STEADY_INTERVAL_MS);
    set = await findSet(ctx, creds, record);
  }
  return set;
}

const currentSet = async (ctx: QueryContext, creds: AccessKeyCredentials, record: TxtRecord) => steady(ctx, creds, record, await findSet(ctx, creds, record));

/** 往已有的记录集里追加值：记录集模型下要把原有的值原样带上整体写回；TTL、描述等不传，维持原值 */
async function appendTo(ctx: QueryContext, creds: AccessKeyCredentials, record: TxtRecord, set: RecordSet): Promise<string> {
  // 暂停（DISABLE）等状态下加进去的值不会生效，验证必然失败，直接报出来
  if (set.status && set.status !== "ACTIVE") {
    throw new CloudApiError(
      "huawei",
      "RecordSetNotActive",
      `${record.fqdn} 已有的 TXT 记录集状态为 ${set.status}（如已暂停），加进去的值不会生效；请在控制台启用或删除该记录集后重试`,
    );
  }
  const records = set.records ?? [];
  if (records.some((r) => unquote(r) === record.value)) return set.id;
  await call(ctx, creds, {
    method: "PUT",
    path: `${setsPath(record)}/${set.id}`,
    // v2.1 修改接口 name、type 必填，按记录集原样回填
    body: { name: set.name ?? apiName(record), type: "TXT", records: [...records, quote(record.value)] },
  });
  return set.id;
}

/** 一次完整的「查 → 新建或追加」，不自动重试 */
async function addOnce(ctx: QueryContext, creds: AccessKeyCredentials, record: TxtRecord): Promise<string> {
  let set = await currentSet(ctx, creds, record);
  if (!set) {
    try {
      const res = await call<HwRecordSet>(ctx, creds, {
        method: "POST",
        path: setsPath(record),
        body: { name: apiName(record), type: "TXT", records: [quote(record.value)], ttl: TTL, line: DEFAULT_LINE },
      });
      if (!res.id) throw new CloudApiError("huawei", "InvalidResponse", "创建记录集的响应里没有 id");
      return res.id;
    } catch (e) {
      // 同名记录集已存在（查过之后才被建出来，或上一次超时的请求其实已成功）：查出来按追加处理
      if (!(e instanceof CloudApiError && DUPLICATE_CODES.has(e.code))) throw e;
      set = await currentSet(ctx, creds, record);
      // 查不到同名 TXT 记录集：DNS.0016 同时表示「与其他记录冲突」，多半是同名下有 CNAME。错误码不变，信息里点明，编排层据此提示 DNS 别名模式不受支持
      if (!set && e.code === "DNS.0016") {
        throw new CloudApiError("huawei", e.code, `${e.message}（同名下没有 TXT 记录集，多半与同名的 CNAME 等记录冲突）`, e.requestId, e.httpStatus);
      }
      if (!set) throw e;
    }
  }
  return appendTo(ctx, creds, record, set);
}

export const huaweiDns = defineDns<AccessKeyCredentials>({
  vendor: "huawei",
  label: "华为云云解析",
  ...familyEnv(ENV_FAMILIES.huawei, readAccessKey(ENV_FAMILIES.huawei)),
  // ns1.huaweicloud-dns.com / .cn（中国大陆）、ns1.huaweicloud-dns.net / .org（中国大陆以外），新建公网域名默认的 NS 记录就是这四个
  // （https://support.huaweicloud.com/dns_faq/dns_faq_012.html），中国站、国际站相同
  nameServerPattern: /(^|\.)huaweicloud-dns\.(com|cn|net|org)$/,

  /**
   * GET /v2/zones?type=public 只列公网域名（内网域名是 type=private），按 offset 翻页、以 metadata.total_count 为准。
   * 文档写 enterprise_project_id 缺省为 "0"（默认企业项目），开通了企业项目、把域名放在别的企业项目里时可能列不出来
   */
  async listZones(ctx, creds) {
    const zones = await paginate<HwZone>(PAGE_SIZE, (_page, offset) =>
      withRetry(ctx, async () => {
        const res = await call<{ zones?: HwZone[] | null; metadata?: { total_count?: number } }>(ctx, creds, {
          path: "/v2/zones",
          query: { type: "public", limit: PAGE_SIZE, offset },
        });
        return { items: res.zones ?? [], total: res.metadata?.total_count };
      }),
    );
    return zones
      .filter((z): z is HwZone & { id: string; name: string } => !!z.id && !!z.name?.trim() && LIVE_ZONE.has(z.status ?? ""))
      .map((z) => {
        const raw = normalizeName(z.name);
        const name = ascii(raw);
        // 中文域名：zone 名用 punycode（与 issue 规范化后的域名一致），接口里的原名留给拼记录集名用
        return { name, id: z.id, ...(raw !== name && { extra: { apiName: raw } }) };
      });
  },

  /**
   * 华为是「记录集」模型：同名同类型同线路只有一个记录集。没有就新建；有就把这次的值追加进去写回，原有的值原样保留。
   * 刚建 / 刚改的记录集处于 PENDING_* 状态时不能再改（根域名与泛域名的验证值紧接着加在同一个名字下），先等它稳定。
   * 读改写整体重试：每次重来都重新读，上一次超时的请求其实已成功时能读到这次的值，不会重复添加
   */
  async addTxt(ctx, creds, record) {
    try {
      return await withRetry(ctx, () => addOnce(ctx, creds, record));
    } catch (e) {
      // 重试用完时最后一次写入的结果未知：再查一次，值已经在了就不算失败，免得这个值没有句柄、无法清理
      if (isRetryable(e)) {
        const set = await findSet(ctx, creds, record).catch(() => undefined);
        if (set?.records?.some((r) => unquote(r) === record.value)) return set.id;
      }
      throw e;
    }
  },

  /**
   * 按名字重新读出记录集（句柄是记录集 ID，记录集里的值可能已被前面的删除改过），只去掉这次加的值写回；
   * 只剩这一个值时删掉整个记录集（records 不能为空）。记录集或值已经不在了视为成功
   */
  async removeTxt(ctx, creds, record) {
    await withRetry(ctx, async () => {
      const set = await currentSet(ctx, creds, record);
      if (!set) return;
      const records = set.records ?? [];
      const rest = records.filter((r) => unquote(r) !== record.value);
      if (rest.length === records.length) return;
      const path = `${setsPath(record)}/${set.id}`;
      try {
        if (rest.length > 0) {
          await call(ctx, creds, { method: "PUT", path, body: { name: set.name ?? apiName(record), type: "TXT", records: rest } });
        } else {
          await call(ctx, creds, { method: "DELETE", path });
        }
      } catch (e) {
        if (e instanceof CloudApiError && GONE_CODES.has(e.code)) return;
        throw e;
      }
    });
  },
});
