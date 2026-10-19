import { ENV_FAMILIES, readTencent, type TencentCredentials } from "../lib/env.js";
import { CloudApiError, isRetryable, withRetry, type QueryContext } from "../lib/http.js";
import { paginate } from "../lib/paginate.js";
import { callTencentOnce } from "../providers/tencent/client.js";
import { familyEnv } from "./env.js";
import { defineDns, normalizeName, relativeName, type DnsZone } from "./types.js";

const SERVICE = { service: "dnspod", version: "2021-03-23" } as const;
/** DescribeDomainList 的 Limit 默认就是 3000 */
const DOMAIN_PAGE = 3000;
const RECORD_PAGE = 100;

/**
 * TTL 最小值按套餐区分（DNSPod 文档「TTL 说明」）：免费版 600 秒，专业版 60 秒，企业版、尊享版 1 秒。
 * 付费套餐统一用 60：各付费套餐都接受，对验证也已足够；套餐判断不准（如已到期）时添加会被 LimitExceeded.RecordTtlLimit 拒绝，再退回 600
 */
const FREE_TTL = 600;
const PAID_TTL = 60;

// DNSPod 自己的限流错误码不匹配通用重试规则（RequestLimitExceeded.* 已能识别），加上 Throttling. 前缀交给 withRetry 重试
const THROTTLE_CODES = new Set(["FailedOperation.FrequencyLimit", "InvalidParameter.OperationIsTooFrequent"]);

/**
 * 新增的记录有短暂的索引延迟（接口文档：查询不到新增记录时 30 秒后重试）：
 * 「记录已存在」却查不到时隔 10 秒再查，最多 3 次
 */
const INDEX_DELAY_MS = 10_000;
const INDEX_RETRIES = 3;

interface DpDomain {
  DomainId?: number;
  /** 域名的原始格式（中文域名为中文） */
  Name?: string;
  Punycode?: string;
  /** 正常 ENABLE、暂停 PAUSE、封禁 SPAM */
  Status?: string;
  /** DNS 没指向 DNSPod 时为 DNSERROR，正常为空 */
  DNSStatus?: string;
  /** 系统为域名分配的有效 DNS */
  EffectiveDNS?: string[] | null;
  IsVip?: string;
}

interface DpRecord {
  RecordId?: number;
  Name?: string;
  Type?: string;
  Value?: string;
  Line?: string;
  LineId?: string;
}

const codeOf = (e: unknown) => (e instanceof CloudApiError ? e.code : undefined);

/** 只发一次；限流码换成 withRetry 认得的形式，由调用方决定是否重试 */
function callOnce<T>(ctx: QueryContext, creds: TencentCredentials, action: string, payload: Record<string, unknown>): Promise<T> {
  return callTencentOnce<T>(ctx, creds, { ...SERVICE, action, payload }).catch((e: unknown) => {
    if (e instanceof CloudApiError && THROTTLE_CODES.has(e.code)) e.code = `Throttling.${e.code}`;
    throw e;
  });
}

/** 幂等的查询 / 删除：可重试的错误自动重试 */
function call<T>(ctx: QueryContext, creds: TencentCredentials, action: string, payload: Record<string, unknown>): Promise<T> {
  return withRetry(ctx, () => callOnce<T>(ctx, creds, action, payload));
}

/** DomainId 优先于 Domain（文档：传了 DomainId 就忽略 Domain），中文域名也不用操心 Domain 的写法 */
function domainParams(zone: DnsZone): Record<string, unknown> {
  const id = Number(zone.id);
  return { Domain: zone.name, ...(Number.isSafeInteger(id) && id > 0 && { DomainId: id }) };
}

/**
 * 暂停解析（PAUSE）的域名 DNSPod 整个不应答，加了 TXT 也验证不了；封禁（SPAM）的不能操作：都当作没托管在这里，
 * 免得别家也托管了这个 zone 时被误判为多家托管。
 * DNSStatus=DNSERROR（DNS 没指向 DNSPod）照样返回并带上 EffectiveDNS：DNSPod 的检测有延迟（刚改 NS 时仍报错），
 * 多家都托管时编排层按 NS 判定用哪家，只有这一家时由生效检查报出 NS 不一致，比直接说找不到 zone 更好排查
 */
const serving = (d: DpDomain) => !["PAUSE", "SPAM"].includes((d.Status ?? "").toUpperCase());

function toZone(d: DpDomain & { DomainId: number; Name: string }): DnsZone {
  const nameServers = (d.EffectiveDNS ?? []).filter((s): s is string => typeof s === "string" && !!s.trim()).map(normalizeName);
  return {
    name: normalizeName(d.Punycode || d.Name),
    id: String(d.DomainId),
    ...(nameServers.length > 0 && { nameServers }),
    extra: { ttl: String(d.IsVip?.toUpperCase() === "YES" ? PAID_TTL : FREE_TTL) },
  };
}

/** TXT 记录值按原样比较；带了引号的去掉再比 */
const unquote = (v: string | undefined) => (v && v.length >= 2 && v.startsWith('"') && v.endsWith('"') ? v.slice(1, -1) : (v ?? ""));

// 默认线路的 LineId 是 "0"；线路名随请求语言变化，没有 LineId 时才看名字
const defaultLine = (r: DpRecord) => (r.LineId !== undefined ? r.LineId === "0" : r.Line === undefined || r.Line === "默认");

/**
 * 同名下同值的 TXT 记录（默认线路）的 ID；SubDomain 精确匹配主机记录，ErrorOnEmpty=no 让没有记录时返回空列表。
 * retry=false 只发一次：在 addTxt 的重试循环里查时由外层重试，免得网络不通时层层重试、等很久
 */
async function findTxt(
  ctx: QueryContext,
  creds: TencentCredentials,
  zone: DnsZone,
  rr: string,
  value: string,
  retry: boolean,
): Promise<string | undefined> {
  const invoke = retry ? call : callOnce;
  const records = await paginate<DpRecord>(RECORD_PAGE, async (_page, offset) => {
    try {
      const res = await invoke<{ RecordList?: DpRecord[] }>(ctx, creds, "DescribeRecordList", {
        ...domainParams(zone),
        SubDomain: rr,
        RecordType: "TXT",
        ErrorOnEmpty: "no",
        Offset: offset,
        Limit: RECORD_PAGE,
      });
      return { items: res.RecordList ?? [] };
    } catch (e) {
      // ErrorOnEmpty 默认是 yes，没有记录时以「记录列表为空」报错；万一参数没起作用，同样当作空列表
      if (codeOf(e) === "ResourceNotFound.NoDataOfRecord") return { items: [] };
      throw e;
    }
  });
  const same = records.find(
    (r) => r.Type?.toUpperCase() === "TXT" && r.Name?.toLowerCase() === rr.toLowerCase() && defaultLine(r) && unquote(r.Value) === value,
  );
  return same?.RecordId !== undefined ? String(same.RecordId) : undefined;
}

/** 「记录已存在」时它一定在，只是新增的记录可能还没进索引：隔一会儿再查 */
async function findIndexed(ctx: QueryContext, find: () => Promise<string | undefined>): Promise<string | undefined> {
  const sleep = ctx.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  for (let i = 0; ; i++) {
    const id = await find();
    if (id || i >= INDEX_RETRIES) return id;
    await sleep(INDEX_DELAY_MS);
  }
}

/** 发一次 CreateRecord（不自动重试）；明确被拒的 TTL、同名同值已存在在这里处理 */
async function createRecord(
  ctx: QueryContext,
  creds: TencentCredentials,
  zone: DnsZone,
  rr: string,
  value: string,
  ttl: number,
  find: () => Promise<string | undefined>,
): Promise<string> {
  try {
    const res = await callOnce<{ RecordId?: number | null; RequestId?: string }>(ctx, creds, "CreateRecord", {
      ...domainParams(zone),
      SubDomain: rr,
      RecordType: "TXT",
      RecordLine: "默认",
      Value: value,
      TTL: ttl,
    });
    if (res.RecordId === undefined || res.RecordId === null) {
      throw new CloudApiError("tencent", "InvalidResponse", "添加解析记录的响应里没有 RecordId", res.RequestId);
    }
    return String(res.RecordId);
  } catch (e) {
    const code = codeOf(e);
    // TTL 低于套餐允许的最小值：请求被明确拒绝、没有加上，换成各套餐都接受的 600 再加
    if (code === "LimitExceeded.RecordTtlLimit" && ttl !== FREE_TTL) return createRecord(ctx, creds, zone, rr, value, FREE_TTL, find);
    // 同名同值已存在：验证值是这次验证专属的，只可能是之前没清理掉的同一条（或上一次超时的请求其实已成功），查出它的 ID 当句柄
    if (code === "InvalidParameter.DomainRecordExist") {
      const id = await findIndexed(ctx, find);
      if (id) return id;
      // 隔 30 秒还查不到：没有句柄，交给编排层按「可能已添加」提示用户核对
      throw new CloudApiError(
        "tencent",
        "RecordMayExist",
        `DNSPod 报同名同值的 TXT 记录已存在（${code}），但隔了 ${(INDEX_DELAY_MS * INDEX_RETRIES) / 1000} 秒仍查不到这条记录的 ID（多半是索引延迟），记录可能已添加`,
        (e as CloudApiError).requestId,
      );
    }
    throw e;
  }
}

export const tencentDns = defineDns<TencentCredentials>({
  vendor: "tencent",
  label: "腾讯云 DNSPod",
  ...familyEnv(ENV_FAMILIES.tencent, readTencent),
  // DNSPod 文档「各套餐 DNS 服务器地址说明」：免费版是账号专属的 *.dnspod.net（如 f1g1ns1.dnspod.net），
  // 专业版 / 企业版 / 尊享版为 ns3、ns4.dnsv2 / dnsv4 / dnsv5.com，旧套餐还有 ns1、ns2.dnsv2~5.com、ns3、ns4.dnsv3.com；
  // dnspod.com 文档里没有列出，保守一并认上（只在接口没返回 EffectiveDNS 时用到）
  nameServerPattern: /(^|\.)(dnspod\.(net|com)|dnsv\d\.com)$/,

  async listZones(ctx, creds) {
    const domains = await paginate<DpDomain>(DOMAIN_PAGE, async (_page, offset) => {
      try {
        // Type=ALL 含别的账号共享给本账号的域名，共享时给了写权限就能加记录
        const res = await call<{ DomainCountInfo?: { DomainTotal?: number }; DomainList?: DpDomain[] }>(ctx, creds, "DescribeDomainList", {
          Type: "ALL",
          Offset: offset,
          Limit: DOMAIN_PAGE,
        });
        return { items: res.DomainList ?? [], total: res.DomainCountInfo?.DomainTotal };
      } catch (e) {
        // 账号下一个域名都没有时报「域名列表为空」，不是返回空列表
        if (codeOf(e) === "ResourceNotFound.NoDataOfDomain") return { items: [], total: 0 };
        throw e;
      }
    });
    return domains
      .filter((d): d is DpDomain & { DomainId: number; Name: string } => d.DomainId !== undefined && !!d.Name?.trim())
      .filter(serving)
      .map(toZone);
  },

  /**
   * DNSPod 是「一条记录一个值」：直接新增一条，同名下已有的其他 TXT 值不受影响。
   * 新增不幂等：请求只发一次，遇到超时、限流等可重试错误时整体重来，先查同名同值的记录，上一次其实已经加上了就直接用它，
   * 查不到（可能还没进索引）再发；重发撞上「记录已存在」时等索引跟上后查出那条，不会重复添加
   */
  async addTxt(ctx, creds, record) {
    const rr = relativeName(record.fqdn, record.zone.name);
    const ttl = Number(record.zone.extra?.ttl) || FREE_TTL;
    const find = (retry: boolean) => findTxt(ctx, creds, record.zone, rr, record.value, retry);
    let sent = false;
    try {
      return await withRetry(ctx, async () => {
        if (sent) {
          const id = await find(false);
          if (id) return id;
        }
        sent = true;
        return await createRecord(ctx, creds, record.zone, rr, record.value, ttl, () => find(true));
      });
    } catch (e) {
      // 重试用完时最后一次添加的结果同样未知：等索引跟上再查，加上了就不算失败，免得这条记录没有句柄、无法清理；查询本身出错就放弃
      if (sent && isRetryable(e)) {
        const id = await findIndexed(ctx, () => find(false)).catch(() => undefined);
        if (id) return id;
      }
      throw e;
    }
  },

  /**
   * 按记录 ID 删除，只删这一条。删除可以原样重试：前一次其实已删掉时报 RecordIdInvalid（记录编号错误，
   * 沿用旧版 API「记录 ID 错误」的含义，即该 ID 的记录不存在），句柄是接口返回的 ID，不会是格式错误，视为已删除
   */
  async removeTxt(ctx, creds, record, handle) {
    try {
      await call(ctx, creds, "DeleteRecord", { ...domainParams(record.zone), RecordId: Number(handle) });
    } catch (e) {
      if (codeOf(e) === "InvalidParameter.RecordIdInvalid") return;
      throw e;
    }
  },
});
