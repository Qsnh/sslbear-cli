import { ENV_FAMILIES, readAliyun, type AliyunCredentials } from "../lib/env.js";
import { CloudApiError, isRetryable, withRetry, type QueryContext } from "../lib/http.js";
import { paginate } from "../lib/paginate.js";
import { callRpc, callRpcOnce } from "../providers/aliyun/client.js";
import { familyEnv } from "./env.js";
import { defineDns, normalizeName, relativeName, type DnsZone } from "./types.js";

// 云解析 DNS 的公网接入点（OpenAPI 元数据里只有这一个）
const API = { endpoint: "alidns.aliyuncs.com", version: "2015-01-09" } as const;
const PAGE_SIZE = 100;

/**
 * TTL 最小值按版本区分（帮助文档「如何配置TTL」）：免费版、个人版 600 秒，企业旗舰版、尊享版 1 秒。
 * 付费企业版统一用 60：各企业版都接受，对验证也已足够；版本判断不准（新出的版本、刚到期）时
 * 添加会被 QuotaExceeded.TTL 拒绝，再退回 600
 */
const FREE_TTL = 600;
const PAID_TTL = 60;
const FREE_VERSIONS = new Set(["mianfei", "version_personal"]);

// 删除时记录已不存在：前者是「解析记录在本账户下不存在」，后者是「您操作的解析记录已经不存在」
const GONE_CODES = new Set(["DomainRecordNotBelongToUser", "InvalidRR.NoExist"]);

const HOST = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/;

interface AliDomain {
  DomainName?: string;
  /** 中文域名的 punycode，英文域名为空 */
  PunyCode?: string;
  /** 云解析给这个域名分配的 DNS 服务器 */
  DnsServers?: { DnsServer?: unknown[] };
  VersionCode?: string;
  InstanceExpired?: boolean;
}

interface AliRecord {
  RecordId?: string;
  RR?: string;
  Type?: string;
  Value?: string;
  Line?: string;
}

/**
 * 接口没有暂停 / 未接入之类的状态字段：域名实际的 NS 没指向阿里云时照样返回。多家都托管同一 zone 时，
 * 编排层用这里的 DnsServers 与域名实际的 NS 比对来判定；只有阿里云托管时由生效检查报出 NS 不一致。
 * 中文域名用 PunyCode 作 zone 名（与 issue 规范化后的域名一致），接口参数仍用原样的 DomainName（id），与 lego 的做法相同
 */
function toZone(d: AliDomain & { DomainName: string }): DnsZone {
  const nameServers = (d.DnsServers?.DnsServer ?? [])
    .filter((s): s is string => typeof s === "string")
    .map(normalizeName)
    .filter((s) => HOST.test(s));
  const paid = !!d.VersionCode && !FREE_VERSIONS.has(d.VersionCode) && d.InstanceExpired !== true;
  return {
    name: normalizeName(d.PunyCode || d.DomainName),
    id: normalizeName(d.DomainName),
    ...(nameServers.length > 0 && { nameServers }),
    extra: { ttl: String(paid ? PAID_TTL : FREE_TTL) },
  };
}

/** TXT 记录值按原样比较；个别接口会带上引号，去掉再比 */
const unquote = (v: string | undefined) => (v && v.length >= 2 && v.startsWith('"') && v.endsWith('"') ? v.slice(1, -1) : (v ?? ""));

/**
 * 同名下同值的 TXT 记录（默认线路）的 ID；DescribeSubDomainRecords 按完整子域名精确查询，带 DomainName 免得把子 zone 认错。
 * retry=false 只发一次：在 addTxt 的重试循环里查时由外层重试，免得网络不通时层层重试、等很久
 */
async function findTxt(
  ctx: QueryContext,
  creds: AliyunCredentials,
  zone: DnsZone,
  rr: string,
  value: string,
  retry: boolean,
): Promise<string | undefined> {
  const rpc = retry ? callRpc : callRpcOnce;
  const records = await paginate<AliRecord>(PAGE_SIZE, async (page) => {
    const res = await rpc<{ TotalCount?: number; DomainRecords?: { Record?: AliRecord[] } }>(ctx, creds, {
      ...API,
      action: "DescribeSubDomainRecords",
      params: {
        DomainName: zone.id,
        SubDomain: rr === "@" ? zone.id : `${rr}.${zone.id}`,
        Type: "TXT",
        PageNumber: page,
        PageSize: PAGE_SIZE,
      },
    });
    return { items: res.DomainRecords?.Record ?? [], total: res.TotalCount };
  });
  const same = records.find(
    (r) =>
      r.Type?.toUpperCase() === "TXT" &&
      r.RR?.toLowerCase() === rr.toLowerCase() &&
      (r.Line ?? "default") === "default" &&
      unquote(r.Value) === value,
  );
  return same?.RecordId ? String(same.RecordId) : undefined;
}

/** 发一次 AddDomainRecord（不自动重试）；明确被拒的 TTL、同名同值已存在在这里处理 */
async function addRecord(
  ctx: QueryContext,
  creds: AliyunCredentials,
  zone: DnsZone,
  rr: string,
  value: string,
  ttl: number,
  find: () => Promise<string | undefined>,
): Promise<string> {
  try {
    // 线路不传即默认线路；RecordId 是 19 位数字，接口以字符串返回，原样当句柄
    const res = await callRpcOnce<{ RecordId?: string; RequestId?: string }>(ctx, creds, {
      ...API,
      action: "AddDomainRecord",
      params: { DomainName: zone.id, RR: rr, Type: "TXT", Value: value, TTL: ttl },
    });
    if (!res.RecordId) throw new CloudApiError("aliyun", "InvalidResponse", "添加解析记录的响应里没有 RecordId", res.RequestId);
    return String(res.RecordId);
  } catch (e) {
    const code = e instanceof CloudApiError ? e.code : undefined;
    // TTL 低于该版本允许的最小值：请求被明确拒绝、没有加上，换成各版本都接受的 600 再加
    if (code === "QuotaExceeded.TTL" && ttl !== FREE_TTL) return addRecord(ctx, creds, zone, rr, value, FREE_TTL, find);
    // 同名同值已存在：验证值是这次验证专属的，只可能是之前没清理掉的同一条（或上一次超时的请求其实已成功），查出它的 ID 当句柄
    if (code === "DomainRecordDuplicate") {
      const id = await find();
      if (id) return id;
    }
    throw e;
  }
}

export const aliyunDns = defineDns<AliyunCredentials>({
  vendor: "aliyun",
  label: "阿里云云解析",
  ...familyEnv(ENV_FAMILIES.aliyun, readAliyun),
  // 免费版 dns1~32.hichina.com、ns1~8.alidns.com，付费版 vip1~8.alidns.com（帮助文档「查看 DNS 服务器状态」）；
  // 用户自定义的 NS 名（用自己域名做的 DNS Host）认不出；DescribeDomains 会直接返回分配的 NS，多数情况用不到这条规则
  nameServerPattern: /(^|\.)(hichina|alidns)\.com$/,

  async listZones(ctx, creds) {
    const domains = await paginate<AliDomain>(PAGE_SIZE, async (page) => {
      const res = await callRpc<{ TotalCount?: number; Domains?: { Domain?: AliDomain[] } }>(ctx, creds, {
        ...API,
        action: "DescribeDomains",
        params: { PageNumber: page, PageSize: PAGE_SIZE },
      });
      return { items: res.Domains?.Domain ?? [], total: res.TotalCount };
    });
    // 公网权威解析的域名列表：内网解析（PrivateZone）是另一个产品，不会出现在这里
    return domains.filter((d): d is AliDomain & { DomainName: string } => !!d.DomainName?.trim()).map(toZone);
  },

  /**
   * 阿里云是「一条记录一个值」：直接新增一条，同名下已有的其他 TXT 值不受影响。
   * 新增不幂等：请求只发一次，遇到超时、限流等可重试错误时整体重来，先查同名同值的记录，
   * 上一次其实已经加上了就直接用它，查不到再发；重发撞上 DomainRecordDuplicate 时同样查出已有的那条
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
        return await addRecord(ctx, creds, record.zone, rr, record.value, ttl, () => find(true));
      });
    } catch (e) {
      // 重试用完时最后一次添加的结果同样未知：再查一次，加上了就不算失败，免得这条记录没有句柄、无法清理
      if (sent && isRetryable(e)) {
        const id = await find(false).catch(() => undefined);
        if (id) return id;
      }
      throw e;
    }
  },

  /** 按记录 ID 删除，只删这一条；删除可以原样重试，前一次其实已删掉时落到「记录不存在」，视为成功 */
  async removeTxt(ctx, creds, _record, handle) {
    try {
      await callRpc(ctx, creds, { ...API, action: "DeleteDomainRecord", params: { RecordId: handle } });
    } catch (e) {
      if (e instanceof CloudApiError && GONE_CODES.has(e.code)) return;
      throw e;
    }
  },
});
