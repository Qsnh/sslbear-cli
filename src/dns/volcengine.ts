import { domainToASCII } from "node:url";
import { ENV_FAMILIES, readAccessKey, type AccessKeyCredentials } from "../lib/env.js";
import { CloudApiError, isRetryable, withRetry, type QueryContext } from "../lib/http.js";
import { paginate } from "../lib/paginate.js";
import { callVolc, callVolcOnce } from "../providers/volcengine/client.js";
import { familyEnv } from "./env.js";
import { defineDns, normalizeName, relativeName, type DnsZone } from "./types.js";

/**
 * 云解析 DNS 的 OpenAPI，接入点 dns.volcengineapi.com（「调用方式」https://www.volcengine.com/docs/6758/155088）。
 * 签名用的服务名 / 地域文档前后不一：「调用方式」的示例代码写 DNS / cn-north-1，各接口页的请求示例、官方 SDK
 * （volcengine-go-sdk、volc-sdk-golang）、lego、acme.sh 都是 dns / cn-beijing，取后者；响应回显的 Service 也一律是小写 dns
 */
const API = { host: "dns.volcengineapi.com", service: "dns", region: "cn-beijing", version: "2018-08-01" } as const;
// ListRecords 的 PageSize 上限名义上 500，但带筛选条件时 500 会报 ErrPageSizeNotValid，统一用 100
const PAGE_SIZE = 100;

/**
 * 各功能版本允许的最小 TTL（「功能版本规格」https://www.volcengine.com/docs/6758/170354）：免费版 600、专业版 300、企业版 60、旗舰版 / 尊享版 1。
 * 不认识的版本按免费版的 600，各版本都接受；版本判断不准（如付费版刚降级）被 ErrSpecNotValid 拒绝时也退回 600
 */
const FREE_TTL = 600;
const MIN_TTL: Record<string, number> = {
  free_inner: FREE_TTL,
  professional_inner: 300,
  enterprise_inner: 60,
  ultimate_inner: 1,
  ultimate_exclusive_inner: 1,
};

/**
 * 解析记录会生效的域名状态（ListZones 的 Stage 筛选，含义见 QueryZone https://www.volcengine.com/docs/6758/155099）：
 * 0 正常；5「请变更 DNS 服务器」（服务升级后分配了新 NS，旧 NS 仍在服务）。
 * 1 待找回、2 NS 没指向云解析、3 异常（未实名、未注册等）时文档写明「解析记录不生效」，这些 zone 不返回：
 * 比如没在父域名做 NS 委派的子域名托管（IsSubDomain），验证记录加在这里不会生效，应当落到父域名所在的服务商。
 * ListZones 的响应里没有 Stage 字段，只能按状态分别筛选
 */
const LIVE_STAGES = ["0", "5"];

interface VolcZone {
  ZID?: number;
  ZoneName?: string;
  TradeCode?: string;
  /** 1 = 不是域名所有者（待找回） */
  CacheStage?: number;
}

interface VolcRecord {
  /** 19 位数字，超出 JS 安全整数，接口以字符串返回 */
  RecordID?: string;
  Host?: string;
  Type?: string;
  Value?: string;
  Line?: string;
}

/** zone 名规范化；中文域名转 punycode，与 issue 规范化后的域名一致（记录按 ZID 寻址，不需要原名） */
const ascii = (name: string) => normalizeName(domainToASCII(normalizeName(name)) || name);

/** TXT 记录值按原样比较（文档要求记录值不带引号）；万一接口带上了引号，去掉再比 */
const unquote = (v: string | undefined) => (v && v.length >= 2 && v.startsWith('"') && v.endsWith('"') ? v.slice(1, -1) : (v ?? ""));

function toZone(z: VolcZone & { ZID: number; ZoneName: string }): DnsZone {
  return { name: ascii(z.ZoneName), id: String(z.ZID), extra: { ttl: String(MIN_TTL[z.TradeCode ?? ""] ?? FREE_TTL) } };
}

/**
 * 同名下同值的 TXT 记录（默认线路）的 ID。SearchMode 管的是 Host 的匹配方式，缺省是模糊匹配，必须显式写 exact；
 * 返回后再按主机记录（接口会转小写）、类型、线路、值核对一遍。
 * retry=false 只发一次：在 addTxt 的重试循环里查时由外层重试，免得网络不通时层层重试、等很久
 */
async function findTxt(
  ctx: QueryContext,
  creds: AccessKeyCredentials,
  zone: DnsZone,
  host: string,
  value: string,
  retry: boolean,
): Promise<string | undefined> {
  const call = retry ? callVolc : callVolcOnce;
  const records = await paginate<VolcRecord>(PAGE_SIZE, async (page) => {
    // 文档里 ListRecords / ListZones 是 GET（参数在 query 上），写接口是 POST JSON
    const res = await call<{ TotalCount?: number; Records?: VolcRecord[] | null }>(ctx, creds, {
      ...API,
      action: "ListRecords",
      method: "GET",
      params: { ZID: zone.id, Host: host, Type: "TXT", SearchMode: "exact", PageNumber: page, PageSize: PAGE_SIZE },
    });
    return { items: res.Records ?? [], total: res.TotalCount };
  });
  const same = records.find(
    (r) =>
      r.Type?.toUpperCase() === "TXT" &&
      r.Host?.toLowerCase() === host.toLowerCase() &&
      (r.Line || "default") === "default" &&
      unquote(r.Value) === value,
  );
  return same?.RecordID ? String(same.RecordID) : undefined;
}

/** 发一次 CreateRecord（不自动重试）；被拒的 TTL、同名同值已存在在这里处理 */
async function addRecord(
  ctx: QueryContext,
  creds: AccessKeyCredentials,
  zone: DnsZone,
  host: string,
  value: string,
  ttl: number,
  find: () => Promise<string | undefined>,
): Promise<string> {
  try {
    const res = await callVolcOnce<{ RecordID?: string }>(ctx, creds, {
      ...API,
      action: "CreateRecord",
      method: "POST",
      // ZID 在 JSON 里是数字；Line 缺省就是 default，显式写上与查重时的线路条件对应
      params: { ZID: Number(zone.id), Host: host, Type: "TXT", Value: value, TTL: ttl, Line: "default" },
    });
    if (!res.RecordID) throw new CloudApiError("volcengine", "InvalidResponse", "添加解析记录的响应里没有 RecordID");
    return String(res.RecordID);
  } catch (e) {
    const code = e instanceof CloudApiError ? e.code : undefined;
    // 参数不符合功能版本规格：多半是 TTL 低于当前版本的下限，请求被明确拒绝、没有加上，换成各版本都接受的 600 再加
    if (code === "ErrSpecNotValid" && ttl !== FREE_TTL) return addRecord(ctx, creds, zone, host, value, FREE_TTL, find);
    // 数据库条目重复（HTTP 409）：同名同值已存在，只可能是之前没清理掉的同一条（或上一次超时的请求其实已成功），查出它的 ID 当句柄
    if (code === "ErrDBDuplicated") {
      const id = await find();
      if (id) return id;
      // 报已存在却查不到：多半是上一次超时的添加其实已成功、查询还没跟上。没有句柄，交给编排层按「可能已添加」提示用户核对
      throw new CloudApiError(
        "volcengine",
        "RecordMayExist",
        `火山引擎报同名同值的 TXT 记录已存在（${code}），但查不到这条记录的 ID（多半是索引延迟），记录可能已添加`,
        (e as CloudApiError).requestId,
      );
    }
    throw e;
  }
}

export const volcengineDns = defineDns<AccessKeyCredentials>({
  vendor: "volcengine",
  label: "火山引擎云解析",
  ...familyEnv(ENV_FAMILIES.volcengine, readAccessKey(ENV_FAMILIES.volcengine)),
  // 免费版 ns1/ns2、专业版及以上 vip1/vip2、开启安全防护 vip3/vip4、海外 intl，都在 volcengine-dns.com 下
  // （「查看域名的 DNS 服务器」https://www.volcengine.com/docs/6758/1472582）；2023-12-06 前添加的域名继续用 ns1~5.volcdns.com
  nameServerPattern: /(^|\.)(volcengine-dns|volcdns)\.com$/,

  /** 公网权威解析的域名列表：私网解析（PrivateZone）是另一个服务（private-zone.volcengineapi.com），不会出现在这里 */
  async listZones(ctx, creds) {
    const zones = new Map<string, DnsZone>();
    for (const stage of LIVE_STAGES) {
      const list = await paginate<VolcZone>(PAGE_SIZE, async (page) => {
        const res = await callVolc<{ Total?: number; Zones?: VolcZone[] | null }>(ctx, creds, {
          ...API,
          action: "ListZones",
          method: "GET",
          params: { Stage: stage, PageNumber: page, PageSize: PAGE_SIZE },
        });
        return { items: res.Zones ?? [], total: res.Total };
      });
      for (const z of list) {
        // CacheStage 1 与 Stage 1 同义（待找回）：万一接口忽略了筛选条件，至少排除它；两次结果重复时按 ZID 去重
        if (typeof z.ZID !== "number" || !z.ZoneName?.trim() || z.CacheStage === 1) continue;
        const zone = toZone(z as VolcZone & { ZID: number; ZoneName: string });
        if (!zones.has(zone.id)) zones.set(zone.id, zone);
      }
    }
    return [...zones.values()];
  },

  /**
   * 火山是「一条记录一个值」（只有 A / AAAA / CNAME 有记录集）：直接新增一条，同名下已有的其他 TXT 值不受影响。
   * 新增不幂等：请求只发一次，遇到超时、限流等可重试错误时整体重来，每次先查同名同值的记录，
   * 上一次其实已经加上了就直接用它，查不到再发；重发撞上 ErrDBDuplicated 时同样查出已有的那条
   */
  async addTxt(ctx, creds, record) {
    const host = relativeName(record.fqdn, record.zone.name);
    const ttl = Number(record.zone.extra?.ttl) || FREE_TTL;
    const find = (retry: boolean) => findTxt(ctx, creds, record.zone, host, record.value, retry);
    let sent = false;
    try {
      return await withRetry(ctx, async () => {
        const id = await find(false);
        if (id) return id;
        sent = true;
        return await addRecord(ctx, creds, record.zone, host, record.value, ttl, () => find(true));
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

  /** 按 RecordID 删除，只删这一条；删除可以原样重试，前一次其实已删掉时落到 ErrDBNotFound（记录不存在），视为成功 */
  async removeTxt(ctx, creds, _record, handle) {
    try {
      await callVolc(ctx, creds, { ...API, action: "DeleteRecord", method: "POST", params: { RecordID: handle } });
    } catch (e) {
      if (e instanceof CloudApiError && e.code === "ErrDBNotFound") return;
      throw e;
    }
  },
});
