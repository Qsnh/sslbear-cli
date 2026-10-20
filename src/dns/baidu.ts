import { randomUUID } from "node:crypto";
import { domainToASCII } from "node:url";
import { ENV_FAMILIES, readAccessKey, type AccessKeyCredentials } from "../lib/env.js";
import { CloudApiError, type QueryContext } from "../lib/http.js";
import { callBce } from "../providers/baidu/client.js";
import { familyEnv } from "./env.js";
import { defineDns, normalizeName, relativeName, type DnsZone } from "./types.js";

/** 公网 DNS 是全局产品，服务域名 dns.baidubce.com（「API 服务域名」https://cloud.baidu.com/doc/DNS/s/5kk5e2pd4） */
const HOST = "dns.baidubce.com";
// maxKeys 缺省、上限都是 1000
const MAX_KEYS = "1000";
/** 防止接口异常（如一直返回同一个 nextMarker）时死循环 */
const MAX_PAGES = 1000;
/**
 * 删除时没有句柄（添加后没查到记录 ID）只能按值查：解析记录列表有延迟，查不到时依次隔 2、3、5 秒再查（总共约 10 秒），
 * 仍查不到就报错，不能当成已经删掉
 */
const UNLISTED_WAITS_MS = [2000, 3000, 5000];

/**
 * 各版本的最小 TTL（「产品定价」版本对比 https://cloud.baidu.com/doc/DNS/s/ojwvyx3em）：基础版（free）300 秒、普惠版（discount）120 秒、企业版（flagship）1 秒。
 * 不认识的版本按基础版的 300，各版本都接受
 */
const FREE_TTL = 300;
const MIN_TTL: Record<string, number> = { free: FREE_TTL, discount: 120, flagship: 1 };

interface BceZone {
  id?: string;
  name?: string;
  /** running 正常、unregister 未被注册、nsunchange NS 尚未修改、failed 服务异常、torenew 未备案 */
  status?: string;
  productVersion?: string;
}

interface BceRecord {
  id?: string;
  rr?: string;
  type?: string;
  value?: string;
  line?: string;
}

const ascii = (name: string) => normalizeName(domainToASCII(normalizeName(name)) || name);

/** TXT 记录值按原样比较（lego、acme.sh 都不加引号）；万一接口带上了引号，去掉再比 */
const unquote = (v: string | undefined) => (v && v.length >= 2 && v.startsWith('"') && v.endsWith('"') ? v.slice(1, -1) : (v ?? ""));

/** marker 分页：isTruncated 为 true 时带上 nextMarker 取下一页（「域名相关接口」「解析记录相关接口」） */
async function listAll<T>(
  ctx: QueryContext,
  creds: AccessKeyCredentials,
  path: string,
  key: "zones" | "records",
  query: Record<string, string> = {},
): Promise<T[]> {
  const all: T[] = [];
  let marker: string | undefined;
  for (let page = 1; page <= MAX_PAGES; page++) {
    const res = await callBce<{ isTruncated?: boolean; nextMarker?: string; zones?: T[] | null; records?: T[] | null }>(ctx, creds, {
      host: HOST,
      path,
      query: { ...query, maxKeys: MAX_KEYS, ...(marker && { marker }) },
    });
    all.push(...(res[key] ?? []));
    if (!res.isTruncated || !res.nextMarker || res.nextMarker === marker) return all;
    marker = res.nextMarker;
  }
  throw new Error(`分页超过 ${MAX_PAGES} 页仍未取完，已中止（接口返回可能异常）`);
}

/** 记录接口按域名寻址（zoneName 在路径上），zone.id 就是接口里的域名 */
const recordsPath = (zone: DnsZone) => `/v1/dns/zone/${zone.id}/record`;

/**
 * 同名下同值的 TXT 记录（默认线路）。rr 是精确还是模糊匹配文档没写，查回来再按主机记录、类型、线路、值核对一遍
 */
async function sameTxt(ctx: QueryContext, creds: AccessKeyCredentials, zone: DnsZone, rr: string, value: string): Promise<(BceRecord & { id: string })[]> {
  const records = await listAll<BceRecord>(ctx, creds, recordsPath(zone), "records", { rr });
  return records.filter(
    (r): r is BceRecord & { id: string } =>
      !!r.id &&
      r.type?.toUpperCase() === "TXT" &&
      r.rr?.toLowerCase() === rr.toLowerCase() &&
      (r.line || "default") === "default" &&
      unquote(r.value) === value,
  );
}

export const baiduDns = defineDns<AccessKeyCredentials>({
  vendor: "baidu",
  label: "百度智能云 DNS",
  ...familyEnv(ENV_FAMILIES.baidu, readAccessKey(ENV_FAMILIES.baidu)),
  // 基础版、普惠版 ns1/ns2.bdydns.cn，企业版 sv1~sv4.bdydns.cn（「开启解析服务」https://cloud.baidu.com/doc/DNS/s/9jxk76qc2）；接口不返回 zone 的 NS
  nameServerPattern: /(^|\.)bdydns\.cn$/,

  // 实测 2026-10：子用户没有智能云解析的读权限时，域名列表返回 200 + 空列表（查解析记录才报 401 PermissionDeny）
  emptyZonesHint: "百度智能云解析返回的域名列表是空的，子用户没有智能云解析的读权限时也是这样（不报错），请确认已授予 DNSReadAccessPolicy（签发还要 DNSOperateAccessPolicy）",

  /**
   * 公网 DNS 的域名列表（内网 DNS 是另一个服务 privatezone.baidubce.com，不会出现在这里）。
   * 返回 running 与 torenew：nsunchange（NS 尚未修改，即未接入）、unregister、failed 时解析记录不会生效。
   * torenew（未备案）照常返回：百度文档写明「域名解析与备案并无直接关联……即使网站未备案或者备案中，这并不影响域名解析的设置和解析的生效」
   * （https://cloud.baidu.com/doc/BCD/s/Yka2olkgy），备案只影响解析到境内服务器的网站能否访问；DNS-01 验证只查 TXT，与之无关
   */
  async listZones(ctx, creds) {
    const zones = await listAll<BceZone>(ctx, creds, "/v1/dns/zone", "zones").catch((e: unknown) => {
      // 实测：没开通智能云解析的账号报 NotFound「could not found: role[BceServiceRole_console_dns]」（缺服务角色），原文看不出原因
      if (e instanceof CloudApiError && /BceServiceRole_console_dns/.test(e.message)) {
        throw new CloudApiError("baidu", e.code, `${e.message}（智能云解析 DNS 未开通：缺少服务角色，请先在百度智能云控制台开通智能云解析）`, e.requestId, e.httpStatus);
      }
      throw e;
    });
    return zones
      .filter((z): z is BceZone & { name: string } => !!z.name?.trim() && (z.status === "running" || z.status === "torenew"))
      .map((z) => ({
        // 中文域名：zone 名用 punycode（与 issue 规范化后的域名一致），路径上仍用接口里的原名
        name: ascii(z.name),
        id: normalizeName(z.name),
        extra: { ttl: String(MIN_TTL[z.productVersion ?? ""] ?? FREE_TTL) },
      }));
  },

  /**
   * 百度是「一条记录一个值」：直接新增一条，同名下已有的其他 TXT 值不受影响；同名同值已存在时直接用它。
   * 添加带 clientToken：同一个 token 的重复请求服务端返回同样的结果、不会重复创建（「通用说明 - 幂等性」https://cloud.baidu.com/doc/DNS/s/Skk5e9in2），
   * 所以可以交给 callBce 原样自动重试。token 每次添加新生成：同一个验证值删掉后 24 小时内再加（如重新执行时 CA 复用了同一个待验证的授权），
   * 沿用旧 token 会被当成重复请求、什么都不做
   */
  async addTxt(ctx, creds, record) {
    const { zone } = record;
    const rr = relativeName(record.fqdn, zone.name);
    const find = async () => (await sameTxt(ctx, creds, zone, rr, record.value))[0]?.id;
    const existing = await find();
    if (existing) return existing;
    try {
      await callBce(ctx, creds, {
        host: HOST,
        method: "POST",
        path: recordsPath(zone),
        query: { clientToken: randomUUID() },
        body: { rr, type: "TXT", value: record.value, ttl: Number(zone.extra?.ttl) || FREE_TTL, line: "default" },
      });
    } catch (e) {
      // 文档没写重复记录的错误码：被拒后再查一次，同名同值已经在了（如前一次请求其实已成功）就用它
      const id = await find().catch(() => undefined);
      if (id) return id;
      throw e;
    }
    // 添加接口没有返回参数（拿不到记录 ID）：再查一次取 ID 当句柄；万一还查不到（列表有延迟）也不算失败，返回空句柄，
    // removeTxt 遇到空句柄时按值查找、查不到会隔一会儿再查，仍查不到报错，不会静默当成已删除
    return (await find()) ?? "";
  },

  /**
   * 句柄（记录 ID）非空时直接按 ID 删除，不依赖列表：列表有延迟，按值查不到会误以为已经删掉、记录却残留。
   * 删除报错时（删除不存在的记录报什么错文档没写）再按值查一次：查不到才视为已删除，还在就抛出原错误。
   * 句柄为空（添加后没查到 ID）只能按值查，查不到时隔一会儿再查，仍查不到就报错，让编排层记为没清理、提示用户核对。
   * 只删值相同的记录，同名下其他 TXT 记录不动；删除带 clientToken（幂等，callBce 自动重试时沿用同一个）
   */
  async removeTxt(ctx, creds, record, handle) {
    const { zone } = record;
    const rr = relativeName(record.fqdn, zone.name);
    const find = () => sameTxt(ctx, creds, zone, rr, record.value);
    const remove = (id: string) => callBce(ctx, creds, { host: HOST, method: "DELETE", path: `${recordsPath(zone)}/${id}`, query: { clientToken: randomUUID() } });
    if (handle) {
      try {
        await remove(handle);
        return;
      } catch (e) {
        // 句柄是添加后在列表里查到的 ID，此时列表里已经有它：现在查不到就是真的不在了。查询也失败时报删除的原错误
        const left = await find().catch(() => undefined);
        if (left?.length === 0) return;
        throw e;
      }
    }
    const sleep = ctx.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
    for (let i = 0; ; i++) {
      const found = await find();
      if (found.length > 0) {
        for (const r of found) await remove(r.id);
        return;
      }
      if (i >= UNLISTED_WAITS_MS.length) {
        const waited = UNLISTED_WAITS_MS.reduce((a, b) => a + b, 0) / 1000;
        throw new CloudApiError(
          "baidu",
          "RecordNotListed",
          `添加时没拿到记录 ID，按值查了 ${i + 1} 次（约 ${waited} 秒）仍查不到 ${record.fqdn} 的这条 TXT 记录：解析记录列表可能有延迟，记录可能还在，请到控制台核对，有就手动删除`,
        );
      }
      await sleep(UNLISTED_WAITS_MS[i]!);
    }
  },
});
