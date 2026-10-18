import type { Credentials, Env } from "../lib/env.js";
import type { QueryContext } from "../lib/http.js";
import type { EnvKeyStatus } from "../providers/registry.js";
import type { DnsVendor } from "../types.js";

/** DNS 服务商托管的一个公网域名（zone） */
export interface DnsZone {
  /** 小写、无结尾点，如 example.com */
  name: string;
  /** 服务商内部的 zone 标识（Cloudflare zone ID、Route 53 hosted zone ID 等）；接口按域名寻址的服务商填 name */
  id: string;
  /** 接口返回的该 zone 的权威 NS（小写、无结尾点）；接口不返回就缺省 */
  nameServers?: string[];
  /** 定位用的附加信息（如 Azure 的资源 ID、Google 的项目），由各适配器自用 */
  extra?: Record<string, string>;
}

/** 一条 DNS-01 验证用的 TXT 记录 */
export interface TxtRecord {
  zone: DnsZone;
  /** 完整记录名，小写、无结尾点，如 _acme-challenge.www.example.com；一定以 zone.name 结尾 */
  fqdn: string;
  /** 验证值（base64url，43 个字符），不带引号 */
  value: string;
}

/**
 * 一家 DNS 服务商的适配器。issue 命令逐条串行调用 addTxt / removeTxt（同名记录集不会被并发读改写），
 * listZones 各服务商之间并行调用。接口错误一律抛 CloudApiError（provider 为 vendor），带上错误码与 RequestId。
 */
export interface DnsProviderDef<C> {
  vendor: DnsVendor;
  /** 中文展示名，如「阿里云云解析」 */
  label: string;
  /** 全部凭证变量名：shell 里设置了其中任一个时，.env 里这一组整组忽略 */
  envNames: readonly string[];
  /** 未配置凭证时提示需要设置的变量 */
  requiredEnv: readonly string[];
  readCredentials(env: Env): Credentials<C>;
  /** env 命令展示用（ID 类给脱敏值，Secret 只标明是否已设置） */
  envKeys(env: Env): EnvKeyStatus[];
  /** 该服务商权威 NS 的主机名规则（小写、无结尾点）；同一 zone 被多家托管时按域名实际的 NS 记录判定用哪家 */
  nameServerPattern: RegExp;
  /** 列出账号下全部公网 zone（自动翻页），私有 zone / 未生效（如待接入）的不返回 */
  listZones(ctx: QueryContext, creds: C): Promise<DnsZone[]>;
  /**
   * 添加一条 TXT 记录，返回删除时要用的句柄（记录 ID 等，格式由适配器决定）。
   * - 同名下已有的其他 TXT 值必须保留（泛域名与根域名的验证值在同一个名字下）。
   * - 同名同值的记录已存在时不报错，返回指向它的句柄：验证值是这次验证专属的，已存在只可能是之前没清理掉的同一条。
   * - TTL 用该服务商允许的最小值（多数 60 / 120 / 300 / 600 秒）。
   */
  addTxt(ctx: QueryContext, creds: C, record: TxtRecord): Promise<string>;
  /** 删除 addTxt 加的那个值：同名下其他值保留；记录已经不存在时视为成功 */
  removeTxt(ctx: QueryContext, creds: C, record: TxtRecord, handle: string): Promise<void>;
}

export function defineDns<C>(def: DnsProviderDef<C>): DnsProviderDef<C> {
  return def;
}

/** 规范化服务商返回的域名 / NS：小写、去掉结尾点 */
export function normalizeName(name: string): string {
  return name.trim().toLowerCase().replace(/\.$/, "");
}

/** 记录名相对 zone 的主机记录：_acme-challenge.www.example.com 在 example.com 下为 _acme-challenge.www；与 zone 同名时为 @ */
export function relativeName(fqdn: string, zone: string): string {
  if (fqdn === zone) return "@";
  if (!fqdn.endsWith(`.${zone}`)) throw new Error(`记录 ${fqdn} 不在 zone ${zone} 下`);
  return fqdn.slice(0, -(zone.length + 1));
}
