import type { AliyunCredentials } from "../../lib/env.js";
import { CloudApiError, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import type { DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { callRpc } from "./client.js";
import { matchHost } from "./esa-rule.js";

interface Site {
  SiteId: number;
  SiteName: string;
  Status?: string;
}

interface DnsRecord {
  RecordName: string;
  Proxied?: boolean;
}

interface SiteCert {
  Id: string;
  Name?: string;
  Type?: string;
  Status?: string;
  CommonName?: string;
  /** 逗号分隔 */
  SAN?: string;
  Issuer?: string;
  /** RSA / ECDSA 等 */
  PubAlg?: string;
  NotBefore?: string;
  NotAfter?: string;
  CreateTime?: string;
  UpdateTime?: string;
}

interface CustomHostname {
  Hostname: string;
  Status?: string;
  SslFlag?: string;
  CertType?: string;
  CertStatus?: string;
  CertNotAfter?: string;
}

/** SSL/TLS 配置（HTTPS 基础配置）：一条全局配置加若干条按主机名匹配的规则 */
interface HttpsConfig {
  ConfigType?: string;
  RuleEnable?: string;
  Rule?: string;
  RuleName?: string;
  Sequence?: number;
  Https?: string;
}

/** partial：命中的规则条件无法判断，HTTPS 是否开启取决于规则是否生效 */
type HttpsSwitch = { state: "on" | "off" | "partial"; rule?: string };

interface Cert {
  raw: SiteCert;
  sans: string[];
  /** CN 与 SAN，小写，用于匹配域名 */
  names: string[];
  notBefore?: string;
  notAfter?: string;
  /** 最近一次配置的时间：已有证书可以原地更新，更新时间缺省时取创建时间 */
  configuredAt?: string;
}

const ENDPOINT = "esa.cn-hangzhou.aliyuncs.com";
const VERSION = "2024-09-10";
// 站点、记录、SaaS 域名列表的 PageSize 上限均为 500；证书列表文档未写上限，取文档示例的量级（每个站点的证书数受套餐配额限制，通常只有几张）
const PAGE = 500;
const CERT_PAGE = 20;

// 各套餐都含 SaaS 域名配额；以防个别套餐不支持时报套餐类错误，这些错误等同没有 SaaS 域名
const SAAS_UNSUPPORTED = new Set(["ErrSiteIdNoteEnterprise", "OperationDenied.UnsupportPlan", "QuotaCheckFailed.Function"]);

/** 站点证书接口的时间是不带时区的 "YYYY-MM-DD HH:mm:ss"，但按文档为 UTC，不同于其他阿里云接口的北京时间 */
function utc(value?: string): string | undefined {
  const s = value?.trim();
  return toIso(s && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s) ? `${s.replace(" ", "T")}Z` : s);
}

/** 证书名是否覆盖该域名：精确匹配，或 *.example.com 匹配一级子域（泛域名记录与同名泛域名证书按精确匹配） */
function covers(names: string[], host: string): boolean {
  const h = host.toLowerCase();
  return names.some((n) => {
    if (n === h) return true;
    if (!n.startsWith("*.")) return false;
    const label = h.slice(0, h.length - n.length + 1);
    return h.endsWith(n.slice(1)) && label.length > 0 && !label.includes(".");
  });
}

const latest = (certs: Cert[], key: (c: Cert) => string | undefined) =>
  certs.reduce((a, b) => ((key(b) ?? "") > (key(a) ?? "") ? b : a));

/**
 * 按 ESA 的证书选择优先级挑出域名当前生效的证书：有效期内的优先，同为有效时配置时间较晚的优先。
 * RSA 与 ECC 证书可能按客户端支持的算法分别下发，各取一张后报告先到期的那张，宁可早报。
 * 没有有效证书时取最近过期的那张以提示已过期；只有申请中 / 申请失败的证书时返回它以展示状态。
 */
function pick(certs: Cert[], now: Date): Cert | undefined {
  if (certs.length === 0) return undefined;
  const t = now.toISOString();
  const issued = certs.filter((c) => c.notAfter);
  const valid = issued.filter((c) => c.notAfter! > t && (!c.notBefore || c.notBefore <= t));
  if (valid.length > 0) {
    const algs = [...new Set(valid.map((c) => c.raw.PubAlg))];
    const effective = algs.map((alg) => latest(valid.filter((c) => c.raw.PubAlg === alg), (c) => c.configuredAt));
    return effective.reduce((a, b) => (b.notAfter! < a.notAfter! ? b : a));
  }
  if (issued.length > 0) return latest(issued, (c) => c.notAfter);
  return certs[0];
}

/**
 * 按站点的 SSL/TLS 配置判断该主机名是否开启 HTTPS。SSL/TLS 规则不可重入：规则优先于全局配置，
 * 启用的规则按序号从小到大取第一条命中的；都不命中时用全局配置；开关缺省为开启。
 * 规则条件无法判断时，命中与否的结果相同才算确定，否则记为 partial。
 */
function httpsSwitch(configs: HttpsConfig[], host: string): HttpsSwitch {
  const state = (c?: HttpsConfig) => (c?.Https === "off" ? "off" : "on");
  const global = configs.find((c) => c.ConfigType === "global");
  const rules = configs
    .filter((c) => c.ConfigType !== "global" && c.RuleEnable !== "off")
    .sort((a, b) => (a.Sequence ?? Infinity) - (b.Sequence ?? Infinity));
  const resolve = (i: number): HttpsSwitch => {
    const rule = rules[i];
    if (!rule) return { state: state(global) };
    const hit = matchHost(rule.Rule ?? "", host);
    if (hit === false) return resolve(i + 1);
    if (hit === true) return compact({ state: state(rule), rule: rule.RuleName });
    const miss = resolve(i + 1);
    return miss.state === state(rule) ? { state: miss.state } : compact({ state: "partial" as const, rule: rule.RuleName });
  };
  return resolve(0);
}

/**
 * 边缘安全加速 ESA：逐个站点查开启代理加速的记录、站点证书、SSL/TLS 配置和 SaaS 域名（站点并发 5）。
 * 证书挂在站点上而不是记录上，按证书的 CN / SAN 匹配到记录；记录的 HTTPS 需要 SSL/TLS 配置开启且有已签发的匹配证书。
 * 只解析不加速的记录不经过 ESA，不列出。SaaS 域名的 SSL 开关和证书单独配置，直接取接口返回值。
 */
export const esa: DomainService<AliyunCredentials> = {
  key: "esa",
  label: "边缘安全加速 ESA",
  async list(ctx: QueryContext, creds: AliyunCredentials, warn: Warn): Promise<DomainRecord[]> {
    const call = <T>(action: string, params: Record<string, string | number>) =>
      callRpc<T>(ctx, creds, { endpoint: ENDPOINT, version: VERSION, action, params });
    const sites = await paginate(PAGE, async (page) => {
      const res = await call<{ Sites?: Site[]; TotalCount?: number }>("ListSites", { PageNumber: page, PageSize: PAGE });
      return { items: res.Sites ?? [], total: res.TotalCount };
    });
    const perSite = await mapLimit(sites, 5, async (site) => {
      const siteParams = { SiteId: site.SiteId };
      const res = await Promise.all([
        paginate(PAGE, async (page) => {
          const r = await call<{ Records?: DnsRecord[]; TotalCount?: number }>("ListRecords", {
            ...siteParams,
            Proxied: "true",
            PageNumber: page,
            PageSize: PAGE,
          });
          return { items: r.Records ?? [], total: r.TotalCount };
        }),
        paginate(CERT_PAGE, async (page) => {
          const r = await call<{ Result?: SiteCert[]; TotalCount?: number }>("ListCertificates", {
            ...siteParams,
            PageNumber: page,
            PageSize: CERT_PAGE,
          });
          return { items: r.Result ?? [], total: r.TotalCount };
        }),
        paginate(PAGE, async (page) => {
          const r = await call<{ Configs?: HttpsConfig[]; TotalCount?: number }>("ListHttpsBasicConfigurations", {
            ...siteParams,
            PageNumber: page,
            PageSize: PAGE,
          });
          return { items: r.Configs ?? [], total: r.TotalCount };
        }).catch((e: unknown) => {
          // 查不到 SSL/TLS 配置时不影响记录和证书的输出，HTTPS 只按证书判断，httpsSwitch 缺省
          warn(e, `site ${site.SiteName} SSL/TLS 配置`);
          return undefined;
        }),
        paginate(PAGE, async (page) => {
          const r = await call<{ Hostnames?: CustomHostname[]; TotalCount?: number }>("ListCustomHostnames", {
            ...siteParams,
            PageNumber: page,
            PageSize: PAGE,
          });
          return { items: r.Hostnames ?? [], total: r.TotalCount };
        }).catch((e: unknown) => {
          if (!(e instanceof CloudApiError && SAAS_UNSUPPORTED.has(e.code))) warn(e, `site ${site.SiteName} SaaS 域名`);
          return [];
        }),
      ]).catch((e: unknown) => {
        warn(e, `site ${site.SiteName}`);
        return undefined;
      });
      if (!res) return [];
      const [records, siteCerts, httpsConfigs, hostnames] = res;
      const certs: Cert[] = siteCerts.map((c) => {
        const sans = c.SAN?.split(",").map((s) => s.trim()).filter(Boolean) ?? [];
        return {
          raw: c,
          sans,
          names: [c.CommonName?.trim() ?? "", ...sans].filter(Boolean).map((n) => n.toLowerCase()),
          notBefore: utc(c.NotBefore),
          notAfter: utc(c.NotAfter),
          configuredAt: utc(c.UpdateTime) ?? utc(c.CreateTime),
        };
      });
      const where = { siteId: String(site.SiteId), site: site.SiteName };
      const fromRecords = records
        // 服务端已按 Proxied 过滤，这里再兜底一次，以防参数被忽略时混入只解析的记录
        .filter((r) => r.Proxied !== false)
        .map((r) => {
          const sw = httpsConfigs && httpsSwitch(httpsConfigs, r.RecordName);
          // HTTPS 关闭时证书不会下发，不展示；只有申请中 / 申请失败的证书时也无法提供 HTTPS，但证书状态仍保留在 cert 里
          const c = sw?.state === "off" ? undefined : pick(certs.filter((x) => covers(x.names, r.RecordName)), ctx.now);
          return compact({
            provider: "aliyun" as const,
            service: "esa",
            domain: r.RecordName,
            status: site.Status,
            https: !!c?.notAfter,
            cert: c
              ? compact({
                  id: c.raw.Id,
                  name: c.raw.Name,
                  commonName: c.raw.CommonName,
                  sans: c.sans,
                  issuer: c.raw.Issuer,
                  notBefore: c.notBefore,
                  notAfter: c.notAfter,
                  status: c.raw.Status,
                })
              : undefined,
            extra: compact({ ...where, certType: c?.raw.Type, httpsSwitch: sw?.state, httpsRule: sw?.rule }),
          });
        });
      const fromSaas = hostnames.map((h) => {
        const https = h.SslFlag === "on";
        return compact({
          provider: "aliyun" as const,
          service: "esa",
          domain: h.Hostname,
          status: h.Status,
          https,
          cert: https ? compact({ notAfter: toIso(h.CertNotAfter), status: h.CertStatus }) : undefined,
          extra: compact({ ...where, hostType: "saas", certType: https ? h.CertType : undefined }),
        });
      });
      return [...fromRecords, ...fromSaas];
    });
    return perSite.flat();
  },
};
