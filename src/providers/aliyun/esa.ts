import type { LocalCert } from "../../deploy/cert.js";
import type { AliyunCredentials } from "../../lib/env.js";
import { CloudApiError, withRetry, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import type { CertInfo, DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { CAS_REGION } from "./cas.js";
import { callRpc, callRpcOnce } from "./client.js";
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
  /** 小写 hex */
  FingerprintSha256?: string;
  /** Type 为 cas 时是数字证书管理服务里的证书 ID */
  CasId?: string | number;
  NotBefore?: string;
  NotAfter?: string;
  CreateTime?: string;
  UpdateTime?: string;
}

interface CustomHostname {
  HostnameId?: number;
  RecordId?: number;
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

function listSiteCerts(ctx: QueryContext, creds: AliyunCredentials, siteId: number | string): Promise<SiteCert[]> {
  return paginate(CERT_PAGE, async (page) => {
    const r = await callRpc<{ Result?: SiteCert[]; TotalCount?: number }>(ctx, creds, {
      endpoint: ENDPOINT,
      version: VERSION,
      action: "ListCertificates",
      params: { SiteId: siteId, PageNumber: page, PageSize: CERT_PAGE },
    });
    return { items: r.Result ?? [], total: r.TotalCount };
  });
}

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
 * RSA 与 ECC 证书可能按客户端支持的算法分别下发，各取一张，按到期先后排列（第一张报告为 cert，宁可早报）。
 * 没有有效证书时取最近过期的那张以提示已过期；只有申请中 / 申请失败的证书时返回它以展示状态。
 */
function effective(certs: Cert[], now: Date): Cert[] {
  if (certs.length === 0) return [];
  const t = now.toISOString();
  const issued = certs.filter((c) => c.notAfter);
  const valid = issued.filter((c) => c.notAfter! > t && (!c.notBefore || c.notBefore <= t));
  if (valid.length > 0) {
    const algs = [...new Set(valid.map((c) => c.raw.PubAlg))];
    return algs
      .map((alg) => latest(valid.filter((c) => c.raw.PubAlg === alg), (c) => c.configuredAt))
      .sort((a, b) => (a.notAfter! < b.notAfter! ? -1 : a.notAfter! > b.notAfter! ? 1 : 0));
  }
  if (issued.length > 0) return [latest(issued, (c) => c.notAfter)];
  return [certs[0]!];
}

/** PubAlg 实测有 RSA、ECDSA */
function algorithmOf(pubAlg?: string): CertInfo["algorithm"] {
  const a = pubAlg?.toUpperCase();
  if (!a) return undefined;
  if (a.includes("SM2")) return "SM2";
  if (a.startsWith("EC")) return "ECC";
  return a.includes("RSA") ? "RSA" : undefined;
}

function certInfo(c: Cert): CertInfo {
  return compact({
    id: c.raw.Id,
    name: c.raw.Name,
    commonName: c.raw.CommonName,
    sans: c.sans,
    issuer: c.raw.Issuer,
    notBefore: c.notBefore,
    notAfter: c.notAfter,
    status: c.raw.Status,
    algorithm: algorithmOf(c.raw.PubAlg),
  });
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

const hex = (s: string) => s.replace(/:/g, "").toLowerCase();

/**
 * 往站点设置 CAS 证书，返回站点证书 ID。站点上已有同一张证书（同指纹，或没给指纹时同 CasId）时带它的 Id 原地更新
 * （如上次已添加、又被更晚配置的证书盖过，原地更新让它重新成为最晚配置的），否则新增一张。
 * 新增不幂等：请求只发一次，遇到超时、限流等可重试错误时整体重来，先重新列出站点证书（不用缓存），
 * 上一轮的新增其实已成功时直接算成功，查不到再发，最多 3 轮。
 */
function setSiteCert(ctx: QueryContext, creds: AliyunCredentials, siteId: string, casId: string, cert: LocalCert): Promise<string> {
  let added = false;
  return withRetry(ctx, async () => {
    const same = (await listSiteCerts(ctx, creds, siteId)).find(
      (c) =>
        (c.Type === "cas" || c.Type === "upload") &&
        (c.FingerprintSha256 ? hex(c.FingerprintSha256) === cert.fingerprint : String(c.CasId) === casId),
    );
    if (same && added) return same.Id;
    if (!same) added = true;
    const res = await callRpcOnce<{ Id?: string }>(ctx, creds, {
      endpoint: ENDPOINT,
      version: VERSION,
      action: "SetCertificate",
      method: "POST",
      params: { SiteId: siteId, Type: "cas", CasId: casId, Region: CAS_REGION, Id: same?.Id },
    });
    return res.Id ?? same?.Id ?? casId;
  });
}

/** 往站点添加一种算法的证书不会替换另一算法的证书：支持该算法的客户端仍可能拿到它，提示用户 */
function keptNote(records: DomainRecord[], algorithm: LocalCert["algorithm"]): string | undefined {
  const kept = new Map<string, CertInfo>();
  for (const r of records) {
    for (const c of r.certs ?? (r.cert ? [r.cert] : [])) {
      if (c.algorithm && c.algorithm !== algorithm && c.algorithm !== "SM2") kept.set(c.id ?? c.name ?? "", c);
    }
  }
  if (kept.size === 0) return undefined;
  const list = [...kept.values()]
    .map((c) => `${c.name ?? c.id}（${c.algorithm}${c.notAfter ? `，${c.notAfter.slice(0, 10)} 到期` : ""}）`)
    .join("、");
  return `已在站点添加新证书；站点上另一算法的证书 ${list} 未被替换，支持该算法的客户端仍可能拿到它`;
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
        listSiteCerts(ctx, creds, site.SiteId),
        paginate(PAGE, async (page) => {
          const r = await call<{ Configs?: HttpsConfig[]; TotalCount?: number }>("ListHttpsBasicConfigurations", {
            ...siteParams,
            PageNumber: page,
            PageSize: PAGE,
          });
          return { items: r.Configs ?? [], total: r.TotalCount };
        }).catch((e: unknown) => {
          // 查不到 SSL/TLS 配置时不影响记录和证书的输出，HTTPS 只按证书判断，httpsSwitch 缺省；
          // 有匹配证书的记录实际可能被开关关掉，标 httpsUnknown
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
          const eff = sw?.state === "off" ? [] : effective(certs.filter((x) => covers(x.names, r.RecordName)), ctx.now);
          const c = eff[0];
          const https = !!c?.notAfter;
          return compact({
            provider: "aliyun" as const,
            service: "esa",
            domain: r.RecordName,
            status: site.Status,
            https,
            cert: c ? certInfo(c) : undefined,
            // RSA 与 ECC 两张同时生效时都列出，部署时只替换与新证书同算法的那张
            certs: eff.length > 1 ? eff.map(certInfo) : undefined,
            extra: compact({
              ...where,
              certType: c?.raw.Type,
              httpsSwitch: sw?.state,
              httpsRule: sw?.rule,
              // 没有已签发的匹配证书时开关怎样都不会提供 HTTPS；有证书时取决于查不到的开关
              httpsUnknown: https && !httpsConfigs ? "true" : undefined,
            }),
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
          extra: compact({
            ...where,
            hostType: "saas",
            certType: https ? h.CertType : undefined,
            hostnameId: h.HostnameId?.toString(),
            recordId: h.RecordId?.toString(),
          }),
        });
      });
      return [...fromRecords, ...fromSaas];
    });
    return perSite.flat();
  },
  deployer: {
    // 普通记录的证书挂在站点上，开启 HTTPS 要动站点级配置；SaaS 域名的 SSL 开关和证书在域名自身上
    unsupported: (record, mode) =>
      mode === "update" || record.extra?.hostType === "saas"
        ? undefined
        : "ESA 普通记录的证书挂在站点上，开启 HTTPS 要改站点的 SSL/TLS 规则或站点证书，影响面超出单个域名，请在 ESA 控制台操作",
    // 站点证书会作用到站点下被它覆盖的普通记录：开着 HTTPS 的会被换证书；没开 HTTPS 但 SSL/TLS 开关不是 off 的
    // （开着 / partial / 查不到，只是还没有匹配的已签发证书）站点一加上证书就会开始提供 HTTPS；开关为 off 的不受影响
    sharedScope: (record) => {
      if (record.extra?.hostType === "saas") return undefined;
      return record.https || record.extra?.httpsSwitch !== "off" ? record.extra?.siteId : undefined;
    },
    async apply(ctx, creds, target, input) {
      const casId = await input.certId();
      const post = <T>(action: string, params: Record<string, string | undefined>) =>
        callRpc<T>(ctx, creds, { endpoint: ENDPOINT, version: VERSION, action, method: "POST", params });
      const first = target.records[0]!;
      if (first.extra?.hostType === "saas") {
        // 更新接口同时提交记录绑定，带回查询到的原值，只改 SSL 开关与证书
        for (const r of target.records) {
          const { hostnameId, recordId } = r.extra ?? {};
          if (!hostnameId) throw new Error(`${r.domain} 缺少 SaaS 域名 ID`);
          await post("UpdateCustomHostname", {
            HostnameId: hostnameId,
            RecordId: recordId,
            SslFlag: "on",
            CertType: "cas",
            CasId: casId,
            CasRegion: CAS_REGION,
          });
        }
        return { certId: casId };
      }
      // 站点证书：新增一张（ESA 按「有效期内、配置时间较晚」优先，新证书即对它覆盖的记录生效），旧证书不删除；
      // 站点上已有同一张证书时原地更新它，不重复添加
      const siteId = first.extra?.siteId;
      if (!siteId) throw new Error(`${first.domain} 缺少 ESA 站点 ID`);
      const certId = await setSiteCert(ctx, creds, siteId, casId, input.cert);
      const note = keptNote(target.records, input.cert.algorithm);
      return { certId, ...(note && { note }) };
    },
  },
};
