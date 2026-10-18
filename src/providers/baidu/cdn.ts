import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import type { CertInfo, DomainRecord } from "../../types.js";
import type { DeployTarget, DomainService, Warn } from "../registry.js";
import { enrichFromCertService } from "./cert.js";
import { callBce } from "./client.js";

const HOST = "cdn.baidubce.com";

interface UserDomain {
  domain: string;
  /** RUNNING / STOPPED / OPERATING */
  status?: string;
}

interface HttpsDomain {
  domain: string;
  certId?: string;
  certName?: string;
  /** 字段名像通用名，实测装的是证书名（与 certName 相同），不使用；通用名与 SAN 从证书管理补全 */
  certCommonName?: string;
  /** CDN API 的时间统一为 UTC ISO 8601（如 2019-07-17T08:00:00Z），通用证书时为 "-" */
  certStartTime?: string;
  certStopTime?: string;
  /** 1 服务端证书，2 客户端证书（双向认证） */
  certType?: number;
  /** 1 使用中，2 已过期；实测 6 天后到期的证书为 3（推测是即将过期），原样输出 */
  status?: number;
}

/**
 * GET /v2/domain/{domain}/config?https 的 https 字段；PUT 用同一结构，其余字段为 httpRedirect、httpRedirectCode、
 * httpsRedirect、httpsRedirectCode、noRedirectedUAs、http2Enabled、verifyClient、sslProtocols
 */
interface HttpsConfig {
  enabled?: boolean;
  /** 关闭 HTTPS 时证书可能仍保持绑定（只有显式传 certId="" 才解绑），此时不算 HTTPS */
  certId?: string;
  [field: string]: unknown;
}

/** /v2/httpsDomains 的 pageSize 上限为 100 */
const HTTPS_PAGE = 100;

const placeholder = (s: string | undefined) => (s && !/^-+$/.test(s.trim()) ? s : undefined);

function toCert(row: HttpsDomain): CertInfo {
  return compact({
    id: row.certId,
    name: row.certName,
    notBefore: toIso(placeholder(row.certStartTime)),
    notAfter: toIso(placeholder(row.certStopTime)),
    status: row.status === undefined ? undefined : String(row.status),
  });
}

/** 同一域名有多张服务端证书（如 RSA + 国密）时取最早到期的那张 */
function earliest(certs: CertInfo[]): CertInfo | undefined {
  const dated = certs.filter((c) => c.notAfter).sort((a, b) => Date.parse(a.notAfter!) - Date.parse(b.notAfter!));
  return dated[0] ?? certs[0];
}

/** 「开启了 HTTPS 的域名列表」批量接口，按域名归组服务端证书 */
async function httpsDomainsBatch(ctx: QueryContext, creds: AccessKeyCredentials): Promise<Map<string, CertInfo[]>> {
  const rows = await paginate(HTTPS_PAGE, async (page) => {
    const res = await callBce<{ count?: number | string; rows?: HttpsDomain[] | null }>(ctx, creds, {
      host: HOST,
      path: "/v2/httpsDomains",
      query: { pageNo: String(page), pageSize: String(HTTPS_PAGE) },
    });
    // 文档示例里 count 是字符串
    const total = Number(res.count);
    return { items: res.rows ?? [], total: Number.isFinite(total) ? total : undefined };
  });
  const byDomain = new Map<string, CertInfo[]>();
  for (const row of rows) {
    // 客户端证书是双向认证用的 CA，不是网站对外提供的证书
    if (row.certType === 2) continue;
    const list = byDomain.get(row.domain) ?? [];
    if (!list.some((c) => c.id === row.certId)) list.push(toCert(row));
    byDomain.set(row.domain, list);
  }
  return byDomain;
}

const configPath = (domain: string) => `/v2/domain/${domain}/config`;

function getHttpsConfig(ctx: QueryContext, creds: AccessKeyCredentials, domain: string): Promise<{ https?: HttpsConfig | null }> {
  return callBce(ctx, creds, { host: HOST, path: configPath(domain), query: { https: "" } });
}

/**
 * HTTPS 列表里同一域名有多张服务端证书时（国际证书 + 国密证书）：HTTPS 配置里绑定的是国际证书（每个域名只能绑一张 RSA / ECC），
 * 其余标为国密（SM2），部署决策只按国际证书判断。查不到配置时记 issue，该域名不标算法、记入 unknown（不知道绑的是哪张国际证书），
 * 部署时也按 unsupported 跳过。
 */
async function markSm2(
  ctx: QueryContext,
  creds: AccessKeyCredentials,
  warn: Warn,
  domains: UserDomain[],
  byDomain: Map<string, CertInfo[]>,
  unknown: Set<string>,
): Promise<void> {
  const multi = domains.filter((d) => (byDomain.get(d.domain)?.length ?? 0) > 1);
  await mapLimit(multi, 5, async (d) => {
    try {
      const intl = (await getHttpsConfig(ctx, creds, d.domain)).https?.certId;
      const certs = byDomain.get(d.domain)!;
      if (!intl || !certs.some((c) => c.id === intl)) return;
      byDomain.set(
        d.domain,
        certs.map((c) => (c.id === intl ? c : { ...c, algorithm: "SM2" as const })),
      );
    } catch (e) {
      warn(e, `domain ${d.domain} HTTPS 配置（用于区分国密证书）`);
      unknown.add(d.domain);
    }
  });
}

/**
 * 批量接口失败时的退路：逐域名查 HTTPS 配置（并发 5），enabled 且有证书 ID 才算 HTTPS，
 * 证书详情之后统一从证书管理按 ID 补全。单个域名失败只记 issue，该域名按未开启 HTTPS 输出并记入 unknown（HTTPS 状态未知）。
 */
async function httpsPerDomain(
  ctx: QueryContext,
  creds: AccessKeyCredentials,
  warn: Warn,
  domains: UserDomain[],
  unknown: Set<string>,
): Promise<Map<string, CertInfo[]>> {
  const byDomain = new Map<string, CertInfo[]>();
  await mapLimit(domains, 5, async (d) => {
    try {
      const https = (await getHttpsConfig(ctx, creds, d.domain)).https;
      if (https?.enabled && https.certId) byDomain.set(d.domain, [{ id: https.certId }]);
    } catch (e) {
      warn(e, `domain ${d.domain} HTTPS 配置`);
      unknown.add(d.domain);
    }
  });
  return byDomain;
}

/** 读回的配置原样写回，只去掉值为 null 的字段与空的 sslProtocols（文档：该参数不能为空列表） */
function writable(cfg: HttpsConfig): HttpsConfig {
  const out: HttpsConfig = {};
  for (const [k, v] of Object.entries(cfg)) {
    if (v === null || v === undefined) continue;
    if (k === "sslProtocols" && Array.isArray(v) && v.length === 0) continue;
    out[k] = v;
  }
  return out;
}

/**
 * 设置 HTTPS（PUT /v2/domain/{domain}/config?https）是全量配置接口：先读出当前配置，只换 certId
 * （部署时同时 enabled=true），跳转、HTTP/2、TLS 版本、双向认证等其余字段原样写回。
 * HSTS、OCSP、QUIC 与国密 HTTPS 是独立的配置项，不受影响。
 * 读到的开关与查询时不同（更新时已关闭、部署时已开启）就不写入；先核对再取证书 ID，核对不过不会上传证书。
 * 返回绑定的证书 ID。
 */
async function bindCert(
  ctx: QueryContext,
  creds: AccessKeyCredentials,
  domain: string,
  mode: DeployTarget["mode"],
  certIdOf: () => Promise<string>,
): Promise<string> {
  const current = (await getHttpsConfig(ctx, creds, domain)).https ?? {};
  if (mode === "update" && current.enabled !== true) {
    throw new CloudApiError("baidu", "HttpsDisabled", `域名 ${domain} 的 HTTPS 已关闭，未替换证书；如需部署并开启 HTTPS 请用 --domain 点名后重新执行`);
  }
  if (mode === "deploy" && current.enabled === true) {
    throw new CloudApiError("baidu", "HttpsAlreadyEnabled", "该域名的 HTTPS 已开启（与查询时不同），未做修改；请重新执行，按更新规则判断");
  }
  const certId = await certIdOf();
  const https: HttpsConfig = { ...writable(current), certId, ...(mode === "deploy" && { enabled: true }) };
  await callBce(ctx, creds, { host: HOST, path: configPath(domain), query: { https: "" }, method: "PUT", body: { https } });
  return certId;
}

/**
 * 域名列表 + 「开启了 HTTPS 的域名列表」两次查询后按域名合并，避免逐域名查配置。
 * 出现在 HTTPS 列表里即为已开启 HTTPS；列表只给证书 ID 没给到期时间的，从证书管理按 ID 补全。
 * 没有域名时不查 HTTPS 列表（未开通 CDN 的账号该接口固定返回响应体为空的 HTTP 500）；
 * HTTPS 列表接口失败时退回逐域名查询 HTTPS 配置。
 * 因查询失败而判断不了 HTTPS 状态或绑定的证书的域名，在 extra 里标 httpsUnknown，部署时不按查询结果写入。
 */
export const cdn: DomainService<AccessKeyCredentials> = {
  key: "cdn",
  label: "CDN",
  async list(ctx: QueryContext, creds: AccessKeyCredentials, warn: Warn): Promise<DomainRecord[]> {
    // 该接口不分页，一次返回全部域名及状态
    const res = await callBce<{ domains?: UserDomain[] | null }>(ctx, creds, { host: HOST, path: "/v2/user/domains", query: { status: "ALL" } });
    const domains = res.domains ?? [];
    if (domains.length === 0) return [];
    const unknown = new Set<string>();
    let certsByDomain: Map<string, CertInfo[]>;
    try {
      certsByDomain = await httpsDomainsBatch(ctx, creds);
    } catch {
      certsByDomain = await httpsPerDomain(ctx, creds, warn, domains, unknown);
    }
    await markSm2(ctx, creds, warn, domains, certsByDomain, unknown);
    const records = domains.map((d) => {
      const certs = certsByDomain.get(d.domain);
      return compact({
        provider: "baidu" as const,
        service: "cdn",
        domain: d.domain,
        status: d.status,
        https: !!certs,
        cert: certs && earliest(certs),
        certs: certs && certs.length > 1 ? certs : undefined,
        extra: unknown.has(d.domain) ? { httpsUnknown: "true" } : undefined,
      });
    });
    return enrichFromCertService(ctx, creds, warn, records);
  },
  deployer: {
    // 实测证书管理不接受没有 CN 的证书（CertificateParameterInvalid）
    requiresCommonName: true,
    unsupported(record) {
      // 查询失败导致状态未知时交给编排层记为可重试的失败（HttpsStateUnknown），不能说成「不支持」
      if (record.extra?.httpsUnknown === "true") return undefined;
      const certs = record.certs ?? [];
      if (certs.length > 1 && !certs.some((c) => c.algorithm === "SM2")) {
        return "该域名绑定了多张证书，但查不到 HTTPS 配置、无法区分国际证书与国密证书，为避免换错未处理；请稍后重试";
      }
      return undefined;
    },
    async apply(ctx, creds, target, input) {
      let certId: string | undefined;
      for (const r of target.records) certId = await bindCert(ctx, creds, r.domain, target.mode, input.certId);
      return compact({ certId });
    },
  },
};
