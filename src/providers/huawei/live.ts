import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import type { CertInfo, DomainRecord } from "../../types.js";
import type { DeployInput, DeployOutcome, DeployTarget, DomainService, Warn } from "../registry.js";
import { callHuawei, listProjects } from "./client.js";
import {
  earliest,
  HTTPS_ALREADY_ENABLED,
  httpsDisabled,
  markHttpsUnknown,
  orderCerts,
  parsePem,
  PEM_FALLBACK_NOTE,
  scmCertIdOrPem,
  SM_CERT_LOCKED,
  smCertLocked,
  withoutSource,
} from "./common.js";
import { enrichFromScm } from "./scm.js";

/**
 * 视频直播的域名按地域隔离：新用户中国站在北京四、国际站在新加坡（ap-southeast-3），
 * 存量用户可能在其它地域。文档列出北京一 / 北京四 / 新加坡，官方 SDK 另有上海一、曼谷，五个都查。
 */
export const LIVE_REGIONS = ["cn-north-4", "cn-north-1", "cn-east-3", "ap-southeast-3", "ap-southeast-2"] as const;
/** ShowCertificateInfo 的 limit 上限 */
const CERT_PAGE = 100;

/**
 * 没在该地域使用直播时可能返回的错误：服务在该地域不可用、项目不可用、接口不存在、直播用户不存在。
 * 这类地域静默跳过，免得每次都为没用到的地域报一堆错误；所有地域都失败时才把错误抛给上层。
 */
const UNUSED_REGION_CODES = new Set(["APIGW.0801", "APIGW.0310", "APIGW.0101", "LIVE.100011009"]);

interface LiveDomain {
  domain: string;
  /** pull 播放域名，push 推流域名 */
  domain_type?: string;
  /** on / off / configuring */
  status?: string;
  service_area?: string;
}

interface LiveCert {
  play_domain: string;
  /** "YYYY-MM-DDTHH:mm:ssZ"，文档写 UTC，实测比证书真实有效期早 8 小时，见 infoTime */
  start_time?: string;
  expire_time?: string;
  /** 0 国际标准证书，1 国密证书 */
  cert_type?: number;
  /** 国密证书：1 签名证书，2 加密证书 */
  gm_cert_type?: number;
  /** scm 云证书管理服务，user 自有证书 */
  source?: string;
  /** 仅 scm 来源的证书有名称与 ID */
  cert_name?: string;
  cert_id?: string;
}

/** ShowDomainHttpsCert：播放域名当前配置的证书内容（PEM，私钥不返回） */
interface HttpsCertConfig {
  certificate?: string | null;
  force_redirect?: boolean | null;
  tls_certificate?: { source?: string | null; cert_id?: string | null; certificate?: string | null } | null;
  gm_certificate?: {
    /** scm 云证书管理服务，user 自有证书 */
    source?: string | null;
    cert_id?: string | null;
    cert_name?: string | null;
    sign_certificate?: string | null;
    enc_certificate?: string | null;
  } | null;
}

/**
 * ShowCertificateInfo 的 start_time / expire_time 虽然带 Z，实测比证书真实有效期早 8 小时
 * （证书 notAfter 13:09:53Z 返回 05:09:53Z，像是把 UTC 时间当北京时间又换算了一次）。
 * 时间优先取 ShowDomainHttpsCert 的 PEM，拿不到 PEM 时才用它并补回 8 小时。
 */
const INFO_SKEW_MS = 8 * 3_600_000;
function infoTime(s: string | undefined): string | undefined {
  const iso = toIso(s);
  return iso && new Date(Date.parse(iso) + INFO_SKEW_MS).toISOString();
}

/** 按证书类型取对应的 PEM：国际证书取 tls_certificate（旧字段 certificate 兜底），国密取签名 / 加密证书 */
function pemFor(c: LiveCert, cfg: HttpsCertConfig | undefined) {
  if (!cfg) return undefined;
  if (c.cert_type === 1) return parsePem(c.gm_cert_type === 2 ? cfg.gm_certificate?.enc_certificate : cfg.gm_certificate?.sign_certificate);
  return parsePem(cfg.tls_certificate?.certificate || cfg.certificate);
}

// 文档里 ShowDomain 的失败示例是 404 LIVE.103011019（资源不存在），列表接口报这个按没有数据处理
function emptyIfNotFound<T>(e: unknown, empty: T): T {
  if (e instanceof CloudApiError && e.code === "LIVE.103011019") return empty;
  throw e;
}

async function listRegion(ctx: QueryContext, creds: AccessKeyCredentials, region: string, projectId: string) {
  const host = `live.${region}.myhuaweicloud.com`;
  const [domains, certs] = await Promise.all([
    callHuawei<{ domain_info?: LiveDomain[] | null }>(ctx, creds, { host, path: `/v1/${projectId}/domain`, projectId })
      .then((res) => res.domain_info ?? [])
      .catch((e: unknown) => emptyIfNotFound(e, [])),
    paginate(CERT_PAGE, async (page) => {
      const res = await callHuawei<{ certificates_info?: LiveCert[] | null; total?: number }>(ctx, creds, {
        host,
        path: `/v2/${projectId}/certificates`,
        // 文档说 offset 是「偏移量」，实测是从 0 开始的页码：total=2 时 offset=1&limit=2 报 LIVE.100011001 page too large
        query: { offset: page - 1, limit: CERT_PAGE },
        projectId,
      });
      return { items: res.certificates_info ?? [], total: res.total };
    }).catch((e: unknown) => emptyIfNotFound(e, [])),
  ]);
  // 只对证书列表里出现、且确实是本地域播放域名的域名逐个取 PEM
  const pulls = new Set(domains.filter((d) => d.domain_type !== "push").map((d) => d.domain));
  const withCert = [...new Set(certs.map((c) => c.play_domain))].filter((d) => pulls.has(d));
  const configs = new Map<string, HttpsCertConfig | { error: unknown }>();
  await mapLimit(withCert, 5, async (domain) => {
    try {
      configs.set(domain, await callHuawei<HttpsCertConfig>(ctx, creds, { host, path: `/v1/${projectId}/guard/https-cert`, query: { domain }, projectId }));
    } catch (error) {
      configs.set(domain, { error });
    }
  });
  return { domains, certs, configs };
}

/**
 * 开着 HTTPS 的域名缺国际证书的到期时间：证书信息全空（compact 后没有 cert），或有国际证书没有到期时间。
 * 部署时按国际证书的到期时间决策，国密证书不参与。
 */
const lacksIntlExpiry = (r: DomainRecord) => r.https && (!r.cert || [r.cert, ...(r.certs ?? [])].some((c) => c.algorithm !== "SM2" && !c.notAfter));

const PUSH_UNSUPPORTED = "推流域名不支持配置 HTTPS 证书（视频直播只有播放域名可以配置证书）";

/** 读到的配置里已有国际或国密证书，即已开启 HTTPS */
function hasCert(cfg: HttpsCertConfig): boolean {
  const gm = cfg.gm_certificate;
  return !!(cfg.certificate || cfg.tls_certificate?.certificate || cfg.tls_certificate?.cert_id || gm?.cert_id || gm?.sign_certificate || gm?.enc_certificate);
}

/**
 * 修改播放域名的 HTTPS 证书（UpdateDomainHttpsCert）是整体覆盖：先读出当前配置（ShowDomainHttpsCert），
 * 强制跳转原样带回；国际证书用 CCM 证书 ID 绑定（CCM 拒收没有 CN 的证书时改为直接传 PEM，source = user）；
 * 国密证书只能按 CCM 证书 ID 带回，自有上传的读不到私钥，无法保留。
 * 直播没有单独的 HTTPS 开关，配置证书即开启，deploy 与 update 的请求相同；
 * deploy（查询时没有证书）读到已配置了证书时说明 HTTPS 其实已开启，不写入，交给重新执行按更新规则判断。
 */
async function applyLive(ctx: QueryContext, creds: AccessKeyCredentials, target: DeployTarget, input: DeployInput): Promise<DeployOutcome> {
  let certId: string | undefined;
  let uploaded = false;
  for (const record of target.records) {
    const region = record.extra?.region;
    const projectId = record.extra?.projectId ?? (region ? (await listProjects(ctx, creds)).get(region) : undefined);
    if (!region || !projectId) {
      throw new CloudApiError("huawei", "ProjectNotFound", `未找到域名 ${record.domain} 所在地域（${region ?? "未知"}）的项目`);
    }
    const req = { host: `live.${region}.myhuaweicloud.com`, path: `/v1/${projectId}/guard/https-cert`, query: { domain: record.domain }, projectId };
    const current = await callHuawei<HttpsCertConfig>(ctx, creds, req);
    if (target.mode === "deploy" && hasCert(current)) throw new CloudApiError("huawei", "HttpsAlreadyEnabled", HTTPS_ALREADY_ENABLED);
    if (target.mode === "update" && !hasCert(current)) throw new CloudApiError("huawei", "HttpsDisabled", httpsDisabled(record.domain));
    const gm = current.gm_certificate;
    const hasGm = !!(gm?.cert_id || gm?.sign_certificate || gm?.enc_certificate);
    if (hasGm && !(gm?.source === "scm" && gm.cert_id)) throw new CloudApiError("huawei", "SmCertNotPreservable", SM_CERT_LOCKED);
    if (!uploaded) {
      certId = await scmCertIdOrPem(input);
      uploaded = true;
    }
    await callHuawei(ctx, creds, {
      ...req,
      method: "PUT",
      body: {
        certificate_format: "PEM",
        ...(typeof current.force_redirect === "boolean" && { force_redirect: current.force_redirect }),
        tls_certificate: certId
          ? { source: "scm", cert_id: certId }
          : { source: "user", certificate: input.cert.certPem, certificate_key: input.cert.keyPem },
        ...(hasGm && { gm_certificate: compact({ source: "scm", cert_id: gm?.cert_id, cert_name: gm?.cert_name }) }),
      },
    });
  }
  return compact({ certId, note: uploaded && !certId ? PEM_FALLBACK_NOTE : undefined });
}

/**
 * 逐地域查直播域名 + 播放域名的 HTTPS 证书列表（ShowCertificateInfo 批量接口），按域名合并；
 * 配了证书的播放域名再查 ShowDomainHttpsCert 取 PEM，解析出 CN / SAN / 签发者和准确的有效期。
 * 直播没有单独的 HTTPS 开关：播放域名配置了证书即开启 HTTPS，删除证书即关闭；推流域名不支持 HTTPS。
 */
export const live: DomainService<AccessKeyCredentials> = {
  key: "live",
  label: "视频直播",
  async list(ctx: QueryContext, creds: AccessKeyCredentials, warn: Warn): Promise<DomainRecord[]> {
    const projects = await listProjects(ctx, creds);
    const regions = LIVE_REGIONS.filter((r) => projects.has(r));
    if (regions.length === 0) {
      throw new CloudApiError("huawei", "ProjectNotFound", `未找到视频直播所在地域（${LIVE_REGIONS.join("、")}）的项目，请确认 AK 所属用户有这些地域的项目权限`);
    }
    const results = await mapLimit(regions, 5, async (region) => {
      try {
        return { region, data: await listRegion(ctx, creds, region, projects.get(region)!) };
      } catch (error) {
        return { region, error };
      }
    });
    const unused = (e: unknown) => e instanceof CloudApiError && UNUSED_REGION_CODES.has(e.code);
    if (results.every((r) => !r.data)) {
      throw (results.find((r) => !unused(r.error)) ?? results[0]!).error;
    }
    const seen = new Set<string>();
    const records: DomainRecord[] = [];
    // 取证书内容失败的域名：补全后国际证书仍缺到期时间的，标 httpsUnknown
    const pemFailed: DomainRecord[] = [];
    for (const { region, data, error } of results) {
      if (!data) {
        if (!unused(error)) warn(error, `region ${region}`);
        continue;
      }
      // 国密证书的签名证书与加密证书各占一条，一个域名可能有多条
      const certsByDomain = new Map<string, (CertInfo & { source?: string })[]>();
      for (const c of data.certs) {
        const cfg = data.configs.get(c.play_domain);
        const pem = pemFor(c, cfg && !("error" in cfg) ? cfg : undefined);
        const cert = compact({
          id: c.cert_id,
          name: c.cert_name,
          ...pem,
          notBefore: pem?.notBefore ?? infoTime(c.start_time),
          notAfter: pem?.notAfter ?? infoTime(c.expire_time),
          ...(c.cert_type === 1 && { algorithm: "SM2" as const }),
          source: c.source,
        });
        certsByDomain.set(c.play_domain, [...(certsByDomain.get(c.play_domain) ?? []), cert]);
      }
      for (const d of data.domains) {
        // 接口若不按地域隔离会在多个地域返回同一域名，只保留第一次出现的
        if (seen.has(d.domain)) continue;
        seen.add(d.domain);
        const cfg = data.configs.get(d.domain);
        if (cfg && "error" in cfg) warn(cfg.error, `domain ${d.domain} HTTPS 证书内容（到期时间改用证书列表）`);
        const all = certsByDomain.get(d.domain) ?? [];
        const best = earliest(all);
        const record: DomainRecord = compact({
          provider: "huawei" as const,
          service: "live",
          domain: d.domain,
          status: d.status,
          https: !!best,
          cert: best && withoutSource(best),
          certs: all.length > 1 ? orderCerts(all).map(withoutSource) : undefined,
          extra: compact({
            region,
            projectId: projects.get(region),
            type: d.domain_type,
            serviceArea: d.service_area,
            certSource: best?.source,
            smCertSource: all.find((c) => c.algorithm === "SM2")?.source,
          }),
        });
        records.push(record);
        if (cfg && "error" in cfg) pemFailed.push(record);
      }
    }
    await enrichFromScm(ctx, creds, warn, records);
    for (const r of pemFailed) if (lacksIntlExpiry(r)) markHttpsUnknown(r);
    return records;
  },
  deployer: {
    unsupported: (record) => (record.extra?.type === "push" ? PUSH_UNSUPPORTED : smCertLocked(record)),
    apply: applyLive,
  },
};
