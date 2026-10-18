import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { CertInfo, DomainRecord } from "../../types.js";
import type { DeployInput, DeployOutcome, DeployTarget, DomainService } from "../registry.js";
import { callHuawei } from "./client.js";
import { certName, earliest, HTTPS_ALREADY_ENABLED, httpsDisabled, orderCerts, parsePem, SM_CERT_LOCKED, smCertLocked, withoutSource } from "./common.js";

/** CDN 是全局服务，不区分地域 */
const HOST = "cdn.myhuaweicloud.com";
const DOMAIN_PAGE = 10000;
// 文档上限也是 10000，但每条都带 PEM 证书内容，取小一些避免单个响应过大
const HTTPS_PAGE = 1000;
/** 开通了企业项目时不传只查默认项目（IAM 用户调用还必须传），all 表示所有企业项目；未开通企业项目时该参数不生效 */
const ALL_PROJECTS = "all";

interface CdnDomain {
  domain_name: string;
  /** online / offline / configuring / configure_failed / checking / check_failed / deleting */
  domain_status?: string;
  business_type?: string;
  service_area?: string;
  /** 0 未开启 HTTPS，其余为开启（文档只写了 1，实测还有 2 / 3） */
  https_status?: number;
}

/** 「certificates」里的单张证书，双证书（国际 + 国密）时各一条 */
interface HttpsCertItem {
  /** server 国际证书，server_sm 国密证书 */
  certificate_type?: string;
  /** 0 自有证书，2 SCM 证书 */
  certificate_source?: number;
  certificate_name?: string;
  /** PEM 证书内容 */
  certificate_value?: string | null;
  /** 证书过期时间，毫秒时间戳 */
  expire_time?: number;
}

interface HttpsDetail {
  domain_name: string;
  cert_name?: string;
  /** PEM 证书内容 */
  certificate?: string | null;
  /** 0 自有证书，1 云托管证书，2 SCM 证书 */
  certificate_type?: number;
  /** 证书过期时间，毫秒时间戳 */
  expiration_time?: number;
  /** 0 未启用，其余为已启用（文档写 1 / 2，实测还有 3） */
  https_status?: number;
  /** 实测接口还会返回证书数组；外层字段只描述其中一张，配了双证书时要看这里 */
  certificates?: HttpsCertItem[] | null;
}

const CERT_SOURCE: Record<number, string> = { 0: "user", 1: "managed", 2: "scm" };

const sourceOf = (n: number | undefined) => (n === undefined ? undefined : (CERT_SOURCE[n] ?? String(n)));

type SourcedCert = CertInfo & { source?: string };

/** 国密证书按接口给的证书类型标 SM2；国际证书的 RSA / ECC 取自 PEM */
function toCert(name: string | undefined, pemText: string | null | undefined, expire: number | undefined, source: number | undefined, sm = false): SourcedCert {
  const pem = parsePem(pemText);
  return compact({ name, ...pem, notAfter: pem?.notAfter ?? toIso(expire), ...(sm && { algorithm: "SM2" as const }), source: sourceOf(source) });
}

/** 一条 HTTPS 记录里的所有证书：有 certificates 数组时以它为准（双证书时国际、国密各一条），否则用外层字段 */
function certsOf(h: HttpsDetail): SourcedCert[] {
  if (h.certificates?.length) {
    return h.certificates.map((c) => toCert(c.certificate_name, c.certificate_value, c.expire_time, c.certificate_source, c.certificate_type === "server_sm"));
  }
  return [toCert(h.cert_name, h.certificate, h.expiration_time, h.certificate_type)];
}

/** ShowDomainFullConfig 里 configs.https 的证书部分（私钥不返回） */
interface HttpsCertConfig {
  certificate_type?: string;
  /** 0 自有证书，1 华为云托管证书，2 SCM 证书 */
  certificate_source?: number;
  scm_certificate_id?: string;
  certificate_name?: string;
  certificate_value?: string | null;
}

interface HttpsConfig extends HttpsCertConfig {
  https_status?: string;
  certificates?: HttpsCertConfig[] | null;
  http2_status?: string | null;
  tls_version?: string | null;
  ocsp_stapling_status?: string | null;
}

const configPath = (domain: string) => `/v1.1/cdn/configuration/domains/${domain}/configs`;

/**
 * 修改域名全量配置（UpdateDomainFullConfig）只发 configs.https：强制跳转、HSTS、QUIC、TLS 加密套件等是 configs 下的其它项，不发即不改；
 * https 对象内未传的 HTTP/2 开关缺省为关闭，所以先读出（ShowDomainFullConfig）把 HTTP/2、TLS 版本、OCSP Stapling 原样带回。
 * 证书直接传 PEM（自有证书）：用 CCM 证书需要先在控制台授权 CDN 访问 CCM（CDN.00010198）。
 * 双证书只支持「国际 + 国密」：配了国密证书时要用 certificates 把两张一起传，国密证书只能按 CCM 证书 ID 带回，自有上传的读不到私钥，无法保留；
 * 带回时证书名称也要原样传，读不到名称就不写入。
 * deploy（查询时 HTTPS 未开启）读到 HTTPS 其实已开启时不写入，交给重新执行按更新规则判断。
 */
async function applyCdn(ctx: QueryContext, creds: AccessKeyCredentials, target: DeployTarget, input: DeployInput): Promise<DeployOutcome> {
  const { cert } = input;
  for (const record of target.records) {
    const res = await callHuawei<{ configs?: { https?: HttpsConfig | null } | null }>(ctx, creds, {
      host: HOST,
      path: configPath(record.domain),
      query: { enterprise_project_id: ALL_PROJECTS },
    });
    const current = res.configs?.https ?? {};
    if (target.mode === "deploy" && current.https_status && current.https_status !== "off") {
      throw new CloudApiError("huawei", "HttpsAlreadyEnabled", HTTPS_ALREADY_ENABLED);
    }
    if (target.mode === "update" && current.https_status === "off") throw new CloudApiError("huawei", "HttpsDisabled", httpsDisabled(record.domain));
    const all = current.certificates?.length ? current.certificates : current.certificate_type ? [current] : [];
    // 关闭 HTTPS 时证书会被一并删除，读到的残留不算
    const sm = current.https_status !== "off" ? all.find((c) => c.certificate_type === "server_sm") : undefined;
    if (sm && !(sm.certificate_source === 2 && sm.scm_certificate_id)) {
      throw new CloudApiError("huawei", "SmCertNotPreservable", SM_CERT_LOCKED);
    }
    if (sm && !sm.certificate_name) {
      throw new CloudApiError(
        "huawei",
        "SmCertNotPreservable",
        `读回的国密证书（CCM 证书 ${sm.scm_certificate_id}）没有证书名称，双证书要把国密证书连同名称原样带回，缺了名称无法确保它被保留；未做修改，请在控制台更换证书`,
      );
    }
    const intl = { certificate_type: "server", certificate_source: 0, certificate_name: certName(cert), certificate_value: cert.certPem, private_key: cert.keyPem };
    const https = {
      https_status: "on",
      ...compact({ http2_status: current.http2_status, tls_version: current.tls_version, ocsp_stapling_status: current.ocsp_stapling_status }),
      ...(sm
        ? {
            certificates: [
              intl,
              { certificate_type: "server_sm", certificate_source: 2, scm_certificate_id: sm.scm_certificate_id, certificate_name: sm.certificate_name },
            ],
          }
        : intl),
    };
    await callHuawei(ctx, creds, {
      host: HOST,
      path: configPath(record.domain),
      method: "PUT",
      query: { enterprise_project_id: ALL_PROJECTS },
      body: { configs: { https } },
    });
  }
  return {};
}

/** 加速域名列表 + 「查询所有绑定HTTPS证书的域名信息」两次分页查询后按域名合并，避免逐个域名查配置 */
export const cdn: DomainService<AccessKeyCredentials> = {
  key: "cdn",
  label: "CDN",
  async list(ctx: QueryContext, creds: AccessKeyCredentials): Promise<DomainRecord[]> {
    const [domains, https] = await Promise.all([
      paginate(DOMAIN_PAGE, async (page) => {
        const res = await callHuawei<{ domains?: CdnDomain[] | null; total?: number }>(ctx, creds, {
          host: HOST,
          path: "/v1.0/cdn/domains",
          query: { page_size: DOMAIN_PAGE, page_number: page, enterprise_project_id: ALL_PROJECTS },
        });
        return { items: res.domains ?? [], total: res.total };
      }),
      paginate(HTTPS_PAGE, async (page) => {
        const res = await callHuawei<{ https?: HttpsDetail[] | null; total?: number }>(ctx, creds, {
          host: HOST,
          path: "/v1.0/cdn/domains/https-certificate-info",
          query: { page_size: HTTPS_PAGE, page_number: page, enterprise_project_id: ALL_PROJECTS },
        });
        return { items: res.https ?? [], total: res.total };
      }),
    ]);
    const httpsByDomain = new Map<string, HttpsDetail[]>();
    for (const h of https) httpsByDomain.set(h.domain_name, [...(httpsByDomain.get(h.domain_name) ?? []), h]);
    return domains.map((d) => {
      const entries = httpsByDomain.get(d.domain_name) ?? [];
      // 域名列表里的 HTTPS 开关为准；缺该字段时看 HTTPS 列表里是否启用
      const enabled = entries.filter((h) => h.https_status !== 0);
      const https = d.https_status === undefined ? enabled.length > 0 : d.https_status !== 0;
      const all = https ? entries.flatMap(certsOf) : [];
      const best = earliest(all);
      return compact({
        provider: "huawei" as const,
        service: "cdn",
        domain: d.domain_name,
        status: d.domain_status,
        https,
        cert: best && withoutSource(best),
        certs: all.length > 1 ? orderCerts(all).map(withoutSource) : undefined,
        extra: compact({
          businessType: d.business_type,
          serviceArea: d.service_area,
          certSource: best?.source,
          smCertSource: all.find((c) => c.algorithm === "SM2")?.source,
        }),
      });
    });
  },
  deployer: {
    unsupported: smCertLocked,
    apply: applyCdn,
  },
};
