import type { AccessKeyCredentials } from "../../lib/env.js";
import type { QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { CertInfo, DomainRecord } from "../../types.js";
import type { DomainService } from "../registry.js";
import { callHuawei } from "./client.js";
import { earliest, parsePem } from "./common.js";

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
  /** 0 未开启 HTTPS，1 开启 */
  https_status?: number;
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
  /** 0 未启用，1 / 2 已启用 */
  https_status?: number;
}

const CERT_SOURCE: Record<number, string> = { 0: "user", 1: "managed", 2: "scm" };

function toCert(h: HttpsDetail): CertInfo & { source?: string } {
  const pem = parsePem(h.certificate);
  return compact({
    name: h.cert_name,
    ...pem,
    notAfter: pem?.notAfter ?? toIso(h.expiration_time),
    source: h.certificate_type === undefined ? undefined : (CERT_SOURCE[h.certificate_type] ?? String(h.certificate_type)),
  });
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
      const best = https ? earliest(entries.map(toCert)) : undefined;
      const { source, ...cert } = best ?? {};
      return compact({
        provider: "huawei" as const,
        service: "cdn",
        domain: d.domain_name,
        status: d.domain_status,
        https,
        cert: best ? cert : undefined,
        extra: compact({ businessType: d.business_type, serviceArea: d.service_area, certSource: source }),
      });
    });
  },
};
