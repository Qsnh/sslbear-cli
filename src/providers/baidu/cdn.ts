import type { AccessKeyCredentials } from "../../lib/env.js";
import type { QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { CertInfo, DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
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
  /** 平台通用证书时为 "-" */
  certCommonName?: string;
  /** CDN API 的时间统一为 UTC ISO 8601（如 2019-07-17T08:00:00Z），通用证书时为 "-" */
  certStartTime?: string;
  certStopTime?: string;
  /** 1 服务端证书，2 客户端证书（双向认证） */
  certType?: number;
  /** 1 使用中，2 已过期 */
  status?: number;
}

/** /v2/httpsDomains 的 pageSize 上限为 100 */
const HTTPS_PAGE = 100;

const placeholder = (s: string | undefined) => (s && !/^-+$/.test(s.trim()) ? s : undefined);

function toCert(row: HttpsDomain): CertInfo {
  return compact({
    id: row.certId,
    name: row.certName,
    commonName: placeholder(row.certCommonName),
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

/**
 * 域名列表 + 「开启了 HTTPS 的域名列表」两次查询后按域名合并，避免逐域名查配置。
 * 出现在 HTTPS 列表里即为已开启 HTTPS；列表只给证书 ID 没给到期时间的，从证书管理按 ID 补全。
 */
export const cdn: DomainService<AccessKeyCredentials> = {
  key: "cdn",
  label: "CDN",
  async list(ctx: QueryContext, creds: AccessKeyCredentials, warn: Warn): Promise<DomainRecord[]> {
    const [domains, httpsRows] = await Promise.all([
      // 该接口不分页，一次返回全部域名及状态
      callBce<{ domains?: UserDomain[] | null }>(ctx, creds, { host: HOST, path: "/v2/user/domains", query: { status: "ALL" } }).then(
        (res) => res.domains ?? [],
      ),
      paginate(HTTPS_PAGE, async (page) => {
        const res = await callBce<{ count?: number | string; rows?: HttpsDomain[] | null }>(ctx, creds, {
          host: HOST,
          path: "/v2/httpsDomains",
          query: { pageNo: String(page), pageSize: String(HTTPS_PAGE) },
        });
        // 文档示例里 count 是字符串
        const total = Number(res.count);
        return { items: res.rows ?? [], total: Number.isFinite(total) ? total : undefined };
      }),
    ]);
    const certsByDomain = new Map<string, CertInfo[]>();
    for (const row of httpsRows) {
      // 客户端证书是双向认证用的 CA，不是网站对外提供的证书
      if (row.certType === 2) continue;
      const list = certsByDomain.get(row.domain) ?? [];
      list.push(toCert(row));
      certsByDomain.set(row.domain, list);
    }
    const records = domains.map((d) => {
      const certs = certsByDomain.get(d.domain);
      return compact({
        provider: "baidu" as const,
        service: "cdn",
        domain: d.domain,
        status: d.status,
        https: !!certs,
        cert: certs && earliest(certs),
      });
    });
    return enrichFromCertService(ctx, creds, warn, records);
  },
};
