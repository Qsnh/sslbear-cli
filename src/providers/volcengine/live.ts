import type { AccessKeyCredentials } from "../../lib/env.js";
import type { QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import type { CertInfo, DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { callVolc } from "./client.js";

interface LiveDomain {
  Domain: string;
  /** push 推流 / pull-flv 拉流 */
  Type?: string;
  Status?: number;
  /** cn / cn-global / cn-oversea */
  Region?: string;
  Vhost?: string;
  ProjectName?: string;
  /** 绑定的 HTTPS 证书的证书链 ID（直播自己的 ID），未绑定时为空 */
  ChainID?: string;
}

interface LiveCert {
  CertID?: string;
  CertName?: string;
  ChainID?: string;
  CertDomainList?: string[] | null;
  /** RFC 3339 UTC */
  NotBefore?: string;
  NotAfter?: string;
  /** OK / Expire / 30days / 15days / 7days / 1days */
  Status?: string;
}

const PAGE = 1000;

const STATUS: Record<number, string> = {
  0: "normal",
  1: "reviewing",
  2: "disabled",
  4: "rejected",
  5: "overdue",
  6: "icp-blocked",
};

const call = <T>(ctx: QueryContext, creds: AccessKeyCredentials, action: string, params: Record<string, number | string>) =>
  callVolc<T>(ctx, creds, { host: "live.volcengineapi.com", service: "live", region: "cn-north-1", version: "2023-01-01", action, method: "POST", params });

const toCert = (c: LiveCert): CertInfo =>
  compact({
    id: c.CertID || c.ChainID,
    name: c.CertName,
    sans: c.CertDomainList ?? undefined,
    notBefore: toIso(c.NotBefore),
    notAfter: toIso(c.NotAfter),
    status: c.Status,
  });

/**
 * 视频直播：ListDomainDetail 列域名（带绑定证书的 ChainID）+ ListCertV2 证书列表按 ChainID 关联。
 * 直播的读接口不返回 HTTPS 开关（只在 BindCert 写接口里），只能以「绑定了证书」视为开启 HTTPS。
 * ListCertV2 缺省只返回启用中的证书，关联不上的 ChainID 再逐个用 DescribeCertDetailSecretV2 查（V2 不含私钥）。
 */
export const live: DomainService<AccessKeyCredentials> = {
  key: "live",
  label: "视频直播",
  async list(ctx: QueryContext, creds: AccessKeyCredentials, warn: Warn): Promise<DomainRecord[]> {
    const [all, certs] = await Promise.all([
      paginate(PAGE, async (page) => {
        const res = await call<{ DomainList?: LiveDomain[] | null; Total?: number }>(ctx, creds, "ListDomainDetail", { PageNum: page, PageSize: PAGE });
        return { items: res.DomainList ?? [], total: res.Total };
      }),
      // 不传分页参数时返回全部
      call<{ CertList?: LiveCert[] | null }>(ctx, creds, "ListCertV2", {}).then((r) => r.CertList ?? []),
    ]);
    // 状态 3 为已删除
    const domains = all.filter((d) => d.Status !== 3);
    const byChain = new Map<string, CertInfo>();
    for (const c of certs) if (c.ChainID) byChain.set(c.ChainID, toCert(c));
    const missing = [...new Set(domains.map((d) => d.ChainID).filter((id): id is string => !!id && !byChain.has(id)))];
    await mapLimit(missing, 5, async (chainId) => {
      try {
        const c = await call<LiveCert>(ctx, creds, "DescribeCertDetailSecretV2", { ChainID: chainId });
        byChain.set(chainId, toCert({ ...c, ChainID: chainId }));
      } catch (e) {
        warn(e, `证书链 ${chainId}`);
      }
    });
    return domains.map((d) => {
      const https = !!d.ChainID;
      return compact({
        provider: "volcengine" as const,
        service: "live",
        domain: d.Domain,
        status: d.Status === undefined ? undefined : (STATUS[d.Status] ?? String(d.Status)),
        https,
        cert: https ? (byChain.get(d.ChainID!) ?? { id: d.ChainID }) : undefined,
        extra: compact({ type: d.Type, region: d.Region, vhost: d.Vhost, project: d.ProjectName }),
      });
    });
  },
};
