import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { CertInfo, DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { fillDualAlgorithms } from "./certs.js";
import { callVolc } from "./client.js";
import { AMBIGUOUS_DUAL, HTTPS_UNKNOWN, ambiguousCerts, ambiguousDual, certsToKeep, earliest, explainNoCommonName, splitList } from "./common.js";

interface CdnDomain {
  Domain: string;
  Status?: string;
  /** 是否启用了 HTTPS 特性 */
  HTTPS?: boolean;
  ServiceType?: string;
  ServiceRegion?: string;
  Project?: string;
}

interface CdnCert {
  CertId?: string;
  /** 证书 CN */
  CertName?: string;
  /** SAN，逗号分隔 */
  DnsName?: string;
  /** running / expiring_soon / expired */
  Status?: string;
  /** Unix 秒 */
  EffectiveTime?: number;
  ExpireTime?: number;
  /** 已关联该证书的加速域名，逗号分隔 */
  ConfiguredDomain?: string | null;
  Desc?: string;
  Source?: string;
}

// 两个列表接口的 PageSize 上限都是 100
const PAGE = 100;

const call = <T>(ctx: QueryContext, creds: AccessKeyCredentials, action: string, params: Record<string, string | number | undefined>) =>
  callVolc<T>(ctx, creds, { host: "cdn.volcengineapi.com", service: "CDN", region: "cn-north-1", version: "2021-03-01", action, method: "POST", params });

function toCert(c: CdnCert, sm: boolean): CertInfo {
  return compact({
    id: c.CertId,
    commonName: c.CertName,
    sans: splitList(c.DnsName),
    notBefore: toIso(c.EffectiveTime),
    notAfter: toIso(c.ExpireTime),
    status: c.Status,
    algorithm: sm ? ("SM2" as const) : undefined,
  });
}

/**
 * CDN：域名列表（带 HTTPS 开关）+ 已关联加速域名的证书列表（ListCdnCertInfo 默认 Configured=true）按域名合并。
 * 双证书模式下一个域名出现在两张证书的 ConfiguredDomain 里，cert 取先到期的那张，certs 列出全部；
 * 证书列表按 EncryType 过滤、缺省只返回 RSA/ECC（inter_cert），国密 SM2（sm_cert）需另查一次。
 * inter_cert 不区分 RSA 与 ECC，双证书域名的证书算法从证书中心按 ID 补（部署时据此只换同算法那张）。
 */
export const cdn: DomainService<AccessKeyCredentials> = {
  key: "cdn",
  label: "CDN",
  async list(ctx: QueryContext, creds: AccessKeyCredentials, warn: Warn): Promise<DomainRecord[]> {
    const listCerts = (encryType: string) =>
      paginate(PAGE, async (page) => {
        const res = await call<{ CertInfo?: CdnCert[] | null; Total?: number }>(ctx, creds, "ListCdnCertInfo", {
          PageNum: page,
          PageSize: PAGE,
          EncryType: encryType,
        });
        return { items: res.CertInfo ?? [], total: res.Total };
      });
    const [domains, interCerts, smCerts] = await Promise.all([
      paginate(PAGE, async (page) => {
        const res = await call<{ Data?: CdnDomain[] | null; Total?: number }>(ctx, creds, "ListCdnDomains", { PageNum: page, PageSize: PAGE });
        return { items: res.Data ?? [], total: res.Total };
      }),
      listCerts("inter_cert"),
      listCerts("sm_cert"),
    ]);
    const certsByDomain = new Map<string, CertInfo[]>();
    for (const [list, sm] of [[interCerts, false], [smCerts, true]] as const) {
      for (const c of list) {
        for (const d of splitList(c.ConfiguredDomain)) certsByDomain.set(d, [...(certsByDomain.get(d) ?? []), toCert(c, sm)]);
      }
    }
    const httpsDomains = domains.filter((d) => d.HTTPS === true);
    // 证书中心查询失败导致双证书的算法不明时，不知道该替换哪一张，打 httpsUnknown 标记（算法本就查不到的仍按 unsupported 处理）
    let algorithmsFailed = false;
    const filled = await fillDualAlgorithms(
      ctx,
      creds,
      (e, target) => {
        algorithmsFailed = true;
        warn(e, target);
      },
      httpsDomains.map((d) => certsByDomain.get(d.Domain) ?? []),
    );
    const certsOf = new Map(httpsDomains.map((d, i) => [d.Domain, filled[i]!]));
    return domains.map((d) => {
      const certs = certsOf.get(d.Domain) ?? [];
      const unknown = algorithmsFailed && ambiguousCerts(certs);
      return compact({
        provider: "volcengine" as const,
        service: "cdn",
        domain: d.Domain,
        status: d.Status,
        https: d.HTTPS === true,
        cert: earliest(certs),
        certs: certs.length > 1 ? certs : undefined,
        extra: compact({ serviceType: d.ServiceType, serviceRegion: d.ServiceRegion, project: d.Project, ...(unknown && HTTPS_UNKNOWN) }),
      });
    });
  },
  deployer: {
    // 实测 CDN 不接受没有 CN 的证书
    requiresCommonName: true,
    unsupported: (record) => (ambiguousDual(record) ? AMBIGUOUS_DUAL : undefined),
    /**
     * BatchDeployCert 只关联证书（控制台文档：关联成功后自动对该域名启用 HTTPS），HTTP/2、TLS 版本等配置不动。
     * 只传一张证书会把双证书域名切回单证书，所以双证书时把另一张（另一算法或国密）作为 CertId2 一起传。
     */
    async apply(ctx, creds, target, input) {
      const [record] = target.records;
      const keep = target.mode === "update" ? certsToKeep(record!, input.cert.algorithm) : [];
      if (keep.length > 1) {
        throw new CloudApiError("volcengine", "TooManyCerts", `域名上有 ${keep.length + 1} 张证书，CDN 最多支持双证书，未做修改`);
      }
      const certId = await input.certId();
      const res = await call<{ DeployResult?: { Domain?: string; Status?: string; ErrorMsg?: string }[] | null }>(ctx, creds, "BatchDeployCert", {
        CertId: certId,
        CertId2: keep[0]?.id,
        Domain: record!.domain,
      }).catch((e) => {
        throw explainNoCommonName(e, input.cert, " CDN ", ["InternalError.DomainSystemError"]);
      });
      const failed = (res.DeployResult ?? []).find((r) => r.Status !== "success");
      if (failed) throw new CloudApiError("volcengine", "DeployCertFailed", `关联证书失败：${failed.ErrorMsg || failed.Status || "未知原因"}`);
      return { certId };
    },
  },
};
