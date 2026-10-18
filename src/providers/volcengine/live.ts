import type { LocalCert } from "../../deploy/cert.js";
import { SAME_CERT_TOLERANCE_MS } from "../../deploy/plan.js";
import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, withRetry, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { memo, paginate } from "../../lib/paginate.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import type { CertInfo, DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { callVolc, callVolcOnce, type VolcRequest } from "./client.js";
import { certName, explainNoCommonName, pemFingerprints } from "./common.js";

interface LiveDomain {
  Domain: string;
  /** push 推流 / pull-flv 拉流 */
  Type?: string;
  Status?: number;
  /** cn / cn-global / cn-oversea */
  Region?: string;
  Vhost?: string;
  ProjectName?: string;
  /** 绑定的 HTTPS 证书的证书链 ID（直播自己的 ID），未绑定或绑定时关闭了 HTTPS 为空 */
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
  ProjectName?: string;
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

const request = (action: string, params: Record<string, unknown>): VolcRequest => ({
  host: "live.volcengineapi.com",
  service: "live",
  region: "cn-north-1",
  version: "2023-01-01",
  action,
  method: "POST",
  params,
});

const call = <T>(ctx: QueryContext, creds: AccessKeyCredentials, action: string, params: Record<string, unknown>) =>
  callVolc<T>(ctx, creds, request(action, params));

const toCert = (c: LiveCert): CertInfo =>
  compact({
    id: c.CertID || c.ChainID,
    name: c.CertName,
    sans: c.CertDomainList ?? undefined,
    notBefore: toIso(c.NotBefore),
    notAfter: toIso(c.NotAfter),
    status: c.Status,
  });

// 控制台标注的证书名称上限
const CERT_NAME_MAX = 40;

const uploads = memo<QueryContext, string>();

/**
 * 直播证书管理里与本地证书同一张的证书链 ID（每次都重新拉 ListCertV2，不用缓存）。ListCertV2 不给指纹：
 * 先按项目与到期时间（48 小时内）筛候选，再逐个用 DescribeCertDetailSecretV2 取证书链比对叶子指纹，
 * 避免把同域名、同到期时间的另一算法证书当成同一张；候选已被删除时按不是同一张处理，读取失败则报错。
 */
async function findLiveCert(ctx: QueryContext, creds: AccessKeyCredentials, cert: LocalCert, project: string): Promise<string | undefined> {
  const list = (await call<{ CertList?: LiveCert[] | null }>(ctx, creds, "ListCertV2", {})).CertList ?? [];
  const newMs = Date.parse(cert.notAfter);
  const candidates = list.filter(
    (c) => c.ChainID && (!c.ProjectName || c.ProjectName === project) && Math.abs(Date.parse(toIso(c.NotAfter) ?? "") - newMs) <= SAME_CERT_TOLERANCE_MS,
  );
  for (const c of candidates) {
    let chain: string[];
    try {
      const detail = await call<{ SSL?: { Chain?: string[] | null } | null }>(ctx, creds, "DescribeCertDetailSecretV2", { ChainID: c.ChainID });
      chain = detail.SSL?.Chain ?? [];
    } catch (e) {
      // 证书在列表与详情之间被删除：不是同一张，看下一个候选；其余错误（限流、超时交给外层整轮重来，无权限等直接报错）
      // 一律抛出，不能当成「不是同一张」去上传，否则缺权限时每次运行都会多传一份
      if (e instanceof CloudApiError && /NotFound|NotExist/i.test(e.code)) continue;
      throw e;
    }
    if (pemFingerprints(chain.join("\n")).includes(cert.fingerprint)) return c.ChainID!;
  }
  return undefined;
}

/**
 * 直播证书管理里与本地证书同一张的证书链 ID；没有就 CreateCert 上传（PEM 在 JSON 请求体里）。证书须与域名所在域名空间同属一个项目。
 * CreateCert 不幂等，只发一次、不自动重试：遇到超时、限流等可重试的错误时整轮重来（最多 3 轮），先重新查重
 * （上一次其实已传成功时直接复用），查不到再传，不会在直播证书管理里传出两份。同一次运行内每个项目只处理一次。
 */
function liveChainId(ctx: QueryContext, creds: AccessKeyCredentials, cert: LocalCert, project: string): Promise<string> {
  return uploads(ctx, `${creds.accessKeyId}/${project}/${cert.fingerprint}`, () =>
    withRetry(ctx, async () => {
      const existing = await findLiveCert(ctx, creds, cert, project);
      if (existing) return existing;
      const created = await callVolcOnce<{ ChainID?: string }>(
        ctx,
        creds,
        request("CreateCert", {
          CertName: certName(cert, CERT_NAME_MAX),
          UseWay: "https",
          ProjectName: project,
          Rsa: { Pubkey: cert.certPem, Prikey: cert.keyPem },
        }),
      ).catch((e) => {
        throw explainNoCommonName(e, cert, "视频直播", ["InvalidParam"]);
      });
      if (!created.ChainID) throw new CloudApiError("volcengine", "InvalidResponse", "上传证书后视频直播没有返回证书链 ID");
      return created.ChainID;
    }),
  );
}

/**
 * 视频直播：ListDomainDetail 列域名（带绑定证书的 ChainID）+ ListCertV2 证书列表按 ChainID 关联。
 * 直播的读接口不返回 HTTPS 开关（只在 BindCert 写接口里）。实测 BindCert 传 HTTPS=false 的域名在 ListDomainDetail / DescribeDomain
 * 里 ChainID 为空，所以 ChainID 非空即「绑定证书并开启 HTTPS」（边缘节点对 HTTPS=false 的域名仍会用该证书完成 TLS 握手，读接口看不到）。
 * 推流域名绑证书用于 RTMPS / HTTPS 推流（443 端口），同样列出。
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
  deployer: {
    // 实测直播 CreateCert 不接受没有 CN 的证书
    requiresCommonName: true,
    /**
     * BindCert 的 HTTP/2（默认关）与 TLS 版本范围（默认最低 TLSv1.2）不传即恢复默认，而直播没有能读出这两项当前值的接口，
     * 所以已开 HTTPS 的拉流域名不能安全地只换证书。推流域名不支持这两项设置，可以更新；没开 HTTPS 的域名点名部署时按默认开启。
     */
    unsupported: (record, mode) =>
      mode === "update" && record.extra?.type !== "push"
        ? "视频直播换证书的接口会把拉流域名的 HTTP/2 与 TLS 版本恢复默认，且读不到当前设置，无法只替换证书；请在直播控制台的 HTTPS 设置里更换"
        : undefined,
    /** 视频直播只能用自己的证书管理（不能直接用证书中心的证书），先上传到直播证书管理再 BindCert 绑定并开启 HTTPS（推流域名即 RTMPS / HTTPS 推流） */
    async apply(ctx, creds, target, input) {
      const [record] = target.records;
      const chainId = await liveChainId(ctx, creds, input.cert, record!.extra?.project || "default");
      await call(ctx, creds, "BindCert", { Domain: record!.domain, ChainID: chainId, HTTPS: true });
      if (record!.extra?.type === "push") return { certId: chainId };
      return { certId: chainId, note: "已开启 HTTPS；HTTP/2 与 TLS 版本为直播默认值（HTTP/2 关闭、最低 TLSv1.2），如需调整请到直播控制台" };
    },
  },
};
