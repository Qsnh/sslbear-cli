import type { TencentCredentials } from "../../lib/env.js";
import { CloudApiError, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { DomainRecord } from "../../types.js";
import type { Deployer, DomainService, Warn } from "../registry.js";
import { callTencent } from "./client.js";
import { asPlatformDomain, isPlatformDomain } from "./platform.js";
import { enrichFromSsl } from "./ssl.js";

interface LiveDomain {
  Name: string;
  /** 0 推流域名，1 播放域名 */
  Type?: number;
  /** 0 停用，1 启用 */
  Status?: number;
}

interface CertBinding {
  DomainName: string;
  CertificateAlias?: string;
  /** 1 已开启 HTTPS，0 关闭 */
  Status?: number;
  CertExpireTime?: string;
  CloudCertId?: string;
}

const DOMAIN_PAGE = 100;
const BINDING_PAGE = 50;

const call = <T>(ctx: QueryContext, creds: TencentCredentials, action: string, payload: Record<string, unknown>) =>
  callTencent<T>(ctx, creds, { service: "live", version: "2018-08-01", action, payload });

interface BindResult {
  MismatchedDomainNames?: string[] | null;
  /** 操作失败的域名，包括 MismatchedDomainNames 里的 */
  Errors?: { DomainName?: string; Code?: string; Message?: string }[] | null;
  RequestId?: string;
}

/**
 * ModifyLiveDomainCertBindings 按 SSL 证书 ID 绑定播放域名：update 时 HTTPS 启用状态传 -1（保持不变），
 * deploy 时传 1（启用）。批量接口受理后单个域名的失败放在 Errors / MismatchedDomainNames 里，需要逐一检查。
 */
const deployer: Deployer<TencentCredentials> = {
  unsupported(record) {
    return record.extra?.type === "push" ? "推流域名不能绑定 HTTPS 证书（直播证书只用于播放域名）" : undefined;
  },
  async apply(ctx, creds, target, input) {
    const domain = target.records[0]!.domain;
    const certId = await input.certId();
    const res = await call<BindResult>(ctx, creds, "ModifyLiveDomainCertBindings", {
      DomainInfos: [{ DomainName: domain, Status: target.mode === "deploy" ? 1 : -1 }],
      CloudCertId: certId,
    });
    const err = res.Errors?.find((e) => !e.DomainName || e.DomainName === domain);
    if (err) throw new CloudApiError("tencent", err.Code ?? "Unknown", err.Message ?? "绑定证书失败", res.RequestId);
    if (res.MismatchedDomainNames?.includes(domain)) {
      throw new CloudApiError("tencent", "CertDomainMismatch", "证书与该域名不匹配，直播已跳过绑定", res.RequestId);
    }
    return { certId };
  },
};

/** 直播域名 + 域名证书绑定关系两次分页查询后按域名合并；绑定里缺到期时间的从 SSL 证书列表补 */
export const live: DomainService<TencentCredentials> = {
  key: "live",
  label: "云直播",
  async list(ctx: QueryContext, creds: TencentCredentials, warn: Warn): Promise<DomainRecord[]> {
    const [domains, bindings] = await Promise.all([
      paginate(DOMAIN_PAGE, async (page) => {
        const res = await call<{ DomainList?: LiveDomain[] | null; AllCount?: number }>(ctx, creds, "DescribeLiveDomains", {
          PageNum: page,
          PageSize: DOMAIN_PAGE,
        });
        return { items: res.DomainList ?? [], total: res.AllCount };
      }),
      paginate(BINDING_PAGE, async (_page, offset) => {
        const res = await call<{ LiveDomainCertBindings?: CertBinding[] | null; TotalNum?: number }>(
          ctx,
          creds,
          "DescribeLiveDomainCertBindings",
          { Offset: offset, Length: BINDING_PAGE },
        );
        return { items: res.LiveDomainCertBindings ?? [], total: res.TotalNum };
      }),
    ]);
    const bindingByDomain = new Map(bindings.map((b) => [b.DomainName, b]));
    const records = domains.map((d) => {
      const b = bindingByDomain.get(d.Name);
      const https = b?.Status === 1;
      const record = compact({
        provider: "tencent" as const,
        service: "live",
        domain: d.Name,
        status: d.Status === undefined ? undefined : d.Status === 1 ? "online" : "offline",
        https,
        // 绑了证书但未开启 HTTPS 的域名不对外提供证书，不计入到期统计
        cert: https && b ? compact({ id: b.CloudCertId, name: b.CertificateAlias, notAfter: toIso(b.CertExpireTime) }) : undefined,
        extra: d.Type === undefined ? undefined : { type: d.Type === 1 ? "play" : "push" },
      });
      // 平台默认推流/播放域名（如 {bizid}.livepush.myqcloud.com）不能绑证书，平台始终用自己的证书提供 HTTPS
      return isPlatformDomain(d.Name) ? asPlatformDomain(record, true) : record;
    });
    return enrichFromSsl(ctx, creds, warn, records);
  },
  deployer,
};
