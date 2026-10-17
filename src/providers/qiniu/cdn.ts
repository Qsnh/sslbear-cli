import type { AccessKeyCredentials } from "../../lib/env.js";
import type { QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { mapLimit } from "../../lib/pool.js";
import type { DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { API_HOST, listByMarker, qiniuGet } from "./client.js";
import { enrichFromSsl } from "./ssl.js";

interface CdnDomain {
  /** 泛域名以点开头，如 .example.com */
  name: string;
  /** normal / wildcard / pan（泛子域名）/ test（七牛分配的测试域名，如 xxx.hd-bkt.clouddn.com） */
  type?: string;
  /** cdn（静态加速）/ dcdn（全站加速），列表与详情都有 */
  product?: string;
  /** http / https，即 HTTPS 开关 */
  protocol?: string;
  geoCover?: string;
  /** 最近一次操作的状态：processing / success / failed / frozen / offlined */
  operatingState?: string;
}

interface CdnDomainDetail extends CdnDomain {
  https?: { certId?: string; forceHttps?: boolean; http2Enable?: boolean } | null;
}

const DOMAIN_PAGE = 1000;

function toRecord(d: CdnDomainDetail): DomainRecord {
  const certId = d.https?.certId || undefined;
  // protocol 为 https 时才必须配置 certId；缺该字段时退而看是否配置了证书
  const https = d.protocol ? d.protocol === "https" : !!certId;
  return compact({
    provider: "qiniu" as const,
    service: "cdn",
    domain: d.name,
    status: d.operatingState,
    https,
    cert: https && certId ? { id: certId } : undefined,
    extra: compact({ type: d.type, product: d.product, geoCover: d.geoCover }),
  });
}

/**
 * CDN 域名（含全站加速 dcdn 域名，二者共用域名管理接口）：列表只有 HTTPS 开关没有证书 ID，
 * 对开启了 HTTPS 的域名逐个查详情（并发 5）取 certId，再从证书列表补全有效期。
 * 已下线 / 冻结的域名照常列出，状态见 status。七牛给每个新建 bucket 自动分配的测试域名（type test，
 * 七牛自有的 *.clouddn.com 域名，不能配置 HTTPS、30 天后回收）不是用户的域名，不列出。
 */
export const cdn: DomainService<AccessKeyCredentials> = {
  key: "cdn",
  label: "CDN",
  async list(ctx: QueryContext, creds: AccessKeyCredentials, warn: Warn): Promise<DomainRecord[]> {
    const domains = await listByMarker(DOMAIN_PAGE, async (query) => {
      const res = await qiniuGet<{ domains?: CdnDomain[] | null; marker?: string }>(ctx, creds, API_HOST, `/domain?${query}`);
      return { items: res.domains ?? [], marker: res.marker };
    }).then((list) => list.filter((d) => d.type !== "test"));
    const records = await mapLimit(domains, 5, async (d) => {
      if (d.protocol === "http") return toRecord(d);
      try {
        const detail = await qiniuGet<CdnDomainDetail>(ctx, creds, API_HOST, `/domain/${encodeURIComponent(d.name)}`);
        return toRecord({ ...d, ...detail });
      } catch (e) {
        warn(e, `domain ${d.name}`);
        return toRecord(d);
      }
    });
    return enrichFromSsl(ctx, creds, warn, records);
  },
};
