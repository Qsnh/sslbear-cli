import type { AccessKeyCredentials } from "../../lib/env.js";
import type { QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { mapLimit } from "../../lib/pool.js";
import type { DomainRecord } from "../../types.js";
import type { Deployer, DomainService, Warn } from "../registry.js";
import { API_HOST, listByMarker, qiniuGet, qiniuRequest } from "./client.js";
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

interface HttpsConf {
  certId?: string;
  forceHttps?: boolean;
  http2Enable?: boolean;
  /** 如 TLSv1.2/TLSv1.3；文档没写域名详情是否返回 */
  tlsVersions?: string;
}

interface CdnDomainDetail extends CdnDomain {
  https?: HttpsConf | null;
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
 * sslize 必传 forceHttps / http2Enable：不强制跳转（控制台默认关闭，开启会改变 HTTP 访问行为）；
 * HTTP/2 的默认值文档没写，按文档示例开启
 */
const SSLIZE_DEFAULTS = { forceHttps: false, http2Enable: true };

/**
 * 七牛单个域名只能绑一张证书，没有双证书。按证书 ID 绑定（先上传到 SSL 证书服务）：
 * - deploy：PUT /domain/<域名>/sslize 开启 HTTPS；
 * - update：PUT /domain/<域名>/httpsconf 换证书。该接口的 forceHttps / http2Enable 不传时是否保留原值没有保证，
 *   所以先读域名详情，把当前的强制跳转、HTTP/2、TLS 版本原样带回，只换 certId。
 * 域名处理中（上一次修改未生效）等情况七牛会拒绝修改（如 400030 正在处理中），错误原样上报，不等待。
 */
const deployer: Deployer<AccessKeyCredentials> = {
  unsupported(record) {
    if (record.extra?.type === "pan") return "泛子域名的 HTTPS 配置继承所属泛域名，不能单独部署证书；请对泛域名（.example.com 形式）部署";
    return undefined;
  },
  async apply(ctx, creds, target, input) {
    let certId: string | undefined;
    let note: string | undefined;
    for (const record of target.records) {
      const path = `/domain/${encodeURIComponent(record.domain)}`;
      if (target.mode === "deploy") {
        certId = await input.certId();
        await qiniuRequest(ctx, creds, API_HOST, `${path}/sslize`, { method: "PUT", body: { certId, ...SSLIZE_DEFAULTS } });
        continue;
      }
      const current = (await qiniuGet<CdnDomainDetail>(ctx, creds, API_HOST, path)).https ?? {};
      certId = await input.certId();
      if (current.certId === certId) {
        note = "域名已绑定该证书，未重复提交";
        continue;
      }
      const keep = compact({ forceHttps: current.forceHttps, http2Enable: current.http2Enable, tlsVersions: current.tlsVersions });
      await qiniuRequest(ctx, creds, API_HOST, `${path}/httpsconf`, { method: "PUT", body: { certId, ...keep } });
    }
    return compact({ certId, note });
  },
};

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
  deployer,
};
