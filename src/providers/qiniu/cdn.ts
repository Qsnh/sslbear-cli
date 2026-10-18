import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, withRetry, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { mapLimit } from "../../lib/pool.js";
import type { DomainRecord } from "../../types.js";
import type { DeployTarget, Deployer, DomainService, Warn } from "../registry.js";
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
  /** 实测域名详情返回数组，如 ["TLSv1.2","TLSv1.3"]；HTTP 域名为 null 或空数组 */
  tlsVersions?: string[] | null;
}

interface CdnDomainDetail extends CdnDomain {
  https?: HttpsConf | null;
}

const DOMAIN_PAGE = 1000;

/** protocol 为 https 时才必须配置 certId；缺该字段时退而看是否配置了证书 */
const httpsOn = (d: CdnDomainDetail) => (d.protocol ? d.protocol === "https" : !!d.https?.certId);

/** httpsUnknown：域名详情没查到，HTTPS 状态或证书 ID 只能按列表猜测，部署时不能按查询结果写入 */
function toRecord(d: CdnDomainDetail, httpsUnknown = false): DomainRecord {
  const certId = d.https?.certId || undefined;
  const https = httpsOn(d);
  return compact({
    provider: "qiniu" as const,
    service: "cdn",
    domain: d.name,
    status: d.operatingState,
    https,
    cert: https && certId ? { id: certId } : undefined,
    extra: compact({ type: d.type, product: d.product, geoCover: d.geoCover, httpsUnknown: httpsUnknown ? "true" : undefined }),
  });
}

/**
 * sslize 必传 forceHttps / http2Enable：不强制跳转（控制台默认关闭，开启会改变 HTTP 访问行为）；
 * HTTP/2 的默认值文档没写，按文档示例开启
 */
const SSLIZE_DEFAULTS = { forceHttps: false, http2Enable: true };

/**
 * 写 HTTPS 配置（sslize / httpsconf）。请求只发一次、不原样重发：超时、限流时第一次可能其实已生效，
 * 重发会收到「正在处理中」（400030）之类的错误，把已生效的修改报成失败。遇到可重试的错误时先重读域名详情：
 * 已绑定新证书（deploy 还要求 HTTPS 已开启）即算成功；deploy 时读到 HTTPS 已用别的证书开启（与查询时不同）就不再写入；
 * 否则再发，总共最多 3 轮。
 */
async function writeHttps(
  ctx: QueryContext,
  creds: AccessKeyCredentials,
  domain: string,
  mode: DeployTarget["mode"],
  body: { certId: string } & Record<string, unknown>,
): Promise<void> {
  const path = `/domain/${encodeURIComponent(domain)}`;
  let sent = false;
  await withRetry(ctx, async () => {
    if (sent) {
      const detail = await qiniuGet<CdnDomainDetail>(ctx, creds, API_HOST, path);
      const bound = detail.https?.certId === body.certId;
      if (bound && (mode === "update" || httpsOn(detail))) return;
      if (mode === "deploy" && httpsOn(detail)) {
        throw new CloudApiError("qiniu", "HttpsAlreadyEnabled", "该域名的 HTTPS 已开启（与查询时不同），未做修改；请重新执行，按更新规则判断");
      }
    }
    sent = true;
    await qiniuRequest(ctx, creds, API_HOST, `${path}/${mode === "deploy" ? "sslize" : "httpsconf"}`, { method: "PUT", body, retry: false });
  });
}

/**
 * 七牛单个域名只能绑一张证书，没有双证书。按证书 ID 绑定（先上传到 SSL 证书服务）：
 * - deploy：PUT /domain/<域名>/sslize 开启 HTTPS；
 * - update：PUT /domain/<域名>/httpsconf 换证书。实测该接口不传 forceHttps 会被重置为 false、不传 tlsVersions
 *   会恢复为默认的 TLSv1.0–1.3（http2Enable 不传时保留原值），所以先读域名详情，把当前的强制跳转、HTTP/2、
 *   TLS 版本原样带回，只换 certId。
 * 域名处理中（上一次修改未生效）等情况七牛会拒绝修改（如 400030 正在处理中），错误原样上报，不等待。
 * 写请求不原样重发，见 writeHttps。
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
      if (target.mode === "deploy") {
        certId = await input.certId();
        await writeHttps(ctx, creds, record.domain, "deploy", { certId, ...SSLIZE_DEFAULTS });
        continue;
      }
      const current = (await qiniuGet<CdnDomainDetail>(ctx, creds, API_HOST, `/domain/${encodeURIComponent(record.domain)}`)).https ?? {};
      certId = await input.certId();
      if (current.certId === certId) {
        note = "域名已绑定该证书，未重复提交";
        continue;
      }
      const keep = compact({ forceHttps: current.forceHttps, http2Enable: current.http2Enable, tlsVersions: current.tlsVersions });
      await writeHttps(ctx, creds, record.domain, "update", { certId, ...keep });
    }
    return compact({ certId, note });
  },
};

/**
 * CDN 域名（含全站加速 dcdn 域名，二者共用域名管理接口）：列表只有 HTTPS 开关没有证书 ID，
 * 对开启了 HTTPS 的域名（以及处理中的域名）逐个查详情（并发 5）取 certId，再从证书列表补全有效期。
 * 处理中的域名按详情输出，即已提交、可能尚未下发到边缘的配置。
 * 详情查询失败的域名按列表信息输出（没有证书 ID，列表缺 protocol 时 https 为 false），并标 httpsUnknown。
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
      // 处理中的域名列表里还是旧的 protocol（实测 sslize 后要等处理完才变），详情才是已提交的配置
      if (d.protocol === "http" && d.operatingState !== "processing") return toRecord(d);
      try {
        const detail = await qiniuGet<CdnDomainDetail>(ctx, creds, API_HOST, `/domain/${encodeURIComponent(d.name)}`);
        return toRecord({ ...d, ...detail });
      } catch (e) {
        warn(e, `domain ${d.name}`);
        return toRecord(d, true);
      }
    });
    return enrichFromSsl(ctx, creds, warn, records);
  },
  deployer,
};
