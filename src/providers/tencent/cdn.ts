import type { TencentCredentials } from "../../lib/env.js";
import { CloudApiError, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { DomainRecord } from "../../types.js";
import type { Deployer, DomainService } from "../registry.js";
import { callTencent } from "./client.js";
import { asPlatformDomain, isPlatformDomain } from "./platform.js";
import { explainMissingCn } from "./ssl.js";

interface CdnHttps {
  Switch?: string;
  Http2?: string | null;
  OcspStapling?: string | null;
  VerifyClient?: string | null;
  Spdy?: string | null;
  /** 实测 CertName 是证书的主域名（托管时自动生成），Message 才是证书备注（即 SSL 证书列表里的备注名） */
  CertInfo?: { CertId?: string; CertName?: string; Message?: string; ExpireTime?: string; DeployTime?: string; From?: string } | null;
  ClientCertInfo?: { Certificate?: string | null; CertName?: string | null } | null;
  Hsts?: { Switch?: string; MaxAge?: number | null; IncludeSubDomains?: string | null } | null;
  TlsVersion?: string[] | null;
  /** 部署状态，只读 */
  SslStatus?: string | null;
}

interface CdnDomain {
  Domain: string;
  Status?: string;
  Area?: string;
  Https?: CdnHttps | null;
  /** HTTPS 服务开关，off 时拦截 HTTPS 请求；缺省为开启 */
  HttpsBilling?: { Switch?: string } | null;
}

/** DescribeDomainsConfig 的 Limit 上限为 100；一次调用覆盖境内与境外域名，用 Area 区分 */
const PAGE = 100;

const call = <T>(ctx: QueryContext, creds: TencentCredentials, action: string, payload: Record<string, unknown>) =>
  callTencent<T>(ctx, creds, { service: "cdn", version: "2018-06-06", action, payload });

async function describeDomain(ctx: QueryContext, creds: TencentCredentials, domain: string): Promise<CdnDomain> {
  const res = await call<{ Domains?: CdnDomain[] | null }>(ctx, creds, "DescribeDomainsConfig", {
    Offset: 0,
    Limit: PAGE,
    Filters: [{ Name: "domain", Value: [domain] }],
  });
  const d = res.Domains?.find((x) => x.Domain.toLowerCase() === domain.toLowerCase());
  if (!d) throw new CloudApiError("tencent", "DomainNotFound", `CDN 上没有找到域名 ${domain}`);
  return d;
}

/**
 * UpdateDomainConfig 对复杂类型整体覆盖（未传的属性取默认值），所以把读到的 Https 可写字段原样带回，
 * 只改开关与证书；SslStatus 是只读状态，客户端证书只带 Certificate / CertName（时间字段作为入参无需填充）。
 */
function httpsWith(current: CdnHttps | null | undefined, certId: string): Record<string, unknown> {
  const h = current ?? {};
  const client = h.ClientCertInfo?.Certificate
    ? compact({ Certificate: h.ClientCertInfo.Certificate, CertName: h.ClientCertInfo.CertName })
    : undefined;
  return compact({
    Switch: "on",
    Http2: h.Http2,
    OcspStapling: h.OcspStapling,
    VerifyClient: h.VerifyClient,
    Spdy: h.Spdy,
    Hsts: h.Hsts ? compact({ ...h.Hsts }) : undefined,
    TlsVersion: h.TlsVersion,
    ClientCertInfo: client,
    CertInfo: { CertId: certId },
  });
}

/** 证书没有 CN 时 CDN 的报错（见 explainMissingCn） */
const NO_CN_CODES = ["FailedOperation.CdnConfigError"];

const HTTPS_BILLING_OFF =
  "已开启 HTTPS，但该域名的 HTTPS 服务（HttpsBilling）处于关闭状态，HTTPS 请求会被拦截；如需对外提供 HTTPS，请在 CDN 控制台开启 HTTPS 服务（按 HTTPS 请求数计费）";

/**
 * update：ModifyDomainConfig 按配置路径只改叶子节点 Https.CertInfo.CertId（官方示例「更新 HTTPS 服务器证书 ID」），
 * 其他 HTTPS 配置（HTTP/2、HSTS、OCSP、TLS 版本等）和强制跳转都不动。
 * deploy：没有单独开启 HTTPS 的路径，先读出 Https 整体配置，开启开关、换上证书后用 UpdateDomainConfig 写回；
 * 读到 HTTPS 其实已开启（查询之后被改过）时不写，交给重新执行时按更新规则判断。
 */
const deployer: Deployer<TencentCredentials> = {
  async apply(ctx, creds, target, input) {
    const domain = target.records[0]!.domain;
    const write = (action: string, payload: Record<string, unknown>) =>
      explainMissingCn(input.cert, " CDN ", NO_CN_CODES, () => call(ctx, creds, action, payload));
    if (target.mode === "update") {
      const certId = await input.certId();
      await write("ModifyDomainConfig", { Domain: domain, Route: "Https.CertInfo.CertId", Value: JSON.stringify({ update: certId }) });
      return { certId };
    }
    const current = await describeDomain(ctx, creds, domain);
    if (current.Https?.Switch === "on") {
      throw new CloudApiError("tencent", "HttpsAlreadyEnabled", "该域名的 HTTPS 已开启（与查询时不同），未做修改；请重新执行，按更新规则判断");
    }
    const certId = await input.certId();
    await write("UpdateDomainConfig", { Domain: domain, Https: httpsWith(current.Https, certId) });
    // HTTPS 服务是计费开关，不替用户打开，只提示
    return { certId, ...(current.HttpsBilling?.Switch === "off" && { note: HTTPS_BILLING_OFF }) };
  },
};

export const cdn: DomainService<TencentCredentials> = {
  key: "cdn",
  label: "CDN",
  async list(ctx: QueryContext, creds: TencentCredentials): Promise<DomainRecord[]> {
    const domains = await paginate(PAGE, async (_page, offset) => {
      const res = await call<{ Domains?: CdnDomain[] | null; TotalNumber?: number }>(ctx, creds, "DescribeDomainsConfig", {
        Offset: offset,
        Limit: PAGE,
      });
      return { items: res.Domains ?? [], total: res.TotalNumber };
    });
    return domains.map((d) => {
      const cert = d.Https?.CertInfo;
      const https = d.Https?.Switch === "on";
      const record = compact({
        provider: "tencent" as const,
        service: "cdn",
        domain: d.Domain,
        status: d.Status,
        https,
        cert: https && cert ? compact({ id: cert.CertId, name: cert.Message || cert.CertName, notAfter: toIso(cert.ExpireTime) }) : undefined,
        extra: d.Area ? { area: d.Area } : undefined,
      });
      // 平台域名（如 *.video.myqcloud.com）有 HTTPS 开关但没有用户证书，HTTPS 以开关为准
      return isPlatformDomain(d.Domain) ? asPlatformDomain(record, https) : record;
    });
  },
  deployer,
};
