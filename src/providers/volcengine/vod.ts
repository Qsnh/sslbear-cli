import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import type { CertInfo, DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { completeCerts } from "./certs.js";
import { callVolc } from "./client.js";
import { earliest } from "./common.js";

/** 点播按地域部署，空间与域名要到空间所在地域的 endpoint 查；柔佛仅对企业用户开放 */
const REGIONS: Record<string, string> = {
  "cn-north-1": "vod.volcengineapi.com",
  "ap-southeast-1": "vod.ap-southeast-1.volcengineapi.com",
};
const MAIN_REGION = "cn-north-1";

interface Space {
  SpaceName: string;
  /** 列出该空间的地域 */
  Region: string;
}

interface VodDomain {
  Domain: string;
  /** vod_play 点播加速 / vod_image 封面加速 / third 自定义源站 */
  DomainType?: string;
}

interface CdnDomain {
  Domain: string;
  /** 是否启用了 HTTPS 特性 */
  HTTPS?: boolean;
  /** online / configuring / offline */
  Status?: string;
  ServiceRegion?: string;
}

interface DomainPage {
  VodInfo?: { Domains?: VodDomain[] | null; Total?: number } | null;
  DomainInfo?: { Data?: CdnDomain[] | null; Total?: number } | null;
}

interface VodCert {
  CertId?: string;
  /** 与 CDN 的 CertInfo 一致，是证书的 CN（实测为证书通用名），不是证书中心里的备注名 */
  CertName?: string;
  /** Unix 秒（实测有返回；缺了从证书中心补）。实测还带完整证书链 Certificate.Certificate（PEM，不含私钥），未使用 */
  EffectiveTime?: number;
  ExpireTime?: number;
}

interface DomainConfig {
  DomainInfo?: {
    DomainConfig?: { HTTPS?: { Switch?: boolean; CertInfo?: VodCert | null; CertInfoList?: VodCert[] | null } | null } | null;
  } | null;
  /** CertificateName 同样是证书 CN */
  VodInfo?: { Certificate?: { CertificateId?: string; CertificateName?: string } | null } | null;
}

const SPACE_PAGE = 10;
// ListVodDomains 的 PageSize 上限
const DOMAIN_PAGE = 100;

type Call = <T>(region: string, version: string, action: string, method: "GET" | "POST", params: Record<string, unknown>) => Promise<T>;

const seconds = (n?: number) => (n ? toIso(n) : undefined);

async function listSpaces(call: Call, region: string): Promise<Space[]> {
  // 只有 Offset / Limit、没有 Total：按名称去重，不足一页或没有新空间即结束
  const spaces = new Map<string, Space>();
  for (let page = 0; page < 200; page++) {
    const res = await call<Space[] | object>(region, "2021-01-01", "ListSpace", "GET", { Offset: spaces.size, Limit: SPACE_PAGE });
    const items = Array.isArray(res) ? res : [];
    const before = spaces.size;
    // 返回的 Region 是账号所属区域，不一定是空间所在地域，后续查询走列出该空间的 endpoint
    for (const s of items) if (s.SpaceName && !spaces.has(s.SpaceName)) spaces.set(s.SpaceName, { SpaceName: s.SpaceName, Region: region });
    if (items.length < SPACE_PAGE || spaces.size === before) break;
  }
  return [...spaces.values()];
}

/** VodInfo（域名类型）与 DomainInfo（HTTPS 开关、状态）是两组列表，按 PageNum 一起翻页后按域名合并 */
async function listDomains(call: Call, space: Space) {
  const types = new Map<string, VodDomain>();
  const cdn = new Map<string, CdnDomain>();
  for (let page = 1; page <= 1000; page++) {
    const res = await call<DomainPage>(space.Region, "2026-01-01", "ListVodDomains", "POST", {
      SpaceName: space.SpaceName,
      ListCdnDomainsParam: { PageNum: page, PageSize: DOMAIN_PAGE },
    });
    const vod = res.VodInfo?.Domains ?? [];
    const data = res.DomainInfo?.Data ?? [];
    for (const d of vod) types.set(d.Domain, d);
    for (const d of data) cdn.set(d.Domain, d);
    const vodDone = types.size >= (res.VodInfo?.Total ?? 0) || vod.length < DOMAIN_PAGE;
    const cdnDone = cdn.size >= (res.DomainInfo?.Total ?? 0) || data.length < DOMAIN_PAGE;
    if ((vodDone && cdnDone) || (vod.length === 0 && data.length === 0)) break;
  }
  const names = new Set([...types.keys(), ...cdn.keys()]);
  return [...names].map((domain) => ({ domain, space, type: types.get(domain)?.DomainType, cdn: cdn.get(domain) }));
}

/**
 * 视频点播：逐地域列空间 → 每个空间 ListVodDomains 拿域名、类型与 HTTPS 开关 →
 * 开启了 HTTPS 的域名再用 DescribeVodDomainConfig 读开关与绑定的证书（RSA + ECC 双证书时取先到期），
 * 证书只有 ID 时从证书中心补全。ListDomain / DescribeDomainConfig 已转为历史版本，不再使用。
 */
export const vod: DomainService<AccessKeyCredentials> = {
  key: "vod",
  label: "视频点播",
  async list(ctx: QueryContext, creds: AccessKeyCredentials, warn: Warn): Promise<DomainRecord[]> {
    const call: Call = (region, version, action, method, params) =>
      callVolc(ctx, creds, { host: REGIONS[region]!, service: "vod", region, version, action, method, params });
    const spaces = new Map<string, Space>();
    for (const region of Object.keys(REGIONS)) {
      let list: Space[];
      try {
        list = await listSpaces(call, region);
      } catch (e) {
        // 主地域失败即服务失败；柔佛未开通 / 无权访问视为没有空间，其余错误记 issue
        if (region === MAIN_REGION) throw e;
        if (!(e instanceof CloudApiError && /^(OperationDenied|RequestForbidden)/.test(e.code))) warn(e, `地域 ${region}`);
        continue;
      }
      for (const s of list) if (!spaces.has(s.SpaceName)) spaces.set(s.SpaceName, s);
    }
    const perSpace = await mapLimit([...spaces.values()], 5, async (space) => {
      try {
        return await listDomains(call, space);
      } catch (e) {
        warn(e, `空间 ${space.SpaceName}`);
        return [];
      }
    });
    const domains = perSpace.flat();
    // 只有开了 HTTPS（或不在 CDN 列表里、开关未知）的域名才需要读配置
    const configs = await mapLimit(domains, 5, async (d) => {
      if (d.cdn && d.cdn.HTTPS !== true) return undefined;
      if (!d.type) return undefined;
      try {
        return await call<DomainConfig>(d.space.Region, "2026-01-01", "DescribeVodDomainConfig", "POST", {
          SpaceName: d.space.SpaceName,
          DomainType: d.type,
          DescribeCdnDomainParam: { Domain: d.domain },
        });
      } catch (e) {
        warn(e, `域名 ${d.domain}`);
        return undefined;
      }
    });
    const candidates = domains.map((d, i) => {
      const https = configs[i]?.DomainInfo?.DomainConfig?.HTTPS;
      const on = https?.Switch ?? d.cdn?.HTTPS === true;
      if (!on) return { on, certs: [] as CertInfo[] };
      const list = https?.CertInfoList?.length ? https.CertInfoList : https?.CertInfo ? [https.CertInfo] : [];
      const certs: CertInfo[] = list
        .filter((c) => c.CertId)
        .map((c) => compact({ id: c.CertId, commonName: c.CertName, notBefore: seconds(c.EffectiveTime), notAfter: seconds(c.ExpireTime) }));
      const fallback = configs[i]?.VodInfo?.Certificate;
      if (certs.length === 0 && fallback?.CertificateId) certs.push(compact({ id: fallback.CertificateId, commonName: fallback.CertificateName }));
      return { on, certs };
    });
    const filled = await completeCerts(ctx, creds, warn, candidates.flatMap((c) => c.certs));
    let next = 0;
    return domains.map((d, i) => {
      const { on, certs } = candidates[i]!;
      const resolved = filled.slice(next, (next += certs.length));
      return compact({
        provider: "volcengine" as const,
        service: "vod",
        domain: d.domain,
        status: d.cdn?.Status,
        https: on,
        cert: on ? earliest(resolved) : undefined,
        extra: compact({ space: d.space.SpaceName, region: d.space.Region, type: d.type, serviceRegion: d.cdn?.ServiceRegion }),
      });
    });
  },
};
