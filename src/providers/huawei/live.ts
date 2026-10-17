import type { AccessKeyCredentials } from "../../lib/env.js";
import { CloudApiError, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { mapLimit } from "../../lib/pool.js";
import { toIso } from "../../lib/time.js";
import type { CertInfo, DomainRecord } from "../../types.js";
import type { DomainService, Warn } from "../registry.js";
import { callHuawei, listProjects } from "./client.js";
import { earliest } from "./common.js";
import { enrichFromScm } from "./scm.js";

/**
 * 视频直播的域名按地域隔离：新用户中国站在北京四、国际站在新加坡（ap-southeast-3），
 * 存量用户可能在其它地域。文档列出北京一 / 北京四 / 新加坡，官方 SDK 另有上海一、曼谷，五个都查。
 */
export const LIVE_REGIONS = ["cn-north-4", "cn-north-1", "cn-east-3", "ap-southeast-3", "ap-southeast-2"] as const;
/** ShowCertificateInfo 的 limit 上限 */
const CERT_PAGE = 100;

/**
 * 没在该地域使用直播时可能返回的错误：服务在该地域不可用、项目不可用、接口不存在、直播用户不存在。
 * 这类地域静默跳过，免得每次都为没用到的地域报一堆错误；所有地域都失败时才把错误抛给上层。
 */
const UNUSED_REGION_CODES = new Set(["APIGW.0801", "APIGW.0310", "APIGW.0101", "LIVE.100011009"]);

interface LiveDomain {
  domain: string;
  /** pull 播放域名，push 推流域名 */
  domain_type?: string;
  /** on / off / configuring */
  status?: string;
  service_area?: string;
}

interface LiveCert {
  play_domain: string;
  /** UTC "YYYY-MM-DDTHH:mm:ssZ" */
  start_time?: string;
  expire_time?: string;
  /** 0 国际标准证书，1 国密证书 */
  cert_type?: number;
  /** scm 云证书管理服务，user 自有证书 */
  source?: string;
  /** 仅 scm 来源的证书有名称与 ID */
  cert_name?: string;
  cert_id?: string;
}

// 文档里 ShowDomain 的失败示例是 404 LIVE.103011019（资源不存在），列表接口报这个按没有数据处理
function emptyIfNotFound<T>(e: unknown, empty: T): T {
  if (e instanceof CloudApiError && e.code === "LIVE.103011019") return empty;
  throw e;
}

async function listRegion(ctx: QueryContext, creds: AccessKeyCredentials, region: string, projectId: string) {
  const host = `live.${region}.myhuaweicloud.com`;
  const [domains, certs] = await Promise.all([
    callHuawei<{ domain_info?: LiveDomain[] | null }>(ctx, creds, { host, path: `/v1/${projectId}/domain`, projectId })
      .then((res) => res.domain_info ?? [])
      .catch((e: unknown) => emptyIfNotFound(e, [])),
    paginate(CERT_PAGE, async (_page, offset) => {
      const res = await callHuawei<{ certificates_info?: LiveCert[] | null; total?: number }>(ctx, creds, {
        host,
        path: `/v2/${projectId}/certificates`,
        query: { offset, limit: CERT_PAGE },
        projectId,
      });
      return { items: res.certificates_info ?? [], total: res.total };
    }).catch((e: unknown) => emptyIfNotFound(e, [])),
  ]);
  return { domains, certs };
}

/**
 * 逐地域查直播域名 + 播放域名的 HTTPS 证书列表（ShowCertificateInfo 批量接口，带到期时间），按域名合并。
 * 直播没有单独的 HTTPS 开关：播放域名配置了证书即开启 HTTPS，删除证书即关闭；推流域名不支持 HTTPS。
 */
export const live: DomainService<AccessKeyCredentials> = {
  key: "live",
  label: "视频直播",
  async list(ctx: QueryContext, creds: AccessKeyCredentials, warn: Warn): Promise<DomainRecord[]> {
    const projects = await listProjects(ctx, creds);
    const regions = LIVE_REGIONS.filter((r) => projects.has(r));
    if (regions.length === 0) {
      throw new CloudApiError("huawei", "ProjectNotFound", `未找到视频直播所在地域（${LIVE_REGIONS.join("、")}）的项目，请确认 AK 所属用户有这些地域的项目权限`);
    }
    const results = await mapLimit(regions, 5, async (region) => {
      try {
        return { region, data: await listRegion(ctx, creds, region, projects.get(region)!) };
      } catch (error) {
        return { region, error };
      }
    });
    const unused = (e: unknown) => e instanceof CloudApiError && UNUSED_REGION_CODES.has(e.code);
    if (results.every((r) => !r.data)) {
      throw (results.find((r) => !unused(r.error)) ?? results[0]!).error;
    }
    const seen = new Set<string>();
    const records: DomainRecord[] = [];
    for (const { region, data, error } of results) {
      if (!data) {
        if (!unused(error)) warn(error, `region ${region}`);
        continue;
      }
      // 国密证书的签名证书与加密证书各占一条，一个域名可能有多条
      const certsByDomain = new Map<string, (CertInfo & { source?: string })[]>();
      for (const c of data.certs) {
        const cert = compact({
          id: c.cert_id,
          name: c.cert_name,
          notBefore: toIso(c.start_time),
          notAfter: toIso(c.expire_time),
          source: c.source,
        });
        certsByDomain.set(c.play_domain, [...(certsByDomain.get(c.play_domain) ?? []), cert]);
      }
      for (const d of data.domains) {
        // 接口若不按地域隔离会在多个地域返回同一域名，只保留第一次出现的
        if (seen.has(d.domain)) continue;
        seen.add(d.domain);
        const best = earliest(certsByDomain.get(d.domain) ?? []);
        const { source, ...cert } = best ?? {};
        records.push(
          compact({
            provider: "huawei" as const,
            service: "live",
            domain: d.domain,
            status: d.status,
            https: !!best,
            cert: best ? cert : undefined,
            extra: compact({ region, type: d.domain_type, serviceArea: d.service_area, certSource: source }),
          }),
        );
      }
    }
    return enrichFromScm(ctx, creds, warn, records);
  },
};
