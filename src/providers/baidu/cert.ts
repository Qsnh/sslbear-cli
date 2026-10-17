import type { AccessKeyCredentials } from "../../lib/env.js";
import type { QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { memo } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { CertificateRecord, DomainRecord } from "../../types.js";
import type { Warn } from "../registry.js";
import { callBce } from "./client.js";

const HOST = "certificate.baidubce.com";

interface CertDetail {
  certId: string;
  certName?: string;
  certCommonName?: string;
  /** 英文逗号分隔 */
  certDNSNames?: string;
  /** UTC，如 2014-06-01T23:00:10Z */
  certStartTime?: string;
  certStopTime?: string;
  /** 1 服务端证书，2 客户端证书（双向认证用的 CA） */
  certType?: number;
  /** UNUSED / IN_USE */
  status?: string;
  expired?: boolean;
}

/** 接口偶尔用一串 "-" 占位，不是真实域名 */
function splitNames(s: string | undefined): string[] | undefined {
  const names = (s ?? "")
    .split(",")
    .map((x) => x.trim())
    .filter((x) => x && !/^-+$/.test(x));
  return names.length ? names : undefined;
}

/**
 * 证书管理的证书列表详情（比 /v1/certificate 多了域名与使用状态），接口不分页、一次返回全部。
 * 只保留服务端证书：客户端证书是双向认证用的 CA，不涉及网站证书续期。
 */
async function fetchAll(ctx: QueryContext, creds: AccessKeyCredentials): Promise<CertificateRecord[]> {
  const res = await callBce<{ certs?: CertDetail[] | null }>(ctx, creds, { host: HOST, path: "/v1/certificate/detail" });
  return (res.certs ?? [])
    .filter((c) => c.certType !== 2)
    .map((c) =>
      compact({
        provider: "baidu" as const,
        id: c.certId,
        name: c.certName,
        commonName: c.certCommonName,
        sans: splitNames(c.certDNSNames),
        notBefore: toIso(c.certStartTime),
        notAfter: toIso(c.certStopTime),
        status: c.status,
      }),
    );
}

const cached = memo<QueryContext, CertificateRecord[]>();

/** 证书管理的证书列表，同一次命令内（certs 与 CDN 补全）只拉一次 */
export function listBaiduCertificates(ctx: QueryContext, creds: AccessKeyCredentials): Promise<CertificateRecord[]> {
  return cached(ctx, `cert:${creds.accessKeyId}`, () => fetchAll(ctx, creds));
}

/** CDN 的 BOS 默认域名等场景用平台通用证书，证书管理里查不到，无需补全 */
const COMMON_CERT_ID = "cert-common";

/**
 * 域名接口缺到期时间时，用证书管理的列表按证书 ID 补全。
 * 补全失败（如没有证书管理只读权限）只记一条 issue，域名本身照常返回。
 */
export async function enrichFromCertService(
  ctx: QueryContext,
  creds: AccessKeyCredentials,
  warn: Warn,
  records: DomainRecord[],
): Promise<DomainRecord[]> {
  const pending = records.filter((r) => r.cert?.id && r.cert.id !== COMMON_CERT_ID && !r.cert.notAfter);
  if (pending.length === 0) return records;
  let certs: CertificateRecord[];
  try {
    certs = await listBaiduCertificates(ctx, creds);
  } catch (e) {
    warn(e, "证书管理列表（用于补全到期时间）");
    return records;
  }
  const byId = new Map(certs.map((c) => [c.id, c]));
  for (const r of pending) {
    const c = byId.get(r.cert!.id!);
    if (!c) continue;
    r.cert = compact({
      ...r.cert,
      name: r.cert!.name ?? c.name,
      commonName: r.cert!.commonName ?? c.commonName,
      sans: c.sans,
      notBefore: c.notBefore,
      notAfter: c.notAfter,
    });
  }
  return records;
}
