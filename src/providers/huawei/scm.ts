import type { AccessKeyCredentials } from "../../lib/env.js";
import type { QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { memo, paginate } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { CertificateRecord, DomainRecord } from "../../types.js";
import type { Warn } from "../registry.js";
import { callHuawei } from "./client.js";

/** 云证书管理服务 CCM（原 SCM）的 SSL 证书接口是全局服务，中国站统一走北京四 */
const SCM_HOST = "scm.cn-north-4.myhuaweicloud.com";
/** limit 只能取 10 / 20 / 50 */
const PAGE = 50;

interface ScmCertificate {
  id: string;
  name?: string;
  domain?: string;
  /** 附加域名，分号分隔，如 "a.example.com;b.example.com" */
  sans?: string;
  type?: string;
  brand?: string;
  /** "2021-05-27 16:46:25.0"，不带时区 */
  expire_time?: string;
  /** ISSUED / EXPIRED / UPLOAD（上传托管的证书）等 */
  status?: string;
}

// 文档未注明时区，与控制台展示一致按北京时间处理；toIso 不认小数秒，先去掉
const scmTime = (s: string | undefined) => toIso(s?.replace(/\.\d+$/, ""));

async function fetchAll(ctx: QueryContext, creds: AccessKeyCredentials): Promise<CertificateRecord[]> {
  const list = await paginate(PAGE, async (_page, offset) => {
    const res = await callHuawei<{ certificates?: ScmCertificate[] | null; total_count?: number }>(ctx, creds, {
      host: SCM_HOST,
      path: "/v3/scm/certificates",
      // offset 为条目偏移（同服务 ListCertificatesByTag 文档写明「从 offset 指定的下一条数据开始」）；
      // expired_days_since 按文档是「有效期内及最多过期 xx 天」、缺省 0，取最大值 1095，让已过期但仍绑定着的证书也能列出和补全
      query: { limit: PAGE, offset, expired_days_since: 1095 },
    });
    return { items: res.certificates ?? [], total: res.total_count };
  });
  return list.map((c) =>
    compact({
      provider: "huawei" as const,
      id: c.id,
      name: c.name,
      commonName: c.domain,
      sans: (c.sans ?? "").split(/[;,]/).map((s) => s.trim()).filter(Boolean),
      issuer: c.brand,
      notAfter: scmTime(c.expire_time),
      status: c.status,
      source: c.status === "UPLOAD" ? "upload" : c.type,
    }),
  );
}

const cached = memo<QueryContext, CertificateRecord[]>();

/** SSL 证书列表，同一次命令内（certs 与各服务补全）只拉一次 */
export function listScmCertificates(ctx: QueryContext, creds: AccessKeyCredentials): Promise<CertificateRecord[]> {
  return cached(ctx, `scm:${creds.accessKeyId}`, () => fetchAll(ctx, creds));
}

/**
 * 域名接口只给了证书 ID、缺到期时间时，用 SSL 证书列表按 ID 补全。
 * 补全失败（如没有 SCM 只读权限）只记一条 issue，域名本身照常返回。
 */
export async function enrichFromScm(
  ctx: QueryContext,
  creds: AccessKeyCredentials,
  warn: Warn,
  records: DomainRecord[],
): Promise<DomainRecord[]> {
  const pending = records.filter((r) => r.cert?.id && !r.cert.notAfter);
  if (pending.length === 0) return records;
  let certs: CertificateRecord[];
  try {
    certs = await listScmCertificates(ctx, creds);
  } catch (e) {
    warn(e, "SSL 证书列表（用于补全到期时间）");
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
      sans: r.cert!.sans ?? c.sans,
      issuer: r.cert!.issuer ?? c.issuer,
      notAfter: c.notAfter,
      status: r.cert!.status ?? c.status,
    });
  }
  return records;
}
