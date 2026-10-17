import type { AliyunCredentials } from "../../lib/env.js";
import type { QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { paginate } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { CertificateRecord } from "../../types.js";
import { callRpc } from "./client.js";

interface CertOrder {
  CertificateId: number | string;
  Name?: string;
  CommonName?: string;
  /** 逗号分隔 */
  Sans?: string;
  Issuer?: string;
  /** YYYY-MM-DD，只有日期；实测为证书有效期的 UTC 日期 */
  StartDate?: string;
  EndDate?: string;
  /** 毫秒时间戳。文档称仅 CPACK / BUY 返回，实测 CERT / UPLOAD 也返回，有则优先使用 */
  CertStartTime?: number;
  CertEndTime?: number;
  Expired?: boolean;
  Upload?: boolean;
  Status?: string;
}

const PAGE = 50;

/** 没有 CertEndTime 时退回只有日期的 EndDate：表示当天仍有效，按北京时间当天 23:59:59 计算，避免到期当天被判为已过期 */
const endOfDay = (date?: string) => (date && /^\d{4}-\d{2}-\d{2}$/.test(date) ? `${date} 23:59:59` : date);

function listOrders(ctx: QueryContext, creds: AliyunCredentials, status?: string): Promise<CertOrder[]> {
  return paginate(PAGE, async (page) => {
    const res = await callRpc<{ CertificateOrderList?: CertOrder[]; TotalCount?: number }>(ctx, creds, {
      endpoint: "cas.aliyuncs.com",
      version: "2020-04-07",
      action: "ListUserCertificateOrder",
      params: { OrderType: "CERT", Status: status, CurrentPage: page, ShowSize: PAGE },
    });
    return { items: res.CertificateOrderList ?? [], total: res.TotalCount };
  });
}

/**
 * 数字证书管理服务（原 SSL 证书）中已签发和上传的证书。
 * OrderType=CERT 不带 Status 只返回有效证书，已过期的需再按 Status=EXPIRED 查一次。
 */
export async function listCasCertificates(ctx: QueryContext, creds: AliyunCredentials): Promise<CertificateRecord[]> {
  const [valid, expired] = await Promise.all([listOrders(ctx, creds), listOrders(ctx, creds, "EXPIRED")]);
  const seen = new Set<string>();
  const out: CertificateRecord[] = [];
  for (const c of [...valid, ...expired]) {
    const id = String(c.CertificateId);
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(
      compact({
        provider: "aliyun" as const,
        id,
        name: c.Name,
        commonName: c.CommonName,
        sans: c.Sans?.split(",").map((s) => s.trim()).filter(Boolean),
        issuer: c.Issuer,
        notBefore: toIso(c.CertStartTime) ?? toIso(c.StartDate),
        notAfter: toIso(c.CertEndTime) ?? toIso(endOfDay(c.EndDate)),
        status: c.Status ?? (c.Expired ? "EXPIRED" : "ISSUED"),
        source: c.Upload === undefined ? undefined : c.Upload ? "upload" : "issued",
      }),
    );
  }
  return out;
}
