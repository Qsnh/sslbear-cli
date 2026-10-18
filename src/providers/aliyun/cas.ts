import { createPrivateKey, randomUUID } from "node:crypto";
import type { LocalCert } from "../../deploy/cert.js";
import { SAME_CERT_TOLERANCE_MS } from "../../deploy/plan.js";
import type { AliyunCredentials } from "../../lib/env.js";
import { CloudApiError, withRetry, type QueryContext } from "../../lib/http.js";
import { compact } from "../../lib/compact.js";
import { memo, paginate } from "../../lib/paginate.js";
import { toIso } from "../../lib/time.js";
import type { CertificateRecord } from "../../types.js";
import { callRpc, callRpcOnce } from "./client.js";
import { percentEncode } from "./sign.js";

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
  /** 证书 SHA-256 指纹，大写 hex */
  Sha2?: string;
  /** 证书序列号，小写 hex */
  SerialNo?: string;
}

const CAS = { endpoint: "cas.aliyuncs.com", version: "2020-04-07" };
const PAGE = 50;
/** UploadUserCertificate 的证书名最长 63 个字符 */
const NAME_MAX = 63;

/** 数字证书管理服务（中国站）所在地域：CDN、OSS、ESA 等按 ID 引用证书时都要带上 */
export const CAS_REGION = "cn-hangzhou";

/** 没有 CertEndTime 时退回只有日期的 EndDate：表示当天仍有效，按北京时间当天 23:59:59 计算，避免到期当天被判为已过期 */
const endOfDay = (date?: string) => (date && /^\d{4}-\d{2}-\d{2}$/.test(date) ? `${date} 23:59:59` : date);

const notAfterOf = (c: CertOrder) => toIso(c.CertEndTime) ?? toIso(endOfDay(c.EndDate));

function listOrders(ctx: QueryContext, creds: AliyunCredentials, status?: string): Promise<CertOrder[]> {
  return paginate(PAGE, async (page) => {
    const res = await callRpc<{ CertificateOrderList?: CertOrder[]; TotalCount?: number }>(ctx, creds, {
      ...CAS,
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
        notAfter: notAfterOf(c),
        status: c.Status ?? (c.Expired ? "EXPIRED" : "ISSUED"),
        source: c.Upload === undefined ? undefined : c.Upload ? "upload" : "issued",
      }),
    );
  }
  return out;
}

/** 上传时的证书名：sslbear-<CN，* 换成 _>-<到期日 YYYYMMDD>[-<后缀>]，超出 63 个字符时截断 CN 部分 */
function uploadName(cert: LocalCert, suffix?: string): string {
  const tail = `-${cert.notAfter.slice(0, 10).replace(/-/g, "")}${suffix ? `-${suffix}` : ""}`;
  const cn = (cert.commonName ?? cert.sans[0] ?? "cert").replace(/\*/g, "_");
  return `sslbear-${cn.slice(0, NAME_MAX - "sslbear-".length - tail.length)}${tail}`;
}

const hex = (s: string) => s.replace(/:/g, "").toLowerCase();
const serial = (s: string) => hex(s).replace(/^0+/, "");
const nameSet = (names: readonly string[]) => [...new Set(names.map((n) => n.trim().toLowerCase()).filter(Boolean))].sort().join(",");

/**
 * 证书服务里的这张是否就是要上传的证书：同 SHA-256 指纹；或同序列号且到期时间相同（序列号只在同一 CA 内唯一）；
 * 接口两者都没给时退而求其次，同 CN、同 SAN 且到期时间相差 48 小时内
 */
function sameCert(o: CertOrder, cert: LocalCert): boolean {
  if (o.Sha2 && hex(o.Sha2) === cert.fingerprint) return true;
  const end = Date.parse(notAfterOf(o) ?? "");
  if (!Number.isFinite(end) || Math.abs(end - Date.parse(cert.notAfter)) > SAME_CERT_TOLERANCE_MS) return false;
  if (o.SerialNo) return serial(o.SerialNo) === serial(cert.serialNumber);
  if (o.Sha2) return false;
  return (
    !!o.CommonName &&
    o.CommonName.toLowerCase() === cert.commonName?.toLowerCase() &&
    nameSet(o.Sans?.split(",") ?? []) === nameSet(cert.sans)
  );
}

/**
 * 阿里云要求传统格式的私钥：RSA 为 PKCS#1（BEGIN RSA PRIVATE KEY），ECC 为 SEC1（BEGIN EC PRIVATE KEY），
 * 文档明确 PKCS#8（BEGIN PRIVATE KEY，certbot 等默认输出）需先转换。转换失败（如 RSA-PSS 密钥）时原样上传
 */
function traditionalKey(keyPem: string): string {
  try {
    const key = createPrivateKey(keyPem);
    return key.export({ type: key.asymmetricKeyType === "ec" ? "sec1" : "pkcs1", format: "pem" }) as string;
  } catch {
    return keyPem;
  }
}

/** 云接口报错可能回显请求参数：转换格式后的私钥与用户提供的原文不同，编排层认不出来，这里先把它隐藏 */
function hideKey(e: unknown, keyPem: string): unknown {
  if (!(e instanceof CloudApiError)) return e;
  const lines = keyPem
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length >= 16 && !l.startsWith("-----"));
  let message = e.message.split(keyPem.trim()).join("[私钥已隐藏]");
  for (const l of lines) {
    for (const form of new Set([l, encodeURIComponent(l), percentEncode(l)])) message = message.split(form).join("[私钥已隐藏]");
  }
  e.message = message;
  return e;
}

/**
 * 上传证书到数字证书管理服务，已有同一张证书时复用。
 * 上传不幂等：遇到超时、限流等可重试错误时整体重来，先重新查重（上一次其实已成功时直接复用），
 * 再带同一个 ClientToken 上传，不会在证书服务里传出两份。
 */
export function uploadCasCertificate(ctx: QueryContext, creds: AliyunCredentials, cert: LocalCert): Promise<{ id: string; reused: boolean }> {
  const clientToken = randomUUID();
  const key = traditionalKey(cert.keyPem);
  return withRetry(ctx, async () => {
    // 不带 Status 只返回有效证书；要上传的证书在有效期内，同一张证书只会在这里
    const orders = await listOrders(ctx, creds);
    const same = orders.find((o) => sameCert(o, cert));
    if (same) return { id: String(same.CertificateId), reused: true };
    // 同一账号下证书名不能重复：同名的是另一张证书（如同域名同日到期、换了私钥）时加指纹后缀
    const taken = new Set(orders.map((o) => o.Name));
    const name = taken.has(uploadName(cert)) ? uploadName(cert, cert.fingerprint.slice(0, 8)) : uploadName(cert);
    const res = await callRpcOnce<{ CertId?: number | string }>(ctx, creds, {
      ...CAS,
      action: "UploadUserCertificate",
      method: "POST",
      params: { Name: name, Cert: cert.certPem, Key: key, ClientToken: clientToken },
    }).catch((e: unknown) => {
      throw hideKey(e, key);
    });
    if (res.CertId === undefined) throw new CloudApiError("aliyun", "InvalidResponse", "上传证书的响应里没有 CertId");
    return { id: String(res.CertId), reused: false };
  });
}

const cachedNames = memo<QueryContext, string>();

/** 证书 ID 对应的证书名（直播按证书名引用证书服务里的证书）；CertFilter=true 不返回证书与私钥内容 */
export function casCertName(ctx: QueryContext, creds: AliyunCredentials, id: string): Promise<string> {
  return cachedNames(ctx, id, async () => {
    const res = await callRpc<{ Name?: string }>(ctx, creds, {
      ...CAS,
      action: "GetUserCertificateDetail",
      params: { CertId: id, CertFilter: "true" },
    });
    if (!res.Name) throw new CloudApiError("aliyun", "InvalidResponse", `数字证书管理服务里的证书 ${id} 没有名称`);
    return res.Name;
  });
}
