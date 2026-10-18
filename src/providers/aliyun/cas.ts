import { X509Certificate, createHash, createPrivateKey, randomUUID } from "node:crypto";
import type { LocalCert } from "../../deploy/cert.js";
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
  /** 实测为签发者的组织名（如 Let's Encrypt） */
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
  /** 文档称「证书 Sha2 值」，实测是证书公钥（SubjectPublicKeyInfo DER）的 SHA-256，大写 hex，不是证书指纹：同一私钥续签的证书相同 */
  Sha2?: string;
  /** 实测是叶子证书 DER 的 SHA-1，大写 hex，能唯一确定一张证书 */
  Fingerprint?: string;
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

/** 上传时的证书名：sslbear-<CN（没有 CN 时取第一个 SAN），* 换成 _>-<到期日 YYYYMMDD>[-<后缀>]，超出 63 个字符时截断 CN 部分 */
function uploadName(cert: LocalCert, suffix?: string): string {
  const tail = `-${cert.notAfter.slice(0, 10).replace(/-/g, "")}${suffix ? `-${suffix}` : ""}`;
  const cn = (cert.commonName ?? cert.sans[0] ?? "cert").replace(/\*/g, "_");
  return `sslbear-${cn.slice(0, NAME_MAX - "sslbear-".length - tail.length)}${tail}`;
}

const hex = (s: string) => s.replace(/:/g, "").toLowerCase();
const serial = (s: string) => hex(s).replace(/^0+/, "");

/** 叶子证书签发者 DN 里的 CN 与 O（小写）：证书服务的 Issuer 是组织名，本地证书的 issuer 只有 CN */
function issuerNames(cert: LocalCert): string[] {
  try {
    return new X509Certificate(cert.certPem).issuer
      .split("\n")
      .map((l) => /^(?:CN|O)=(.+)$/.exec(l.trim())?.[1]?.trim().toLowerCase())
      .filter((v): v is string => !!v);
  } catch {
    return [];
  }
}

/** 精确的时间戳（毫秒）与本地证书的时间一致；只有日期的 StartDate / EndDate 无法确认，不算一致 */
const sameTime = (ms: number | undefined, iso: string) => ms !== undefined && toIso(ms) === iso;

/** 本地叶子证书的 SHA-1 指纹与公钥 SHA-256（小写 hex），对应证书服务列表的 Fingerprint 与 Sha2 */
function localHashes(cert: LocalCert): { sha1?: string; spki?: string } {
  try {
    const x = new X509Certificate(cert.certPem);
    return {
      sha1: hex(x.fingerprint),
      spki: createHash("sha256").update(x.publicKey.export({ type: "spki", format: "der" })).digest("hex"),
    };
  } catch {
    return {};
  }
}

/**
 * 证书服务里的这张是否就是要上传的证书，只认能确定的：给了 Fingerprint（证书 SHA-1）就只看它；
 * 否则要求同序列号（只在同一 CA 内唯一），再加上同公钥（Sha2），没给 Sha2 时同签发者且起止时间一致。
 * 都确认不了时按不是同一张处理，宁可多传一份：同 CN、同 SAN、同到期的 RSA / ECC 两张证书不能互相复用，
 * 同一私钥续签的证书 Sha2 相同也不能复用
 */
function sameCert(o: CertOrder, cert: LocalCert, local: { sha1?: string; spki?: string }): boolean {
  if (o.Fingerprint && local.sha1) return hex(o.Fingerprint) === local.sha1;
  if (!o.SerialNo || serial(o.SerialNo) !== serial(cert.serialNumber)) return false;
  if (o.Sha2 && local.spki) return hex(o.Sha2) === local.spki;
  const issuer = o.Issuer?.trim().toLowerCase();
  return (
    !!issuer &&
    issuerNames(cert).includes(issuer) &&
    sameTime(o.CertStartTime, cert.notBefore) &&
    sameTime(o.CertEndTime, cert.notAfter)
  );
}

/** 证书名不能与账号下已有的重复：依次尝试不带后缀、带指纹前 8 位、再加序号 */
function freeName(cert: LocalCert, taken: Set<string | undefined>): string {
  const fp = cert.fingerprint.slice(0, 8);
  for (let i = 0; ; i++) {
    const name = uploadName(cert, i === 0 ? undefined : i === 1 ? fp : `${fp}-${i}`);
    if (!taken.has(name)) return name;
  }
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
  const local = localHashes(cert);
  return withRetry(ctx, async () => {
    // 不带 Status 只返回有效证书；要上传的证书在有效期内，同一张证书只会在这里
    const orders = await listOrders(ctx, creds);
    const same = orders.find((o) => sameCert(o, cert, local));
    if (same) return { id: String(same.CertificateId), reused: true };
    // 同一账号下证书名不能重复：同名的是另一张证书（如同域名同日到期、换了私钥）时加后缀
    const name = freeName(cert, new Set(orders.map((o) => o.Name)));
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
