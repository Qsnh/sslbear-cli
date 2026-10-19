import { X509Certificate, createPrivateKey, randomBytes, type KeyObject } from "node:crypto";
import { accessSync, chmodSync, constants, existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { loadLocalCert, normalizeDomain, type LocalCert } from "../deploy/cert.js";
import type { Env } from "../lib/env.js";
import { UsageError } from "../query.js";
import { generateAccountKey } from "./csr.js";
import type { KeyType } from "./types.js";

export const CERT_FILE = "fullchain.pem";
export const KEY_FILE = "privkey.pem";

const DAY_MS = 86_400_000;
/** 剩余超过 30 天才复用：与 deploy「30 天内到期才自动替换」的口径一致，复用的证书部署时不会被当成快到期 */
const REUSE_MIN_DAYS = 30;

/** 状态目录根：SSLBEAR_CLI_HOME（CI / 测试用，相对路径按当前目录解析）或 <主目录>/.sslbear-cli */
export function stateRoot(env: Env, home: string, cwd: string): string {
  const custom = env.SSLBEAR_CLI_HOME?.trim();
  return custom ? resolve(cwd, custom) : join(home, ".sslbear-cli");
}

/** 先写同目录的临时文件再改名：中途失败不会留下写了一半的私钥 / 证书；权限在改名前设好 */
function writeAtomic(path: string, data: string, mode: number): void {
  const tmp = `${path}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  try {
    // 创建时就带上权限，私钥从落盘起就不会被其他用户读到；再 chmod 一次，不受 umask 影响
    writeFileSync(tmp, data, { mode, flag: "wx" });
    chmodSync(tmp, mode);
    renameSync(tmp, path);
  } catch (e) {
    rmSync(tmp, { force: true });
    throw e;
  }
}

/** 新建的目录一律 700；已存在的目录（如 --out 指向的现有目录）不改权限，免得影响其他程序读取 */
function ensureDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
}

/**
 * ACME 账号私钥（每个 CA 一把，ECDSA P-256）：<根>/acme/<CA 主机名>/account.pem。
 * 没有就生成并以 600 写入；created 表示这是第一次运行（会注册账号，即同意 CA 的订阅协议）
 */
export function loadAccountKey(root: string, directoryUrl: string): { key: KeyObject; created: boolean; path: string } {
  const path = join(root, "acme", new URL(directoryUrl).host, "account.pem");
  if (existsSync(path)) {
    try {
      return { key: createPrivateKey(readFileSync(path, "utf8")), created: false, path };
    } catch {
      // 不带原始错误：openssl 的错误信息可能夹带私钥片段
      throw new UsageError(`ACME 账号私钥文件无法解析：${path}（删除该文件后重新运行会注册新账号）`);
    }
  }
  const key = generateAccountKey();
  ensureDir(dirname(path));
  writeAtomic(path, key.export({ type: "pkcs8", format: "pem" }) as string, 0o600);
  return { key, created: true, path };
}

/** 保存目录里现有的证书 */
export interface ExistingCert {
  /** 能通过 loadLocalCert 校验（链齐全、私钥匹配、在有效期内）时才有：复用判断只认它 */
  valid?: LocalCert;
  /** fullchain.pem 的叶子证书，过期、私钥不匹配也保留：续签时算 ARI 标识（replaces）用 */
  leaf?: { pem: string; sans: string[]; staging: boolean };
}

const PEM_CERT = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;

/** Let's Encrypt 测试环境的中间证书 CN 都带 (STAGING)，如「(STAGING) Pseudo Plastic P12」 */
export function isStagingIssuer(issuerCn: string | undefined): boolean {
  return /STAGING/i.test(issuerCn ?? "");
}

function issuerCn(cert: X509Certificate): string | undefined {
  return (cert.issuer ?? "")
    .split("\n")
    .map((l) => /^CN=(.*)$/.exec(l.trim())?.[1])
    .find((v) => v !== undefined);
}

/** 校验不通过时退而读第一张证书：我们写的 fullchain 叶子在前 */
function readLeaf(certText: string): ExistingCert["leaf"] {
  const pem = PEM_CERT.exec(certText)?.[0];
  if (!pem) return undefined;
  try {
    const cert = new X509Certificate(pem);
    const sans = (cert.subjectAltName ?? "")
      .split(/,\s*/)
      .filter((s) => s.startsWith("DNS:"))
      .map((s) => normalizeDomain(s.slice(4)));
    return { pem, sans, staging: isStagingIssuer(issuerCn(cert)) };
  } catch {
    return undefined;
  }
}

/** 读保存目录里的 fullchain.pem + privkey.pem；文件缺失、读不了、不合格都当作没有可复用的证书 */
export function readExisting(dir: string, now: Date): ExistingCert {
  let certText: string;
  try {
    certText = readFileSync(join(dir, CERT_FILE), "utf8");
  } catch {
    return {};
  }
  let valid: LocalCert | undefined;
  try {
    valid = loadLocalCert(certText, readFileSync(join(dir, KEY_FILE), "utf8"), now);
  } catch {
    // 私钥缺失、不匹配、证书过期等：不能复用，但叶子证书仍可用来续签
  }
  const leaf = valid
    ? { pem: PEM_CERT.exec(valid.certPem)![0], sans: valid.sans, staging: isStagingIssuer(valid.issuer) }
    : readLeaf(certText);
  return { ...(valid && { valid }), ...(leaf && { leaf }) };
}

const sameSet = (a: readonly string[], b: readonly string[]) => {
  const sa = new Set(a);
  const sb = new Set(b);
  return sa.size === sb.size && [...sa].every((x) => sb.has(x));
};

/** 现有证书能否直接复用：同一组域名（不计顺序）、同算法、同为正式 / 测试环境，且距到期超过 30 天 */
export function canReuse(cert: LocalCert, want: { domains: readonly string[]; keyType: KeyType; staging: boolean; now: Date }): boolean {
  return (
    sameSet(cert.sans, want.domains) &&
    cert.algorithm === (want.keyType === "rsa" ? "RSA" : "ECC") &&
    isStagingIssuer(cert.issuer) === want.staging &&
    Date.parse(cert.notAfter) - want.now.getTime() > REUSE_MIN_DAYS * DAY_MS
  );
}

/**
 * 签发前确认保存目录可写（只读检查，不创建目录）：签完才发现写不进去，这张证书就白签了、还占配额。
 * 目录不存在时检查最近一级已存在的上级目录
 */
export function assertWritable(dir: string): void {
  let p = dir;
  while (!existsSync(p) && dirname(p) !== p) p = dirname(p);
  if (!statSync(p).isDirectory()) throw new UsageError(`证书保存位置不可用：${p} 不是目录`);
  try {
    accessSync(p, constants.W_OK);
  } catch {
    throw new UsageError(`证书保存目录不可写：${p}（可用 --out 指定其他目录）`);
  }
  for (const name of [CERT_FILE, KEY_FILE]) {
    const f = join(dir, name);
    if (existsSync(f) && statSync(f).isDirectory()) throw new UsageError(`证书保存位置不可用：${f} 是目录`);
  }
}

/** 写证书文件：目录 700（新建时），privkey.pem 600、fullchain.pem 644；先写私钥，中途失败时下次校验不匹配会重签 */
export function writeCertFiles(dir: string, cert: LocalCert): { cert: string; key: string } {
  ensureDir(dir);
  const files = { cert: join(dir, CERT_FILE), key: join(dir, KEY_FILE) };
  writeAtomic(files.key, cert.keyPem, 0o600);
  writeAtomic(files.cert, cert.certPem, 0o644);
  return files;
}
