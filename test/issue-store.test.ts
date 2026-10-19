import { mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { loadLocalCert, type LocalCert } from "../src/deploy/cert.js";
import { assertWritable, canReuse, isStagingIssuer, loadAccountKey, readExisting, stateRoot, writeCertFiles } from "../src/issue/store.js";
import { LETSENCRYPT_DIRECTORY, LETSENCRYPT_STAGING_DIRECTORY } from "../src/issue/types.js";
import { UsageError } from "../src/query.js";

const FIX = fileURLToPath(new URL("./fixtures/deploy/", import.meta.url));
const read = (f: string) => readFileSync(join(FIX, f), "utf8");
const NOW = new Date("2026-10-15T00:00:00Z");
const tmp = () => mkdtempSync(join(tmpdir(), "sslbear-issue-"));
const mode = (p: string) => statSync(p).mode & 0o777;
const RSA = () => loadLocalCert(read("rsa-fullchain.pem"), read("rsa-key.pem"), NOW);

describe("状态目录与账号私钥", () => {
  it("状态目录：SSLBEAR_CLI_HOME（相对路径按 cwd）优先，否则 <主目录>/.sslbear-cli", () => {
    expect(stateRoot({}, "/home/u", "/work")).toBe("/home/u/.sslbear-cli");
    expect(stateRoot({ SSLBEAR_CLI_HOME: "/var/sslbear" }, "/home/u", "/work")).toBe("/var/sslbear");
    expect(stateRoot({ SSLBEAR_CLI_HOME: "state" }, "/home/u", "/work")).toBe("/work/state");
    expect(stateRoot({ SSLBEAR_CLI_HOME: "  " }, "/home/u", "/work")).toBe("/home/u/.sslbear-cli");
  });

  it("每个 CA 一把 ECDSA P-256 账号私钥：首次生成（600，目录 700），之后复用同一把", () => {
    const root = join(tmp(), ".sslbear-cli");
    const first = loadAccountKey(root, LETSENCRYPT_DIRECTORY);
    expect(first.created).toBe(true);
    expect(first.path).toBe(join(root, "acme", "acme-v02.api.letsencrypt.org", "account.pem"));
    expect(first.key.asymmetricKeyType).toBe("ec");
    expect(first.key.asymmetricKeyDetails?.namedCurve).toBe("prime256v1");
    expect(mode(first.path)).toBe(0o600);
    expect(mode(join(root, "acme", "acme-v02.api.letsencrypt.org"))).toBe(0o700);
    expect(mode(root)).toBe(0o700);
    // 只有 account.pem，没有残留的临时文件
    expect(readdirSync(join(root, "acme", "acme-v02.api.letsencrypt.org"))).toEqual(["account.pem"]);

    const again = loadAccountKey(root, LETSENCRYPT_DIRECTORY);
    expect(again.created).toBe(false);
    expect(again.key.export({ type: "pkcs8", format: "der" })).toEqual(first.key.export({ type: "pkcs8", format: "der" }));

    const staging = loadAccountKey(root, LETSENCRYPT_STAGING_DIRECTORY);
    expect(staging.created).toBe(true);
    expect(staging.path).toContain("acme-staging-v02.api.letsencrypt.org");
  });

  it("账号私钥文件损坏：参数错误，提示删除后重新注册，不带文件内容", () => {
    const root = tmp();
    const dir = join(root, "acme", "acme-v02.api.letsencrypt.org");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "account.pem"), "-----BEGIN PRIVATE KEY-----\nc2VjcmV0LWdhcmJhZ2U=\n-----END PRIVATE KEY-----\n");
    expect(() => loadAccountKey(root, LETSENCRYPT_DIRECTORY)).toThrow(UsageError);
    expect(() => loadAccountKey(root, LETSENCRYPT_DIRECTORY)).toThrow(/删除该文件后重新运行/);
    expect(() => loadAccountKey(root, LETSENCRYPT_DIRECTORY)).not.toThrow(/c2VjcmV0/);
  });
});

describe("读现有证书", () => {
  it("没有文件：什么都没有", () => {
    expect(readExisting(join(tmp(), "nope"), NOW)).toEqual({});
  });

  it("合格的证书：valid + 叶子（叶子在前）", () => {
    const dir = tmp();
    writeFileSync(join(dir, "fullchain.pem"), read("rsa-fullchain.pem"));
    writeFileSync(join(dir, "privkey.pem"), read("rsa-key.pem"));
    const e = readExisting(dir, NOW);
    expect(e.valid).toMatchObject({ commonName: "example.com", algorithm: "RSA" });
    expect(e.leaf).toMatchObject({ sans: ["example.com", "*.example.com"], staging: false });
    expect(e.leaf!.pem).toMatch(/^-----BEGIN CERTIFICATE-----/);
    expect(e.valid!.certPem.startsWith(e.leaf!.pem)).toBe(true);
  });

  it("过期 / 私钥缺失 / 私钥不匹配：不能复用，但叶子证书仍可用来算 ARI 标识", () => {
    const dir = tmp();
    writeFileSync(join(dir, "fullchain.pem"), read("rsa-fullchain.pem"));
    expect(readExisting(dir, NOW).valid).toBeUndefined();
    expect(readExisting(dir, NOW).leaf?.sans).toEqual(["example.com", "*.example.com"]);

    writeFileSync(join(dir, "privkey.pem"), read("other-key.pem"));
    expect(readExisting(dir, NOW)).toEqual({ leaf: expect.objectContaining({ staging: false }) });

    writeFileSync(join(dir, "privkey.pem"), read("rsa-key.pem"));
    const expired = readExisting(dir, new Date("2027-02-01T00:00:00Z"));
    expect(expired.valid).toBeUndefined();
    expect(expired.leaf?.pem).toBe(readExisting(dir, NOW).leaf?.pem);
  });

  it("证书文件不是 PEM：当作没有", () => {
    const dir = tmp();
    writeFileSync(join(dir, "fullchain.pem"), "garbage");
    expect(readExisting(dir, NOW)).toEqual({});
  });
});

describe("复用判断", () => {
  const want = { domains: ["*.example.com", "example.com"], keyType: "rsa" as const, staging: false, now: NOW };

  it("同一组域名（不计顺序）、同算法、同环境、距到期超过 30 天才复用", () => {
    const cert = RSA();
    expect(canReuse(cert, want)).toBe(true);
    expect(canReuse(cert, { ...want, domains: ["example.com"] })).toBe(false);
    expect(canReuse(cert, { ...want, domains: ["example.com", "*.example.com", "www.example.com"] })).toBe(false);
    expect(canReuse(cert, { ...want, keyType: "ecc" })).toBe(false);
    expect(canReuse(loadLocalCert(read("ecc-fullchain.pem"), read("ecc-key.pem"), NOW), { ...want, keyType: "ecc" })).toBe(true);
  });

  it("距到期正好 30 天不复用，多一点才复用", () => {
    const cert = RSA(); // 2027-01-01 到期
    expect(canReuse(cert, { ...want, now: new Date("2026-12-02T00:00:00Z") })).toBe(false);
    expect(canReuse(cert, { ...want, now: new Date("2026-12-01T23:59:59Z") })).toBe(true);
  });

  it("测试环境（签发者 CN 含 STAGING）与正式环境互不复用", () => {
    const staging: LocalCert = { ...RSA(), issuer: "(STAGING) Pseudo Plastic P12" };
    expect(isStagingIssuer("(STAGING) Counterfeit Cashew R10")).toBe(true);
    expect(isStagingIssuer("R12")).toBe(false);
    expect(isStagingIssuer(undefined)).toBe(false);
    expect(canReuse(staging, want)).toBe(false);
    expect(canReuse(staging, { ...want, staging: true })).toBe(true);
    expect(canReuse(RSA(), { ...want, staging: true })).toBe(false);
  });
});

describe("写证书文件", () => {
  it("目录 700，privkey 600、fullchain 644，内容为校验后的证书与私钥，不留临时文件", () => {
    const dir = join(tmp(), "certs", "example.com_rsa");
    const cert = RSA();
    const files = writeCertFiles(dir, cert);
    expect(files).toEqual({ cert: join(dir, "fullchain.pem"), key: join(dir, "privkey.pem") });
    expect(mode(dir)).toBe(0o700);
    expect(mode(join(dir, ".."))).toBe(0o700);
    expect(mode(files.key)).toBe(0o600);
    expect(mode(files.cert)).toBe(0o644);
    expect(readFileSync(files.cert, "utf8")).toBe(cert.certPem);
    expect(readFileSync(files.key, "utf8")).toBe(cert.keyPem);
    expect(readdirSync(dir).sort()).toEqual(["fullchain.pem", "privkey.pem"]);
  });

  it("覆盖已有文件时权限也重设；已存在的目录不改权限", () => {
    const dir = tmp();
    chmodSync(dir, 0o755);
    writeFileSync(join(dir, "privkey.pem"), "old", { mode: 0o644 });
    writeCertFiles(dir, RSA());
    expect(mode(join(dir, "privkey.pem"))).toBe(0o600);
    expect(mode(dir)).toBe(0o755);
  });

  it("签发前检查保存目录可写：不存在时查最近的上级；不可写 / 是文件时参数错误", () => {
    const base = tmp();
    expect(() => assertWritable(join(base, "a", "b"))).not.toThrow();
    writeFileSync(join(base, "file"), "x");
    expect(() => assertWritable(join(base, "file", "sub"))).toThrow(/不是目录/);
    const ro = join(base, "ro");
    mkdirSync(ro, { mode: 0o500 });
    expect(() => assertWritable(join(ro, "certs"))).toThrow(/不可写/);
    mkdirSync(join(base, "c", "privkey.pem"), { recursive: true });
    expect(() => assertWritable(join(base, "c"))).toThrow(/是目录/);
  });
});
