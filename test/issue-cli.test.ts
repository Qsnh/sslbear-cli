import { createPrivateKey } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { DnsZone, TxtRecord } from "../src/dns/types.js";
import { ariCertId, buildCsr } from "../src/issue/csr.js";
import { RETRY_SETTLE_MS } from "../src/issue/run.js";
import { AcmeError, LETSENCRYPT_DIRECTORY, LETSENCRYPT_STAGING_DIRECTORY } from "../src/issue/types.js";
import { CloudApiError } from "../src/lib/http.js";
import type { DnsVendor } from "../src/types.js";
import { ALIYUN_ENV, runCli, TENCENT_ENV, type CliResult, type RunCliOptions } from "./helpers.js";
import { CLOUDFLARE_ENV, fakeAcme, fakeDnsDefs, fakeLookup, fakeWorld, type FakeAcmeOptions } from "./issue-fakes.js";

// CSR / ARI 归 ACME 那一路实现：这里只替换这两个函数，生成私钥等照常用真实现
vi.mock("../src/issue/csr.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/issue/csr.js")>()),
  buildCsr: vi.fn(() => Buffer.from("fake-csr")),
  ariCertId: vi.fn(() => "fake-ari-id"),
}));

const FIX = fileURLToPath(new URL("./fixtures/deploy/", import.meta.url));
const read = (f: string) => readFileSync(join(FIX, f), "utf8");
/** 证书有效期 2026-01-01 ~ 2027-01-01：此时剩 78 天，可复用 */
const NOW = "2026-10-15T00:00:00Z";
const DOMAINS = "example.com,*.example.com";
const FQDN = "_acme-challenge.example.com";
const mode = (p: string) => statSync(p).mode & 0o777;
const tmp = () => mkdtempSync(join(tmpdir(), "sslbear-issue-"));

/** 证书私钥正文（不含 BEGIN / END 行）：任何输出里都不能出现 */
const KEY_LINES = (["rsa-key.pem", "ecc-key.pem"] as const).flatMap((f) =>
  read(f)
    .split("\n")
    .filter((l) => l && !l.startsWith("-----")),
);

function expectNoKey(r: CliResult): void {
  for (const line of KEY_LINES) {
    expect(r.stdout).not.toContain(line);
    expect(r.stderr).not.toContain(line);
  }
}

interface SetupOptions {
  zones?: Partial<Record<DnsVendor, DnsZone[]>>;
  ns?: Record<string, string[]>;
  overrides?: Parameters<typeof fakeDnsDefs>[2];
  acme?: Partial<FakeAcmeOptions>;
  env?: Record<string, string>;
  ecc?: boolean;
}

/** 假的阿里云云解析托管 example.com，权威 DNS 立即可见；假 CA 返回 fixtures 里的证书链；home 为临时目录 */
function setup(o: SetupOptions = {}) {
  const home = tmp();
  const world = fakeWorld(o.ns ?? { "example.com": ["dns1.hichina.com", "dns2.hichina.com"] });
  const dnsDefs = fakeDnsDefs(o.zones ?? { aliyun: [{ name: "example.com", id: "example.com" }] }, world, o.overrides);
  const dnsLookup = fakeLookup(world);
  const ca = fakeAcme(world, { certPem: read(o.ecc ? "ecc-fullchain.pem" : "rsa-fullchain.pem"), ...o.acme });
  const key = createPrivateKey(read(o.ecc ? "ecc-key.pem" : "rsa-key.pem"));
  const generateKey = vi.fn(() => key);
  const root = join(home, ".sslbear-cli");
  const issue = (argv: string[], extra: RunCliOptions = {}) =>
    runCli(["issue", ...argv], { env: o.env ?? ALIYUN_ENV, now: NOW, cwd: home, home, dnsDefs, dnsLookup, acme: ca.factory, generateKey, ...extra });
  return { home, root, world, dnsDefs, dnsLookup, ca, generateKey, issue, certDir: join(root, "certs", o.ecc ? "example.com_ecc" : "example.com_rsa") };
}

const errOf = (r: CliResult) => JSON.parse(r.stderr);
/** waitAuthorization 在授权变成 invalid 时抛的错误 */
const invalidAuthz = (type: string, detail: string) => Object.assign(new AcmeError(type, detail, 403), { invalidAuthorization: true });
const visibleTxt = (world: ReturnType<typeof fakeWorld>) => [...world.txt.values()].flat();

beforeEach(() => {
  vi.mocked(buildCsr).mockClear();
  vi.mocked(ariCertId).mockClear();
});

describe("issue 签发成功", () => {
  it("输出契约：stdout 一行 {ok:true,data}，文件为绝对路径，dns 每个域名一项且已清理；--json 时 stderr 为空", async () => {
    const s = setup();
    const r = await s.issue(["-d", DOMAINS, "--json"]);
    expect(r.code).toBe(0);
    expect(r.stderr).toBe("");
    expect(r.stdout.trim().split("\n")).toHaveLength(1);
    const d = r.json.data;
    expect(Object.keys(d)).toEqual(["reused", "staging", "files", "cert", "dns", "issues"]);
    expect(d).toMatchObject({ reused: false, staging: false, issues: [] });
    expect(d.files).toEqual({ cert: join(s.certDir, "fullchain.pem"), key: join(s.certDir, "privkey.pem") });
    expect(d.cert).toEqual({
      commonName: "example.com",
      sans: ["example.com", "*.example.com"],
      notBefore: "2026-01-01T00:00:00.000Z",
      notAfter: "2027-01-01T00:00:00.000Z",
      algorithm: "RSA",
      fingerprint: expect.stringMatching(/^[0-9a-f]{64}$/),
      issuer: "sslbear test CA",
    });
    expect(d.dns).toEqual([
      { domain: "example.com", provider: "aliyun", zone: "example.com", record: FQDN, cleaned: true },
      { domain: "*.example.com", provider: "aliyun", zone: "example.com", record: FQDN, cleaned: true },
    ]);
    // 文件：内容为 CA 给的链与注入的私钥，权限 700 / 600 / 644
    expect(readFileSync(d.files.cert, "utf8")).toContain("-----BEGIN CERTIFICATE-----");
    expect(createPrivateKey(readFileSync(d.files.key, "utf8")).export({ type: "pkcs8", format: "der" })).toEqual(
      s.generateKey.mock.results[0]!.value.export({ type: "pkcs8", format: "der" }),
    );
    expect(mode(s.certDir)).toBe(0o700);
    expect(mode(d.files.key)).toBe(0o600);
    expect(mode(d.files.cert)).toBe(0o644);
    expect(mode(join(s.root, "acme", "acme-v02.api.letsencrypt.org", "account.pem"))).toBe(0o600);
    expectNoKey(r);
  });

  it("流程：classic 配置文件下单 → 串行加两个同名 TXT 值 → 生效后通知验证 → 先清理再 finalize", async () => {
    const s = setup();
    await s.issue(["-d", DOMAINS, "--json"]);
    expect(s.ca.factory).toHaveBeenCalledWith(expect.anything(), { directoryUrl: LETSENCRYPT_DIRECTORY, accountKey: expect.anything() });
    expect(s.ca.client.ensureAccount).toHaveBeenCalledWith(undefined);
    // 第一次签发：保存目录里没有旧证书，不带 replaces
    expect(s.ca.client.newOrder).toHaveBeenCalledWith(["example.com", "*.example.com"], { profile: "classic" });
    expect(s.world.log).toEqual([
      "account",
      "order example.com,*.example.com",
      `add aliyun ${FQDN} v-tok-example.com`,
      `add aliyun ${FQDN} v-tok-*.example.com`,
      "answer example.com",
      "answer *.example.com",
      "wait example.com",
      "wait *.example.com",
      `remove aliyun ${FQDN} v-tok-example.com h1`,
      `remove aliyun ${FQDN} v-tok-*.example.com h2`,
      "finalize",
      "download",
    ]);
    expect(s.world.maxConcurrentAdds).toBe(1);
    expect(visibleTxt(s.world)).toEqual([]);
    // 两个权威服务器都查过；CSR 用注入的私钥、全部域名
    expect(s.dnsLookup.queried).toEqual([`ip:dns1.hichina.com ${FQDN}`, `ip:dns2.hichina.com ${FQDN}`]);
    expect(buildCsr).toHaveBeenCalledWith(s.generateKey.mock.results[0]!.value, ["example.com", "*.example.com"]);
    expect(s.generateKey).toHaveBeenCalledWith("rsa");
    expect(s.ca.client.waitAuthorization).toHaveBeenCalledWith("https://ca.test/authz/example.com", 120_000);
    expect(s.ca.client.finalize).toHaveBeenCalledWith(expect.objectContaining({ url: "https://ca.test/order/1" }), Buffer.from("fake-csr"), 120_000);
  });

  it("表格模式：进度写 stderr，stdout 为结果与 deploy 提示", async () => {
    const s = setup();
    const r = await s.issue(["-d", DOMAINS]);
    expect(r.code).toBe(0);
    expect(r.stderr).toContain(`已在 阿里云云解析 添加 ${FQDN}`);
    expect(r.stderr).toContain("等待 DNS 生效");
    expect(r.stderr).toContain(`已从 阿里云云解析 删除 ${FQDN}`);
    expect(r.stderr).toContain("注册 Let's Encrypt 账号（即同意其订阅协议");
    expect(r.stdout).toContain("已签发证书：");
    expect(r.stdout).toContain("example.com, *.example.com（RSA，");
    expect(r.stdout).toContain(`证书文件：${join(s.certDir, "fullchain.pem")}`);
    expect(r.stdout).toContain(`deploy --cert ${join(s.certDir, "fullchain.pem")} --key ${join(s.certDir, "privkey.pem")}`);
    expect(r.stdout).not.toContain("警告");
    expectNoKey(r);
  });

  it("ECC：--key-type ecc 生成 P-256 私钥，保存在 _ecc 目录；--email 传给账号注册", async () => {
    const s = setup({ ecc: true });
    const r = await s.issue(["-d", DOMAINS, "--key-type", "ECC", "--email", "ops@example.org", "--json"]);
    expect(r.code).toBe(0);
    expect(s.generateKey).toHaveBeenCalledWith("ecc");
    expect(r.json.data.cert.algorithm).toBe("ECC");
    expect(r.json.data.files.cert).toBe(join(s.certDir, "fullchain.pem"));
    expect(s.ca.client.ensureAccount).toHaveBeenCalledWith("ops@example.org");
  });

  it("授权已是 valid 的域名跳过，不加记录、不列进 dns；全部 valid 时不改 DNS 也不等待", async () => {
    const s = setup({ acme: { valid: ["*.example.com"] } });
    const r = await s.issue(["-d", DOMAINS, "--json"]);
    expect(r.code).toBe(0);
    expect(r.json.data.dns.map((x: any) => x.domain)).toEqual(["example.com"]);
    expect(s.world.log.filter((l) => l.startsWith("add"))).toEqual([`add aliyun ${FQDN} v-tok-example.com`]);
    expect(s.ca.client.answerChallenge).toHaveBeenCalledTimes(1);

    const all = setup({ acme: { valid: ["example.com", "*.example.com"] } });
    const r2 = await all.issue(["-d", DOMAINS, "--json"]);
    expect(r2.code).toBe(0);
    expect(r2.json.data.dns).toEqual([]);
    expect(all.dnsDefs.aliyun.addTxt).not.toHaveBeenCalled();
    expect(all.dnsLookup.queryTxt).not.toHaveBeenCalled();
    expect(all.ca.client.answerChallenge).not.toHaveBeenCalled();
  });

  it("CA 目录没有 classic 配置文件时不指定 profile", async () => {
    const s = setup({ acme: { directory: { profiles: undefined } } });
    await s.issue(["-d", "example.com", "--json"]);
    expect(s.ca.client.newOrder).toHaveBeenCalledWith(["example.com"], {});
  });

  it("凭证不完整被跳过的服务商记进 issues（表格模式在 stderr 提示）", async () => {
    const s = setup({ env: { ...ALIYUN_ENV, AZURE_TENANT_ID: "tenant" } });
    const j = await s.issue(["-d", DOMAINS, "--json"]);
    expect(j.json.data.issues).toEqual([{ provider: "azure", kind: "error", code: "IncompleteCredentials", message: expect.stringContaining("AZURE_CLIENT_ID") }]);
    const t = await s.issue(["-d", DOMAINS, "--force"]);
    expect(t.stderr).toContain("提示：azure（Azure DNS）凭证不完整");
  });

  it("SSLBEAR_CLI_HOME 改状态目录；--out 相对当前目录", async () => {
    const s = setup();
    const state = join(s.home, "state");
    const r = await s.issue(["-d", DOMAINS, "--json"], { env: { ...ALIYUN_ENV, SSLBEAR_CLI_HOME: state } });
    expect(r.json.data.files.cert).toBe(join(state, "certs", "example.com_rsa", "fullchain.pem"));
    expect(existsSync(join(state, "acme", "acme-v02.api.letsencrypt.org", "account.pem"))).toBe(true);

    const out = await s.issue(["-d", "*.example.com,example.com", "--out", "my-certs", "--json"]);
    expect(out.json.data.files).toEqual({ cert: join(s.home, "my-certs", "fullchain.pem"), key: join(s.home, "my-certs", "privkey.pem") });
  });
});

describe("复用、--force 与续签", () => {
  it("同一组域名（不计顺序）、同算法、剩余 30 天以上：直接复用，不调用 CA、不查 DNS；--dry-run 也一样", async () => {
    const s = setup();
    const out = ["--out", "certs"];
    expect((await s.issue(["-d", DOMAINS, ...out, "--json"])).code).toBe(0);
    s.ca.factory.mockClear();
    vi.mocked(s.dnsDefs.aliyun.listZones).mockClear();

    // 默认目录名取第一个域名，换顺序会换目录；同一个目录里比较域名集合时不计顺序
    const r = await s.issue(["-d", "*.example.com,EXAMPLE.com.", ...out, "--json"]);
    expect(r.code).toBe(0);
    expect(r.json.data).toMatchObject({ reused: true, staging: false, dns: [], issues: [], cert: { notAfter: "2027-01-01T00:00:00.000Z" } });
    expect(Object.keys(r.json.data)).toEqual(["reused", "staging", "files", "cert", "dns", "issues"]);

    const dry = await s.issue(["-d", DOMAINS, ...out, "--dry-run", "--json"]);
    expect(Object.keys(dry.json.data)).toEqual(["dryRun", "reused", "staging", "files", "cert", "dns", "issues"]);
    expect(dry.json.data).toMatchObject({ dryRun: true, reused: true, dns: [] });
    expect(s.ca.factory).not.toHaveBeenCalled();
    expect(s.dnsDefs.aliyun.listZones).not.toHaveBeenCalled();

    const table = await s.issue(["-d", DOMAINS, ...out]);
    expect(table.stdout).toContain("已有可复用的证书，未重新签发");
    expect(table.stdout).toContain("剩 78 天");
  });

  it("域名不同、剩余不足 30 天时重新签发，并带上旧证书的 ARI 标识", async () => {
    const s = setup();
    await s.issue(["-d", DOMAINS, "--json"]);
    const late = await s.issue(["-d", DOMAINS, "--json"], { now: "2026-12-15T00:00:00Z" });
    expect(late.json.data.reused).toBe(false);
    expect(ariCertId).toHaveBeenCalledWith(expect.stringMatching(/^-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----$/));
    expect(s.ca.client.newOrder).toHaveBeenLastCalledWith(["example.com", "*.example.com"], { profile: "classic", replaces: "fake-ari-id" });
  });

  it("--force：已有可复用的证书也重签；旧证书已过期也能算 ARI 标识", async () => {
    const s = setup();
    await s.issue(["-d", DOMAINS, "--json"]);
    const r = await s.issue(["-d", DOMAINS, "--force", "--json"]);
    expect(r.json.data.reused).toBe(false);
    expect(s.ca.client.newOrder).toHaveBeenCalledTimes(2);
    expect(s.ca.client.newOrder).toHaveBeenLastCalledWith(expect.anything(), { profile: "classic", replaces: "fake-ari-id" });
    // 只有 --force 的那次重新加了记录
    expect(s.world.log.filter((l) => l.startsWith("add"))).toHaveLength(4);

    vi.mocked(ariCertId).mockClear();
    // 证书过期后 loadLocalCert 校验不过，但叶子证书仍用来续签；CA 返回的新证书同样过期，这次签发会失败，只看下单
    await s.issue(["-d", DOMAINS, "--json"], { now: "2027-02-01T00:00:00Z" });
    expect(ariCertId).toHaveBeenCalledTimes(1);
    expect(s.ca.client.newOrder).toHaveBeenLastCalledWith(expect.anything(), { profile: "classic", replaces: "fake-ari-id" });
  });

  it("带 replaces 下单失败：去掉 replaces 重试一次；限流时不重试", async () => {
    const s = setup();
    await s.issue(["-d", DOMAINS, "--json"]);
    const original = s.ca.client.newOrder.getMockImplementation()!;
    s.ca.client.newOrder.mockImplementation(async (domains, opts) => {
      if (opts?.replaces) throw new AcmeError("alreadyReplaced", "certificate already replaced", 409);
      return original(domains, opts);
    });
    const r = await s.issue(["-d", DOMAINS, "--force", "--json"]);
    expect(r.code).toBe(0);
    expect(s.ca.client.newOrder.mock.calls.slice(-2).map((c) => c[1])).toEqual([{ profile: "classic", replaces: "fake-ari-id" }, { profile: "classic" }]);

    s.ca.client.newOrder.mockClear();
    s.ca.client.newOrder.mockImplementation(async () => Promise.reject(new AcmeError("rateLimited", "too many new orders", 429, 3600)));
    const limited = await s.issue(["-d", DOMAINS, "--force", "--json"]);
    expect(limited.code).toBe(1);
    expect(s.ca.client.newOrder).toHaveBeenCalledTimes(1);
  });

  it("CA 不支持 ARI、ARI 标识算不出来时不带 replaces", async () => {
    const s = setup({ acme: { directory: { renewalInfo: undefined } } });
    await s.issue(["-d", DOMAINS, "--json"]);
    await s.issue(["-d", DOMAINS, "--force", "--json"]);
    expect(s.ca.client.newOrder).toHaveBeenLastCalledWith(expect.anything(), { profile: "classic" });

    const t = setup();
    await t.issue(["-d", DOMAINS, "--json"]);
    vi.mocked(ariCertId).mockImplementationOnce(() => {
      throw new Error("未实现");
    });
    expect((await t.issue(["-d", DOMAINS, "--force", "--json"])).code).toBe(0);
    expect(t.ca.client.newOrder).toHaveBeenLastCalledWith(expect.anything(), { profile: "classic" });
  });

  it("--staging：测试环境的 CA、账号与 _staging 目录，不复用、不续签正式证书", async () => {
    const s = setup();
    await s.issue(["-d", DOMAINS, "--json"]);
    const r = await s.issue(["-d", DOMAINS, "--staging", "--json"]);
    expect(r.code).toBe(0);
    expect(r.json.data).toMatchObject({ reused: false, staging: true });
    expect(r.json.data.files.cert).toBe(join(s.root, "certs", "example.com_rsa_staging", "fullchain.pem"));
    expect(s.ca.factory).toHaveBeenLastCalledWith(expect.anything(), { directoryUrl: LETSENCRYPT_STAGING_DIRECTORY, accountKey: expect.anything() });
    expect(existsSync(join(s.root, "acme", "acme-staging-v02.api.letsencrypt.org", "account.pem"))).toBe(true);
    // 正式证书原样保留
    expect(existsSync(join(s.certDir, "fullchain.pem"))).toBe(true);

    // --out 指向正式证书所在目录：拒绝签发（参数错误），正式证书不会被测试证书覆盖
    s.ca.factory.mockClear();
    const before = readFileSync(join(s.certDir, "fullchain.pem"), "utf8");
    const same = await s.issue(["-d", DOMAINS, "--staging", "--out", s.certDir, "--force", "--json"]);
    expect(same.code).toBe(2);
    expect(errOf(same)).toMatchObject({ status: "UsageError", message: expect.stringContaining("已有正式环境的证书") });
    expect(s.ca.factory).not.toHaveBeenCalled();
    expect(readFileSync(join(s.certDir, "fullchain.pem"), "utf8")).toBe(before);
  });

  it("CA 返回授权的顺序与申请顺序不同时，按 -d 的顺序加记录、输出 dns", async () => {
    const s = setup();
    const original = s.ca.client.newOrder.getMockImplementation()!;
    s.ca.client.newOrder.mockImplementation(async (domains, opts) => {
      const order = await original(domains, opts);
      return { ...order, authorizations: [...order.authorizations].reverse() };
    });
    const r = await s.issue(["-d", DOMAINS, "--json"]);
    expect(r.json.data.dns.map((d: any) => d.domain)).toEqual(["example.com", "*.example.com"]);
    expect(s.world.log.filter((l) => l.startsWith("add"))).toEqual([`add aliyun ${FQDN} v-tok-example.com`, `add aliyun ${FQDN} v-tok-*.example.com`]);
  });
});

describe("--dry-run", () => {
  it("只查凭证与 zone：不调用 CA、不改 DNS、不写文件、不生成账号私钥", async () => {
    const s = setup({ zones: { aliyun: [{ name: "example.com", id: "example.com" }], cloudflare: [{ name: "sub.example.com", id: "z1" }] }, env: { ...ALIYUN_ENV, ...CLOUDFLARE_ENV } });
    const r = await s.issue(["-d", "example.com,*.sub.example.com", "--dry-run", "--json"]);
    expect(r.code).toBe(0);
    expect(Object.keys(r.json.data)).toEqual(["dryRun", "reused", "staging", "files", "dns", "issues"]);
    expect(r.json.data).toMatchObject({ dryRun: true, reused: false, staging: false, issues: [] });
    expect(r.json.data.dns).toEqual([
      { domain: "example.com", provider: "aliyun", zone: "example.com", record: FQDN },
      { domain: "*.sub.example.com", provider: "cloudflare", zone: "sub.example.com", record: "_acme-challenge.sub.example.com" },
    ]);
    expect(s.ca.factory).not.toHaveBeenCalled();
    expect(s.world.log).toEqual([]);
    expect(existsSync(s.root)).toBe(false);

    const t = await s.issue(["-d", "example.com,*.sub.example.com", "--dry-run"]);
    expect(t.stdout).toContain("--dry-run 预览：未申请证书、未修改 DNS");
    expect(t.stdout).toMatch(/\*\.sub\.example\.com\s+Cloudflare\s+sub\.example\.com\s+_acme-challenge\.sub\.example\.com/);
  });
});

describe("issue 参数与凭证错误（exit 2，不调用任何接口）", () => {
  it("各类参数错误", async () => {
    const s = setup();
    const cases: [string[], string][] = [
      [[], "--domain"],
      [["-d", ","], "--domain 不能为空"],
      [["-d", "1.2.3.4"], "IP"],
      [["-d", "a.*.example.com"], "泛域名"],
      [["-d", "example.com", "--key-type", "dsa"], "--key-type 只能是 rsa 或 ecc"],
      [["-d", "example.com", "--dns", "namecheap"], '不支持的 DNS 服务商 "namecheap"'],
      [["-d", "example.com", "--dns", ","], "--dns 不能为空"],
      [["-d", "example.com", "--dns-timeout", "5"], "--dns-timeout 需为 10~3600 的整数"],
      [["-d", "example.com", "--dns-timeout", "1.5"], "--dns-timeout"],
      [["-d", "example.com", "--email", "not-an-email"], "--email"],
      [["-d", "example.com", "--dns", "cloudflare"], "cloudflare（Cloudflare）未配置凭证"],
    ];
    for (const [args, expected] of cases) {
      const r = await s.issue([...args, "--json"]);
      expect(r.code, args.join(" ")).toBe(2);
      expect(r.stdout).toBe("");
      expect(errOf(r)).toMatchObject({ ok: false, status: "UsageError", message: expect.stringContaining(expected) });
    }
    expect(s.dnsDefs.aliyun.listZones).not.toHaveBeenCalled();
    expect(s.ca.factory).not.toHaveBeenCalled();
  });

  it("一家 DNS 服务商都没配置：提示 11 家各自需要的变量；--dns 指定的配置不完整也是参数错误", async () => {
    const s = setup({ env: {} });
    const r = await s.issue(["-d", "example.com", "--json"]);
    expect(r.code).toBe(2);
    const msg = errOf(r).message;
    expect(msg).toContain("未检测到任何 DNS 服务商凭证");
    expect(msg).toContain("CLOUDFLARE_API_TOKEN");
    expect(msg).toContain("GODADDY_API_KEY");

    const g = await s.issue(["-d", "example.com", "--dns", "godaddy", "--json"], { env: { ...ALIYUN_ENV, GODADDY_API_KEY: "k" } });
    expect(g.code).toBe(2);
    expect(errOf(g).message).toContain("GODADDY_API_SECRET");
  });

  it("保存目录不可写：签发前就报参数错误", async () => {
    const s = setup();
    const ro = join(s.home, "ro");
    mkdirSync(ro, { mode: 0o500 });
    const r = await s.issue(["-d", "example.com", "--out", join(ro, "x"), "--json"]);
    expect(r.code).toBe(2);
    expect(errOf(r).message).toContain("不可写");
    expect(s.dnsDefs.aliyun.listZones).not.toHaveBeenCalled();
  });

  it("--help 写明规则、订阅协议、耗时、status 与退出码", async () => {
    const r = await runCli(["issue", "--help"]);
    expect(r.code).toBe(0);
    for (const s of ["订阅协议", "1~2 分钟", "ZoneNotFound", "ZoneAmbiguous", "DnsRecordFailed", "DnsPropagationTimeout", "AcmeChallengeFailed", "AcmeRateLimited", "AcmeError", "--dns-timeout", "_staging", "cleaned: false"]) {
      expect(r.stdout).toContain(s);
    }
  });
});

describe("issue 失败（exit 1）：stderr 一行错误 JSON，带 dns / issues，已加的 TXT 都已清理", () => {
  it("ZoneNotFound：带 domains 与列 zone 失败的服务商", async () => {
    const s = setup({
      env: { ...ALIYUN_ENV, ...CLOUDFLARE_ENV },
      overrides: { cloudflare: { listZones: vi.fn(async () => Promise.reject(new CloudApiError("cloudflare", "Unauthorized", "bad token", "ray-1", 403))) } },
    });
    const r = await s.issue(["-d", "www.example.org,example.com", "--json"]);
    expect(r.code).toBe(1);
    expect(r.stdout).toBe("");
    const e = errOf(r);
    expect(Object.keys(e)).toEqual(["ok", "status", "message", "retryable", "domains", "dns", "issues"]);
    expect(e).toMatchObject({ ok: false, status: "ZoneNotFound", retryable: false, domains: ["www.example.org"], dns: [] });
    expect(e.issues).toEqual([{ provider: "cloudflare", kind: "error", code: "Unauthorized", message: "bad token", requestId: "ray-1" }]);
    expect(s.ca.factory).not.toHaveBeenCalled();

    const t = await s.issue(["-d", "www.example.org"]);
    expect(t.stderr).toContain("警告：cloudflare（Cloudflare）列出 zone 失败：Unauthorized bad token（RequestId: ray-1）");
    expect(t.code).toBe(1);
    expect(t.stderr).toContain("错误：以下域名不在所选 DNS 服务商（aliyun、cloudflare）的任何 zone 里：www.example.org");
  });

  it("ZoneNotFound：有服务商因网络错误列 zone 失败时可重试", async () => {
    const s = setup({
      env: { ...ALIYUN_ENV, ...CLOUDFLARE_ENV },
      overrides: { cloudflare: { listZones: vi.fn(async () => Promise.reject(new CloudApiError("cloudflare", "NetworkError", "网络错误：api.cloudflare.com ECONNRESET"))) } },
    });
    expect(errOf(await s.issue(["-d", "www.example.org", "--json"]))).toMatchObject({ status: "ZoneNotFound", retryable: true });
  });

  it("ZoneAmbiguous：带 domain、providers", async () => {
    const s = setup({
      zones: { aliyun: [{ name: "example.com", id: "a" }], tencent: [{ name: "example.com", id: "t" }] },
      ns: { "example.com": ["ns1.unknown-dns.net"] },
      env: { ...ALIYUN_ENV, ...TENCENT_ENV },
    });
    const r = await s.issue(["-d", "*.example.com", "--json"]);
    expect(r.code).toBe(1);
    expect(errOf(r)).toMatchObject({ status: "ZoneAmbiguous", domain: "*.example.com", providers: ["aliyun", "tencent"], retryable: false });
    expect(s.ca.factory).not.toHaveBeenCalled();
    // 用 --dns 指定后照常签发
    expect((await s.issue(["-d", "*.example.com", "--dns", "tencent", "--json"])).code).toBe(0);
    expect(s.dnsDefs.tencent.addTxt).toHaveBeenCalled();
    expect(s.dnsDefs.aliyun.addTxt).not.toHaveBeenCalled();
  });

  it("DnsRecordFailed：删除已加的记录，不通知 CA；带 provider、code、requestId、retryable", async () => {
    let n = 0;
    const s = setup({
      overrides: {
        aliyun: {
          addTxt: vi.fn(async () => {
            if (++n === 2) throw new CloudApiError("aliyun", "Forbidden.RAM", "User not authorized", "rid-9", 403);
            return "h1";
          }),
        },
      },
    });
    const r = await s.issue(["-d", DOMAINS, "--json"]);
    expect(r.code).toBe(1);
    const e = errOf(r);
    expect(Object.keys(e)).toEqual(["ok", "status", "message", "retryable", "provider", "code", "requestId", "dns", "issues"]);
    expect(e).toMatchObject({ status: "DnsRecordFailed", provider: "aliyun", code: "Forbidden.RAM", requestId: "rid-9", retryable: false });
    expect(e.message).toContain(`在 阿里云云解析 添加 ${FQDN} 失败：Forbidden.RAM User not authorized（RequestId: rid-9）`);
    expect(e.message).toContain("本次添加的 1 条 TXT 记录已删除");
    expect(e.dns).toEqual([{ domain: "example.com", provider: "aliyun", zone: "example.com", record: FQDN, cleaned: true }]);
    expect(s.dnsDefs.aliyun.removeTxt).toHaveBeenCalledTimes(1);
    expect(s.ca.client.answerChallenge).not.toHaveBeenCalled();
    expect(existsSync(s.certDir)).toBe(false);
  });

  it("DnsRecordFailed：超时等结果不确定的添加失败可重试，并把这条列进 dns 提醒核对；CNAME 冲突时点明原因", async () => {
    const s = setup({ overrides: { aliyun: { addTxt: vi.fn(async () => Promise.reject(new CloudApiError("aliyun", "Timeout", "请求超时（15000ms）：alidns.aliyuncs.com"))) } } });
    const e = errOf(await s.issue(["-d", "example.com", "--json"]));
    expect(e).toMatchObject({ status: "DnsRecordFailed", retryable: true, code: "Timeout" });
    expect(e.dns).toEqual([
      { domain: "example.com", provider: "aliyun", zone: "example.com", record: FQDN, cleaned: false, message: expect.stringContaining('值为 "v-tok-example.com"') },
    ]);
    expect(e.message).toContain("有 1 条 TXT 记录可能残留");

    const c = setup({ overrides: { aliyun: { addTxt: vi.fn(async () => Promise.reject(new CloudApiError("aliyun", "DomainRecordConflict", "The DNS record conflicts with CNAME"))) } } });
    expect(errOf(await c.issue(["-d", "example.com", "--json"])).message).toContain("不支持 _acme-challenge 的 DNS 别名模式");
  });

  it("DnsPropagationTimeout：可重试，message 说明 NS 情况，记录已清理", async () => {
    // NS 认不出是谁家的（自定义 NS）：照常加记录，等不到生效时超时
    const s = setup({ ns: { "example.com": ["ns1.vanity-dns.net"] } });
    s.dnsLookup.queryTxt = vi.fn(async () => []);
    const r = await s.issue(["-d", DOMAINS, "--dns-timeout", "10", "--json"]);
    expect(r.code).toBe(1);
    const e = errOf(r);
    expect(e).toMatchObject({ status: "DnsPropagationTimeout", retryable: true });
    expect(e.message).toContain("等待 10 秒后");
    expect(e.message).toContain("域名的 NS 没有指向 阿里云云解析");
    expect(e.dns.map((d: any) => d.cleaned)).toEqual([true, true]);
    expect(visibleTxt(s.world)).toEqual([]);
    expect(s.ca.client.answerChallenge).not.toHaveBeenCalled();
    expect(s.dnsLookup.queryTxt).toHaveBeenCalledTimes(3);
  });

  it("权威 DNS 全部连不上：固定等待后照常验证签发", async () => {
    const s = setup();
    s.dnsLookup.queryTxt = vi.fn(async () => Promise.reject(Object.assign(new Error("timeout"), { code: "ETIMEOUT" })));
    const r = await s.issue(["-d", DOMAINS]);
    expect(r.code).toBe(0);
    expect(r.stderr).toContain("固定等待 30 秒");
  });

  it("AcmeChallengeFailed：带 domain、acmeType、detail；记录已清理", async () => {
    const s = setup({
      acme: {
        waitAuthorization: async (url) => {
          if (url.endsWith("*.example.com")) throw invalidAuthz("unauthorized", "Incorrect TXT record found at _acme-challenge.example.com");
        },
      },
    });
    const r = await s.issue(["-d", DOMAINS, "--json"]);
    expect(r.code).toBe(1);
    const e = errOf(r);
    expect(e).toMatchObject({ status: "AcmeChallengeFailed", retryable: false, domain: "*.example.com", acmeType: "unauthorized", detail: expect.stringContaining("Incorrect TXT") });
    expect(e.dns.map((d: any) => d.cleaned)).toEqual([true, true]);
    expect(s.ca.client.finalize).not.toHaveBeenCalled();
  });

  it("授权过期等不是验证失败的错误按 AcmeError 处理（重跑会重新下单）", async () => {
    const s = setup({ acme: { waitAuthorization: async () => Promise.reject(new AcmeError("unauthorized", "example.com：授权已失效（expired），请重新下单")) } });
    const e = errOf(await s.issue(["-d", DOMAINS, "--json"]));
    expect(e).toMatchObject({ status: "AcmeError", acmeType: "unauthorized" });
  });

  it("验证超时 / 网络错误按 AcmeError（可重试）处理，不当成验证失败", async () => {
    const s = setup({ acme: { waitAuthorization: async () => Promise.reject(new AcmeError("timeout", "授权 120 秒内没有完成")) } });
    expect(errOf(await s.issue(["-d", "example.com", "--json"]))).toMatchObject({ status: "AcmeError", acmeType: "timeout", retryable: true });
  });

  it("AcmeRateLimited：带 retryAfter，不改 DNS", async () => {
    const s = setup({ acme: { newOrder: async () => Promise.reject(new AcmeError("rateLimited", "too many certificates for this exact set of identifiers", 429, 3600)) } });
    const r = await s.issue(["-d", DOMAINS, "--json"]);
    expect(r.code).toBe(1);
    expect(errOf(r)).toMatchObject({ status: "AcmeRateLimited", retryable: true, retryAfter: 3600, dns: [], issues: [] });
    expect(errOf(r).message).toContain("约 3600 秒后可重试");
    expect(s.dnsDefs.aliyun.addTxt).not.toHaveBeenCalled();
  });

  it("AcmeError：finalize 网络错误时记录已在 finalize 前清理，不写文件", async () => {
    const s = setup({ acme: { finalize: async () => Promise.reject(new AcmeError("network", "网络错误：acme-v02.api.letsencrypt.org ECONNRESET")) } });
    const r = await s.issue(["-d", DOMAINS, "--json"]);
    expect(r.code).toBe(1);
    const e = errOf(r);
    expect(Object.keys(e)).toEqual(["ok", "status", "message", "retryable", "acmeType", "dns", "issues"]);
    expect(e).toMatchObject({ status: "AcmeError", acmeType: "network", retryable: true });
    expect(e.dns.map((d: any) => d.cleaned)).toEqual([true, true]);
    expect(existsSync(join(s.certDir, "fullchain.pem"))).toBe(false);
  });

  it("CA 返回的证书与私钥不匹配 / 不覆盖申请的域名：AcmeError badCertificate，不写文件，不泄露私钥", async () => {
    const s = setup({ acme: { certPem: read("ecc-fullchain.pem") } });
    const r = await s.issue(["-d", DOMAINS, "--json"]);
    expect(errOf(r)).toMatchObject({ status: "AcmeError", acmeType: "badCertificate", message: expect.stringContaining("私钥与证书不匹配") });
    expect(existsSync(join(s.certDir, "privkey.pem"))).toBe(false);
    expectNoKey(r);

    const w = setup();
    const r2 = await w.issue(["-d", "www.example.com", "--json"]);
    expect(errOf(r2)).toMatchObject({ status: "AcmeError", acmeType: "badCertificate", message: expect.stringContaining("没有覆盖 www.example.com") });
  });

  it("CA 客户端抛出的其他错误：status Unknown，仍带 dns、issues", async () => {
    const s = setup();
    s.ca.factory.mockImplementation(async () => Promise.reject(new Error("未实现")));
    const r = await s.issue(["-d", "example.com", "--json"]);
    expect(r.code).toBe(1);
    expect(errOf(r)).toEqual({ ok: false, status: "Unknown", message: "未实现", retryable: false, dns: [], issues: [] });
  });
});

describe("清理失败", () => {
  const failingRemove = () =>
    vi.fn(async (_c: unknown, _cr: unknown, r: { value: string }) => {
      if (r.value === "v-tok-*.example.com") throw new CloudApiError("aliyun", "InternalError", "backend busy", "rid-r");
    });

  it("签发照常成功，dns[].cleaned 为 false 并带原因；表格模式醒目提示手动删除", async () => {
    const s = setup({ overrides: { aliyun: { removeTxt: failingRemove() } } });
    const r = await s.issue(["-d", DOMAINS, "--json"]);
    expect(r.code).toBe(0);
    expect(r.json.data.dns).toEqual([
      { domain: "example.com", provider: "aliyun", zone: "example.com", record: FQDN, cleaned: true },
      {
        domain: "*.example.com",
        provider: "aliyun",
        zone: "example.com",
        record: FQDN,
        cleaned: false,
        message: `删除失败：InternalError backend busy（RequestId: rid-r）；请到 阿里云云解析 手动删除 ${FQDN} 下值为 "v-tok-*.example.com" 的 TXT 记录`,
      },
    ]);

    const t = await s.issue(["-d", DOMAINS, "--force"]);
    expect(t.code).toBe(0);
    expect(t.stdout).toMatch(/\*\.example\.com\s+阿里云云解析\s+example\.com\s+_acme-challenge\.example\.com\s+删除失败/);
    expect(t.stdout).toContain("警告：以下 1 条 TXT 记录可能残留在 DNS 服务商那边，请到控制台手动删除：");
    expect(t.stderr).toContain(`警告：从 阿里云云解析 删除 ${FQDN} 失败，需要手动删除`);
  });

  it("签发失败且清理也失败：错误里列出需手动删除的记录", async () => {
    const s = setup({
      overrides: { aliyun: { removeTxt: failingRemove() } },
      acme: { waitAuthorization: async () => Promise.reject(invalidAuthz("dns", "DNS problem: SERVFAIL")) },
    });
    const j = await s.issue(["-d", DOMAINS, "--json"]);
    const e = errOf(j);
    expect(e.status).toBe("AcmeChallengeFailed");
    // 验证因 DNS 失败会重新下单再试一次：两轮各有一条删不掉，第一轮删掉的不再列出
    expect(e.message).toContain("有 2 条 TXT 记录可能残留，需要手动删除（见 dns）");
    expect(e.dns.map((d: any) => d.cleaned)).toEqual([false, true, false]);

    const t = await s.issue(["-d", DOMAINS]);
    expect(t.code).toBe(1);
    expect(t.stderr).toContain("警告：以下 2 条 TXT 记录可能残留");
    expect(t.stderr).toContain("错误：CA 验证 example.com 失败（dns）");
  });
});

describe("env 命令的 DNS 服务商与 .env 整组屏蔽", () => {
  it("env --json 增加 data.dns：11 家各自的 state 与 keys（密钥类只标明是否已设置）", async () => {
    const r = await runCli(["env", "--json"], { env: { ...ALIYUN_ENV, ...CLOUDFLARE_ENV, AWS_ACCESS_KEY_ID: "AKIAEXAMPLE12345678" } });
    expect(r.code).toBe(0);
    expect(Object.keys(r.json.data)).toEqual(["envFile", "providers", "dns"]);
    const dns = Object.fromEntries(r.json.data.dns.map((d: any) => [d.provider, d]));
    expect(Object.keys(dns)).toEqual(["aliyun", "tencent", "volcengine", "huawei", "baidu", "cloudflare", "aws", "google", "azure", "digitalocean", "godaddy"]);
    expect(dns.aliyun).toMatchObject({ state: "ok" });
    expect(dns.cloudflare).toEqual({ provider: "cloudflare", state: "ok", keys: [{ name: "CLOUDFLARE_API_TOKEN", required: true, set: true }] });
    expect(dns.aws.state).toBe("incomplete");
    expect(dns.aws.keys[0]).toEqual({ name: "AWS_ACCESS_KEY_ID", required: true, set: true, masked: "AKIA********5678" });
    expect(dns.google).toMatchObject({ state: "missing" });
    expect(r.stdout).not.toContain(CLOUDFLARE_ENV.CLOUDFLARE_API_TOKEN);
  });

  it("env 表格增加「DNS 服务商（issue 用）」一节，与云厂商共用凭证的不重复列变量", async () => {
    const r = await runCli(["env"], { env: { ...CLOUDFLARE_ENV } });
    expect(r.stdout).toContain("DNS 服务商（issue 用）");
    expect(r.stdout).toContain("阿里云云解析（aliyun）：未配置（与阿里云共用凭证）");
    expect(r.stdout).toContain("Cloudflare（cloudflare）：已配置\n  CLOUDFLARE_API_TOKEN 已设置");
    expect(r.stdout).toContain("GoDaddy（godaddy）：未配置\n  GODADDY_API_KEY 未设置（必填）\n  GODADDY_API_SECRET 未设置（必填）");
  });

  it("shell 里设置了某家 DNS 服务商的任一变量时，.env 里这家整组忽略；其他家照常读", async () => {
    const dir = tmp();
    writeFileSync(join(dir, ".env"), "AWS_ACCESS_KEY_ID=file-id\nAWS_SECRET_ACCESS_KEY=file-secret\nCLOUDFLARE_API_TOKEN=file-token\n");
    const r = await runCli(["env", "--json"], { env: { AWS_ACCESS_KEY_ID: "AKIASHELL000000000" }, cwd: dir });
    const dns = Object.fromEntries(r.json.data.dns.map((d: any) => [d.provider, d]));
    // AWS 只有 shell 里的 ID：.env 里的 Secret 不会拼进来
    expect(dns.aws.state).toBe("incomplete");
    expect(dns.aws.keys[1]).toEqual({ name: "AWS_SECRET_ACCESS_KEY", required: true, set: false });
    expect(dns.cloudflare.state).toBe("ok");
  });
});

describe("issue 被中止", () => {
  it("等待生效时收到中止信号：删除本次加的记录、输出 Interrupted；正常流程随后不会重复删除", async () => {
    const s = setup();
    let onSignal: (() => Promise<void>) | undefined;
    const untrap = vi.fn();
    const trapInterrupt = vi.fn((fn: () => Promise<void>) => ((onSignal = fn), untrap));
    // 第一次查权威 DNS 时模拟收到信号（入口会等 onSignal 完成后退出进程；测试里进程不退出，正常流程会接着走完）
    let signalled: Promise<void> | undefined;
    const dnsLookup = fakeLookup(s.world, {
      queryTxt: vi.fn(async (_ip: string, fqdn: string) => {
        signalled ??= onSignal!();
        await signalled;
        return s.world.txt.get(fqdn) ?? [];
      }),
    });
    const r = await s.issue(["-d", DOMAINS, "--json"], { dnsLookup, trapInterrupt });
    // 只有信号处理输出的那一行：正常流程随后不再输出、不再通知验证、不再 finalize
    expect(r.stdout).toBe("");
    expect(r.stderr.split("\n")).toHaveLength(1);
    const interrupted = JSON.parse(r.stderr);
    expect(interrupted).toMatchObject({ ok: false, status: "Interrupted", retryable: true, message: "签发被中止；本次添加的 2 条 TXT 记录已删除", issues: [] });
    expect(interrupted.dns.map((d: { cleaned: boolean }) => d.cleaned)).toEqual([true, true]);
    expect(s.world.log.filter((l) => l.startsWith("remove"))).toHaveLength(2);
    expect(s.world.log).not.toContain("answer example.com");
    expect(s.ca.client.finalize).not.toHaveBeenCalled();
    // 清理完成后撤销登记：之后再按 Ctrl+C 不会再跑清理
    expect(trapInterrupt).toHaveBeenCalledTimes(1);
    expect(untrap).toHaveBeenCalledTimes(1);
  });

  it("正在添加记录时收到中止信号：等这次添加结束再一起删除，不再添加后面的记录", async () => {
    let onSignal: (() => Promise<void>) | undefined;
    const trapInterrupt = vi.fn((fn: () => Promise<void>) => ((onSignal = fn), () => {}));
    let signalled: Promise<void> | undefined;
    const s = setup({
      overrides: {
        aliyun: {
          addTxt: vi.fn(async (_ctx: unknown, _creds: unknown, r: TxtRecord) => {
            // 第一次添加还没返回时收到信号
            signalled ??= onSignal!();
            await new Promise((res) => setTimeout(res, 5));
            s.world.txt.set(r.fqdn, [...(s.world.txt.get(r.fqdn) ?? []), r.value]);
            s.world.log.push(`add ${r.value}`);
            return `h-${r.value}`;
          }),
        },
      },
    });
    const r = await s.issue(["-d", DOMAINS, "--json"], { trapInterrupt });
    await signalled;
    const e = JSON.parse(r.stderr);
    expect(e).toMatchObject({ status: "Interrupted", message: "签发被中止；本次添加的 1 条 TXT 记录已删除" });
    expect(e.dns).toEqual([{ domain: "example.com", provider: "aliyun", zone: "example.com", record: FQDN, cleaned: true }]);
    // 第二条没有再添加；第一条（中止时正在添加的）已删除
    expect(s.world.log.filter((l) => l.startsWith("add"))).toEqual(["add v-tok-example.com"]);
    expect(visibleTxt(s.world)).toEqual([]);
  });
});

describe("验证因 DNS 查不到记录失败时重试一次", () => {
  it("第一次 NXDOMAIN：重新下单、加长等待后成功；dns 只列第二轮的记录", async () => {
    let calls = 0;
    const s = setup({
      acme: {
        waitAuthorization: async () => {
          if (calls++ === 0) throw invalidAuthz("dns", "DNS problem: NXDOMAIN looking up TXT for _acme-challenge.example.com");
        },
      },
    });
    const sleeps: number[] = [];
    const r = await s.issue(["-d", DOMAINS, "--json"], { sleep: async (ms: number) => void sleeps.push(ms) });
    expect(r.code).toBe(0);
    expect(s.ca.client.newOrder).toHaveBeenCalledTimes(2);
    expect(sleeps).toContain(RETRY_SETTLE_MS);
    expect(r.json.data.dns.map((d: any) => [d.domain, d.cleaned])).toEqual([
      ["example.com", true],
      ["*.example.com", true],
    ]);
    expect(s.world.log.filter((l) => l.startsWith("add"))).toHaveLength(4);
    expect(s.world.log.filter((l) => l.startsWith("remove"))).toHaveLength(4);
  });

  it("CAA 拒绝等非 DNS 原因不重试；第二次仍因 DNS 失败就报错", async () => {
    const caa = setup({ acme: { waitAuthorization: async () => Promise.reject(invalidAuthz("caa", "CAA record forbids issuance")) } });
    expect(errOf(await caa.issue(["-d", DOMAINS, "--json"]))).toMatchObject({ status: "AcmeChallengeFailed", acmeType: "caa" });
    expect(caa.ca.client.newOrder).toHaveBeenCalledTimes(1);

    const dns = setup({ acme: { waitAuthorization: async () => Promise.reject(invalidAuthz("dns", "DNS problem: NXDOMAIN")) } });
    expect(errOf(await dns.issue(["-d", DOMAINS, "--json"]))).toMatchObject({ status: "AcmeChallengeFailed", acmeType: "dns" });
    expect(dns.ca.client.newOrder).toHaveBeenCalledTimes(2);
  });
});

describe("域名的 NS 已换到别家", () => {
  it("只有 DNSPod 托管、实际 NS 属于火山引擎：ZoneNotFound，不加任何记录", async () => {
    const s = setup({ zones: { tencent: [{ name: "example.com", id: "1" }] }, ns: { "example.com": ["ns1.volcengine-dns.com", "ns2.volcengine-dns.com"] }, env: TENCENT_ENV });
    const r = await s.issue(["-d", DOMAINS, "--json"]);
    expect(r.code).toBe(1);
    expect(errOf(r)).toMatchObject({ status: "ZoneNotFound", nameServerOwner: "volcengine" });
    expect(s.world.log.filter((l) => l.startsWith("add"))).toEqual([]);
  });
});
