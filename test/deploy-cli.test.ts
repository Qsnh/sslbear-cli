import { readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { ENV_FAMILIES } from "../src/lib/env.js";
import { CloudApiError, type QueryContext } from "../src/lib/http.js";
import { formatDate } from "../src/lib/time.js";
import type { ProviderDefs } from "../src/query.js";
import type { Deployer, DeployInput, DeployTarget, DomainService, ProviderDef } from "../src/providers/registry.js";
import type { DomainRecord, Provider } from "../src/types.js";
import { ALIYUN_ENV, fakeFetch, runCli, type CliResult, type RunCliOptions } from "./helpers.js";

const FIX = fileURLToPath(new URL("./fixtures/deploy/", import.meta.url));
const NOW = "2026-10-15T00:00:00Z";
const DUE = "2026-10-25T00:00:00Z"; // 剩 10 天
const LATER = "2026-12-01T00:00:00Z"; // 剩 47 天，未到更新时间
/** 私钥正文（不含 BEGIN / END 行），任何输出里都不能出现 */
const KEY_LINES = readFileSync(join(FIX, "rsa-key.pem"), "utf8")
  .split("\n")
  .filter((l) => l && !l.startsWith("-----"));
const CERT_ARGS = ["--cert", "rsa-fullchain.pem", "--key", "rsa-key.pem"];

function rec(domain: string, r: Partial<DomainRecord> = {}): DomainRecord {
  return { provider: "aliyun", service: "cdn", domain, https: true, cert: { name: "old", notAfter: DUE }, ...r };
}

const okDeployer = () => ({
  apply: vi.fn(async (_c: QueryContext, _cr: unknown, _t: DeployTarget, input: DeployInput) => ({ certId: await input.certId() })),
});

/** 假的阿里云：只有一个 CDN 服务（list 可计数），其余云厂商都未配置凭证；写法同 deploy-run.test.ts */
function fakeDefs(records: DomainRecord[], deployer?: Deployer<unknown>) {
  const list = vi.fn(async () => records.map((r) => ({ ...r })));
  const upload = vi.fn(async () => ({ id: "cas-1", reused: false }));
  const def = (provider: Provider, services: DomainService<unknown>[]): ProviderDef<unknown> => ({
    provider,
    envFamilies: ENV_FAMILIES[provider],
    readCredentials: () => ({ state: "ok", credentials: { p: provider } }),
    services,
    listCertificates: async () => [],
    isInactive: () => false,
  });
  const missing = (provider: Provider) => ({ ...def(provider, []), readCredentials: () => ({ state: "missing" as const }) });
  const defs: ProviderDefs = {
    aliyun: { ...def("aliyun", [{ key: "cdn", label: "CDN", list, ...(deployer && { deployer }) }]), uploadCertificate: upload },
    tencent: missing("tencent"),
    volcengine: missing("volcengine"),
    huawei: missing("huawei"),
    baidu: missing("baidu"),
    qiniu: missing("qiniu"),
  };
  return { defs, list, upload };
}

function deploy(argv: string[], opts: RunCliOptions = {}): Promise<CliResult> {
  return runCli(["deploy", ...CERT_ARGS, ...argv], { cwd: FIX, now: NOW, ...opts });
}

function expectNoKey(r: CliResult): void {
  for (const line of KEY_LINES) {
    expect(r.stdout).not.toContain(line);
    expect(r.stderr).not.toContain(line);
  }
}

const domainsOf = (results: { domain: string; action: string }[]) => results.map((x) => [x.domain, x.action]);

describe("deploy 参数与证书校验", () => {
  it("缺 --cert、文件不存在、证书缺链、私钥不匹配：exit 2，不查询云接口，输出不含私钥", async () => {
    const { defs, list } = fakeDefs([rec("a.example.com")], okDeployer());
    const cases: [string[], string][] = [
      [["--key", "rsa-key.pem"], "--cert"],
      [["--cert", "nope.pem", "--key", "rsa-key.pem"], `--cert 指定的文件不存在：${join(FIX, "nope.pem")}`],
      [["--cert", "rsa-fullchain.pem", "--key", "nope-key.pem"], `--key 指定的文件不存在：${join(FIX, "nope-key.pem")}`],
      [["--cert", "leaf-only.pem", "--key", "rsa-key.pem"], "中间证书"],
      [["--cert", "rsa-fullchain.pem", "--key", "other-key.pem"], "私钥与证书不匹配"],
      // 把私钥当成证书传进来：报错里也不能回显文件内容
      [["--cert", "rsa-key.pem", "--key", "rsa-key.pem"], "没有 PEM 格式的证书"],
    ];
    for (const [args, expected] of cases) {
      const j = await runCli(["deploy", ...args, "--json"], { cwd: FIX, now: NOW, defs });
      expect(j.code, args.join(" ")).toBe(2);
      expect(j.stdout).toBe("");
      expect(JSON.parse(j.stderr)).toMatchObject({ ok: false, status: "UsageError", message: expect.stringContaining(expected) });
      expectNoKey(j);

      const t = await runCli(["deploy", ...args], { cwd: FIX, now: NOW, defs });
      expect(t.code, args.join(" ")).toBe(2);
      expect(t.stderr).toContain(expected);
      expectNoKey(t);
    }
    expect(list).not.toHaveBeenCalled();
  });

  it("-d 给了空值时 exit 2，不会退化成处理全部域名", async () => {
    const { defs, list } = fakeDefs([rec("a.example.com")], okDeployer());
    const r = await deploy(["-d", ",", "--json"], { defs });
    expect(r.code).toBe(2);
    expect(JSON.parse(r.stderr)).toMatchObject({ status: "UsageError", message: expect.stringContaining("--domain") });
    expect(list).not.toHaveBeenCalled();
  });

  it("证书与私钥按 cwd 解析成绝对路径后读取", async () => {
    const { defs } = fakeDefs([rec("a.example.com")], okDeployer());
    const readFile = vi.fn((path: string) => readFileSync(join(FIX, basename(path)), "utf8"));
    const r = await runCli(["deploy", ...CERT_ARGS, "--dry-run", "--json"], { cwd: "/work", now: NOW, defs, readFile });
    expect(r.code).toBe(0);
    expect(readFile.mock.calls.map((c) => c[0])).toEqual(["/work/rsa-fullchain.pem", "/work/rsa-key.pem"]);
  });
});

describe("deploy 范围、执行与输出契约", () => {
  it("-d 可逗号分隔、可重复，点名的域名都生效且只处理它们", async () => {
    const { defs } = fakeDefs(["a", "b", "c", "d"].map((x) => rec(`${x}.example.com`)), okDeployer());
    const r = await deploy(["-d", "a.example.com,B.example.com", "-d", "c.example.com", "--dry-run", "--json"], { defs });
    expect(r.code).toBe(0);
    expect(domainsOf(r.json.data.results)).toEqual([
      ["a.example.com", "would_update"],
      ["b.example.com", "would_update"],
      ["c.example.com", "would_update"],
    ]);
  });

  it("--dry-run --json 只输出计划：不上传、不调用 apply，data 不带内部计数", async () => {
    const dep = okDeployer();
    const { defs, upload } = fakeDefs([rec("a.example.com"), rec("b.example.com", { https: false, cert: undefined })], dep);
    const r = await deploy(["--dry-run", "--json"], { defs });
    expect(r.code).toBe(0);
    expect(r.json.ok).toBe(true);
    expect(Object.keys(r.json.data)).toEqual(["dryRun", "cert", "uploads", "results", "issues"]);
    expect(r.json.data.dryRun).toBe(true);
    expect(r.json.data.cert).toMatchObject({ commonName: "example.com", algorithm: "RSA", notAfter: "2027-01-01T00:00:00.000Z" });
    expect(domainsOf(r.json.data.results)).toEqual([
      ["a.example.com", "would_update"],
      ["b.example.com", "skipped"],
    ]);
    expect(dep.apply).not.toHaveBeenCalled();
    expect(upload).not.toHaveBeenCalled();
    expectNoKey(r);
  });

  it("全部成功：exit 0，stdout 单行 {ok:true,data}", async () => {
    const dep = okDeployer();
    const { defs, upload } = fakeDefs([rec("a.example.com"), rec("b.example.com", { https: false, cert: undefined })], dep);
    const r = await deploy(["-d", "a.example.com,b.example.com", "--json"], { defs });
    expect(r.code).toBe(0);
    expect(r.stderr).toBe("");
    expect(r.stdout.trim().split("\n")).toHaveLength(1);
    expect(r.json.ok).toBe(true);
    expect(r.json.data.dryRun).toBe(false);
    expect(r.json.data.results).toEqual([
      expect.objectContaining({ domain: "a.example.com", action: "updated", after: { id: "cas-1", notAfter: "2027-01-01T00:00:00.000Z" } }),
      expect.objectContaining({ domain: "b.example.com", action: "deployed" }),
    ]);
    expect(r.json.data.uploads).toEqual([{ provider: "aliyun", certId: "cas-1", reused: false }]);
    expect(upload).toHaveBeenCalledTimes(1);
    expect(dep.apply).toHaveBeenCalledTimes(2);
    expectNoKey(r);
  });

  it("有域名失败：exit 1，stderr 为 DeployFailed 并平铺完整结果", async () => {
    const dep = {
      apply: vi.fn(async (_c: QueryContext, _cr: unknown, t: DeployTarget, input: DeployInput) => {
        if (t.records[0]!.domain === "b.example.com") throw new CloudApiError("aliyun", "Forbidden", "denied", "rid-1", 403);
        return { certId: await input.certId() };
      }),
    };
    const { defs } = fakeDefs([rec("a.example.com"), rec("b.example.com")], dep);

    const j = await deploy(["--json"], { defs });
    expect(j.code).toBe(1);
    expect(j.stdout).toBe("");
    const err = JSON.parse(j.stderr);
    expect(err).toMatchObject({ ok: false, status: "DeployFailed", dryRun: false, message: expect.stringMatching(/^1 个域名部署失败/), issues: [] });
    expect(Object.keys(err)).toEqual(["ok", "status", "message", "dryRun", "cert", "uploads", "results", "issues"]);
    expect(err.results).toEqual([
      expect.objectContaining({ domain: "a.example.com", action: "updated" }),
      expect.objectContaining({ domain: "b.example.com", action: "failed", code: "Forbidden", requestId: "rid-1", retryable: false }),
    ]);
    expect(err.uploads).toEqual([{ provider: "aliyun", certId: "cas-1", reused: false }]);

    const t = await deploy([], { defs });
    expect(t.code).toBe(1);
    expect(t.stdout).toMatch(/^阿里云\s+CDN\s+b\.example\.com\s+失败\s+Forbidden denied（RequestId: rid-1）$/m);
    expect(t.stdout).toContain("更新 1，部署 0，跳过 0（其中需确认 0），失败 1");
    expect(t.stderr).toContain("错误：1 个域名部署失败");
  });

  it("dry-run 时点名的域名找不到也算失败：exit 1", async () => {
    const { defs } = fakeDefs([rec("a.example.com")], okDeployer());
    const r = await deploy(["-d", "ghost.example.com", "--dry-run", "--json"], { defs });
    expect(r.code).toBe(1);
    const err = JSON.parse(r.stderr);
    expect(err).toMatchObject({ status: "DeployFailed", dryRun: true });
    expect(err.results).toEqual([expect.objectContaining({ domain: "ghost.example.com", action: "failed", code: "DomainNotFound" })]);
  });

  it("所有查询都失败：与 domains 一致 exit 1，stderr 带 issues", async () => {
    const { defs, list } = fakeDefs([], okDeployer());
    list.mockRejectedValue(new CloudApiError("aliyun", "Forbidden.RAM", "User not authorized", "rid-9", 403));
    const j = await deploy(["--json"], { defs });
    expect(j.code).toBe(1);
    expect(JSON.parse(j.stderr)).toMatchObject({ ok: false, status: "Forbidden.RAM", issues: [expect.objectContaining({ service: "cdn", code: "Forbidden.RAM" })] });
    const t = await deploy([], { defs });
    expect(t.code).toBe(1);
    expect(t.stderr).toContain("警告：aliyun/cdn 查询失败：Forbidden.RAM User not authorized（RequestId: rid-9）");
    expect(t.stderr).toContain("没有任何查询成功");
  });
});

describe("deploy 终端二次确认", () => {
  // a 剩 10 天直接更新；b 剩 47 天需确认
  const records = () => [rec("a.example.com"), rec("b.example.com", { cert: { name: "old", notAfter: LATER } })];
  const applied = (dep: ReturnType<typeof okDeployer>) => dep.apply.mock.calls.map((c) => c[2].records.map((x) => x.domain)).flat().sort();

  it("回答 y：列出需确认的域名后询问一次，用同一份查询结果强制更新", async () => {
    const dep = okDeployer();
    const { defs, list } = fakeDefs(records(), dep);
    const confirm = vi.fn(async () => true);
    const r = await deploy([], { defs, confirm });
    expect(r.code).toBe(0);
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(confirm).toHaveBeenCalledWith("以上 1 个域名的当前证书未到更新时间，是否提前更换？[y/N]");
    expect(list).toHaveBeenCalledTimes(1);
    expect(applied(dep)).toEqual(["a.example.com", "b.example.com"]);
    expect(r.stdout).toMatch(/^云厂商\s+服务\s+域名\s+说明$/m);
    expect(r.stdout).toMatch(/^阿里云\s+CDN\s+b\.example\.com\s+当前证书还剩 47 天，未到更新时间$/m);
    expect(r.stdout).toMatch(/^阿里云\s+CDN\s+b\.example\.com\s+已更新\s+旧证书 \d{4}-\d{2}-\d{2} 到期（剩 47 天）$/m);
    expect(r.stdout).not.toContain("需确认的域名");
  });

  it("回答 n：需确认的域名保持跳过，其余照常执行", async () => {
    const dep = okDeployer();
    const { defs, list } = fakeDefs(records(), dep);
    const confirm = vi.fn(async () => false);
    const r = await deploy([], { defs, confirm });
    expect(r.code).toBe(0);
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(list).toHaveBeenCalledTimes(1);
    expect(applied(dep)).toEqual(["a.example.com"]);
    expect(r.stdout).toMatch(/^阿里云\s+CDN\s+b\.example\.com\s+跳过\s+需确认：当前证书还剩 47 天，未到更新时间$/m);
    expect(r.stdout).toContain("需确认的域名：向用户确认后加 --force 重新执行");
  });

  it("--json、--force、--dry-run 或没有需确认的域名时不询问", async () => {
    for (const argv of [["--json"], ["--force"], ["--dry-run"]]) {
      const { defs } = fakeDefs(records(), okDeployer());
      const confirm = vi.fn(async () => true);
      const r = await deploy(argv, { defs, confirm });
      expect(r.code, argv.join(" ")).toBe(0);
      expect(confirm, argv.join(" ")).not.toHaveBeenCalled();
    }
    const forced = okDeployer();
    await deploy(["--force"], { defs: fakeDefs(records(), forced).defs, confirm: async () => false });
    expect(applied(forced)).toEqual(["a.example.com", "b.example.com"]);

    const confirm = vi.fn(async () => true);
    await deploy([], { defs: fakeDefs([rec("a.example.com")], okDeployer()).defs, confirm });
    expect(confirm).not.toHaveBeenCalled();
  });
});

describe("deploy 表格输出", () => {
  it("dry-run：证书说明、每个域名一行、汇总与需确认提示", async () => {
    const { defs } = fakeDefs(
      [
        rec("a.example.com"),
        rec("b.example.com", { cert: { name: "old", notAfter: LATER } }),
        rec("c.example.com", { https: false, cert: undefined }),
        rec("other.org"),
      ],
      okDeployer(),
    );
    const r = await deploy(["--dry-run"], { defs });
    expect(r.code).toBe(0);
    const lines = r.stdout.split("\n");
    expect(lines[0]).toBe(`证书：example.com（RSA，${formatDate("2027-01-01T00:00:00.000Z")} 到期）；--dry-run 预览，未做任何修改`);
    expect(lines[2]).toMatch(/^云厂商\s+服务\s+域名\s+动作\s+说明$/);
    expect(lines[3]).toMatch(/^阿里云\s+CDN\s+a\.example\.com\s+将更新\s+旧证书 \d{4}-\d{2}-\d{2} 到期（剩 10 天）$/);
    expect(lines[4]).toMatch(/^阿里云\s+CDN\s+b\.example\.com\s+跳过\s+需确认：当前证书还剩 47 天，未到更新时间$/);
    expect(lines[5]).toMatch(/^阿里云\s+CDN\s+c\.example\.com\s+跳过\s+未开启 HTTPS；如需部署请用 --domain 点名该域名$/);
    expect(r.stdout).not.toContain("other.org");
    expect(r.stdout).toContain("将更新 1，将部署 0，跳过 2（其中需确认 1），失败 0");
    expect(r.stdout).toContain("需确认的域名：向用户确认后加 --force 重新执行");
    expect(r.stdout).not.toContain("各云生效");
  });

  it("执行后：汇总已执行的数量，并提示稍后用 domains 核对", async () => {
    const { defs } = fakeDefs([rec("a.example.com"), rec("b.example.com", { https: false, cert: undefined })], okDeployer());
    const r = await deploy(["-d", "a.example.com,b.example.com"], { defs });
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/^阿里云\s+CDN\s+a\.example\.com\s+已更新\s+旧证书 \d{4}-\d{2}-\d{2} 到期（剩 10 天）$/m);
    expect(r.stdout).toMatch(/^阿里云\s+CDN\s+b\.example\.com\s+已部署\s+开启 HTTPS$/m);
    expect(r.stdout).toContain("更新 1，部署 1，跳过 0（其中需确认 0），失败 0");
    expect(r.stdout).toContain("各云生效需要几秒到几分钟，可稍后用 sslbear-cli domains 核对");
    expect(r.stdout).not.toContain("需确认的域名");
  });

  it("没有被证书覆盖的域名时给出提示", async () => {
    const { defs } = fakeDefs([rec("other.org")], okDeployer());
    const r = await deploy([], { defs });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("证书覆盖的域名（example.com, *.example.com）在所选云厂商上没有找到");
  });
});

describe("deploy 使用真实的云厂商定义", () => {
  // 各云 deployer 合入后改成真实执行路径：阿里云 CDN 的域名应被更新，并断言写接口的请求
  it("服务还没有 deployer 时记为 unsupported，exit 0，只发查询请求", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeUserDomains") {
        return { body: { TotalCount: 1, Domains: { PageData: [{ DomainName: "www.example.com", SslProtocol: "on", DomainStatus: "online" }] } } };
      }
      if (req.action === "DescribeCdnHttpsDomainList") {
        return { body: { TotalCount: 1, CertInfos: { CertInfo: [{ DomainName: "www.example.com", CertName: "old", CertExpireTime: "2026-10-25 08:00:00" }] } } };
      }
      return undefined;
    });
    const r = await deploy(["-p", "aliyun", "-s", "cdn", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.results).toEqual([
      expect.objectContaining({ provider: "aliyun", service: "cdn", domain: "www.example.com", action: "skipped", reason: "unsupported" }),
    ]);
    expect(new Set(fetch.calls.map((c) => c.action))).toEqual(new Set(["DescribeUserDomains", "DescribeCdnHttpsDomainList"]));
  });
});
