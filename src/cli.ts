import { resolve } from "node:path";
import { Command, Option } from "commander";
import { envStatus, renderCerts, renderDomains, renderEnv } from "./render.js";
import { loadEnvFile, type Env } from "./lib/env.js";
import type { Fetch, QueryContext } from "./lib/http.js";
import { ExitError, fail, outJson, type OutputOptions } from "./lib/output.js";
import {
  PROVIDER_DEFS,
  UsageError,
  filterCertificates,
  filterDomains,
  queryCertificates,
  queryDomains,
  type QueryIssue,
} from "./query.js";
import { PROVIDERS, type Provider } from "./types.js";
import { VERSION } from "./version.js";

export interface Deps {
  env: Env;
  fetch: Fetch;
  now: () => Date;
  cwd: string;
  sleep?: (ms: number) => Promise<void>;
}

interface CommonOpts {
  json?: boolean;
  envFile?: string;
}

interface QueryOpts extends CommonOpts {
  provider?: string[];
  service?: string[];
  domain?: string;
  expiringWithin?: number;
  timeout: number;
}

const ALL_SERVICE_KEYS = [...new Set(Object.values(PROVIDER_DEFS).flatMap((d) => d.services.map((s) => s.key)))];

const csv = (value: string, prev: string[] = []) => [
  ...prev,
  ...value
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean),
];

function positiveInt(name: string) {
  return (value: string) => {
    const n = Number(value);
    if (!Number.isInteger(n) || n < 0) throw new UsageError(`${name} 需为非负整数，收到 "${value}"`);
    return n;
  };
}

function validateProviders(list: string[] | undefined): Provider[] | undefined {
  for (const p of list ?? []) {
    if (!PROVIDERS.includes(p as Provider)) throw new UsageError(`不支持的云厂商 "${p}"，可选：${PROVIDERS.join(", ")}`);
  }
  return list as Provider[] | undefined;
}

function validateServices(list: string[] | undefined): string[] | undefined {
  for (const s of list ?? []) {
    if (!ALL_SERVICE_KEYS.includes(s)) {
      const hint = Object.values(PROVIDER_DEFS).map((d) => `${d.provider}: ${d.services.map((x) => x.key).join(", ")}`);
      throw new UsageError(`不支持的服务 "${s}"，可选：\n  ${hint.join("\n  ")}`);
    }
  }
  return list;
}

/** 环境变量快照 + .env 文件：显式 --env-file 不存在时报错，默认的 ./.env 不存在则忽略 */
function loadEnv(deps: Deps, opts: CommonOpts): { env: Env; envFile?: string } {
  const env: Env = { ...deps.env };
  if (opts.envFile) {
    const path = resolve(deps.cwd, opts.envFile);
    if (!loadEnvFile(path, env)) throw new UsageError(`--env-file 指定的文件不存在：${path}`);
    return { env, envFile: path };
  }
  const path = resolve(deps.cwd, ".env");
  return loadEnvFile(path, env) ? { env, envFile: path } : { env };
}

function createContext(deps: Deps, opts: QueryOpts): QueryContext {
  return {
    env: loadEnv(deps, opts).env,
    fetch: deps.fetch,
    now: deps.now(),
    timeoutMs: opts.timeout,
    ...(deps.sleep && { sleep: deps.sleep }),
  };
}

function withQuery(cmd: Command, serviceHelp?: string): Command {
  cmd.option("-p, --provider <list>", `只查指定云厂商，逗号分隔（${PROVIDERS.join(", ")}）；默认查所有已配置凭证的云厂商`, csv);
  if (serviceHelp) cmd.option("-s, --service <list>", `只查指定服务，逗号分隔。${serviceHelp}`, csv);
  return cmd
    .option("-d, --domain <keyword>", "按域名关键字过滤（同时匹配证书的通用名和 SAN）")
    .addOption(
      new Option("-e, --expiring-within <days>", "只看 N 天内到期（含已过期）的证书").argParser(positiveInt("--expiring-within")),
    )
    .addOption(new Option("--timeout <ms>", "单个请求超时（毫秒）").default(15000).argParser(positiveInt("--timeout")))
    .option("--json", "输出单行 JSON：成功 {ok:true,data}，失败 {ok:false,status,message}")
    .option("--env-file <path>", "从指定文件加载环境变量（默认加载当前目录的 .env，若存在）");
}

/** 只有「所有查询都失败」才算命令失败；部分失败照常输出数据，并在 issues / stderr 里说明 */
function reportIssues(opts: OutputOptions, result: { issues: QueryIssue[]; attempted: number; failed: number }): void {
  const { issues } = result;
  if (!opts.json) {
    for (const i of issues) {
      const where = `${i.provider}/${i.service}${i.target ? ` ${i.target}` : ""}`;
      const rid = i.requestId ? `（RequestId: ${i.requestId}）` : "";
      console.error(i.kind === "inactive" ? `提示：${where} 未开通或无资源（${i.code}）` : `警告：${where} 查询失败：${i.code} ${i.message}${rid}`);
    }
  }
  const errors = issues.filter((i) => i.kind === "error");
  if (result.failed > 0 && result.failed === result.attempted && errors.length > 0) {
    // 表格模式下每条错误已逐行打印，这里只给结论；JSON 模式只有这一条输出，带上全部明细
    const message = opts.json
      ? `全部查询失败：${errors.map((e) => `${e.provider}/${e.service} ${e.code} ${e.message}`).join("；")}`
      : `全部 ${result.attempted} 项查询均失败，请检查凭证与权限`;
    fail(opts, errors[0]!.code, message);
  }
}

export function buildProgram(deps: Deps): Command {
  const program = new Command("sslbear-cli")
    .description("证书熊 CLI：查询阿里云、腾讯云云服务上的域名及其 SSL 证书（凭证从环境变量读取）")
    .version(VERSION)
    .showHelpAfterError()
    .exitOverride();

  const serviceHelp = Object.values(PROVIDER_DEFS)
    .map((d) => `${d.provider}: ${d.services.map((s) => `${s.key}(${s.label})`).join(", ")}`)
    .join("；");

  withQuery(
    program.command("domains").description("列出云服务上的域名及其绑定的 SSL 证书，按剩余天数升序"),
    serviceHelp,
  ).action(async (opts: QueryOpts) => {
    const out = { json: !!opts.json };
    const ctx = createContext(deps, opts);
    const sel = { providers: validateProviders(opts.provider), services: validateServices(opts.service) };
    const result = await queryDomains(ctx, sel);
    const items = filterDomains(result.items, { keyword: opts.domain, expiringWithin: opts.expiringWithin });
    reportIssues(out, result);
    if (out.json) outJson({ items, issues: result.issues });
    else console.log(renderDomains(items, opts.expiringWithin));
  });

  withQuery(
    program.command("certs").description("列出证书服务中的证书（阿里云数字证书管理服务 / 腾讯云 SSL 证书），按剩余天数升序"),
  ).action(async (opts: QueryOpts) => {
    const out = { json: !!opts.json };
    const ctx = createContext(deps, opts);
    const result = await queryCertificates(ctx, { providers: validateProviders(opts.provider) });
    const items = filterCertificates(result.items, { keyword: opts.domain, expiringWithin: opts.expiringWithin });
    reportIssues(out, result);
    if (out.json) outJson({ items, issues: result.issues });
    else console.log(renderCerts(items, opts.expiringWithin));
  });

  program
    .command("env")
    .description("检查环境变量里的云厂商凭证配置（脱敏显示）")
    .option("--json", "输出单行 JSON")
    .option("--env-file <path>", "从指定文件加载环境变量（默认加载当前目录的 .env，若存在）")
    .action((opts: CommonOpts) => {
      const { env, envFile } = loadEnv(deps, opts);
      if (opts.json) outJson({ envFile: envFile ?? null, providers: envStatus(env) });
      else console.log(renderEnv(env, envFile));
    });

  return program;
}

/** 统一出口：返回进程退出码，便于测试 */
export async function run(argv: string[], deps: Deps): Promise<number> {
  const json = argv.includes("--json");
  try {
    await buildProgram(deps).parseAsync(argv, { from: "user" });
    return 0;
  } catch (e) {
    if (e instanceof ExitError) return e.exitCode;
    const code = (e as { code?: string }).code ?? "";
    if (code.startsWith("commander.")) {
      return code === "commander.helpDisplayed" || code === "commander.version" || code === "commander.help" ? 0 : 2;
    }
    try {
      if (e instanceof UsageError) fail({ json }, "UsageError", e.message, 2);
      fail({ json }, "Unknown", String((e as Error)?.message ?? e), 1);
    } catch (exit) {
      return (exit as ExitError).exitCode;
    }
  }
}
