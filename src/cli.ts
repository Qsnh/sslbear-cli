import { resolve } from "node:path";
import { Command, Option } from "commander";
import { envStatus, renderCerts, renderDomains, renderEnv } from "./render.js";
import { familyNames, loadEnvFile, type Env } from "./lib/env.js";
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

function intArg(name: string, min: number, max: number) {
  return (value: string) => {
    const n = Number(value);
    if (!/^\d+$/.test(value) || n < min || n > max) throw new UsageError(`${name} 需为 ${min}~${max} 的整数，收到 "${value}"`);
    return n;
  };
}

function validateProviders(list: string[] | undefined): Provider[] | undefined {
  for (const p of list ?? []) {
    if (!PROVIDERS.includes(p as Provider)) throw new UsageError(`不支持的云厂商 "${p}"，可选：${PROVIDERS.join(", ")}`);
  }
  return list && ([...new Set(list)] as Provider[]);
}

function validateServices(list: string[] | undefined): string[] | undefined {
  for (const s of list ?? []) {
    if (!ALL_SERVICE_KEYS.includes(s)) {
      const hint = Object.values(PROVIDER_DEFS).map((d) => `${d.provider}: ${d.services.map((x) => x.key).join(", ")}`);
      throw new UsageError(`不支持的服务 "${s}"，可选：\n  ${hint.join("\n  ")}`);
    }
  }
  return list && [...new Set(list)];
}

/** 每家云厂商的全部凭证变量为一组：shell 里设置了其中任何一个，就不再从 .env 读这家的凭证 */
const CREDENTIAL_GROUPS = Object.values(PROVIDER_DEFS).map((d) => familyNames(d.envFamilies));

/** 环境变量快照 + .env 文件：显式 --env-file 不存在时报错，默认的 ./.env 不存在则忽略 */
function loadEnv(deps: Deps, opts: CommonOpts): { env: Env; envFile?: string } {
  const env: Env = { ...deps.env };
  if (opts.envFile) {
    const path = resolve(deps.cwd, opts.envFile);
    if (!loadEnvFile(path, env, CREDENTIAL_GROUPS)) throw new UsageError(`--env-file 指定的文件不存在：${path}`);
    return { env, envFile: path };
  }
  const path = resolve(deps.cwd, ".env");
  return loadEnvFile(path, env, CREDENTIAL_GROUPS) ? { env, envFile: path } : { env };
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
      new Option("-e, --expiring-within <days>", "只看 N 天内到期（含已过期）的证书").argParser(intArg("--expiring-within", 0, 36500)),
    )
    .addOption(new Option("--timeout <ms>", "单个请求超时（毫秒）").default(15000).argParser(intArg("--timeout", 1, 600000)))
    .option("--json", "输出单行 JSON：成功 {ok:true,data}，失败 {ok:false,status,message}")
    .option("--env-file <path>", "从指定文件加载环境变量（默认加载当前目录的 .env，若存在）");
}

function printIssues(opts: OutputOptions, issues: QueryIssue[]): void {
  if (opts.json) return;
  for (const i of issues) {
    const where = `${i.provider}/${i.service}${i.target ? ` ${i.target}` : ""}`;
    const rid = i.requestId ? `（RequestId: ${i.requestId}）` : "";
    console.error(i.kind === "inactive" ? `提示：${where} 未开通或无资源（${i.code}）` : `警告：${where} 查询失败：${i.code} ${i.message}${rid}`);
  }
}

/**
 * 只有「所有查询都失败」才算命令失败；部分失败照常输出数据，问题在数据之后输出到 stderr，
 * JSON 模式下放在 data.issues 里。
 */
function emit<T>(opts: OutputOptions, result: { issues: QueryIssue[]; succeeded: number }, items: T[], render: () => string): void {
  const errors = result.issues.filter((i) => i.kind === "error");
  if (result.succeeded === 0 && errors.length > 0) {
    printIssues(opts, result.issues);
    // 表格模式下每条问题已逐行打印，这里只给结论；JSON 模式在 message 里带上错误明细、issues 里带上全部问题
    const message = opts.json
      ? `没有任何查询成功：${errors.map((e) => `${e.provider}/${e.service} ${e.code} ${e.message}`).join("；")}`
      : `没有任何查询成功（${errors.length} 项失败），请检查凭证与权限`;
    fail(opts, errors[0]!.code, message, 1, { issues: result.issues });
  }
  if (opts.json) outJson({ items, issues: result.issues });
  else console.log(render());
  printIssues(opts, result.issues);
}

export function buildProgram(deps: Deps, output: OutputOptions = { json: false }): Command {
  const program = new Command("sslbear-cli")
    .description("证书熊 CLI：查询阿里云、腾讯云云服务上的域名及其 SSL 证书（凭证从环境变量读取）")
    .version(VERSION)
    .exitOverride();
  // JSON 模式下参数错误由 run() 统一输出为 JSON，屏蔽 commander 自带的文本报错与帮助
  if (output.json) program.configureOutput({ writeErr: () => {}, outputError: () => {} });
  else program.showHelpAfterError();

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
    emit(out, result, items, () => renderDomains(items, opts.expiringWithin));
  });

  withQuery(
    program.command("certs").description("列出证书服务中的证书（阿里云数字证书管理服务 / 腾讯云 SSL 证书），按剩余天数升序"),
  ).action(async (opts: QueryOpts) => {
    const out = { json: !!opts.json };
    const ctx = createContext(deps, opts);
    const result = await queryCertificates(ctx, { providers: validateProviders(opts.provider) });
    const items = filterCertificates(result.items, { keyword: opts.domain, expiringWithin: opts.expiringWithin });
    emit(out, result, items, () => renderCerts(items, opts.expiringWithin));
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
    await buildProgram(deps, { json }).parseAsync(argv, { from: "user" });
    return 0;
  } catch (e) {
    if (e instanceof ExitError) return e.exitCode;
    const code = (e as { code?: string }).code ?? "";
    try {
      if (code.startsWith("commander.")) {
        // --help / --version 为 0；缺子命令时 commander 打印帮助并给出非 0 退出码，按参数错误处理
        if ((e as { exitCode?: number }).exitCode === 0) return 0;
        if (json) fail({ json }, "UsageError", (e as Error).message.replace(/^error: /, ""), 2);
        return 2;
      }
      if (e instanceof UsageError) fail({ json }, "UsageError", e.message, 2);
      fail({ json }, "Unknown", String((e as Error)?.message ?? e), 1);
    } catch (exit) {
      return (exit as ExitError).exitCode;
    }
  }
}
