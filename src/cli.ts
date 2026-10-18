import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Command, Option } from "commander";
import { loadLocalCert } from "./deploy/cert.js";
import { renderConfirm, renderDeploy } from "./deploy/render.js";
import { buildPlan, executeDeploy, queryForDeploy, type DeployOptions, type DeployPlan, type DeployReport } from "./deploy/run.js";
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
  type ProviderDefs,
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
  /** 读取 --cert / --key 指定的文件，参数为绝对路径；缺省读本地文件 */
  readFile?: (path: string) => string;
  /** 终端里询问是否继续；入口只在 stdin、stdout 都是终端时提供，AI / 脚本调用时没有 */
  confirm?: (question: string) => Promise<boolean>;
  /** 只供测试注入假的云厂商定义（deploy 用）；缺省为 PROVIDER_DEFS */
  defs?: ProviderDefs;
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

interface DeployCliOpts extends CommonOpts {
  cert: string;
  key: string;
  provider?: string[];
  service?: string[];
  /** 精确匹配的域名列表，与 domains 的关键字过滤不同 */
  domain?: string[];
  force?: boolean;
  dryRun?: boolean;
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

function createContext(deps: Deps, opts: CommonOpts & { timeout: number }): QueryContext {
  return {
    env: loadEnv(deps, opts).env,
    fetch: deps.fetch,
    now: deps.now(),
    timeoutMs: opts.timeout,
    ...(deps.sleep && { sleep: deps.sleep }),
  };
}

/** 调用云接口的命令共用：请求超时、JSON 输出、.env 文件 */
function withCommon(cmd: Command): Command {
  return cmd
    .addOption(new Option("--timeout <ms>", "单个请求超时（毫秒）").default(15000).argParser(intArg("--timeout", 1, 600000)))
    .option("--json", "输出单行 JSON：成功 {ok:true,data}，失败 {ok:false,status,message}")
    .option("--env-file <path>", "从指定文件加载环境变量（默认加载当前目录的 .env，若存在）");
}

function withQuery(cmd: Command, serviceHelp?: string): Command {
  cmd.option("-p, --provider <list>", `只查指定云厂商，逗号分隔（${PROVIDERS.join(", ")}）；默认查所有已配置凭证的云厂商`, csv);
  if (serviceHelp) cmd.option("-s, --service <list>", `只查指定服务，逗号分隔。${serviceHelp}`, csv);
  return withCommon(
    cmd
      .option("-d, --domain <keyword>", "按域名关键字过滤（同时匹配证书的通用名和 SAN）")
      .addOption(
        new Option("-e, --expiring-within <days>", "只看 N 天内到期（含已过期）的证书").argParser(intArg("--expiring-within", 0, 36500)),
      ),
  );
}

function printIssues(opts: OutputOptions, issues: QueryIssue[]): void {
  if (opts.json) return;
  for (const i of issues) {
    const where = `${i.provider}/${i.service}${i.target ? ` ${i.target}` : ""}`;
    const rid = i.requestId ? `（RequestId: ${i.requestId}）` : "";
    console.error(i.kind === "inactive" ? `提示：${where} 未开通或无资源（${i.code}）` : `警告：${where} 查询失败：${i.code} ${i.message}${rid}`);
  }
}

/** 所有查询都失败时命令失败（exit 1） */
function failIfNoneSucceeded(opts: OutputOptions, result: { issues: QueryIssue[]; succeeded: number }): void {
  const errors = result.issues.filter((i) => i.kind === "error");
  if (result.succeeded === 0 && errors.length > 0) {
    printIssues(opts, result.issues);
    // 表格模式下每条问题已逐行打印，这里只给结论；JSON 模式在 message 里带上错误明细、issues 里带上全部问题
    const message = opts.json
      ? `没有任何查询成功：${errors.map((e) => `${e.provider}/${e.service} ${e.code} ${e.message}`).join("；")}`
      : `没有任何查询成功（${errors.length} 项失败），请检查凭证与权限`;
    fail(opts, errors[0]!.code, message, 1, { issues: result.issues });
  }
}

/**
 * 只有「所有查询都失败」才算命令失败；部分失败照常输出数据，问题在数据之后输出到 stderr，
 * JSON 模式下放在 data.issues 里。
 */
function emit<T>(opts: OutputOptions, result: { issues: QueryIssue[]; succeeded: number }, items: T[], render: () => string): void {
  failIfNoneSucceeded(opts, result);
  if (opts.json) outJson({ items, issues: result.issues });
  else console.log(render());
  printIssues(opts, result.issues);
}

/** 读取 --cert / --key 指定的文件，路径相对当前目录；报错只带路径，不带文件内容 */
function readInput(deps: Deps, flag: string, path: string): string {
  const abs = resolve(deps.cwd, path);
  try {
    return (deps.readFile ?? ((p: string) => readFileSync(p, "utf8")))(abs);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT") throw new UsageError(`${flag} 指定的文件不存在：${abs}`);
    throw new UsageError(`${flag} 指定的文件无法读取：${abs}（${code ?? (e as Error).message}）`);
  }
}

/** 输出给调用方的报告：去掉内部的查询成功计数 */
function deployData(r: DeployReport) {
  return { dryRun: r.dryRun, cert: r.cert, uploads: r.uploads, results: r.results, issues: r.issues };
}

/**
 * 有任一域名失败、或所有查询都失败即 exit 1：JSON 模式把完整报告平铺在 stderr 的错误对象里，调用方仍能逐个域名判断
 * （所有查询都失败时点名的域名也有逐条的失败结果）
 */
function emitDeploy(opts: OutputOptions, report: DeployReport): void {
  const failed = report.results.filter((r) => r.action === "failed");
  const errors = report.issues.filter((i) => i.kind === "error");
  const noneSucceeded = report.succeeded === 0 && errors.length > 0;
  if (failed.length > 0 || noneSucceeded) {
    // 查询全部失败且没有逐条结果时不打印表格：「在所选云厂商上没有找到」会误导
    if (!opts.json && report.results.length > 0) console.log(renderDeploy(report));
    printIssues(opts, report.issues);
    const parts: string[] = [];
    if (noneSucceeded) {
      // 表格模式下每条问题已逐行打印，这里只给结论；JSON 模式在 message 里带上错误明细
      parts.push(
        opts.json
          ? `没有任何查询成功：${errors.map((e) => `${e.provider}/${e.service}${e.target ? ` ${e.target}` : ""} ${e.code} ${e.message}`).join("；")}`
          : `没有任何查询成功（${errors.length} 项失败），请检查凭证与权限`,
      );
    }
    if (failed.length > 0) {
      const head = `${failed.length} 个域名部署失败${report.dryRun ? "（--dry-run 预览，未做任何修改）" : ""}`;
      parts.push(opts.json ? `${head}：${failed.map((r) => `${r.provider ? `${r.provider}/${r.service} ` : ""}${r.domain} ${r.code}`).join("；")}` : head);
    }
    fail(opts, "DeployFailed", parts.join("。"), 1, deployData(report));
  }
  if (opts.json) outJson(deployData(report));
  else console.log(renderDeploy(report));
  printIssues(opts, report.issues);
}

/** 人在终端运行时：列出需确认的域名当场询问，同意则等同 --force 重新出计划（复用同一份查询结果） */
async function confirmEarly(confirm: NonNullable<Deps["confirm"]>, plan: DeployPlan, forced: () => DeployPlan): Promise<DeployPlan> {
  const due = plan.report.results.filter((r) => r.needsConfirm);
  if (due.length === 0) return plan;
  console.log(renderConfirm(due));
  return (await confirm(`以上 ${due.length} 个域名的当前证书未到更新时间，是否提前更换？[y/N]`)) ? forced() : plan;
}

const DEPLOY_DESCRIPTION = `把本地证书（fullchain + 私钥）部署到云服务上被它覆盖的域名，或替换这些域名上快到期的旧证书。
会修改云上配置（只改 HTTPS 证书，不动其他配置，不删除旧证书），建议先加 --dry-run 预览。

部署规则：
  - 只处理证书覆盖的域名：与证书 SAN 精确匹配，*.example.com 只覆盖一级子域（不含 example.com 本身）
  - 已开启 HTTPS 的域名：当前证书 30 天内到期（含已过期）时直接替换；还有 30 天以上、查不到到期时间、比新证书还晚、
    或与新证书同时到期但签发时间不同（重签的证书）时跳过并标记 needsConfirm，须先向用户确认，
    用户同意后加 --force 重新执行（可配合 -d 只针对这些域名）
  - 未开启 HTTPS 的域名默认不动；用 -d 点名后部署并开启 HTTPS
  - 已是这张证书的域名自动跳过，重复执行是安全的
  - 证书挂在多条记录共享的配置上（如阿里云 ESA 站点）时，同组被证书覆盖的记录要么一起更新、要么都不动
  - 查询失败、无法判断 HTTPS 现状的域名不做修改，记为失败（可稍后重试）
  - 人在终端里直接运行（非 --json）时，会列出需确认的域名并当场询问是否提前更换`;

const DEPLOY_HELP_AFTER = `
--json 结果：data.results 每项对应一个域名，action 为 deployed / updated / would_deploy / would_update / skipped / failed；
skipped 的 reason 为跳过原因，needsConfirm: true 的须先问用户；failed 带 code、requestId，retryable 表示能否原样重试。

跳过原因（reason）：
  platform_managed     平台默认域名，由云厂商提供证书
  unsupported          该服务 / 记录不支持通过 CLI 部署（message 写明原因）
  https_off            未开启 HTTPS 且未用 -d 点名
  already_current      已是这张证书（查不到当前证书的算法时无法区分同期签发的 RSA / ECC 两张，用 -d 点名并加 --force 可强制替换）
  unknown_expiry       查不到当前证书的到期时间（需确认）
  newer_current        当前证书比新证书到期还晚（需确认）
  not_due              当前证书还有 30 天以上才到期（需确认）
  same_expiry          当前证书与新证书到期时间相同，但签发时间或算法不同（如重签的证书、RSA 换 ECC）（需确认）
  shared_cert_blocked  证书挂在共享的配置上，同组有记录挡住了更新；message 列出挡住的记录与放行方法
需确认的跳过带 needsConfirm: true：须先向用户确认，用户同意后加 --force 重新执行。

failed 的常见 code：HttpsStateUnknown（查询该域名的 HTTPS 配置失败，无法判断现状，未做修改，可稍后重试）、
DomainNotFound（-d 点名的域名在所选云厂商 / 服务上找不到）、NotCovered（-d 点名的域名不被证书覆盖）、
CertWithoutCommonName（该服务不接受没有 CN 的证书，如 Let's Encrypt shortlived / tlsserver 证书，请改用带 CN 的证书）、
HttpsAlreadyEnabled / HttpsDisabled（写入前发现 HTTPS 已开启 / 关闭，与查询时不同，未做修改，重新执行即可），其余为云接口的错误码。

退出码：
  0  没有失败（全部成功或跳过，包括什么都没改）
  1  有域名部署失败，或所有查询都失败（--json 时 stderr 输出 {"ok":false,"status":"DeployFailed",...}，带完整的 results、issues）
  2  参数、证书文件或凭证配置错误（未做任何修改）

示例：
  sslbear-cli deploy --cert fullchain.pem --key privkey.pem --dry-run
  sslbear-cli deploy --cert fullchain.pem --key privkey.pem --json
  sslbear-cli deploy --cert fullchain.pem --key privkey.pem -d www.example.com,api.example.com --force --json`;

export function buildProgram(deps: Deps, output: OutputOptions = { json: false }): Command {
  const program = new Command("sslbear-cli")
    .description("证书熊 CLI：查询阿里云、腾讯云、火山引擎、华为云、百度智能云、七牛云等云服务上的域名及其 SSL 证书，并可把本地证书部署 / 更新到这些域名（凭证从环境变量读取）")
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
    program.command("certs").description("列出各云厂商证书服务中的证书（如阿里云数字证书管理服务、腾讯云 SSL 证书），按剩余天数升序"),
  ).action(async (opts: QueryOpts) => {
    const out = { json: !!opts.json };
    const ctx = createContext(deps, opts);
    const result = await queryCertificates(ctx, { providers: validateProviders(opts.provider) });
    const items = filterCertificates(result.items, { keyword: opts.domain, expiringWithin: opts.expiringWithin });
    emit(out, result, items, () => renderCerts(items, opts.expiringWithin));
  });

  withCommon(
    program
      .command("deploy")
      .summary("把本地证书部署到云服务上被它覆盖的域名，或替换快到期的旧证书（会修改云上配置）")
      .description(DEPLOY_DESCRIPTION)
      .requiredOption("--cert <path>", "证书文件（PEM，叶子证书 + 中间证书链，如 fullchain.pem）")
      .requiredOption("--key <path>", "私钥文件（PEM，RSA 或 ECC，不支持加密私钥）")
      .option("-p, --provider <list>", `只处理指定云厂商，逗号分隔（${PROVIDERS.join(", ")}）；默认为所有已配置凭证的云厂商`, csv)
      .option("-s, --service <list>", `只处理指定服务，逗号分隔（取值同 domains）。${serviceHelp}`, csv)
      .option("-d, --domain <list>", "只处理这些域名（精确匹配，逗号分隔，可重复）；点名的域名没开 HTTPS 时会部署并开启。与 domains 命令的 -d（关键字过滤）不同", csv)
      .option("--force", "当前证书还有 30 天以上才到期（或到期时间查不到、比新证书还晚、与新证书同时到期但签发时间不同）时也替换；AI 调用前须先向用户确认")
      .option("--dry-run", "只输出计划，不做任何写操作（也不上传证书）"),
  )
    .addHelpText("after", DEPLOY_HELP_AFTER)
    .action(async (opts: DeployCliOpts) => {
      const out = { json: !!opts.json };
      const defs = deps.defs ?? PROVIDER_DEFS;
      // -p / -s / -d 写了但解析为空（如 -d ","、-p ""）时不能退化成处理全部
      if (opts.provider?.length === 0) throw new UsageError("--provider 不能为空");
      if (opts.service?.length === 0) throw new UsageError("--service 不能为空");
      if (opts.domain?.length === 0) throw new UsageError("--domain 不能为空");
      const sel: DeployOptions = {
        providers: validateProviders(opts.provider),
        services: validateServices(opts.service),
        ...(opts.domain && { domains: [...new Set(opts.domain)] }),
        force: !!opts.force,
        dryRun: !!opts.dryRun,
      };
      const ctx = createContext(deps, opts);
      const cert = loadLocalCert(readInput(deps, "--cert", opts.cert), readInput(deps, "--key", opts.key), ctx.now);
      // 所有查询都失败也照常出计划：点名的域名得到逐条的失败结果，由 emitDeploy 以 DeployFailed + 完整报告退出
      const query = await queryForDeploy(ctx, sel, defs);
      let plan = buildPlan(ctx, cert, sel, query, defs);
      if (!out.json && !sel.dryRun && !sel.force && deps.confirm) {
        plan = await confirmEarly(deps.confirm, plan, () => buildPlan(ctx, cert, { ...sel, force: true }, query, defs));
      }
      emitDeploy(out, sel.dryRun ? plan.report : await executeDeploy(ctx, cert, plan));
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
