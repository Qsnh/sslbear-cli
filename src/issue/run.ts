import type { KeyObject } from "node:crypto";
import { join } from "node:path";
import { loadLocalCert, type LocalCert } from "../deploy/cert.js";
import type { DnsDefs } from "../dns/index.js";
import type { TxtRecord } from "../dns/types.js";
import { CloudApiError, isRetryable, isRetryableCode, type QueryContext } from "../lib/http.js";
import { UsageError } from "../query.js";
import type { DnsVendor } from "../types.js";
import { ariCertId, buildCsr } from "./csr.js";
import { certDirName } from "./domains.js";
import { PropagationTimeout, waitForTxt, type DnsLookup, type PropagationZone } from "./propagation.js";
import {
  assertWritable,
  canReuse,
  CERT_FILE,
  KEY_FILE,
  loadAccountKey,
  readExisting,
  stateRoot,
  writeCertFiles,
  type ExistingCert,
} from "./store.js";
import {
  AcmeError,
  LETSENCRYPT_DIRECTORY,
  LETSENCRYPT_STAGING_DIRECTORY,
  type AcmeClient,
  type AcmeOrder,
  type KeyType,
} from "./types.js";
import { findZones, resolveDnsTargets, ZoneError, type DnsIssue, type ZoneMatch } from "./zones.js";

export interface IssueOptions {
  /** 已规范化、去重的域名，第一个为 CN */
  domains: string[];
  keyType: KeyType;
  /** --out 的绝对路径；缺省为 <状态目录>/certs/<目录名> */
  out?: string;
  /** --dns 显式指定的服务商；缺省为所有已配置凭证的 */
  dns?: DnsVendor[];
  email?: string;
  staging: boolean;
  force: boolean;
  dryRun: boolean;
  dnsTimeoutMs: number;
}

export type AcmeFactory = (ctx: QueryContext, opts: { directoryUrl: string; accountKey: KeyObject }) => Promise<AcmeClient>;

export interface IssueDeps {
  /** 用户主目录：状态目录默认在 <主目录>/.sslbear-cli */
  home: string;
  cwd: string;
  dnsDefs: DnsDefs;
  dnsLookup: DnsLookup;
  acme: AcmeFactory;
  generateKey: (type: KeyType) => KeyObject;
  /** 人在终端运行时每一步打一行进度（写 stderr）；--json 时不传 */
  progress?: (message: string) => void;
  /** 进程被 Ctrl+C / kill 时先清理再退出：加 TXT 记录前登记，清理完成后撤销（返回撤销登记的函数）。测试不传 */
  trapInterrupt?: (hooks: InterruptHooks) => () => void;
}

/** 中止时用：先 cleanup，来不及完成时退而用 snapshot 输出现状 */
export interface InterruptHooks {
  /** 停止再加新记录，等正在进行的添加结束，删除本次加的记录，返回最终的 dns[] 与 issues[] */
  cleanup(): Promise<RunState>;
  /** 清理没来得及完成时的现状：还没确认删除的记录标 cleaned: false 并说明怎么手动删 */
  snapshot(): RunState;
}

/** 收到中止信号后正常流程不再输出任何结果：中止的结果已由信号处理输出，进程随后退出 */
export class IssueAborted extends Error {
  constructor() {
    super("签发被中止");
    this.name = "IssueAborted";
  }
}

/** 一个需要验证的域名对应的 TXT 记录；--dry-run 时没有 cleaned */
export interface DnsResult {
  domain: string;
  provider: DnsVendor;
  zone: string;
  record: string;
  /** 本次加的值已删除；false 时 message 写明原因，需要用户手动删除 */
  cleaned?: boolean;
  message?: string;
}

export type IssuedCert = Pick<LocalCert, "commonName" | "sans" | "notBefore" | "notAfter" | "algorithm" | "fingerprint" | "issuer">;

export interface IssueReport {
  dryRun: boolean;
  reused: boolean;
  staging: boolean;
  files: { cert: string; key: string };
  /** 复用或签发成功时有；--dry-run 只在复用时有 */
  cert?: IssuedCert;
  dns: DnsResult[];
  issues: DnsIssue[];
}

/** 签发失败：status 见设计文档的 status 表，extra 平铺进 stderr 的错误 JSON（含已知的 dns、issues） */
export class IssueError extends Error {
  constructor(
    public status: string,
    message: string,
    public extra: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "IssueError";
  }
}

/** 授权验证、finalize 的轮询上限：Let's Encrypt 通常几秒到几十秒 */
export const AUTHZ_TIMEOUT_MS = 120_000;
export const FINALIZE_TIMEOUT_MS = 120_000;

const realSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export function certInfo(c: LocalCert): IssuedCert {
  return {
    ...(c.commonName && { commonName: c.commonName }),
    sans: c.sans,
    notBefore: c.notBefore,
    notAfter: c.notAfter,
    algorithm: c.algorithm,
    fingerprint: c.fingerprint,
    ...(c.issuer && { issuer: c.issuer }),
  };
}

function acmeFailure(e: AcmeError): IssueError {
  if (e.type === "rateLimited") {
    const after = e.retryAfter !== undefined ? `，约 ${e.retryAfter} 秒后可重试` : "";
    return new IssueError("AcmeRateLimited", `触发 Let's Encrypt 频率限制${after}：${e.detail}`, {
      retryable: true,
      ...(e.retryAfter !== undefined && { retryAfter: e.retryAfter }),
    });
  }
  const sub = e.subproblems?.length ? `（${e.subproblems.join("；")}）` : "";
  return new IssueError("AcmeError", `ACME 错误（${e.type}）：${e.detail}${sub}`, { retryable: e.retryable, acmeType: e.type });
}

/** _acme-challenge 已有 CNAME（DNS 别名模式）时各家接口会报冲突，提示里点明原因 */
function cnameHint(e: unknown): string {
  const text = e instanceof Error ? `${(e as CloudApiError).code ?? ""} ${e.message}` : "";
  return /cname/i.test(text) ? "（该名字下可能已有 CNAME 记录：不支持 _acme-challenge 的 DNS 别名模式，删除该 CNAME 后重试）" : "";
}

const rid = (e: unknown) => (e instanceof CloudApiError && e.requestId ? `（RequestId: ${e.requestId}）` : "");
const errText = (e: unknown) => (e instanceof CloudApiError ? `${e.code} ${e.message}` : String((e as Error)?.message ?? e));

/** 已添加、待清理的一条记录 */
interface Added {
  match: ZoneMatch;
  record: TxtRecord;
  handle: string;
  result: DnsResult;
}

/** 与中止信号共享的状态 */
interface Control {
  aborted: boolean;
  /** 正在进行的那次添加 */
  inflight?: Promise<unknown>;
  /** 每条记录没删掉时给用户的手动删除说明（中止时来不及确认删除的用） */
  manual: Map<DnsResult, string>;
}

/** 服务商报已存在却查不到记录（RecordMayExist）、超时 / 网络错误：记录可能已经加上了，但没有句柄删不掉 */
function maybeAdded(e: unknown): boolean {
  return isRetryable(e) || (e instanceof CloudApiError && e.code === "RecordMayExist");
}

interface Challenge {
  domain: string;
  authzUrl: string;
  challengeUrl: string;
  token: string;
  match: ZoneMatch;
}

/** 本次运行累积的、失败时也要输出的状态 */
export interface RunState {
  dns: DnsResult[];
  issues: DnsIssue[];
}

/**
 * 签发一张证书。参数已由 cli 校验；凭证问题、保存目录不可写抛 UsageError（此时还没调用任何接口），
 * 其余失败抛 IssueError。无论成败，本次添加的 TXT 记录都会在返回前逐条删除，删除结果在 dns[] 里。
 */
export async function runIssue(ctx: QueryContext, opts: IssueOptions, deps: IssueDeps): Promise<IssueReport> {
  const say = deps.progress ?? (() => {});
  // 1. 凭证（参数错误在这之前已由 cli 拦下）
  const { targets, issues } = resolveDnsTargets(ctx.env, deps.dnsDefs, opts.dns);
  const state: RunState = { dns: [], issues };
  const root = stateRoot(ctx.env, deps.home, deps.cwd);
  const dir = opts.out ?? join(root, "certs", certDirName(opts.domains[0]!, opts.keyType, opts.staging));
  const files = { cert: join(dir, CERT_FILE), key: join(dir, KEY_FILE) };
  const report = (r: Pick<IssueReport, "reused" | "cert" | "dns">): IssueReport => ({ dryRun: opts.dryRun, staging: opts.staging, files, ...r, issues });

  // 2. 复用检查（不联网）：重复执行不浪费 Let's Encrypt 配额，--dry-run 也一样
  const existing = readExisting(dir, ctx.now);
  if (!opts.force && existing.valid && canReuse(existing.valid, { ...opts, now: ctx.now })) {
    return report({ reused: true, cert: certInfo(existing.valid), dns: [] });
  }
  // 默认目录名已区分环境；--out 指到正式证书所在的目录时也绝不能让测试证书覆盖它
  if (opts.staging && existing.leaf && !existing.leaf.staging) {
    throw new UsageError(`${dir} 里已有正式环境的证书，--staging 签发的测试证书不会覆盖它；请换一个 --out 目录`);
  }
  assertWritable(dir);
  const directoryUrl = opts.staging ? LETSENCRYPT_STAGING_DIRECTORY : LETSENCRYPT_DIRECTORY;
  // 联网之前就读出（或生成）账号私钥：文件损坏是本地问题（UsageError，exit 2），不该等调用过 DNS 接口才发现
  const account = opts.dryRun ? undefined : loadAccountKey(root, directoryUrl);

  try {
    // 3. 查找 zone
    say("查找各域名所在的 DNS 服务商…");
    const found = await findZones(ctx, deps.dnsLookup, targets, opts.domains).catch((e: unknown) => {
      if (!(e instanceof ZoneError)) throw e;
      issues.push(...e.issues);
      // 有服务商因网络、限流列 zone 失败时，稍后重试可能就找到了
      const retryable = e.status === "ZoneNotFound" && e.issues.some((i) => isRetryableCode(i.code));
      throw new IssueError(e.status, e.message, { retryable, ...e.extra });
    });
    issues.push(...found.issues);
    for (const m of found.matches) say(`${m.domain} 由 ${m.target.def.label} 解析（zone ${m.zone.name}）`);

    // 4. --dry-run 到此为止
    if (opts.dryRun) {
      const dns = found.matches.map((m) => ({ domain: m.domain, provider: m.target.def.vendor, zone: m.zone.name, record: m.record }));
      return report({ reused: false, dns });
    }

    const cert = await issue(ctx, opts, deps, { directoryUrl, account: account!, dir, existing, matches: found.matches, state, say });
    writeCertFiles(dir, cert);
    say(`证书已保存到 ${dir}`);
    return report({ reused: false, cert: certInfo(cert), dns: state.dns });
  } catch (e) {
    throw withState(e, state);
  }
}

function asIssueError(e: unknown): IssueError {
  if (e instanceof IssueError) return e;
  if (e instanceof AcmeError) return acmeFailure(e);
  return new IssueError("Unknown", String((e as Error)?.message ?? e), { retryable: false });
}

/** 失败输出统一带上已知的 dns、issues；UsageError 原样抛出（exit 2） */
function withState(e: unknown, state: RunState): unknown {
  if (e instanceof UsageError || e instanceof IssueAborted) return e;
  const err = asIssueError(e);
  err.extra = { ...err.extra, dns: state.dns, issues: state.issues };
  return err;
}

/** 本次加的记录清理得怎样，接在失败 message 末尾：表格模式下用户只看得到 message */
export function cleanupNote(dns: DnsResult[]): string {
  const left = dns.filter((d) => d.cleaned !== true).length;
  return left > 0 ? `有 ${left} 条 TXT 记录可能残留，需要手动删除（见 dns）` : `本次添加的 ${dns.length} 条 TXT 记录已删除`;
}

function withCleanup(e: unknown, dns: DnsResult[]): unknown {
  if (e instanceof UsageError || e instanceof IssueAborted || dns.length === 0) return e;
  const err = asIssueError(e);
  return new IssueError(err.status, `${err.message}；${cleanupNote(dns)}`, err.extra);
}

interface IssueCtx {
  directoryUrl: string;
  account: ReturnType<typeof loadAccountKey>;
  dir: string;
  existing: ExistingCert;
  matches: ZoneMatch[];
  state: RunState;
  say: (message: string) => void;
}

/** 第 5~10 步：下单、设置 DNS、等生效、验证、清理、finalize、下载并校验 */
async function issue(ctx: QueryContext, opts: IssueOptions, deps: IssueDeps, ic: IssueCtx): Promise<LocalCert> {
  const { say } = ic;
  const { directoryUrl, account } = ic;
  const client = await deps.acme(ctx, { directoryUrl, accountKey: account.key });
  const ca = `Let's Encrypt ${opts.staging ? "测试环境" : ""}账号`;
  const tos = client.directory.termsOfService ? `：${client.directory.termsOfService}` : "";
  say(account.created ? `注册 ${ca}（即同意其订阅协议${tos}）…` : `使用已有的 ${ca}（${account.path}）`);
  await client.ensureAccount(opts.email);

  // 5. 下单
  let order = await placeOrder(client, opts, ic);

  // 6~8. 设置 DNS、等生效、验证；无论成败都先清理再往下走
  const added: Added[] = [];
  const control: Control = { aborted: false, manual: new Map() };
  // 正常流程与中断信号可能同时触发清理，只跑一次：记录集模型的服务商读改写不能并发
  let cleaning: Promise<void> | undefined;
  const cleanupOnce = () => (cleaning ??= cleanup(ctx, added, say));
  const untrap = deps.trapInterrupt?.({
    async cleanup() {
      control.aborted = true;
      // 正在进行的添加可能已在服务商那边生效：等它结束、拿到句柄再一起删，否则会漏删
      await control.inflight?.catch(() => {});
      await cleanupOnce();
      return ic.state;
    },
    snapshot: () => ({
      issues: ic.state.issues,
      dns: ic.state.dns.map((d) => (d.cleaned === undefined ? { ...d, cleaned: false, message: control.manual.get(d) } : d)),
    }),
  });
  let failure: { error: unknown } | undefined;
  try {
    const challenges = await pendingChallenges(client, order, ic);
    await addRecords(ctx, client, challenges, added, ic, control);
    if (added.length > 0) await propagate(deps, added, opts, ctx, say);
    // 已中止时不再通知验证：记录已经（或正在）删除，验证必然失败，白白消耗 Let's Encrypt 的验证失败配额
    if (control.aborted) throw new IssueAborted();
    await validate(client, challenges, say);
  } catch (error) {
    failure = { error };
  }
  // 9. 清理：只删本次加的值，失败不影响签发结果，但要在 dns[] 里写明
  await cleanupOnce();
  untrap?.();
  if (control.aborted) throw new IssueAborted();
  if (failure) throw withCleanup(failure.error, ic.state.dns);

  // 10. 签发
  say("生成证书私钥并提交 CSR…");
  const key = deps.generateKey(opts.keyType);
  order = await client.finalize(order, buildCsr(key, opts.domains), FINALIZE_TIMEOUT_MS);
  if (!order.certificate) throw new IssueError("AcmeError", "订单已完成，但 CA 没有返回证书下载地址", { retryable: true, acmeType: "noCertificate" });
  say("下载证书…");
  const pem = await client.downloadCertificate(order.certificate);
  return verifyIssued(pem, key, opts.domains, ctx.now);
}

/** ARI 续签标识：保存目录里有同为正式 / 测试环境、与本次至少有一个相同域名的旧证书（CA 只接受这样的 replaces） */
function renewalId(existing: ExistingCert, opts: IssueOptions): string | undefined {
  const leaf = existing.leaf;
  if (!leaf || leaf.staging !== opts.staging || !leaf.sans.some((d) => opts.domains.includes(d))) return undefined;
  try {
    return ariCertId(leaf.pem);
  } catch {
    // 算不出来（如证书没有 AKI）就当作新签：replaces 只影响续签配额，不影响能否签发
    return undefined;
  }
}

async function placeOrder(client: AcmeClient, opts: IssueOptions, ic: IssueCtx): Promise<AcmeOrder> {
  // 显式要 classic：保证证书带 CN（国内多数云服务拒收没有 CN 的证书），不受 CA 默认配置文件变化的影响
  const profile = client.directory.profiles && "classic" in client.directory.profiles ? "classic" : undefined;
  const replaces = client.directory.renewalInfo ? renewalId(ic.existing, opts) : undefined;
  ic.say(`向 Let's Encrypt 下单${replaces ? "（续签）" : ""}…`);
  try {
    return await client.newOrder(opts.domains, { ...(profile && { profile }), ...(replaces && { replaces }) });
  } catch (e) {
    // 旧证书已被续签过、不是这个账号签的等都会让带 replaces 的订单被拒：去掉它重试一次。限流时重试没有意义
    if (!replaces || (e instanceof AcmeError && e.type === "rateLimited")) throw e;
    ic.say(`带续签标识下单失败（${(e as Error).message}），去掉后重试…`);
    return client.newOrder(opts.domains, profile ? { profile } : {});
  }
}

/** 取每个待验证授权的 dns-01 质询；已是 valid 的（CA 复用了近期的验证）跳过 */
async function pendingChallenges(client: AcmeClient, order: AcmeOrder, ic: IssueCtx): Promise<Challenge[]> {
  const list: Challenge[] = [];
  for (const url of order.authorizations) {
    const authz = await client.getAuthorization(url);
    const domain = authz.wildcard ? `*.${authz.domain}` : authz.domain;
    if (authz.status === "valid") {
      ic.say(`${domain} 已有有效的验证，跳过`);
      continue;
    }
    const match = ic.matches.find((m) => m.domain === domain);
    if (authz.status !== "pending" || !authz.challenge || !match) {
      const why = !match ? "不在本次申请的域名里" : !authz.challenge ? "没有 dns-01 质询" : `状态为 ${authz.status}`;
      throw new IssueError("AcmeError", `CA 返回的授权 ${domain} ${why}`, { retryable: false, acmeType: "unexpectedAuthorization" });
    }
    list.push({ domain, authzUrl: url, challengeUrl: authz.challenge.url, token: authz.challenge.token, match });
  }
  // CA 返回授权的顺序不一定与申请时相同：按 -d 的顺序加记录、输出 dns[]，结果稳定可比
  const rank = (c: Challenge) => ic.matches.indexOf(c.match);
  return list.sort((a, b) => rank(a) - rank(b));
}

/**
 * 串行添加：同名记录集（根域名与泛域名共用 _acme-challenge.example.com）的读改写不能并发。
 * 每条记录在调用服务商之前就记进 dns[]（没有 cleaned）：中止时来不及确认的也能列出来让用户核对
 */
async function addRecords(ctx: QueryContext, client: AcmeClient, challenges: Challenge[], added: Added[], ic: IssueCtx, control: Control): Promise<void> {
  for (const c of challenges) {
    if (control.aborted) throw new IssueAborted();
    const { def, creds } = c.match.target;
    const record: TxtRecord = { zone: c.match.zone, fqdn: c.match.record, value: client.dnsTxtValue(c.token) };
    const result: DnsResult = { domain: c.domain, provider: def.vendor, zone: c.match.zone.name, record: record.fqdn };
    ic.state.dns.push(result);
    control.manual.set(result, `请到 ${def.label} 核对 ${record.fqdn} 下值为 "${record.value}" 的 TXT 记录，存在就手动删除`);
    try {
      // 先登记再调用：信号可能在 addTxt 同步执行的那一段里到达，登记晚了中止清理就不会等它
      const adding = Promise.resolve().then(() => def.addTxt(ctx, creds, record));
      control.inflight = adding;
      const handle = await adding;
      added.push({ match: c.match, record, handle, result });
      ic.say(`已在 ${def.label} 添加 ${record.fqdn}`);
    } catch (e) {
      if (maybeAdded(e)) {
        Object.assign(result, { cleaned: false, message: `添加时${errText(e)}，服务商可能已添加成功；${control.manual.get(result)}` });
      } else {
        // 服务商明确拒绝（如缺权限）：没加上，不用列出来
        ic.state.dns.splice(ic.state.dns.indexOf(result), 1);
      }
      const code = e instanceof CloudApiError ? e.code : "Unknown";
      throw new IssueError("DnsRecordFailed", `在 ${def.label} 添加 ${record.fqdn} 失败：${errText(e)}${rid(e)}${cnameHint(e)}`, {
        retryable: maybeAdded(e),
        provider: def.vendor,
        code,
        ...(e instanceof CloudApiError && e.requestId && { requestId: e.requestId }),
      });
    } finally {
      control.inflight = undefined;
    }
  }
}

/** 按 zone 归并本次加的记录，等它们在权威 DNS 上生效 */
async function propagate(deps: IssueDeps, added: Added[], opts: IssueOptions, ctx: QueryContext, say: (m: string) => void): Promise<void> {
  const zones = new Map<string, PropagationZone>();
  for (const a of added) {
    const { zone } = a.match;
    let z = zones.get(zone.name);
    if (!z) {
      const def = a.match.target.def;
      z = { zone: zone.name, label: def.label, nameServerPattern: def.nameServerPattern, records: [], ...(zone.nameServers && { nameServers: zone.nameServers }) };
      zones.set(zone.name, z);
    }
    const rec = z.records.find((r) => r.fqdn === a.record.fqdn);
    if (rec) rec.values.push(a.record.value);
    else z.records.push({ fqdn: a.record.fqdn, values: [a.record.value] });
  }
  say(`等待 DNS 生效（最长 ${opts.dnsTimeoutMs / 1000} 秒）…`);
  try {
    await waitForTxt(deps.dnsLookup, [...zones.values()], { timeoutMs: opts.dnsTimeoutMs, sleep: ctx.sleep ?? realSleep, progress: say });
  } catch (e) {
    if (e instanceof PropagationTimeout) throw new IssueError("DnsPropagationTimeout", e.message, { retryable: true });
    throw e;
  }
}

/** 先逐个通知质询（CA 可以并行验证），再逐个轮询授权直到 valid */
async function validate(client: AcmeClient, challenges: Challenge[], say: (m: string) => void): Promise<void> {
  if (challenges.length === 0) return;
  for (const c of challenges) await client.answerChallenge(c.challengeUrl);
  say("已通知 CA 验证，等待结果…");
  for (const c of challenges) {
    try {
      await client.waitAuthorization(c.authzUrl, AUTHZ_TIMEOUT_MS);
    } catch (e) {
      // 只有授权变成 invalid 才是验证没通过；网络错误、授权过期、请求被拒等按普通 ACME 错误处理（授权过期重跑就会重新下单）
      if (e instanceof AcmeError && e.invalidAuthorization) {
        throw new IssueError("AcmeChallengeFailed", `CA 验证 ${c.domain} 失败（${e.type}）：${e.detail}`, {
          retryable: false,
          domain: c.domain,
          acmeType: e.type,
          detail: e.detail,
        });
      }
      throw e;
    }
    say(`验证通过：${c.domain}`);
  }
}

/** 逐条删除本次加的记录；单条失败只记在 dns[] 里，不抛错 */
async function cleanup(ctx: QueryContext, added: Added[], say: (m: string) => void): Promise<void> {
  for (const a of added) {
    const { def, creds } = a.match.target;
    try {
      await def.removeTxt(ctx, creds, a.record, a.handle);
      a.result.cleaned = true;
      say(`已从 ${def.label} 删除 ${a.record.fqdn}`);
    } catch (e) {
      a.result.cleaned = false;
      a.result.message = `删除失败：${errText(e)}${rid(e)}；请到 ${def.label} 手动删除 ${a.record.fqdn} 下值为 "${a.record.value}" 的 TXT 记录`;
      say(`警告：从 ${def.label} 删除 ${a.record.fqdn} 失败，需要手动删除`);
    }
  }
}

/** CA 返回的证书链：链齐全、与私钥匹配、在有效期内，且覆盖的正是本次申请的域名 */
function verifyIssued(pem: string, key: KeyObject, domains: readonly string[], now: Date): LocalCert {
  let cert: LocalCert;
  try {
    cert = loadLocalCert(pem, key.export({ type: "pkcs8", format: "pem" }) as string, now);
  } catch (e) {
    throw new IssueError("AcmeError", `CA 返回的证书没有通过校验：${(e as Error).message}`, { retryable: false, acmeType: "badCertificate" });
  }
  const missing = domains.filter((d) => !cert.sans.includes(d));
  if (missing.length > 0) {
    throw new IssueError("AcmeError", `CA 返回的证书没有覆盖 ${missing.join(", ")}`, { retryable: false, acmeType: "badCertificate" });
  }
  return cert;
}
