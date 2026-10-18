import { CloudApiError, isRetryable, isRetryableCode, type QueryContext } from "../lib/http.js";
import { mapLimit } from "../lib/pool.js";
import { PROVIDER_DEFS, queryDomains, resolveTargets, type DomainQueryResult, type ProviderDefs, type QueryIssue } from "../query.js";
import type { DeployTarget, DomainService, ProviderDef } from "../providers/registry.js";
import type { CertInfo, DomainRecord, Provider } from "../types.js";
import { certCovers, normalizeDomain, type LocalCert } from "./cert.js";
import { CONFIRM_HINT, decide, type Decision, type SkipReason } from "./plan.js";

export interface DeployOptions {
  providers?: Provider[];
  services?: string[];
  /** --domain 点名的域名（精确匹配） */
  domains?: string[];
  force: boolean;
  dryRun: boolean;
}

export interface DeployResult {
  /** 点名的域名在所有服务上都找不到时没有 provider / service */
  provider?: Provider;
  service?: string;
  domain: string;
  action: "deployed" | "updated" | "would_deploy" | "would_update" | "skipped" | "failed";
  reason?: SkipReason;
  message?: string;
  needsConfirm?: true;
  before?: CertInfo & { daysLeft?: number };
  after?: { id?: string; notAfter: string };
  code?: string;
  requestId?: string;
  retryable?: boolean;
}

export interface DeployReport {
  dryRun: boolean;
  cert: Pick<LocalCert, "commonName" | "sans" | "notAfter" | "algorithm" | "fingerprint">;
  uploads: { provider: Provider; certId: string; reused: boolean }[];
  results: DeployResult[];
  issues: QueryIssue[];
  /** 查询成功的服务数，为 0 且有错误即视为全部查询失败 */
  succeeded: number;
}

interface PendingItem {
  def: ProviderDef<unknown>;
  creds: unknown;
  service: DomainService<unknown>;
  target: DeployTarget;
  /** 组内每条记录对应的结果，执行后就地更新 */
  results: DeployResult[];
}

export interface DeployPlan {
  report: DeployReport;
  pending: PendingItem[];
}

const UNSUPPORTED_SERVICE = "该服务暂不支持通过 CLI 部署证书";

const HTTPS_UNKNOWN = "查询该域名的 HTTPS 配置失败（见 issues），无法判断现状，未做修改；可稍后重试";

interface Candidate {
  record: DomainRecord;
  service: DomainService<unknown>;
  decision: Decision;
  /** 在本次处理范围内（未用 -d，或被 -d 点名） */
  inScope: boolean;
  /** 查询失败导致不知道是否开着 HTTPS / 绑着什么证书（extra.httpsUnknown），不能做任何决定 */
  httpsUnknown: boolean;
}

function before(d: Decision): DeployResult["before"] {
  return d.oldCert ? { ...d.oldCert, ...(d.oldDaysLeft !== undefined && { daysLeft: d.oldDaysLeft }) } : undefined;
}

function skipped(r: DomainRecord, d: Decision): DeployResult {
  return {
    provider: r.provider,
    service: r.service,
    domain: r.domain,
    action: "skipped",
    ...(d.reason && { reason: d.reason }),
    ...(d.message && { message: d.message }),
    ...(d.needsConfirm && { needsConfirm: true as const }),
    ...(d.oldCert && { before: before(d) }),
  };
}

function planned(r: DomainRecord, d: Decision, cert: LocalCert): DeployResult {
  return {
    provider: r.provider,
    service: r.service,
    domain: r.domain,
    action: d.kind === "deploy" ? "would_deploy" : "would_update",
    ...(d.oldCert && { before: before(d) }),
    after: { notAfter: cert.notAfter },
  };
}

function failure(r: Partial<DomainRecord> & { domain: string }, code: string, message: string, retryable = false): DeployResult {
  return {
    ...(r.provider && { provider: r.provider }),
    ...(r.service && { service: r.service }),
    domain: r.domain,
    action: "failed",
    code,
    message,
    retryable,
  };
}

/**
 * 共享作用域（如 ESA 站点）里挡住整组的记录：不在范围内、HTTPS 状态未知、没开 HTTPS（加上共享证书后它会开始用新证书），
 * 或自身会被跳过（已是该证书的除外）。没有阻挡项才整组执行。
 */
function blocks(c: Candidate): boolean {
  if (!c.inScope || c.httpsUnknown || !c.record.https) return true;
  return c.decision.kind === "skip" && c.decision.reason !== "already_current";
}

/** 阻挡项都在范围内、且都是「需确认」的跳过时，--force 能放行整组 */
function confirmable(blockers: Candidate[]): boolean {
  return blockers.every((b) => b.inScope && !b.httpsUnknown && b.decision.needsConfirm);
}

function withoutConfirmHint(message: string | undefined): string | undefined {
  const suffix = `；${CONFIRM_HINT}`;
  return message?.endsWith(suffix) ? message.slice(0, -suffix.length) : message;
}

/** 阻挡项的原因，如「未用 -d 点名」「当前证书还剩 47 天」 */
function blockerNote(c: Candidate): string {
  const d = c.decision;
  const notes: string[] = [];
  if (!c.inScope) notes.push("未用 -d 点名");
  if (c.httpsUnknown) notes.push("查询 HTTPS 配置失败，无法判断现状");
  else if (!c.record.https) notes.push("未开启 HTTPS，站点加证书后会开始用新证书提供 HTTPS");
  else if (d.kind === "skip" && d.reason !== "already_current") {
    notes.push(d.reason === "not_due" ? `当前证书还剩 ${d.oldDaysLeft} 天` : (withoutConfirmHint(d.message) ?? d.reason ?? ""));
  }
  return notes.join("；");
}

/** 共享组被挡住时的说明：逐个列出阻挡项及原因，并说明怎样才能放行 */
function sharedBlockedMessage(group: Candidate[], blockers: Candidate[], canConfirm: boolean): string {
  const list = blockers.map((b) => `${b.record.domain}（${blockerNote(b)}）`).join("、");
  const head = `证书挂在多条记录共享的配置上（如 ESA 站点），无法只更新其中一部分；挡住更新的记录：${list}`;
  if (canConfirm) {
    // 已是该证书的记录不带 needsConfirm，按提示用 -d 只点名需确认的域名时会漏掉它们，变成范围外的阻挡项
    const current = group.filter((c) => c.decision.reason === "already_current").map((c) => c.record.domain);
    const note = current.length ? `；用 -d 时须同时点名同组已是该证书的 ${current.join("、")}` : "";
    return `${head}${note}；${CONFIRM_HINT}`;
  }
  const hints: string[] = [];
  if (blockers.some((b) => !b.inScope)) hints.push("把未点名的记录一并用 -d 点名");
  if (blockers.some((b) => b.decision.needsConfirm)) hints.push("需确认的记录向用户确认后加 --force");
  if (blockers.some((b) => b.httpsUnknown)) hints.push("查询失败的记录稍后重试");
  const stuck = (b: Candidate) => !b.httpsUnknown && (!b.record.https || (b.decision.kind === "skip" && !b.decision.needsConfirm && b.decision.reason !== "already_current"));
  if (blockers.some(stuck)) hints.push("未开启 HTTPS 或无法处理的记录无法通过本命令放行，需先在云厂商控制台处理");
  return `${head}；放行方法：${hints.join("；")}`;
}

/** 查询所选云厂商 / 服务上的现状；与 buildPlan 拆开，终端确认后可用同一份结果重新出计划，不再查一遍云接口 */
export function queryForDeploy(ctx: QueryContext, opts: DeployOptions, defs: ProviderDefs = PROVIDER_DEFS): Promise<DomainQueryResult> {
  return queryDomains(ctx, { providers: opts.providers, services: opts.services }, defs);
}

export async function planDeploy(ctx: QueryContext, cert: LocalCert, opts: DeployOptions, defs: ProviderDefs = PROVIDER_DEFS): Promise<DeployPlan> {
  return buildPlan(ctx, cert, opts, await queryForDeploy(ctx, opts, defs), defs);
}

/** 按查询结果出计划（纯计算，不调用云接口） */
export function buildPlan(ctx: QueryContext, cert: LocalCert, opts: DeployOptions, query: DomainQueryResult, defs: ProviderDefs = PROVIDER_DEFS): DeployPlan {
  const targets = new Map(resolveTargets(ctx.env, opts.providers, defs).map((t) => [t.def.provider, t]));
  const named = opts.domains?.length ? new Set(opts.domains.map(normalizeDomain)) : undefined;
  const results: DeployResult[] = [];
  const pending: PendingItem[] = [];

  // 点名的域名：查无此域名、证书不覆盖都明确记为失败
  if (named) {
    const queried = new Set(query.items.map((r) => normalizeDomain(r.domain)));
    // 整个服务或其中某个子项（bucket、站点等）查询失败，域名都可能在里面；有可重试的失败时重试可能就找到了
    const errors = query.issues.filter((i) => i.kind === "error");
    const failedQueries = [...new Set(errors.map((i) => `${i.provider}/${i.service}${i.target ? ` ${i.target}` : ""}`))];
    const retryable = errors.some((i) => isRetryableCode(i.code));
    for (const name of named) {
      if (queried.has(name)) continue;
      const hint = failedQueries.length ? `；以下查询失败，域名可能在其中：${failedQueries.join("、")}` : "";
      results.push(failure({ domain: name }, "DomainNotFound", `所选云厂商 / 服务上没有找到该域名${hint}`, retryable));
    }
  }

  const candidates: Candidate[] = [];
  for (const record of query.items) {
    const isNamed = named?.has(normalizeDomain(record.domain)) ?? false;
    if (!certCovers(cert.sans, record.domain)) {
      if (isNamed) results.push(failure(record, "NotCovered", `证书不覆盖该域名（证书域名：${cert.sans.join(", ")}）`));
      continue;
    }
    const def = defs[record.provider];
    const service = def.services.find((s) => s.key === record.service)!;
    const inScope = !named || isNamed;
    const unsupportedFor = (mode: DeployTarget["mode"]) => (service.deployer ? service.deployer.unsupported?.(record, mode) : UNSUPPORTED_SERVICE);
    // 平台托管、或无论开没开 HTTPS 都不能部署的记录，状态未知也无妨：照常按决策表跳过
    const neverDeployable = record.extra?.managed === "platform" || (unsupportedFor("update") && unsupportedFor("deploy"));
    if (record.extra?.httpsUnknown === "true" && !neverDeployable) {
      // 不能当成没开 HTTPS 跳过（它可能正是要更新的域名），也不能部署或更新：一律记为可重试的失败；
      // 仍参与共享作用域分组，挡住同组的其他记录
      if (inScope) results.push(failure(record, "HttpsStateUnknown", HTTPS_UNKNOWN, true));
      candidates.push({ record, service, decision: { kind: "skip" }, inScope, httpsUnknown: true });
      continue;
    }
    const unsupported = unsupportedFor(record.https ? "update" : "deploy") ?? (neverDeployable ? unsupportedFor("update") : undefined);
    const decision = decide(record, cert, { named: isNamed, force: opts.force, now: ctx.now, ...(unsupported && { unsupported }) });
    candidates.push({ record, service, decision, inScope, httpsUnknown: false });
  }

  const groups = new Map<string, Candidate[]>();
  for (const c of candidates) {
    // 不论是否开着 HTTPS 都问 deployer：没开 HTTPS 的记录也可能被共享证书波及（站点加证书后开始用新证书）
    const scope = c.service.deployer?.sharedScope?.(c.record);
    if (scope === undefined) continue;
    const key = `${c.record.provider}/${c.record.service}/${scope}`;
    groups.set(key, [...(groups.get(key) ?? []), c]);
  }
  const grouped = new Set([...groups.values()].flat());

  const push = (c: Candidate, records: DomainRecord[], mode: DeployTarget["mode"], items: DeployResult[]) => {
    const { def, creds } = targets.get(c.record.provider)!;
    pending.push({ def, creds, service: c.service, target: { records, mode }, results: items });
  };

  for (const c of candidates) {
    if (!c.inScope || c.httpsUnknown || grouped.has(c)) continue;
    if (c.decision.kind === "skip") {
      results.push(skipped(c.record, c.decision));
      continue;
    }
    const item = planned(c.record, c.decision, cert);
    results.push(item);
    push(c, [c.record], c.decision.kind, [item]);
  }

  // 共享作用域：先算阻挡项，再给组内范围内的记录出结果（HTTPS 状态未知的已在上面记为失败）
  for (const group of groups.values()) {
    const inScope = group.filter((c) => c.inScope && !c.httpsUnknown);
    const blockers = group.filter(blocks);
    if (blockers.length === 0) {
      // 此时组内全部在范围内、开着 HTTPS，且不是更新就是已是该证书
      for (const c of inScope.filter((x) => x.decision.kind === "skip")) results.push(skipped(c.record, c.decision));
      const updates = inScope.filter((c) => c.decision.kind === "update");
      if (updates.length === 0) continue;
      const items = updates.map((c) => planned(c.record, c.decision, cert));
      results.push(...items);
      push(updates[0]!, updates.map((c) => c.record), "update", items);
      continue;
    }
    const canConfirm = confirmable(blockers);
    const message = sharedBlockedMessage(group, blockers, canConfirm);
    for (const c of inScope) {
      const d = c.decision;
      // 自身就不会处理的（已是该证书、不支持、没开 HTTPS 未点名等）照常报自身原因；
      // --force 能放行整组时，需确认的记录也照常报自身原因（本身已带 needsConfirm）
      if (d.kind === "skip" && (!d.needsConfirm || canConfirm)) {
        results.push(skipped(c.record, d));
        continue;
      }
      results.push({
        ...skipped(c.record, { kind: "skip", ...(d.oldCert && { oldCert: d.oldCert }), ...(d.oldDaysLeft !== undefined && { oldDaysLeft: d.oldDaysLeft }) }),
        reason: "shared_cert_blocked",
        message,
        ...(canConfirm && { needsConfirm: true as const }),
      });
    }
  }

  results.sort(byTarget);
  return {
    report: {
      dryRun: opts.dryRun,
      cert: { ...(cert.commonName && { commonName: cert.commonName }), sans: cert.sans, notAfter: cert.notAfter, algorithm: cert.algorithm, fingerprint: cert.fingerprint },
      uploads: [],
      results,
      issues: query.issues,
      succeeded: query.succeeded,
    },
    pending,
  };
}

/** 按云厂商 / 服务 / 域名排序，找不到云厂商的（DomainNotFound）排最后 */
function byTarget(a: DeployResult, b: DeployResult): number {
  const key = (r: DeployResult) => `${r.provider ? "0" : "1"}/${r.provider ?? ""}/${r.service ?? ""}/${r.domain}`;
  return key(a).localeCompare(key(b));
}

/** 云接口的报错可能回显请求参数，输出前把私钥内容替换掉 */
export function redactKey(text: string, keyPem: string): string {
  const lines = keyPem
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length >= 16 && !l.startsWith("-----"));
  let out = text.split(keyPem.trim()).join("[私钥已隐藏]");
  for (const l of lines) {
    for (const form of new Set([l, encodeURIComponent(l)])) out = out.split(form).join("[私钥已隐藏]");
  }
  return out;
}

export async function executeDeploy(ctx: QueryContext, cert: LocalCert, plan: DeployPlan): Promise<DeployReport> {
  const { report } = plan;
  const uploads = new Map<Provider, Promise<string>>();
  const certIdFor = (def: ProviderDef<unknown>, creds: unknown) => () => {
    let p = uploads.get(def.provider);
    if (!p) {
      p = def.uploadCertificate
        ? def.uploadCertificate(ctx, creds, cert).then((u) => {
            report.uploads.push({ provider: def.provider, certId: u.id, reused: u.reused });
            return u.id;
          })
        : Promise.reject(new CloudApiError(def.provider, "UploadUnsupported", "该云厂商暂不支持上传证书到证书服务"));
      uploads.set(def.provider, p);
    }
    return p;
  };

  const byService = new Map<string, PendingItem[]>();
  for (const p of plan.pending) {
    const key = `${p.def.provider}/${p.service.key}`;
    byService.set(key, [...(byService.get(key) ?? []), p]);
  }
  await Promise.all(
    [...byService.values()].map((items) =>
      mapLimit(items, 3, async (p) => {
        try {
          const outcome = await p.service.deployer!.apply(ctx, p.creds, p.target, { cert, certId: certIdFor(p.def, p.creds) });
          for (const r of p.results) {
            r.action = p.target.mode === "deploy" ? "deployed" : "updated";
            r.after = { ...(outcome.certId && { id: outcome.certId }), notAfter: cert.notAfter };
            if (outcome.note) r.message = outcome.note;
          }
        } catch (e) {
          const err = e instanceof CloudApiError ? e : undefined;
          const message = redactKey(String((e as Error)?.message ?? e), cert.keyPem);
          for (const r of p.results) {
            r.action = "failed";
            delete r.after;
            Object.assign(r, {
              code: err?.code ?? "Unknown",
              message,
              ...(err?.requestId && { requestId: err.requestId }),
              retryable: isRetryable(e),
            });
          }
        }
      }),
    ),
  );
  return report;
}
