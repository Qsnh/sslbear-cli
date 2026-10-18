import { CloudApiError, isRetryable, type QueryContext } from "../lib/http.js";
import { mapLimit } from "../lib/pool.js";
import { PROVIDER_DEFS, queryDomains, resolveTargets, type DomainQueryResult, type ProviderDefs, type QueryIssue } from "../query.js";
import type { DeployTarget, DomainService, ProviderDef } from "../providers/registry.js";
import type { CertInfo, DomainRecord, Provider } from "../types.js";
import { certCovers, normalizeDomain, type LocalCert } from "./cert.js";
import { decide, type Decision, type SkipReason } from "./plan.js";

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

interface Candidate {
  record: DomainRecord;
  service: DomainService<unknown>;
  decision: Decision;
  /** 在本次处理范围内（未用 -d，或被 -d 点名） */
  inScope: boolean;
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

function failure(r: Partial<DomainRecord> & { domain: string }, code: string, message: string): DeployResult {
  return {
    ...(r.provider && { provider: r.provider }),
    ...(r.service && { service: r.service }),
    domain: r.domain,
    action: "failed",
    code,
    message,
    retryable: false,
  };
}

/** 共享作用域（如 ESA 站点）：组内被新证书覆盖、开着 HTTPS 的记录必须全都在范围内且都会被更新，才整组执行 */
function resolveShared(group: Candidate[]): { blockedBy: Candidate[]; confirmable: boolean } {
  const blockedBy = group.filter((c) => !c.inScope || (c.decision.kind !== "update" && c.decision.reason !== "already_current"));
  return { blockedBy, confirmable: blockedBy.length > 0 && blockedBy.every((c) => c.inScope && c.decision.needsConfirm) };
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
    const failedServices = query.issues.filter((i) => i.kind === "error" && !i.target).map((i) => `${i.provider}/${i.service}`);
    for (const name of named) {
      if (queried.has(name)) continue;
      const hint = failedServices.length ? `；以下服务查询失败，域名可能在其中：${failedServices.join("、")}` : "";
      results.push(failure({ domain: name }, "DomainNotFound", `所选云厂商 / 服务上没有找到该域名${hint}`));
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
    const mode = record.https ? "update" : "deploy";
    const unsupported = service.deployer ? service.deployer.unsupported?.(record, mode) : UNSUPPORTED_SERVICE;
    const decision = decide(record, cert, { named: isNamed, force: opts.force, now: ctx.now, ...(unsupported && { unsupported }) });
    candidates.push({ record, service, decision, inScope: !named || isNamed });
  }

  const groups = new Map<string, Candidate[]>();
  for (const c of candidates) {
    // 没开 HTTPS 的记录不受共享证书影响
    const scope = c.record.https ? c.service.deployer?.sharedScope?.(c.record) : undefined;
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
    if (!c.inScope || grouped.has(c)) continue;
    if (c.decision.kind === "skip") {
      results.push(skipped(c.record, c.decision));
      continue;
    }
    const item = planned(c.record, c.decision, cert);
    results.push(item);
    push(c, [c.record], c.decision.kind, [item]);
  }

  for (const group of groups.values()) {
    const inScope = group.filter((c) => c.inScope);
    const updates = inScope.filter((c) => c.decision.kind === "update");
    const { blockedBy, confirmable } = resolveShared(group);
    for (const c of inScope.filter((x) => x.decision.kind === "skip")) results.push(skipped(c.record, c.decision));
    if (updates.length === 0) continue;
    if (blockedBy.length > 0) {
      const names = blockedBy.map((b) => b.record.domain).join("、");
      const why = confirmable
        ? `它们未到更新时间，确需提前更换请向用户确认后加 --force 重新执行`
        : `请把它们一并用 --domain 点名，或等它们也满足更新条件后重新执行`;
      for (const c of updates) {
        results.push({
          ...skipped(c.record, { kind: "skip", ...(c.decision.oldCert && { oldCert: c.decision.oldCert }), ...(c.decision.oldDaysLeft !== undefined && { oldDaysLeft: c.decision.oldDaysLeft }) }),
          reason: "shared_cert_blocked",
          message: `证书挂在共享的配置上，会同时换掉 ${names} 的证书；${why}`,
          ...(confirmable && { needsConfirm: true as const }),
        });
      }
      continue;
    }
    const items = updates.map((c) => planned(c.record, c.decision, cert));
    results.push(...items);
    push(updates[0]!, updates.map((c) => c.record), "update", items);
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
