import type { Env } from "./lib/env.js";
import { CloudApiError, type QueryContext } from "./lib/http.js";
import { daysUntil } from "./lib/time.js";
import { aliyun } from "./providers/aliyun/index.js";
import { baidu } from "./providers/baidu/index.js";
import { huawei } from "./providers/huawei/index.js";
import { qiniu } from "./providers/qiniu/index.js";
import { requiredEnvNames, type ProviderDef } from "./providers/registry.js";
import { tencent } from "./providers/tencent/index.js";
import { volcengine } from "./providers/volcengine/index.js";
import type { CertificateRecord, DomainRecord, Provider } from "./types.js";

// 各厂商凭证类型不同，注册表里统一擦除；调用时凭证与 provider 一一对应
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const PROVIDER_DEFS: Record<Provider, ProviderDef<any>> = { aliyun, tencent, volcengine, huawei, baidu, qiniu };

export interface QueryIssue {
  provider: Provider;
  service: string;
  /** inactive = 服务未开通（不算失败），error = 调用失败 */
  kind: "inactive" | "error";
  code: string;
  message: string;
  /** 出错的子项，如 OSS bucket、EdgeOne 站点 */
  target?: string;
  requestId?: string;
}

export class UsageError extends Error {}

export interface Selection {
  /** 显式指定的云厂商；缺省为所有已配置凭证的云厂商 */
  providers?: Provider[];
  services?: string[];
}

export interface Target {
  def: ProviderDef<unknown>;
  creds: unknown;
}

export type ProviderDefs = Record<Provider, ProviderDef<any>>; // eslint-disable-line @typescript-eslint/no-explicit-any

/** 解析要查询的云厂商：显式指定但未配置、或配置不完整时报参数错误 */
export function resolveTargets(env: Env, providers?: Provider[], defs: ProviderDefs = PROVIDER_DEFS): Target[] {
  const explicit = providers && providers.length > 0;
  const targets: Target[] = [];
  for (const p of explicit ? providers : (Object.keys(defs) as Provider[])) {
    const def = defs[p];
    const state = def.readCredentials(env);
    if (state.state === "incomplete") {
      throw new UsageError(`${p} 凭证不完整，缺少环境变量 ${state.missing.join(", ")}`);
    }
    if (state.state === "missing") {
      if (explicit) throw new UsageError(`${p} 未配置凭证，需要设置环境变量：${requiredEnvNames(def).join("、")}`);
      continue;
    }
    targets.push({ def, creds: state.credentials });
  }
  if (targets.length === 0) {
    const hints = Object.values(defs).map((d) => `${d.provider}: ${requiredEnvNames(d).join("、")}`);
    throw new UsageError(`未检测到任何云厂商凭证，请设置环境变量（或写入当前目录或 ~/.sslbear-cli 下的 .env）：\n  ${hints.join("\n  ")}`);
  }
  return targets;
}

export function toIssue(def: ProviderDef<unknown>, service: string, e: unknown, target?: string): QueryIssue {
  const where = { provider: def.provider, service, ...(target && { target }) };
  if (e instanceof CloudApiError) {
    return {
      ...where,
      kind: def.isInactive(e.code, e.message) ? "inactive" : "error",
      code: e.code,
      message: e.message,
      ...(e.requestId && { requestId: e.requestId }),
    };
  }
  return { ...where, kind: "error", code: "Unknown", message: String((e as Error)?.message ?? e) };
}

export interface DomainQueryResult {
  items: DomainRecord[];
  issues: QueryIssue[];
  /** 整体成功的查询数（云厂商 × 服务），为 0 且有错误即视为全部失败 */
  succeeded: number;
}

export async function queryDomains(ctx: QueryContext, sel: Selection, defs: ProviderDefs = PROVIDER_DEFS): Promise<DomainQueryResult> {
  const targets = resolveTargets(ctx.env, sel.providers, defs);
  const jobs = targets.flatMap(({ def, creds }) => {
    const services = sel.services?.length ? def.services.filter((s) => sel.services!.includes(s.key)) : def.services;
    return services.map((svc) => ({ def, svc, creds }));
  });
  if (jobs.length === 0) {
    throw new UsageError(`所选云厂商不支持服务：${sel.services?.join(", ")}`);
  }
  const items: DomainRecord[] = [];
  const issues: QueryIssue[] = [];
  const settled = await Promise.allSettled(
    jobs.map((j) => j.svc.list(ctx, j.creds, (e, target) => issues.push(toIssue(j.def, j.svc.key, e, target)))),
  );
  settled.forEach((r, i) => {
    const job = jobs[i]!;
    if (r.status === "fulfilled") items.push(...r.value);
    else issues.push(toIssue(job.def, job.svc.key, r.reason));
  });
  for (const item of items) {
    const days = daysUntil(item.cert?.notAfter, ctx.now);
    if (days !== undefined) item.daysLeft = days;
  }
  return { items, issues, succeeded: settled.filter((r) => r.status === "fulfilled").length };
}

export interface CertQueryResult {
  items: CertificateRecord[];
  issues: QueryIssue[];
  succeeded: number;
}

export async function queryCertificates(ctx: QueryContext, sel: Selection): Promise<CertQueryResult> {
  const targets = resolveTargets(ctx.env, sel.providers);
  const settled = await Promise.allSettled(targets.map(({ def, creds }) => def.listCertificates(ctx, creds)));
  const items: CertificateRecord[] = [];
  const issues: QueryIssue[] = [];
  settled.forEach((r, i) => {
    const { def } = targets[i]!;
    if (r.status === "fulfilled") items.push(...r.value);
    else issues.push(toIssue(def, "cert", r.reason));
  });
  for (const item of items) {
    const days = daysUntil(item.notAfter, ctx.now);
    if (days !== undefined) item.daysLeft = days;
  }
  return { items, issues, succeeded: settled.filter((r) => r.status === "fulfilled").length };
}

export interface Filter {
  keyword?: string;
  expiringWithin?: number;
}

function matchesKeyword(values: (string | undefined)[], keyword: string): boolean {
  const k = keyword.toLowerCase();
  return values.some((v) => v?.toLowerCase().includes(k));
}

function byExpiry<T extends { daysLeft?: number }>(a: T, b: T): number {
  return (a.daysLeft ?? Number.POSITIVE_INFINITY) - (b.daysLeft ?? Number.POSITIVE_INFINITY);
}

/** 过滤后按剩余天数升序排列（最急的在前，无证书的排最后），同天数按厂商/服务/域名 */
export function filterDomains(items: DomainRecord[], f: Filter): DomainRecord[] {
  return items
    .filter((d) => !f.keyword || matchesKeyword([d.domain, d.cert?.commonName, ...(d.cert?.sans ?? [])], f.keyword))
    .filter((d) => f.expiringWithin === undefined || (d.daysLeft !== undefined && d.daysLeft <= f.expiringWithin))
    .sort((a, b) => byExpiry(a, b) || `${a.provider}/${a.service}/${a.domain}`.localeCompare(`${b.provider}/${b.service}/${b.domain}`));
}

export function filterCertificates(items: CertificateRecord[], f: Filter): CertificateRecord[] {
  return items
    .filter((c) => !f.keyword || matchesKeyword([c.name, c.commonName, ...(c.sans ?? [])], f.keyword))
    .filter((c) => f.expiringWithin === undefined || (c.daysLeft !== undefined && c.daysLeft <= f.expiringWithin))
    .sort((a, b) => byExpiry(a, b) || `${a.provider}/${a.commonName ?? ""}`.localeCompare(`${b.provider}/${b.commonName ?? ""}`));
}
