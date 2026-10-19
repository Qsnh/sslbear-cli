import type { DnsDefs } from "../dns/index.js";
import { normalizeName, type DnsProviderDef, type DnsZone } from "../dns/types.js";
import type { Env } from "../lib/env.js";
import { CloudApiError, type QueryContext } from "../lib/http.js";
import { UsageError } from "../query.js";
import { DNS_VENDORS, type DnsVendor } from "../types.js";
import { challengeName } from "./domains.js";
import { nsBelongsTo, type DnsLookup } from "./propagation.js";

export interface DnsTarget {
  def: DnsProviderDef<unknown>;
  creds: unknown;
}

/** 列 zone 失败、凭证不完整被跳过的 DNS 服务商；签发不因此失败，但要让调用方知道少查了哪家 */
export interface DnsIssue {
  provider: DnsVendor;
  kind: "error";
  code: string;
  message: string;
  requestId?: string;
}

/**
 * 解析要查找 zone 的 DNS 服务商。
 * - --dns 显式指定的没配置 / 配置不完整：参数错误；
 * - 默认模式下配置不完整的跳过并记进 issues：DNS 类变量常被其他工具共用（如 AZURE_*、AWS_*），
 *   不能像其他命令那样因为一家只配了一半就整条报错；
 * - 一家都没配置：参数错误，列出各家需要的变量。
 */
export function resolveDnsTargets(env: Env, defs: DnsDefs, vendors?: readonly DnsVendor[]): { targets: DnsTarget[]; issues: DnsIssue[] } {
  const explicit = !!vendors && vendors.length > 0;
  const targets: DnsTarget[] = [];
  const issues: DnsIssue[] = [];
  for (const v of explicit ? vendors : DNS_VENDORS) {
    const def = defs[v];
    const state = def.readCredentials(env);
    if (state.state === "ok") {
      targets.push({ def, creds: state.credentials });
      continue;
    }
    if (explicit) {
      throw new UsageError(
        state.state === "missing"
          ? `${v}（${def.label}）未配置凭证，需要设置环境变量：${def.requiredEnv.join("、")}`
          : `${v}（${def.label}）凭证不完整，缺少环境变量 ${state.missing.join(", ")}`,
      );
    }
    if (state.state === "incomplete") {
      issues.push({ provider: v, kind: "error", code: "IncompleteCredentials", message: `凭证不完整（缺少 ${state.missing.join(", ")}），已跳过` });
    }
  }
  if (targets.length === 0) {
    const skipped = issues.length > 0 ? `（${issues.map((i) => i.provider).join("、")} 凭证不完整）` : "";
    const hints = DNS_VENDORS.map((v) => `${v}（${defs[v].label}）: ${defs[v].requiredEnv.join("、")}`);
    throw new UsageError(`未检测到任何 DNS 服务商凭证${skipped}，请设置环境变量（或写入当前目录 .env）：\n  ${hints.join("\n  ")}`);
  }
  return { targets, issues };
}

export function toDnsIssue(provider: DnsVendor, e: unknown): DnsIssue {
  if (e instanceof CloudApiError) {
    return { provider, kind: "error", code: e.code, message: e.message, ...(e.requestId && { requestId: e.requestId }) };
  }
  return { provider, kind: "error", code: "Unknown", message: String((e as Error)?.message ?? e) };
}

/** 一个域名的验证记录加在哪家、哪个 zone */
export interface ZoneMatch {
  domain: string;
  target: DnsTarget;
  zone: DnsZone;
  /** _acme-challenge.<域名>，泛域名去掉 "*." */
  record: string;
}

/** zone 查找失败：status 为 ZoneNotFound / ZoneAmbiguous，extra 为输出契约里的附加字段 */
export class ZoneError extends Error {
  constructor(
    public status: "ZoneNotFound" | "ZoneAmbiguous",
    message: string,
    public extra: Record<string, unknown>,
    public issues: DnsIssue[],
  ) {
    super(message);
    this.name = "ZoneError";
  }
}

interface Hosted {
  target: DnsTarget;
  zone: DnsZone;
}

const vendorsOf = (list: Hosted[]) => [...new Set(list.map((h) => h.target.def.vendor))];

/**
 * 找出每个域名由哪家的哪个 zone 解析：各服务商并行列 zone（失败记进 issues，不影响其他家），取最长后缀匹配的 zone
 * （子域单独托管在别家时以子域为准）。多家都托管了这个最长 zone 时（迁移 DNS 后旧服务商没删），
 * 查该 zone 实际的 NS 判定，只有一家对得上才用它，否则 ZoneAmbiguous。
 */
export async function findZones(
  ctx: QueryContext,
  lookup: DnsLookup,
  targets: DnsTarget[],
  domains: readonly string[],
): Promise<{ matches: ZoneMatch[]; issues: DnsIssue[] }> {
  const issues: DnsIssue[] = [];
  const hosted: Hosted[] = [];
  const settled = await Promise.allSettled(targets.map((t) => t.def.listZones(ctx, t.creds)));
  settled.forEach((r, i) => {
    const target = targets[i]!;
    if (r.status === "rejected") issues.push(toDnsIssue(target.def.vendor, r.reason));
    else hosted.push(...r.value.map((zone) => ({ target, zone: { ...zone, name: normalizeName(zone.name) } })));
  });

  // 同一个 zone 的 NS 只查一次（根域名与泛域名、同 zone 的多个子域）
  const nsCache = new Map<string, Promise<string[] | undefined>>();
  const actualNs = (zone: string) => {
    if (!nsCache.has(zone)) nsCache.set(zone, lookup.resolveNs(zone).then((ns) => ns.map(normalizeName), () => undefined));
    return nsCache.get(zone)!;
  };

  const matches: ZoneMatch[] = [];
  const notFound: string[] = [];
  const ambiguous: { domain: string; zone: string; candidates: Hosted[]; ns?: string[] }[] = [];
  for (const domain of domains) {
    const base = domain.replace(/^\*\./, "");
    const candidates = hosted.filter((h) => base === h.zone.name || base.endsWith(`.${h.zone.name}`));
    if (candidates.length === 0) {
      notFound.push(domain);
      continue;
    }
    const longest = Math.max(...candidates.map((h) => h.zone.name.length));
    const top = candidates.filter((h) => h.zone.name.length === longest);
    let chosen = top[0]!;
    if (top.length > 1) {
      const ns = await actualNs(chosen.zone.name);
      const serving = ns ? top.filter((h) => ns.some((host) => nsBelongsTo(host, h.zone, h.target.def.nameServerPattern))) : [];
      if (serving.length !== 1) {
        ambiguous.push({ domain, zone: chosen.zone.name, candidates: top, ...(ns && { ns }) });
        continue;
      }
      chosen = serving[0]!;
    }
    matches.push({ domain, target: chosen.target, zone: chosen.zone, record: challengeName(domain) });
  }

  // 找不到比判不出更根本：先报 ZoneNotFound
  if (notFound.length > 0) {
    const checked = targets.map((t) => t.def.vendor).join("、");
    const failed = issues.length > 0 ? `；其中 ${issues.map((i) => `${i.provider} 列出 zone 失败（${i.code} ${i.message}）`).join("，")}，多半是缺权限` : "";
    throw new ZoneError(
      "ZoneNotFound",
      `以下域名不在所选 DNS 服务商（${checked}）的任何 zone 里：${notFound.join(", ")}${failed}。请确认域名由这些服务商解析，或配置实际托管该域名的服务商的凭证`,
      { domains: notFound },
      issues,
    );
  }
  const first = ambiguous[0];
  if (first) {
    const providers = vendorsOf(first.candidates);
    const hosts = first.ns ? `按 ${first.zone} 实际的 NS（${first.ns.join(", ")}）` : `查不到 ${first.zone} 的 NS 记录，`;
    const message =
      providers.length === 1
        ? `${providers[0]} 里有多个同名 zone ${first.zone}，${hosts}无法判定实际使用哪一个`
        : `多家 DNS 服务商都托管了 ${first.zone}（${providers.join("、")}），${hosts}无法判定 ${first.domain} 实际由哪家解析，请用 --dns 指定`;
    throw new ZoneError("ZoneAmbiguous", message, { domain: first.domain, providers }, issues);
  }
  return { matches, issues };
}
