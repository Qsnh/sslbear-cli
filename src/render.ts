import { mask, type Env } from "./lib/env.js";
import { renderTable } from "./lib/table.js";
import { formatDate } from "./lib/time.js";
import { envKeyStatus } from "./providers/registry.js";
import { PROVIDER_DEFS } from "./query.js";
import { PROVIDER_LABEL, type CertificateRecord, type DomainRecord, type Provider } from "./types.js";

function serviceLabel(provider: Provider, key: string): string {
  return PROVIDER_DEFS[provider].services.find((s) => s.key === key)?.label ?? key;
}

function days(d: number | undefined): string {
  if (d === undefined) return "-";
  return d < 0 ? `已过期 ${-d} 天` : String(d);
}

export function renderDomains(items: DomainRecord[], expiringWithin?: number): string {
  if (items.length === 0) return expiringWithin === undefined ? "没有查到域名。" : `没有 ${expiringWithin} 天内到期的证书。`;
  const table = renderTable(
    ["云厂商", "服务", "域名", "HTTPS", "证书", "到期时间", "剩余天数"],
    items.map((d) => [
      PROVIDER_LABEL[d.provider],
      serviceLabel(d.provider, d.service),
      d.domain,
      d.https ? "开启" : "关闭",
      d.cert?.name ?? d.cert?.commonName ?? d.cert?.id ?? "-",
      formatDate(d.cert?.notAfter),
      days(d.daysLeft),
    ]),
  );
  const expired = items.filter((d) => d.daysLeft !== undefined && d.daysLeft < 0).length;
  const soon = items.filter((d) => d.daysLeft !== undefined && d.daysLeft >= 0 && d.daysLeft <= 30).length;
  const plain = items.filter((d) => !d.https).length;
  const parts = [`共 ${items.length} 个域名`];
  if (expired) parts.push(`${expired} 个证书已过期`);
  if (soon) parts.push(`${soon} 个 30 天内到期`);
  if (plain) parts.push(`${plain} 个未开启 HTTPS`);
  return `${table}\n\n${parts.join("，")}`;
}

export function renderCerts(items: CertificateRecord[], expiringWithin?: number): string {
  if (items.length === 0) return expiringWithin === undefined ? "没有查到证书。" : `没有 ${expiringWithin} 天内到期的证书。`;
  const table = renderTable(
    ["云厂商", "证书 ID", "名称", "绑定域名", "到期时间", "剩余天数", "状态"],
    items.map((c) => {
      const domains = c.sans?.length ? c.sans : c.commonName ? [c.commonName] : [];
      const shown = domains.length > 3 ? `${domains.slice(0, 3).join(", ")} 等 ${domains.length} 个` : domains.join(", ");
      return [
        PROVIDER_LABEL[c.provider],
        c.id,
        c.name ?? "-",
        shown || "-",
        formatDate(c.notAfter),
        days(c.daysLeft),
        c.status ?? "-",
      ];
    }),
  );
  return `${table}\n\n共 ${items.length} 张证书`;
}

export function envStatus(env: Env) {
  return Object.values(PROVIDER_DEFS).map((def) => {
    const state = def.readCredentials(env);
    return {
      provider: def.provider,
      state: state.state,
      keys: envKeyStatus(def, env, mask),
      services: def.services.map((s) => s.key),
    };
  });
}

const STATE_LABEL = { ok: "已配置", missing: "未配置", incomplete: "配置不完整" } as const;

export function renderEnv(env: Env, envFile?: string): string {
  const lines = [`.env 文件：${envFile ?? "未加载（当前目录不存在 .env）"}`, ""];
  for (const s of envStatus(env)) {
    lines.push(`${PROVIDER_LABEL[s.provider]}（${s.provider}）：${STATE_LABEL[s.state]}`);
    for (const k of s.keys) {
      const value = k.set ? (k.masked ? `= ${k.masked}` : "已设置") : k.required ? "未设置（必填）" : "未设置（可选）";
      lines.push(`  ${k.name} ${value}`);
    }
    lines.push(`  可查询服务：${s.services.join(", ")}`, "");
  }
  return lines.join("\n").trimEnd();
}
