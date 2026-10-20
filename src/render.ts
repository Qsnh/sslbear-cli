import { DNS_DEFS, type DnsDefs } from "./dns/index.js";
import { mask, type Env } from "./lib/env.js";
import { renderTable } from "./lib/table.js";
import { formatDate } from "./lib/time.js";
import { envKeyStatus, type EnvKeyStatus } from "./providers/registry.js";
import { PROVIDER_DEFS } from "./query.js";
import { DNS_VENDORS, PROVIDER_LABEL, PROVIDERS, type CertificateRecord, type DomainRecord, type Provider } from "./types.js";

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
      // 平台默认域名（如腾讯云 *.myqcloud.com）用云厂商自己的证书，用户无需续期
      d.extra?.managed === "platform" ? "平台托管" : (d.cert?.name ?? d.cert?.commonName ?? d.cert?.id ?? "-"),
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

/** issue 命令可用的 DNS 服务商；前 5 家与云厂商共用凭证，状态与上面的云厂商一致 */
export function dnsEnvStatus(env: Env, defs: DnsDefs = DNS_DEFS) {
  return DNS_VENDORS.map((v) => ({ provider: v, state: defs[v].readCredentials(env).state, keys: defs[v].envKeys(env) }));
}

const STATE_LABEL = { ok: "已配置", missing: "未配置", incomplete: "配置不完整" } as const;

function keyLine(k: EnvKeyStatus): string {
  const value = k.set ? (k.masked ? `= ${k.masked}` : "已设置") : k.required ? "未设置（必填）" : "未设置（可选）";
  return `  ${k.name} ${value}`;
}

export function renderEnv(env: Env, envFile?: string, dnsDefs: DnsDefs = DNS_DEFS): string {
  const lines = [`.env 文件：${envFile ?? "未加载（当前目录和 ~/.sslbear-cli 下都没有 .env）"}`, ""];
  for (const s of envStatus(env)) {
    lines.push(`${PROVIDER_LABEL[s.provider]}（${s.provider}）：${STATE_LABEL[s.state]}`);
    lines.push(...s.keys.map(keyLine), `  可查询服务：${s.services.join(", ")}`, "");
  }
  lines.push("DNS 服务商（issue 用）：", "");
  for (const s of dnsEnvStatus(env, dnsDefs)) {
    const label = `${dnsDefs[s.provider].label}（${s.provider}）：${STATE_LABEL[s.state]}`;
    // 与云厂商共用凭证的不再重复列变量
    if ((PROVIDERS as readonly string[]).includes(s.provider)) lines.push(`${label}（与${PROVIDER_LABEL[s.provider as Provider]}共用凭证）`);
    else lines.push(label, ...s.keys.map(keyLine));
  }
  return lines.join("\n").trimEnd();
}
