import { DNS_DEFS } from "../dns/index.js";
import { renderTable } from "../lib/table.js";
import { daysUntil, formatDate } from "../lib/time.js";
import type { DnsVendor } from "../types.js";
import type { DnsResult, IssueReport, IssuedCert } from "./run.js";
import type { DnsIssue } from "./zones.js";

const label = (p: DnsVendor) => DNS_DEFS[p].label;

function certLine(cert: IssuedCert, now: Date): string {
  const left = daysUntil(cert.notAfter, now);
  const days = left === undefined ? "" : `，剩 ${left} 天`;
  const issuer = cert.issuer ? `，签发者 ${cert.issuer}` : "";
  return `${cert.sans.join(", ")}（${cert.algorithm}，${formatDate(cert.notAfter)} 到期${days}${issuer}）`;
}

function dnsTable(dns: DnsResult[], withCleanup: boolean): string {
  const headers = ["域名", "DNS 服务商", "zone", "验证记录", ...(withCleanup ? ["清理"] : [])];
  return renderTable(
    headers,
    dns.map((d) => [d.domain, label(d.provider), d.zone, d.record, ...(withCleanup ? [d.cleaned ? "已删除" : "删除失败"] : [])]),
  );
}

/** 删除失败的记录：醒目列出，让用户去控制台手动删 */
export function leftoverNotes(dns: readonly DnsResult[]): string[] {
  const left = dns.filter((d) => d.cleaned === false);
  if (left.length === 0) return [];
  return [
    `警告：以下 ${left.length} 条 TXT 记录可能残留在 DNS 服务商那边，请到控制台手动删除：`,
    ...left.map((d) => `  ${label(d.provider)} ${d.record}（${d.domain}）：${d.message ?? "删除失败"}`),
  ];
}

/** 表格模式的结果（stdout） */
export function renderIssue(r: IssueReport, now: Date): string {
  const env = r.staging ? "（Let's Encrypt 测试环境，证书不受浏览器信任）" : "";
  const files = [`证书文件：${r.files.cert}`, `私钥文件：${r.files.key}`];
  if (r.dryRun) {
    if (r.reused && r.cert) {
      return [`--dry-run 预览：已有可复用的证书${env}，正式运行也不会重新签发（加 --force 可强制重签）`, certLine(r.cert, now), ...files].join("\n");
    }
    return [`--dry-run 预览：未申请证书、未修改 DNS${env}`, "", dnsTable(r.dns, false), "", `证书将保存到：${r.files.cert}、${r.files.key}`].join("\n");
  }
  const lines = [r.reused ? `已有可复用的证书，未重新签发${env}（加 --force 可强制重签）：` : `已签发证书${env}：`, `  ${certLine(r.cert!, now)}`, ...files];
  if (r.dns.length > 0) lines.push("", dnsTable(r.dns, true));
  const notes = leftoverNotes(r.dns);
  if (notes.length > 0) lines.push("", ...notes);
  lines.push("", `部署到云服务：sslbear-cli deploy --cert ${r.files.cert} --key ${r.files.key} --dry-run`);
  return lines.join("\n");
}

/** 进度行写 stderr，stdout 只留结果；--json 时调用方不传进度回调 */
export function printProgress(message: string): void {
  console.error(message);
}

/** 列 zone 失败、凭证不完整被跳过的服务商（stderr） */
export function issueNotes(issues: readonly DnsIssue[]): string[] {
  return issues.map((i) => {
    const rid = i.requestId ? `（RequestId: ${i.requestId}）` : "";
    return i.code === "IncompleteCredentials"
      ? `提示：${i.provider}（${label(i.provider)}）${i.message}`
      : `警告：${i.provider}（${label(i.provider)}）列出 zone 失败：${i.code} ${i.message}${rid}`;
  });
}
