import { renderTable } from "../lib/table.js";
import { formatDate } from "../lib/time.js";
import { PROVIDER_DEFS } from "../query.js";
import { PROVIDER_LABEL } from "../types.js";
import { CONFIRM_HINT } from "./plan.js";
import type { DeployReport, DeployResult } from "./run.js";

const ACTION_LABEL: Record<DeployResult["action"], string> = {
  deployed: "已部署",
  updated: "已更新",
  would_deploy: "将部署",
  would_update: "将更新",
  skipped: "跳过",
  failed: "失败",
};

/** 云厂商、服务两列；点名但哪里都找不到的域名没有云厂商 / 服务 */
function where(r: DeployResult): [string, string] {
  if (!r.provider) return ["-", "-"];
  const label = PROVIDER_DEFS[r.provider].services.find((s) => s.key === r.service)?.label;
  return [PROVIDER_LABEL[r.provider], label ?? r.service ?? "-"];
}

/** 「向用户确认后加 --force」每行都写太长，表格里去掉，统一在末尾提示一次 */
function brief(message: string | undefined): string {
  const suffix = `；${CONFIRM_HINT}`;
  return message?.endsWith(suffix) ? message.slice(0, -suffix.length) : (message ?? "");
}

function oldCert(before: DeployResult["before"]): string | undefined {
  if (!before) return undefined;
  if (!before.notAfter) return "旧证书到期时间未知";
  const d = before.daysLeft;
  const left = d === undefined ? "" : d < 0 ? `（已过期 ${-d} 天）` : `（剩 ${d} 天）`;
  return `旧证书 ${formatDate(before.notAfter)} 到期${left}`;
}

function note(r: DeployResult): string {
  const join = (...parts: (string | undefined)[]) => parts.filter(Boolean).join("；") || "-";
  switch (r.action) {
    case "failed":
      return `${r.code ?? "Unknown"} ${r.message ?? ""}${r.requestId ? `（RequestId: ${r.requestId}）` : ""}`;
    case "skipped":
      return join(r.needsConfirm ? `需确认：${brief(r.message)}` : r.message);
    case "updated":
    case "would_update":
      return join(oldCert(r.before), r.message);
    default:
      return join("开启 HTTPS", r.message);
  }
}

export function renderDeploy(report: DeployReport): string {
  const { cert, results, dryRun } = report;
  const head = `证书：${cert.commonName ?? cert.sans[0] ?? "-"}（${cert.algorithm}，${formatDate(cert.notAfter)} 到期）${dryRun ? "；--dry-run 预览，未做任何修改" : ""}`;
  if (results.length === 0) return `${head}\n\n证书覆盖的域名（${cert.sans.join(", ")}）在所选云厂商上没有找到`;

  const table = renderTable(
    ["云厂商", "服务", "域名", "动作", "说明"],
    results.map((r) => [...where(r), r.domain, ACTION_LABEL[r.action], note(r)]),
  );
  const count = (...actions: DeployResult["action"][]) => results.filter((r) => actions.includes(r.action)).length;
  const confirm = results.filter((r) => r.needsConfirm).length;
  const updated = count("updated", "would_update");
  const deployed = count("deployed", "would_deploy");
  const lines = [
    `${dryRun ? "将更新" : "更新"} ${updated}，${dryRun ? "将部署" : "部署"} ${deployed}，跳过 ${count("skipped")}（其中需确认 ${confirm}），失败 ${count("failed")}`,
  ];
  if (!dryRun && updated + deployed > 0) lines.push("各云生效需要几秒到几分钟，可稍后用 sslbear-cli domains 核对");
  if (confirm > 0) lines.push("需确认的域名：向用户确认后加 --force 重新执行（可配合 -d 只针对这些域名）");
  return `${head}\n\n${table}\n\n${lines.join("\n")}`;
}

/** 终端二次确认前列出需确认的域名 */
export function renderConfirm(items: DeployResult[]): string {
  return renderTable(
    ["云厂商", "服务", "域名", "说明"],
    items.map((r) => [...where(r), r.domain, brief(r.message) || "-"]),
  );
}
