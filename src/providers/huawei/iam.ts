/**
 * 无权限时在报错里写出缺少的 IAM 权限与可授予的系统策略。新版 IAM（身份策略）的拒绝原文带被拒的授权项（实测 2026-10：
 * 「User: … is not authorized to perform: cdn:configuration:modifyHttpsConf on resource: … because no identity-based policy allows …」，
 * 错误码各服务不同：CDN.0004、SCM.4002、LIVE.100011003、DNS.1802，均为 HTTP 403）；
 * OBS 只返回 403 AccessDenied，也可能来自桶策略，由 obs.ts 按接口名推断、措辞为「可能」。
 */

/** 各服务可授予的系统策略：[查询, 部署]，每项为 [新版身份策略, 旧版角色与策略]（与 docs/permissions.md 一致）；没有合适系统策略的为 undefined */
type Pair = readonly [string, string];
const POLICIES: Record<string, readonly [Pair | undefined, Pair]> = {
  cdn: [
    ["CDNDomainReadOnlyPolicy", "CDN DomainReadOnlyAccess"],
    ["CDNDomainConfigurationPolicy", "CDN DomainConfiguration"],
  ],
  scm: [
    ["SCMReadOnlyPolicy", "SCM ReadOnlyAccess"],
    ["SCMFullPolicy", "SCM FullAccess"],
  ],
  live: [
    ["LiveReadOnlyPolicy", "Live ReadOnlyAccess"],
    ["LiveFullAccessPolicy", "Live FullAccess"],
  ],
  // OBS 的只读系统策略不含读取桶的自定义域名
  obs: [undefined, ["OBSFullAccessPolicy", "OBS Administrator"]],
  dns: [
    ["DNSFullAccessPolicy", "DNS FullAccess"],
    ["DNSFullAccessPolicy", "DNS FullAccess"],
  ],
};

/** 授权项的操作部分（第三段）是读操作：list / get / query… 开头；导出证书（scm:cert:export）也在只读策略里 */
const isRead = (action: string) => /^(list|get|query|show|export|download)/i.test(action.split(":")[2] ?? "");

function systemPolicy(action: string): string {
  const pair = POLICIES[action.split(":")[0] ?? ""]?.[isRead(action) ? 0 : 1];
  return pair ? `，可授予系统策略 ${pair[0]}，旧版 IAM 授予 ${pair[1]}` : "，需用自定义策略授予";
}

/** 追加在原错误信息后的说明，如「（缺少 IAM 权限 scm:cert:import，可授予系统策略 SCMFullPolicy，旧版 IAM 授予 SCM FullAccess）」 */
export function permissionHint(action: string, uncertain = false): string {
  return `（${uncertain ? "可能" : ""}缺少 IAM 权限 ${action}${POLICIES[action.split(":")[0] ?? ""] ? systemPolicy(action) : ""}）`;
}

const ACTION_IN_MESSAGE = /not authorized to perform:? ([\w-]+:[\w-]+:[\w-]+)/i;

/** 原文带被拒的授权项时追加说明，否则原样返回 */
export function explainDenied(message: string): string {
  const action = ACTION_IN_MESSAGE.exec(message)?.[1];
  return action ? `${message}${permissionHint(action)}` : message;
}
