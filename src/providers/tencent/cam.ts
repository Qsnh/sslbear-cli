/**
 * 无权限时在报错里写出缺少的 CAM 权限与可授予的预设策略。API 3.0 的拒绝原文带被拒的 Action（实测 2026-10：
 * 「you are not authorized to perform operation (cdn:UpdateDomainConfig) resource (…) has no permission」，
 * 错误码各服务不同：AuthFailure.UnauthorizedOperation、UnauthorizedOperation、UnauthorizedOperation.CdnCamUnauthorized）；
 * COS 只返回 AccessDenied，按接口名推断。
 */

/** 各服务的预设策略：[只读, 读写]（与 docs/permissions.md 一致） */
const POLICIES: Record<string, readonly [string, string]> = {
  ssl: ["QcloudSSLReadOnlyAccess", "QcloudSSLFullAccess"],
  cdn: ["QcloudCDNReadOnlyAccess", "QcloudCDNFullAccess"],
  teo: ["QcloudTEOReadOnlyaccess", "QcloudTEOFullAccess"],
  cos: ["QcloudCOSReadOnlyAccess", "QcloudCOSFullAccess"],
  live: ["QcloudLIVEReadOnlyAccess", "QcloudLIVEFullAccess"],
  vod: ["QcloudVODReadonlyAccess", "QcloudVODFullAccess"],
  dnspod: ["QcloudDNSPodReadOnlyAccess", "QcloudDNSPodFullAccess"],
};

/** DNSPod 只有签发用到，签发要增删记录：即使被拒的是查询接口也给读写策略 */
const WRITE_ONLY_ADVICE = new Set(["dnspod"]);

function presetPolicy(action: string): string | undefined {
  const [service = "", api = ""] = action.split(":");
  const policies = POLICIES[service];
  if (!policies) return undefined;
  const readOnly = !WRITE_ONLY_ADVICE.has(service) && /^(Describe|List|Get)/.test(api);
  return policies[readOnly ? 0 : 1];
}

/** 追加在原错误信息后的说明，如「（缺少 CAM 权限 cdn:UpdateDomainConfig，可授予预设策略 QcloudCDNFullAccess）」 */
export function permissionHint(action: string, uncertain = false): string {
  const policy = presetPolicy(action);
  return `（${uncertain ? "可能" : ""}缺少 CAM 权限 ${action}${policy ? `，可授予预设策略 ${policy}` : ""}）`;
}

const ACTION_IN_MESSAGE = /not authorized to perform operation \(([\w-]+:\w+)\)/;
/** 原文没带 Action 时也能确定是缺 CAM 权限的错误码 */
const DENIED_CODE = /^AuthFailure\.UnauthorizedOperation$|CamUnauthorized$/;

/**
 * API 3.0 的错误信息：缺 CAM 权限时把原文压成一行（原文带换行）并追加说明；其他错误原样返回。
 * fallbackAction 是本次调用的「服务:接口名」，原文没写 Action 时用它
 */
export function explainDenied(code: string, message: string, fallbackAction: string): string {
  const action = ACTION_IN_MESSAGE.exec(message)?.[1] ?? (DENIED_CODE.test(code) ? fallbackAction : undefined);
  if (!action) return message;
  return `${message.replace(/\s+/g, " ").trim()}${permissionHint(action)}`;
}
