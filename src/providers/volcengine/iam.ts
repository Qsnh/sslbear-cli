/**
 * 无权限时在报错里写出缺少的 IAM 权限与可授予的系统策略。OpenAPI 的拒绝原文大多带被拒的 Action（实测 2026-10：
 * AccessDenied「User is not authorized to perform: dcdn:CreateCertBind on resource: …」，HTTP 状态 200 / 403 都有）；
 * CDN 是 AccessDenied.IAMUnauthorized「您没有权限操作域名: x」，不说缺哪个，用本次调用的「服务:接口名」。
 * TOS 只有 403 AccessDenied（EC 0003-00000012），也可能来自桶策略，由 tos.ts 按接口名推断、措辞为「可能」。
 */

/** 各服务的系统策略：[只读, 读写]（与 docs/permissions.md 一致）；键为小写的服务代码，拒绝原文里的大小写不固定（如 dcdn、ImageX） */
const POLICIES: Record<string, readonly [string, string]> = {
  certificate_service: ["SSLReadOnly", "SSLFullAccess"],
  cdn: ["CDNReadOnlyAccess", "CDNFullAccess"],
  dcdn: ["DCDNReadOnlyAccess", "DCDNFullAccess"],
  tos: ["TOSReadOnlyAccess", "TOSFullAccess"],
  vod: ["VodReadOnlyAccess", "VodFullAccessV2"],
  live: ["LIVEReadOnlyAccess", "LIVEFullAccess"],
  imagex: ["ImageXReadOnlyAccess", "ImageXFullAccessV2"],
  dns: ["DNSReadOnlyAccess", "DNSFullAccess"],
};

/** 云解析只有签发用到，签发要增删记录：即使被拒的是查询接口也给读写策略 */
const WRITE_ONLY_ADVICE = new Set(["dns"]);

function systemPolicy(action: string): string | undefined {
  const [service = "", api = ""] = action.split(":");
  const key = service.toLowerCase();
  const policies = POLICIES[key];
  if (!policies) return undefined;
  const readOnly = !WRITE_ONLY_ADVICE.has(key) && /^(Describe|List|Get|Certificate(Get|List))/.test(api);
  return policies[readOnly ? 0 : 1];
}

/** 追加在原错误信息后的说明，如「（缺少 IAM 权限 dcdn:CreateCertBind，可授予系统策略 DCDNFullAccess）」 */
export function permissionHint(action: string, uncertain = false): string {
  const policy = systemPolicy(action);
  return `（${uncertain ? "可能" : ""}缺少 IAM 权限 ${action}${policy ? `，可授予系统策略 ${policy}` : ""}）`;
}

const ACTION_IN_MESSAGE = /not authorized to perform:? ([\w-]+:\w+)/i;
/** 缺 IAM 权限的错误码：通用的 AccessDenied（CodeN 100013）、CDN 的 AccessDenied.IAMUnauthorized */
const DENIED_CODES = new Set(["AccessDenied", "AccessDenied.IAMUnauthorized"]);
const DENIED_CODE_N = 100013;

/**
 * OpenAPI 的错误信息：缺 IAM 权限时追加说明，其他错误原样返回。
 * fallbackAction 是本次调用的「服务:接口名」，原文没写 Action 时用它
 */
export function explainDenied(code: string, codeN: number | undefined, message: string, fallbackAction: string): string {
  const named = ACTION_IN_MESSAGE.exec(message)?.[1];
  const action = named ?? (DENIED_CODES.has(code) || codeN === DENIED_CODE_N ? fallbackAction : undefined);
  return action ? `${message}${permissionHint(action)}` : message;
}
