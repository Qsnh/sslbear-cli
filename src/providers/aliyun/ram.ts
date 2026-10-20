/**
 * 无权限时在报错里写出缺少的 RAM 权限。阿里云的拒绝原文不说缺哪个权限（OSS 甚至只说 bucket 不属于你）；
 * 证书服务、点播等会在 AccessDeniedDetail.AuthAction 里给出被拒的 Action，云解析、直播、ESA 只给加密的诊断信息，
 * 这时按「服务代码:接口名」推出——与 api.aliyun.com 元数据里各接口的 ramActions 一致。
 */

/** RAM 服务代码与接入点主机名第一段不同的服务 */
const SERVICE_OF_HOST: Record<string, string> = { cas: "yundun-cert" };

/** 接入点主机名 + 接口名 → RAM Action，如 vod.cn-shanghai.aliyuncs.com + SetVodDomainSSLCertificate → vod:SetVodDomainSSLCertificate */
export function ramAction(endpoint: string, action: string): string {
  const head = endpoint.split(".")[0]!;
  return `${SERVICE_OF_HOST[head] ?? head}:${action}`;
}

/** 包含该服务全部只读 / 读写权限的系统策略名前缀（与 docs/permissions.md 一致） */
const POLICY_PREFIX: Record<string, string> = {
  cdn: "AliyunCDN",
  dcdn: "AliyunDCDN",
  esa: "AliyunESA",
  oss: "AliyunOSS",
  live: "AliyunLive",
  vod: "AliyunVOD",
  "yundun-cert": "AliyunYundunCert",
  alidns: "AliyunDNS",
};

/** 云解析只有签发用到，签发要增删记录：即使被拒的是查询接口也给读写策略 */
const WRITE_ONLY_ADVICE = new Set(["alidns"]);

function systemPolicy(action: string): string | undefined {
  const [service = "", api = ""] = action.split(":");
  const prefix = POLICY_PREFIX[service];
  if (!prefix) return undefined;
  const readOnly = !WRITE_ONLY_ADVICE.has(service) && /^(Describe|List|Get)/.test(api);
  return `${prefix}${readOnly ? "ReadOnlyAccess" : "FullAccess"}`;
}

export interface PermissionDenial {
  action: string;
  /** 被策略显式拒绝（NoPermissionType 为 ExplicitDeny）：加授权没用 */
  explicit?: boolean;
  /** 只凭错误码推断（如 OSS 的 AccessDenied 也可能来自 bucket 策略），措辞为「可能」 */
  uncertain?: boolean;
}

/** 追加在原错误信息后的说明，如「（缺少 RAM 权限 cdn:SetCdnDomainSSLCertificate，可授予系统策略 AliyunCDNFullAccess）」 */
export function permissionHint({ action, explicit, uncertain }: PermissionDenial): string {
  if (explicit) return `（RAM 权限 ${action} 被策略显式拒绝，请在 RAM 控制台解除该拒绝）`;
  const policy = systemPolicy(action);
  return `（${uncertain ? "可能" : ""}缺少 RAM 权限 ${action}${policy ? `，可授予系统策略 ${policy}` : ""}）`;
}
