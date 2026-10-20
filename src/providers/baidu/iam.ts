/**
 * 无权限时在报错里写出可授予的系统策略。百度智能云的拒绝原文都不说缺哪个权限（实测 2026-10）：
 * CDN 403 Forbidden「the current sub user does not have permission」、证书管理 403 BceSignatureValidateException.UnauthorizedException
 * 「您没有当前操作的访问权限」、智能云解析 401 PermissionDeny「logical permission deny.」（列域名不报错、返回空列表，见 dns/baidu.ts）。
 * 按接入点与请求方法推断：读接口给只读策略，写接口给运维策略（策略名以控制台的系统策略列表为准，与 docs/permissions.md 一致）。
 */

interface Rule {
  /** 拒绝时的错误码与原文 */
  denied: (code: string, message: string) => boolean;
  read: string;
  write: string;
}

const RULES: Record<string, Rule> = {
  "cdn.baidubce.com": {
    denied: (code, message) => code === "Forbidden" && /permission/i.test(message),
    read: "系统策略 CDNReadAccessPolicy，或自定义策略里 bce:cdn 的 QueryDomainList、QueryDomainConfig",
    write: "系统策略 CDNOperateAccessPolicy，或自定义策略里 bce:cdn 的 UpdateDomain",
  },
  "certificate.baidubce.com": {
    denied: (code) => code === "BceSignatureValidateException.UnauthorizedException",
    read: "系统策略 CASReadAccessPolicy",
    write: "系统策略 CASOperateAccessPolicy",
  },
  // 只有签发用到，签发要增删记录：查询被拒也给运维策略
  "dns.baidubce.com": {
    denied: (code) => code === "PermissionDeny",
    read: "系统策略 DNSReadAccessPolicy、DNSOperateAccessPolicy",
    write: "系统策略 DNSReadAccessPolicy、DNSOperateAccessPolicy",
  },
};

/** 缺权限时在原文后追加「（缺少权限，可授予系统策略 x）」，其他错误原样返回；method 为请求方法，GET 算读接口 */
export function explainDenied(host: string, method: string, code: string, message: string): string {
  const rule = RULES[host];
  if (!rule?.denied(code, message)) return message;
  return `${message}（缺少权限，可授予${method === "GET" ? rule.read : rule.write}）`;
}
