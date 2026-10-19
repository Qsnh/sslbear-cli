/** ACME（RFC 8555）各模块之间的约定：acme.ts 实现客户端，run.ts 编排签发流程 */

export const LETSENCRYPT_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory";
export const LETSENCRYPT_STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory";

export type KeyType = "rsa" | "ecc";

export interface AcmeDirectory {
  url: string;
  newNonce: string;
  newAccount: string;
  newOrder: string;
  /** RFC 9773 ACME Renewal Information；CA 不支持时缺省 */
  renewalInfo?: string;
  /** meta.profiles：配置文件名 → 说明；CA 不支持配置文件时缺省 */
  profiles?: Record<string, string>;
  termsOfService?: string;
}

export interface AcmeOrder {
  url: string;
  status: "pending" | "ready" | "processing" | "valid" | "invalid";
  /** 授权的 URL，与 identifiers 一一对应 */
  authorizations: string[];
  finalize: string;
  /** status 为 valid 时才有 */
  certificate?: string;
}

export interface AcmeAuthorization {
  url: string;
  status: "pending" | "valid" | "invalid" | "deactivated" | "expired" | "revoked";
  /** 验证对象的域名：泛域名 *.example.com 的授权为 example.com 且 wildcard = true */
  domain: string;
  wildcard: boolean;
  /** dns-01 质询；授权已是 valid 时可能缺省 */
  challenge?: { url: string; token: string; status: string };
}

export interface AcmeClient {
  readonly directory: AcmeDirectory;
  /** 注册账号或取回已有账号（同意 CA 的订阅协议）；之后的请求都用账号 URL（kid）签名 */
  ensureAccount(email?: string): Promise<void>;
  /** profile：CA 支持配置文件时指定（Let's Encrypt 用 classic）；replaces：ARI 证书标识，表示这是对那张证书的续签 */
  newOrder(domains: readonly string[], opts?: { profile?: string; replaces?: string }): Promise<AcmeOrder>;
  getAuthorization(url: string): Promise<AcmeAuthorization>;
  /** dns-01 的 TXT 记录值：base64url(SHA-256(token + "." + 账号公钥 JWK 指纹)) */
  dnsTxtValue(token: string): string;
  /** 通知 CA 开始验证质询 */
  answerChallenge(url: string): Promise<void>;
  /** 轮询授权直到 valid；变为 invalid 时抛 AcmeError（type 为质询里的错误类型，detail 为 CA 给的原因）；超时抛 AcmeError type "timeout" */
  waitAuthorization(url: string, timeoutMs: number): Promise<void>;
  /** 提交 CSR（DER）并轮询订单直到 valid，返回带 certificate URL 的订单；invalid 抛 AcmeError */
  finalize(order: AcmeOrder, csrDer: Buffer, timeoutMs: number): Promise<AcmeOrder>;
  /** 下载证书链 PEM（叶子在前） */
  downloadCertificate(url: string): Promise<string>;
}

/**
 * ACME 出错：CA 返回的 problem document（RFC 7807）或网络错误。
 * type 为去掉 "urn:ietf:params:acme:error:" 前缀后的短名（如 rateLimited、unauthorized、dns），
 * 网络错误为 "network"，超时为 "timeout"
 */
export class AcmeError extends Error {
  /** 授权变成了 invalid（CA 验证没通过）；只有 waitAuthorization 会设置，用来与请求被拒、授权过期等区分 */
  invalidAuthorization = false;

  constructor(
    public type: string,
    public detail: string,
    public httpStatus?: number,
    /** Retry-After 响应头（秒），限流时 CA 会给 */
    public retryAfter?: number,
    /** 子问题（如多个域名各自的验证失败原因），格式「域名：原因」 */
    public subproblems?: string[],
  ) {
    super(detail);
    this.name = "AcmeError";
  }

  /** 网络错误、超时、CA 服务端错误、限流值得稍后原样重试 */
  get retryable(): boolean {
    return ["network", "timeout", "serverInternal", "rateLimited", "badNonce"].includes(this.type) || (this.httpStatus ?? 0) >= 500;
  }
}
