export type Provider = "aliyun" | "tencent" | "volcengine" | "huawei" | "baidu" | "qiniu";

export const PROVIDERS: readonly Provider[] = ["aliyun", "tencent", "volcengine", "huawei", "baidu", "qiniu"];

/** issue 命令可用来自动设置 DNS 验证记录的 DNS 服务商：前 5 家与云厂商同名，复用同一组凭证 */
export type DnsVendor =
  | "aliyun"
  | "tencent"
  | "volcengine"
  | "huawei"
  | "baidu"
  | "cloudflare"
  | "aws"
  | "google"
  | "azure"
  | "digitalocean"
  | "godaddy";

export const DNS_VENDORS: readonly DnsVendor[] = [
  "aliyun",
  "tencent",
  "volcengine",
  "huawei",
  "baidu",
  "cloudflare",
  "aws",
  "google",
  "azure",
  "digitalocean",
  "godaddy",
];

/** 调用了接口的一方：云厂商或 DNS 服务商（错误信息、限流重试用） */
export type Vendor = Provider | DnsVendor;

export const PROVIDER_LABEL: Record<Provider, string> = {
  aliyun: "阿里云",
  tencent: "腾讯云",
  volcengine: "火山引擎",
  huawei: "华为云",
  baidu: "百度智能云",
  qiniu: "七牛云",
};

/** 证书信息，各云厂商字段归一后的结果；时间统一为 ISO 8601 (UTC) */
export interface CertInfo {
  id?: string;
  name?: string;
  commonName?: string;
  sans?: string[];
  issuer?: string;
  notBefore?: string;
  notAfter?: string;
  /** 云厂商返回的原始状态值 */
  status?: string;
  /** 证书密钥算法，双证书服务用来区分同一域名上的两张证书 */
  algorithm?: "RSA" | "ECC" | "SM2";
}

/** 某个云服务上配置的一个域名，以及它当前绑定的证书 */
export interface DomainRecord {
  provider: Provider;
  service: string;
  domain: string;
  /** 域名在该云服务上的状态（原始值） */
  status?: string;
  https: boolean;
  cert?: CertInfo;
  /** 域名同时绑了多张证书（RSA + ECC 双证书、国际 + 国密）时列出全部；cert 为其中最早到期的一张 */
  certs?: CertInfo[];
  /** 证书剩余天数，负数表示已过期；无证书或无到期时间时缺省 */
  daysLeft?: number;
  /** bucket / zone / region 等定位信息 */
  extra?: Record<string, string | undefined>;
}

/** 证书服务（阿里云数字证书管理服务、腾讯云 SSL 证书等）里的一张证书 */
export interface CertificateRecord extends CertInfo {
  provider: Provider;
  id: string;
  daysLeft?: number;
  /** 证书来源：上传 / 购买 / 免费等（原始值） */
  source?: string;
}
