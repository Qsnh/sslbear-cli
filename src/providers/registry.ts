import { resolveFamily, type Credentials, type Env, type EnvFamily } from "../lib/env.js";
import type { QueryContext } from "../lib/http.js";
import type { LocalCert } from "../deploy/cert.js";
import type { CertificateRecord, DomainRecord, Provider } from "../types.js";

/**
 * 逐个 bucket / 站点 / 域名展开查询的服务，单个子项失败时调用 warn 记录并继续，
 * 不让一个子项拖垮整个服务；target 标明是哪个子项。
 */
export type Warn = (error: unknown, target: string) => void;

export interface DomainService<C> {
  key: string;
  label: string;
  list(ctx: QueryContext, creds: C, warn: Warn): Promise<DomainRecord[]>;
  /** 部署证书的能力；未定义表示该服务不支持通过 CLI 部署 */
  deployer?: Deployer<C>;
}

export interface DeployTarget {
  /** 通常只有 1 条；sharedScope 相同的记录合并为一组一次部署（如阿里云 ESA 同一站点） */
  records: DomainRecord[];
  /** deploy = 原先没开 HTTPS，绑定证书并开启；update = 只替换证书 */
  mode: "deploy" | "update";
}

export interface DeployInput {
  cert: LocalCert;
  /** 把证书上传到本云的证书服务并返回证书 ID：每次运行每家云最多上传一次，证书服务里已有同一张证书时复用 */
  certId(): Promise<string>;
}

export interface DeployOutcome {
  /** 绑定到域名上的证书 ID（服务直接收 PEM 时可能没有） */
  certId?: string;
  /** 需要提示用户的补充说明 */
  note?: string;
}

export interface Deployer<C> {
  /** 记录级的限制：返回不支持的原因（中文），undefined 表示支持；如推流域名不能绑证书、该服务不能经 API 开启 HTTPS */
  unsupported?(record: DomainRecord, mode: DeployTarget["mode"]): string | undefined;
  /**
   * 证书挂在多个域名共享的对象上时（如 ESA 站点）返回该对象的键，同键的记录要么一起更新、要么都不动。
   * 没开 HTTPS 的记录也会被询问：共享证书会让它开始提供 HTTPS 的，同样要返回键（它会挡住整组）
   */
  sharedScope?(record: DomainRecord): string | undefined;
  /**
   * 该服务不接受（或收下却不生效）没有通用名（CN）的证书：要部署 / 更新时编排层直接记为失败（CertWithoutCommonName），
   * 不上传、不调用 apply。true 用通用说明，字符串为自定义说明
   */
  requiresCommonName?: boolean | string;
  /** 执行部署；失败直接抛错（CloudApiError 会带上错误码与 RequestId） */
  apply(ctx: QueryContext, creds: C, target: DeployTarget, input: DeployInput): Promise<DeployOutcome>;
}

export interface ProviderDef<C> {
  provider: Provider;
  /** 支持的环境变量名族，第一个为推荐名 */
  envFamilies: readonly EnvFamily[];
  readCredentials(env: Env): Credentials<C>;
  services: DomainService<C>[];
  listCertificates(ctx: QueryContext, creds: C): Promise<CertificateRecord[]>;
  /** 上传证书到本云的证书服务（先查重，已有同一张证书时返回其 ID 且 reused = true） */
  uploadCertificate?(ctx: QueryContext, creds: C, cert: LocalCert): Promise<{ id: string; reused: boolean }>;
  /** 判断错误是否表示「该服务未开通」，这类情况记为提示而非失败 */
  isInactive(code: string, message: string): boolean;
}

export function defineProvider<C>(def: ProviderDef<C>): ProviderDef<C> {
  return def;
}

export function requiredEnvNames(def: ProviderDef<unknown>): string[] {
  const f = def.envFamilies[0]!;
  return [f.id, f.secret];
}

export interface EnvKeyStatus {
  name: string;
  required: boolean;
  set: boolean;
  /** 仅 ID 类变量给出脱敏值，Secret / Token 只标明是否已设置 */
  masked?: string;
}

/** 按实际生效的名族展示（都没设置时展示推荐名族） */
export function envKeyStatus(def: Pick<ProviderDef<unknown>, "envFamilies">, env: Env, mask: (v: string) => string): EnvKeyStatus[] {
  const r = resolveFamily(env, def.envFamilies);
  const f = r.state === "missing" ? def.envFamilies[0]! : r.family;
  const get = (name: string) => env[name]?.trim() || undefined;
  const id = get(f.id);
  const keys: EnvKeyStatus[] = [
    { name: f.id, required: true, set: !!id, ...(id && { masked: mask(id) }) },
    { name: f.secret, required: true, set: !!get(f.secret) },
  ];
  if (f.token) keys.push({ name: f.token, required: false, set: !!get(f.token) });
  return keys;
}
