import { pick, type CredentialState, type Env } from "../lib/env.js";
import type { QueryContext } from "../lib/http.js";
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
}

export interface EnvKeySpec {
  /** 按优先级排列的候选变量名，第一个为推荐名 */
  names: readonly string[];
  required: boolean;
  /** 密钥类变量只显示是否已设置，不显示任何字符 */
  secret: boolean;
}

export interface ProviderDef<C> {
  provider: Provider;
  envKeys: EnvKeySpec[];
  readCredentials(env: Env): CredentialState<C>;
  services: DomainService<C>[];
  listCertificates(ctx: QueryContext, creds: C): Promise<CertificateRecord[]>;
  /** 判断错误是否表示「该服务未开通」，这类情况记为提示而非失败 */
  isInactive(code: string, message: string): boolean;
}

export function defineProvider<C>(def: ProviderDef<C>): ProviderDef<C> {
  return def;
}

export function requiredEnvNames(def: ProviderDef<unknown>): string[] {
  return def.envKeys.filter((k) => k.required).map((k) => k.names[0] as string);
}

export interface EnvKeyStatus {
  name: string;
  required: boolean;
  /** 实际生效的变量名（可能是别名），未设置时缺省 */
  source?: string;
  /** 非密钥类变量的脱敏值 */
  masked?: string;
}

export function envKeyStatus(def: ProviderDef<unknown>, env: Env, mask: (v: string) => string): EnvKeyStatus[] {
  return def.envKeys.map((k) => {
    const hit = pick(env, k.names);
    return {
      name: k.names[0] as string,
      required: k.required,
      ...(hit && { source: hit.name, ...(!k.secret && { masked: mask(hit.value) }) }),
    };
  });
}
