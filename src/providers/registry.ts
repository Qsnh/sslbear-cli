import { resolveFamily, type Credentials, type Env, type EnvFamily } from "../lib/env.js";
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

export interface ProviderDef<C> {
  provider: Provider;
  /** 支持的环境变量名族，第一个为推荐名 */
  envFamilies: readonly EnvFamily[];
  readCredentials(env: Env): Credentials<C>;
  services: DomainService<C>[];
  listCertificates(ctx: QueryContext, creds: C): Promise<CertificateRecord[]>;
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
export function envKeyStatus(def: ProviderDef<unknown>, env: Env, mask: (v: string) => string): EnvKeyStatus[] {
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
