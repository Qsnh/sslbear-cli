import { familyNames, mask, type Credentials, type Env, type EnvFamily } from "../lib/env.js";
import { envKeyStatus, type EnvKeyStatus } from "../providers/registry.js";
import type { DnsProviderDef } from "./types.js";

type EnvPart<C> = Pick<DnsProviderDef<C>, "envNames" | "requiredEnv" | "readCredentials" | "envKeys">;

/** 与云厂商共用凭证的 DNS 服务商（阿里云、腾讯云等）：变量名族、读取方式都沿用云厂商的 */
export function familyEnv<C>(families: readonly EnvFamily[], read: (env: Env) => Credentials<C>): EnvPart<C> {
  const f = families[0]!;
  return {
    envNames: familyNames(families),
    requiredEnv: [f.id, f.secret],
    readCredentials: read,
    envKeys: (env) => envKeyStatus({ envFamilies: families }, env, mask),
  };
}

/** DNS 专用服务商的一个凭证变量 */
export interface EnvVar {
  name: string;
  /** 别名，name 没设置时依次尝试 */
  aliases?: readonly string[];
  required: boolean;
  /** true = 密钥类，env 命令只显示是否已设置；false = ID / 路径类，显示脱敏值 */
  secret: boolean;
}

const get = (env: Env, v: EnvVar) => [v.name, ...(v.aliases ?? [])].map((n) => env[n]?.trim()).find(Boolean);

/**
 * 按变量清单读取凭证：必填项一个都没设置为 missing，只设置了一部分为 incomplete。
 * build 收到的 values 以 EnvVar.name 为键（别名也归到 name 下），可选项没设置时没有该键。
 */
export function varsEnv<C>(vars: readonly EnvVar[], build: (values: Record<string, string>) => C): EnvPart<C> {
  const required = vars.filter((v) => v.required);
  return {
    envNames: vars.flatMap((v) => [v.name, ...(v.aliases ?? [])]),
    requiredEnv: required.map((v) => v.name),
    readCredentials(env) {
      const missing = required.filter((v) => !get(env, v)).map((v) => v.name);
      if (missing.length === required.length) return { state: "missing" };
      if (missing.length > 0) return { state: "incomplete", missing };
      const values: Record<string, string> = {};
      for (const v of vars) {
        const value = get(env, v);
        if (value) values[v.name] = value;
      }
      return { state: "ok", credentials: build(values) };
    },
    envKeys(env): EnvKeyStatus[] {
      return vars.map((v) => {
        const value = get(env, v);
        return { name: v.name, required: v.required, set: !!value, ...(value && !v.secret && { masked: mask(value) }) };
      });
    },
  };
}
