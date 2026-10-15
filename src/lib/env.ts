import { existsSync, readFileSync } from "node:fs";

export type Env = Record<string, string | undefined>;

const QUOTED = /^(["'])((?:\\.|(?!\1).)*)\1\s*(?:#.*)?$/;

/**
 * 解析 .env 内容：支持 `export ` 前缀、# 注释、单/双引号包裹（引号后可跟注释）。
 * 双引号内支持 \n \" \\ 转义；不带引号的值从 " #" 起视为注释。
 */
export function parseDotenv(content: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    const key = m[1] as string;
    const rest = m[2] as string;
    const q = QUOTED.exec(rest);
    if (q) {
      const body = q[2] as string;
      result[key] = q[1] === '"' ? body.replace(/\\(.)/g, (_, c: string) => (c === "n" ? "\n" : c)) : body;
    } else {
      result[key] = rest.replace(/\s+#.*$/, "");
    }
  }
  return result;
}

/**
 * 读取 .env 文件合并进 env，返回文件是否存在。
 * 已存在的变量不会被覆盖；groups 中任一变量已在 env 里设置时，整组都不从文件读取，
 * 避免同一云厂商的 ID 取自 shell、Secret / Token 取自 .env 拼出一组错配的凭证。
 */
export function loadEnvFile(path: string, env: Env, groups: readonly (readonly string[])[] = []): boolean {
  if (!existsSync(path)) return false;
  const fileVars = parseDotenv(readFileSync(path, "utf8"));
  const blocked = new Set(groups.filter((g) => g.some((name) => env[name]?.trim())).flat());
  for (const [k, v] of Object.entries(fileVars)) {
    if (env[k] === undefined && !blocked.has(k)) env[k] = v;
  }
  return true;
}

export interface AliyunCredentials {
  accessKeyId: string;
  accessKeySecret: string;
  securityToken?: string;
}

export interface TencentCredentials {
  secretId: string;
  secretKey: string;
  sessionToken?: string;
}

/**
 * 每家云厂商支持的变量名族：官方 SDK 变量名在前，常见别名在后。
 * 同一组凭证（ID / Secret / Token）只从同一个名族里取，不跨名族拼凑。
 */
export const ENV_FAMILIES = {
  aliyun: [
    { id: "ALIBABA_CLOUD_ACCESS_KEY_ID", secret: "ALIBABA_CLOUD_ACCESS_KEY_SECRET", token: "ALIBABA_CLOUD_SECURITY_TOKEN" },
    { id: "ALIYUN_ACCESS_KEY_ID", secret: "ALIYUN_ACCESS_KEY_SECRET", token: "ALIYUN_SECURITY_TOKEN" },
  ],
  tencent: [{ id: "TENCENTCLOUD_SECRET_ID", secret: "TENCENTCLOUD_SECRET_KEY", token: "TENCENTCLOUD_SESSION_TOKEN" }],
} as const;

export interface EnvFamily {
  id: string;
  secret: string;
  token: string;
}

export function familyNames(families: readonly EnvFamily[]): string[] {
  return families.flatMap((f) => [f.id, f.secret, f.token]);
}

const value = (env: Env, name: string) => env[name]?.trim() || undefined;

export type CredentialState =
  | { state: "ok"; family: EnvFamily; id: string; secret: string; token?: string }
  | { state: "missing" }
  | { state: "incomplete"; family: EnvFamily; missing: string[] };

/** 取第一个设置了 ID 或 Secret 的名族；该名族缺任一必填项即为配置不完整 */
export function resolveFamily(env: Env, families: readonly EnvFamily[]): CredentialState {
  const family = families.find((f) => value(env, f.id) || value(env, f.secret));
  if (!family) return { state: "missing" };
  const id = value(env, family.id);
  const secret = value(env, family.secret);
  if (!id || !secret) return { state: "incomplete", family, missing: [!id ? family.id : family.secret] };
  const token = value(env, family.token);
  return { state: "ok", family, id, secret, ...(token && { token }) };
}

export type Credentials<T> = { state: "ok"; credentials: T } | Exclude<CredentialState, { state: "ok" }>;

export function readAliyun(env: Env): Credentials<AliyunCredentials> {
  const r = resolveFamily(env, ENV_FAMILIES.aliyun);
  if (r.state !== "ok") return r;
  return { state: "ok", credentials: { accessKeyId: r.id, accessKeySecret: r.secret, ...(r.token && { securityToken: r.token }) } };
}

export function readTencent(env: Env): Credentials<TencentCredentials> {
  const r = resolveFamily(env, ENV_FAMILIES.tencent);
  if (r.state !== "ok") return r;
  return { state: "ok", credentials: { secretId: r.id, secretKey: r.secret, ...(r.token && { sessionToken: r.token }) } };
}

/** 展示用脱敏：保留首尾各 4 位 */
export function mask(value: string): string {
  if (value.length <= 8) return "*".repeat(value.length);
  return `${value.slice(0, 4)}${"*".repeat(Math.min(value.length - 8, 8))}${value.slice(-4)}`;
}
