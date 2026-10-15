import { existsSync, readFileSync } from "node:fs";

export type Env = Record<string, string | undefined>;

/**
 * 解析 .env 内容：支持 `export ` 前缀、# 注释、单/双引号包裹。
 * 已存在的环境变量不会被覆盖，保证 shell 里显式设置的值优先。
 */
export function parseDotenv(content: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    const key = m[1] as string;
    let value = (m[2] as string).trim();
    const quote = value[0];
    if ((quote === '"' || quote === "'") && value.length >= 2 && value.endsWith(quote)) {
      value = value.slice(1, -1);
      if (quote === '"') value = value.replace(/\\n/g, "\n");
    } else {
      value = value.replace(/\s+#.*$/, "");
    }
    result[key] = value;
  }
  return result;
}

/** 读取 .env 文件合并进 env（不覆盖已有值），返回文件是否存在 */
export function loadEnvFile(path: string, env: Env): boolean {
  if (!existsSync(path)) return false;
  for (const [k, v] of Object.entries(parseDotenv(readFileSync(path, "utf8")))) {
    if (env[k] === undefined) env[k] = v;
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

/** 每个配置项按顺序取第一个非空的环境变量：官方 SDK 变量名在前，常见别名在后 */
export const ENV_KEYS = {
  aliyun: {
    accessKeyId: ["ALIBABA_CLOUD_ACCESS_KEY_ID", "ALIYUN_ACCESS_KEY_ID"],
    accessKeySecret: ["ALIBABA_CLOUD_ACCESS_KEY_SECRET", "ALIYUN_ACCESS_KEY_SECRET"],
    securityToken: ["ALIBABA_CLOUD_SECURITY_TOKEN", "ALIYUN_SECURITY_TOKEN"],
  },
  tencent: {
    secretId: ["TENCENTCLOUD_SECRET_ID"],
    secretKey: ["TENCENTCLOUD_SECRET_KEY"],
    sessionToken: ["TENCENTCLOUD_SESSION_TOKEN"],
  },
} as const;

export interface EnvValue {
  name: string;
  value: string;
}

export function pick(env: Env, names: readonly string[]): EnvValue | undefined {
  for (const name of names) {
    const value = env[name]?.trim();
    if (value) return { name, value };
  }
  return undefined;
}

export type CredentialState<T> =
  | { state: "ok"; credentials: T }
  | { state: "missing" }
  | { state: "incomplete"; missing: string[] };

export function readAliyun(env: Env): CredentialState<AliyunCredentials> {
  const k = ENV_KEYS.aliyun;
  const id = pick(env, k.accessKeyId);
  const secret = pick(env, k.accessKeySecret);
  if (!id && !secret) return { state: "missing" };
  if (!id || !secret) {
    return { state: "incomplete", missing: [!id ? k.accessKeyId[0] : k.accessKeySecret[0]] };
  }
  const token = pick(env, k.securityToken);
  return {
    state: "ok",
    credentials: { accessKeyId: id.value, accessKeySecret: secret.value, ...(token && { securityToken: token.value }) },
  };
}

export function readTencent(env: Env): CredentialState<TencentCredentials> {
  const k = ENV_KEYS.tencent;
  const id = pick(env, k.secretId);
  const key = pick(env, k.secretKey);
  if (!id && !key) return { state: "missing" };
  if (!id || !key) {
    return { state: "incomplete", missing: [!id ? k.secretId[0] : k.secretKey[0]] };
  }
  const token = pick(env, k.sessionToken);
  return {
    state: "ok",
    credentials: { secretId: id.value, secretKey: key.value, ...(token && { sessionToken: token.value }) },
  };
}

/** 展示用脱敏：保留首尾各 4 位 */
export function mask(value: string): string {
  if (value.length <= 8) return "*".repeat(value.length);
  return `${value.slice(0, 4)}${"*".repeat(Math.min(value.length - 8, 8))}${value.slice(-4)}`;
}
