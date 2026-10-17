import type { Provider } from "../types.js";
import type { Env } from "./env.js";

export type Fetch = typeof fetch;

export interface QueryContext {
  fetch: Fetch;
  timeoutMs: number;
  now: Date;
  env: Env;
  /** 测试注入，免去重试退避的真实等待 */
  sleep?: (ms: number) => Promise<void>;
}

export class CloudApiError extends Error {
  constructor(
    public provider: Provider,
    public code: string,
    message: string,
    public requestId?: string,
    public httpStatus?: number,
  ) {
    super(message);
    this.name = "CloudApiError";
  }
}

export interface RawResponse {
  status: number;
  text: string;
}

const RETRYABLE = /Throttl|RequestLimitExceeded|ServiceUnavailable|^Timeout$|^NetworkError$/;
const MAX_ATTEMPTS = 3;

/** 限流（含 HTTP 429）、超时和网络错误自动重试（指数退避），其余错误原样抛出 */
export async function withRetry<T>(ctx: QueryContext, fn: () => Promise<T>): Promise<T> {
  const sleep = ctx.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  for (let attempt = 1; ; attempt++) {
    try {
      return await fn();
    } catch (e) {
      const retryable = e instanceof CloudApiError && (RETRYABLE.test(e.code) || e.httpStatus === 429);
      if (!retryable || attempt >= MAX_ATTEMPTS) throw e;
      await sleep(500 * 2 ** (attempt - 1));
    }
  }
}

export async function send(ctx: QueryContext, provider: Provider, url: string, init: RequestInit): Promise<RawResponse> {
  // 读响应体也在超时与网络错误处理范围内：响应头到了但响应体卡住 / 连接中断同样要重试
  try {
    const res = await ctx.fetch(url, { ...init, signal: AbortSignal.timeout(ctx.timeoutMs) });
    return { status: res.status, text: await res.text() };
  } catch (e) {
    const err = e as Error;
    if (err.name === "TimeoutError" || err.name === "AbortError") {
      throw new CloudApiError(provider, "Timeout", `请求超时（${ctx.timeoutMs}ms）：${new URL(url).host}`);
    }
    const cause = (err as { cause?: { code?: string } }).cause?.code;
    throw new CloudApiError(provider, "NetworkError", `网络错误：${new URL(url).host} ${cause ?? err.message}`);
  }
}

export function parseJson(provider: Provider, raw: RawResponse): unknown {
  try {
    return JSON.parse(raw.text);
  } catch {
    throw new CloudApiError(provider, "InvalidResponse", `响应不是合法 JSON（HTTP ${raw.status}）：${raw.text.slice(0, 200)}`, undefined, raw.status);
  }
}
