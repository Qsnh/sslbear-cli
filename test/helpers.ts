import { vi } from "vitest";
import { run } from "../src/cli.js";
import type { Fetch } from "../src/lib/http.js";

export interface FakeRequest {
  url: URL;
  method: string;
  headers: Record<string, string>;
  body: string;
  /** 阿里云 RPC 的 Action（query 参数）或腾讯云的 X-TC-Action */
  action?: string;
  /** 腾讯云请求体 JSON */
  json?: Record<string, unknown>;
}

export type FakeReply = { status?: number; body: unknown } | undefined;

/** 按请求路由返回固定响应；没命中的请求返回 404，测试里能直接看到漏了哪个接口 */
export function fakeFetch(route: (req: FakeRequest) => FakeReply): Fetch & { calls: FakeRequest[] } {
  const calls: FakeRequest[] = [];
  const fn = async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init?.headers ?? {}) as Record<string, string>)) headers[k.toLowerCase()] = v;
    const body = typeof init?.body === "string" ? init.body : "";
    const req: FakeRequest = {
      url,
      method: init?.method ?? "GET",
      headers,
      body,
      action: url.searchParams.get("Action") ?? headers["x-tc-action"],
      ...(body.startsWith("{") && { json: JSON.parse(body) }),
    };
    calls.push(req);
    const reply = route(req);
    if (!reply) return new Response(`no route: ${req.method} ${url.host} ${req.action ?? url.search}`, { status: 404 });
    const text = typeof reply.body === "string" ? reply.body : JSON.stringify(reply.body);
    return new Response(text, { status: reply.status ?? 200 });
  };
  return Object.assign(fn as Fetch, { calls });
}

export interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
  /** --json 模式下解析后的 stdout */
  json?: any;
}

export async function runCli(argv: string[], opts: { env?: Record<string, string>; fetch?: Fetch; now?: string; cwd?: string } = {}): Promise<CliResult> {
  const out: string[] = [];
  const err: string[] = [];
  const log = vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => void out.push(a.join(" ")));
  const error = vi.spyOn(console, "error").mockImplementation((...a: unknown[]) => void err.push(a.join(" ")));
  const stdoutWrite = vi.spyOn(process.stdout, "write").mockImplementation((s: string | Uint8Array) => (out.push(String(s)), true));
  const stderrWrite = vi.spyOn(process.stderr, "write").mockImplementation((s: string | Uint8Array) => (err.push(String(s)), true));
  try {
    const code = await run(argv, {
      env: opts.env ?? {},
      fetch: opts.fetch ?? fakeFetch(() => undefined),
      now: () => new Date(opts.now ?? "2026-10-15T00:00:00Z"),
      cwd: opts.cwd ?? "/nonexistent-sslbear-test",
      sleep: async () => {},
    });
    const stdout = out.join("\n");
    let json: unknown;
    if (argv.includes("--json") && stdout.trim()) json = JSON.parse(stdout.trim());
    return { code, stdout, stderr: err.join("\n"), json };
  } finally {
    log.mockRestore();
    error.mockRestore();
    stdoutWrite.mockRestore();
    stderrWrite.mockRestore();
  }
}

export const ALIYUN_ENV = { ALIBABA_CLOUD_ACCESS_KEY_ID: "LTAItestid0000", ALIBABA_CLOUD_ACCESS_KEY_SECRET: "testsecret" };
export const TENCENT_ENV = { TENCENTCLOUD_SECRET_ID: "AKIDtest00000000", TENCENTCLOUD_SECRET_KEY: "testkey" };
