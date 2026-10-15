/** fail() 不直接 process.exit：抛 ExitError 由入口统一退出，测试才能捕获退出码 */
export class ExitError extends Error {
  constructor(
    public exitCode: number,
    message?: string,
  ) {
    super(message ?? `exit ${exitCode}`);
  }
}

export interface OutputOptions {
  json: boolean;
}

export function outJson(data: unknown): void {
  console.log(JSON.stringify({ ok: true, data }));
}

/** exitCode：1 = 接口/网络错误，2 = 参数或配置错误 */
export function fail(opts: OutputOptions, status: number | string, message: string, exitCode = 1): never {
  if (opts.json) {
    console.error(JSON.stringify({ ok: false, status, message }));
  } else {
    console.error(`错误：${message}`);
  }
  throw new ExitError(exitCode, message);
}
