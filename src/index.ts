import { homedir } from "node:os";
import { createInterface } from "node:readline/promises";
import { run } from "./cli.js";

/** 终端里询问 [y/N]：y / yes（不区分大小写）为同意，其余（含直接回车、Ctrl+D）为不同意 */
async function confirm(question: string): Promise<boolean> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  // Ctrl+C 中止整个命令：此时还没有做任何修改
  rl.on("SIGINT", () => {
    rl.close();
    process.stdout.write("\n");
    process.exit(130);
  });
  // 输入被关闭（Ctrl+D）时 question 不会返回，按不同意处理
  const closed = new Promise<string>((r) => rl.once("close", () => r("")));
  try {
    const answer = await Promise.race([rl.question(`${question} `), closed]);
    return /^y(es)?$/i.test(answer.trim());
  } finally {
    rl.close();
  }
}

/**
 * 收到 SIGINT / SIGTERM 时先跑 onSignal（issue 删除本次加的 TXT 记录）再退出，最多等 30 秒；
 * 再按一次 Ctrl+C 立即退出
 */
function trapInterrupt(onSignal: () => Promise<void>): () => void {
  let fired = false;
  const handler = (signal: NodeJS.Signals) => {
    const code = signal === "SIGINT" ? 130 : 143;
    if (fired) process.exit(code);
    fired = true;
    const limit = new Promise<void>((r) => setTimeout(r, 30_000).unref());
    // 等 stderr 写完再退出：macOS 上写管道是异步的，直接 exit 会丢掉最后那行错误 JSON
    void Promise.race([onSignal(), limit])
      .catch(() => {})
      .finally(() => process.stderr.write("", () => process.exit(code)));
  };
  process.on("SIGINT", handler);
  process.on("SIGTERM", handler);
  return () => {
    process.off("SIGINT", handler);
    process.off("SIGTERM", handler);
  };
}

const code = await run(process.argv.slice(2), {
  env: process.env,
  fetch: globalThis.fetch,
  now: () => new Date(),
  cwd: process.cwd(),
  home: homedir(),
  trapInterrupt,
  // 只有人在终端直接运行时才交互；AI / 脚本调用（管道、重定向）不询问
  ...(process.stdin.isTTY && process.stdout.isTTY && { confirm }),
});
process.exitCode = code;
