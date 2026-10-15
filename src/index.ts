import { run } from "./cli.js";

const code = await run(process.argv.slice(2), {
  env: process.env,
  fetch: globalThis.fetch,
  now: () => new Date(),
  cwd: process.cwd(),
});
process.exitCode = code;
