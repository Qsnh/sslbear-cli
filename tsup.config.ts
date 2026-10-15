import { defineConfig } from "tsup";

// 打成单文件、依赖全部内联：npx 拉包后无需再装依赖，冷启动更快
export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  target: "node18",
  platform: "node",
  bundle: true,
  noExternal: [/.*/],
  clean: true,
  minify: false,
  // commander 是 CJS，内联进 ESM 产物后需要真实的 require 来加载 node 内置模块
  banner: {
    js: '#!/usr/bin/env node\nimport { createRequire as __createRequire } from "node:module";\nconst require = __createRequire(import.meta.url);',
  },
});
