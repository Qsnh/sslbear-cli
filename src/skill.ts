import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Env } from "./lib/env.js";

export const SKILL_NAME = "sslbear-cli";

/**
 * 包内的 skill 目录：源码（src/skill.ts）和打包产物（dist/index.js）都在包根目录下一层，
 * 所以都是 ../skills/sslbear-cli。同一份文件也供 `npx skills add Qsnh/sslbear-cli` 从仓库安装
 */
export const SKILL_SOURCE = fileURLToPath(new URL(`../skills/${SKILL_NAME}/`, import.meta.url));

interface AgentDef {
  label: string;
  /** agent 的用户级配置目录：存在即视为本机装了这个 agent，skill 装进它下面的 skills/ */
  home: (env: Env, home: string) => string;
}

const at =
  (...parts: string[]) =>
  (_env: Env, home: string) =>
    join(home, ...parts);

/** 名称与目录沿用 skills CLI（vercel-labs/skills）的约定，用户在两边用同一个名字 */
export const SKILL_AGENTS: Record<string, AgentDef> = {
  "claude-code": { label: "Claude Code", home: (env, home) => env.CLAUDE_CONFIG_DIR?.trim() || join(home, ".claude") },
  codex: { label: "Codex", home: (env, home) => env.CODEX_HOME?.trim() || join(home, ".codex") },
  cursor: { label: "Cursor", home: at(".cursor") },
  "gemini-cli": { label: "Gemini CLI", home: at(".gemini") },
  "github-copilot": { label: "GitHub Copilot", home: at(".copilot") },
  opencode: { label: "OpenCode", home: (env, home) => join(env.XDG_CONFIG_HOME?.trim() || join(home, ".config"), "opencode") },
  openclaw: { label: "OpenClaw", home: at(".openclaw") },
  codebuddy: { label: "CodeBuddy", home: at(".codebuddy") },
  workbuddy: { label: "WorkBuddy", home: at(".workbuddy") },
  trae: { label: "Trae", home: at(".trae") },
  "trae-cn": { label: "Trae CN", home: at(".trae-cn") },
  qoder: { label: "Qoder", home: at(".qoder") },
  "qwen-code": { label: "Qwen Code", home: at(".qwen") },
  "kiro-cli": { label: "Kiro CLI", home: at(".kiro") },
  windsurf: { label: "Windsurf", home: at(".codeium", "windsurf") },
  "hermes-agent": { label: "Hermes Agent", home: (env, home) => env.HERMES_HOME?.trim() || join(home, ".hermes") },
  // 跨 agent 的通用目录，Cline 等直接读这里
  agents: { label: "通用目录 ~/.agents", home: at(".agents") },
};

export type InstallAction = "created" | "updated" | "unchanged";

export interface InstallResult {
  agent: string;
  /** 安装后的 skill 目录 */
  path: string;
  action: InstallAction;
}

/** 本机装了的 agent（配置目录存在） */
export function detectAgents(env: Env, home: string): string[] {
  return Object.entries(SKILL_AGENTS)
    .filter(([, a]) => existsSync(a.home(env, home)))
    .map(([name]) => name);
}

export function agentSkillsDir(agent: string, env: Env, home: string): string {
  return join(SKILL_AGENTS[agent]!.home(env, home), "skills");
}

/** 递归列出目录下的文件（相对路径，/ 分隔），忽略点文件 */
function listFiles(dir: string, prefix = ""): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith(".")) continue;
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) files.push(...listFiles(join(dir, entry.name), rel));
    else files.push(rel);
  }
  return files.sort();
}

/** 读出包内 skill 的全部文件：相对路径 → 内容 */
export function readSkillFiles(source: string = SKILL_SOURCE): Record<string, string> {
  return Object.fromEntries(listFiles(source).map((rel) => [rel, readFileSync(join(source, rel), "utf8")]));
}

/**
 * 把 skill 写进 <skillsDir>/sslbear-cli/，幂等：内容一致时不动；有差异（含多出的旧文件）时整个目录重写，
 * 升级后不会残留已删除的文档。目录名是本 skill 专用的，重写不会波及其他 skill
 */
export function installSkill(agent: string, skillsDir: string, files: Record<string, string>): InstallResult {
  const dir = join(skillsDir, SKILL_NAME);
  const wanted = Object.keys(files).sort();
  const existed = existsSync(dir);
  let inSync = false;
  if (existed) {
    try {
      const current = listFiles(dir);
      inSync = current.join("\n") === wanted.join("\n") && wanted.every((rel) => readFileSync(join(dir, rel), "utf8") === files[rel]);
    } catch {
      // 读不了（如同名的是个文件）就整个重写
    }
  }
  if (!inSync) {
    // 同名的可能是 skills CLI 建的符号链接：rmSync 只删链接本身，不动链接指向的目录
    rmSync(dir, { recursive: true, force: true });
    for (const rel of wanted) {
      const path = join(dir, rel);
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, files[rel]!);
    }
  }
  return { agent, path: dir, action: inSync ? "unchanged" : existed ? "updated" : "created" };
}
