import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { Command } from "commander";
import { describe, expect, it } from "vitest";
import pkg from "../package.json" with { type: "json" };
import { buildProgram } from "../src/cli.js";
import { SKILL_AGENTS, SKILL_SOURCE, readSkillFiles } from "../src/skill.js";
import { fakeFetch, runCli } from "./helpers.js";

const tmp = () => mkdtempSync(join(tmpdir(), "sslbear-skill-"));
const FILES = readSkillFiles();

/** 安装结果与包内的 skill 逐个文件一致 */
function expectInstalled(dir: string): void {
  for (const [rel, content] of Object.entries(FILES)) expect(readFileSync(join(dir, rel), "utf8")).toBe(content);
}

describe("skill install", () => {
  it("默认装进检测到的 agent，重复执行不改动，内容有差异时整个目录重写", async () => {
    const home = tmp();
    mkdirSync(join(home, ".claude"));
    mkdirSync(join(home, ".codex"));
    const r = await runCli(["skill", "install", "--json"], { home });
    expect(r.code).toBe(0);
    expect(r.json.data).toEqual({
      skill: "sslbear-cli",
      version: pkg.version,
      installed: [
        { agent: "claude-code", path: join(home, ".claude/skills/sslbear-cli"), action: "created" },
        { agent: "codex", path: join(home, ".codex/skills/sslbear-cli"), action: "created" },
      ],
    });
    expectInstalled(join(home, ".claude/skills/sslbear-cli"));
    expect(existsSync(join(home, ".cursor"))).toBe(false);

    const again = await runCli(["skill", "install", "--json"], { home });
    expect(again.json.data.installed.map((i: any) => i.action)).toEqual(["unchanged", "unchanged"]);

    // 旧版本留下的文件、被改过的文件：整个目录按当前版本重写
    const dir = join(home, ".claude/skills/sslbear-cli");
    writeFileSync(join(dir, "references/old.md"), "旧文档");
    writeFileSync(join(dir, "SKILL.md"), "改过");
    const updated = await runCli(["skill", "install", "--json"], { home });
    expect(updated.json.data.installed.map((i: any) => i.action)).toEqual(["updated", "unchanged"]);
    expect(existsSync(join(dir, "references/old.md"))).toBe(false);
    expectInstalled(dir);
  });

  it("--agent 指定的没检测到也装；CLAUDE_CONFIG_DIR / CODEX_HOME 改了配置目录时装到那里", async () => {
    const home = tmp();
    const claudeHome = join(tmp(), "claude-config");
    const r = await runCli(["skill", "install", "--agent", "cursor,claude-code,cursor", "--json"], {
      home,
      env: { CLAUDE_CONFIG_DIR: claudeHome },
    });
    expect(r.code).toBe(0);
    expect(r.json.data.installed).toEqual([
      { agent: "cursor", path: join(home, ".cursor/skills/sslbear-cli"), action: "created" },
      { agent: "claude-code", path: join(claudeHome, "skills/sslbear-cli"), action: "created" },
    ]);
    expectInstalled(join(claudeHome, "skills/sslbear-cli"));
  });

  it("只给 --dir 时只装进这个目录（相对当前目录），不装进检测到的 agent", async () => {
    const home = tmp();
    mkdirSync(join(home, ".claude"));
    const cwd = tmp();
    const r = await runCli(["skill", "install", "--dir", ".claude/skills", "--json"], { home, cwd });
    expect(r.code).toBe(0);
    expect(r.json.data.installed).toEqual([{ agent: "custom", path: join(cwd, ".claude/skills/sslbear-cli"), action: "created" }]);
    expect(existsSync(join(home, ".claude/skills"))).toBe(false);
    expectInstalled(join(cwd, ".claude/skills/sslbear-cli"));
  });

  it("同名的是 skills CLI 建的符号链接时换成真实目录，不动链接指向的目录", async () => {
    const home = tmp();
    const shared = join(home, ".agents/skills/sslbear-cli");
    mkdirSync(shared, { recursive: true });
    writeFileSync(join(shared, "SKILL.md"), "skills CLI 装的旧版");
    mkdirSync(join(home, ".claude/skills"), { recursive: true });
    symlinkSync(shared, join(home, ".claude/skills/sslbear-cli"));
    const r = await runCli(["skill", "install", "--agent", "claude-code", "--json"], { home });
    expect(r.json.data.installed[0].action).toBe("updated");
    expect(lstatSync(join(home, ".claude/skills/sslbear-cli")).isSymbolicLink()).toBe(false);
    expectInstalled(join(home, ".claude/skills/sslbear-cli"));
    expect(readFileSync(join(shared, "SKILL.md"), "utf8")).toBe("skills CLI 装的旧版");
  });

  it("不支持的 agent、--agent 为空、没检测到任何 agent 时 exit 2，不写任何文件", async () => {
    const home = tmp();
    for (const argv of [["--agent", "vscode"], ["--agent", ","], []]) {
      const r = await runCli(["skill", "install", ...argv, "--json"], { home });
      expect(r.code).toBe(2);
      expect(JSON.parse(r.stderr)).toMatchObject({ ok: false, status: "UsageError" });
    }
    expect(JSON.parse((await runCli(["skill", "install", "--json"], { home })).stderr).message).toContain("--dir");
  });

  it("终端输出列出每个 agent 的安装位置和结果", async () => {
    const home = tmp();
    mkdirSync(join(home, ".agents"));
    const r = await runCli(["skill", "install"], { home });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain(`sslbear-cli skill（${pkg.version}）`);
    expect(r.stdout).toMatch(/通用目录 ~\/\.agents\s+\S+\.agents\/skills\/sslbear-cli\s+新安装/);
  });

  it("不调用任何云接口", async () => {
    const fetch = fakeFetch(() => undefined);
    await runCli(["skill", "install", "--dir", tmp()], { fetch });
    expect(fetch.calls).toHaveLength(0);
  });
});

/** 列出所有命令（含子命令）支持的长参数 */
function longOptions(cmd: Command): string[] {
  return [...cmd.options.map((o) => o.long ?? ""), ...cmd.commands.flatMap(longOptions)].filter(Boolean);
}

describe("skill 文档与 CLI 保持一致", () => {
  const all = Object.values(FILES).join("\n");

  it("SKILL.md 的 frontmatter 合规：name 与目录名一致，description 不超过 1024 字符", () => {
    const m = /^---\nname: (.+)\ndescription: (.+)\n---\n/.exec(FILES["SKILL.md"]!);
    expect(m).not.toBeNull();
    expect(m![1]).toBe("sslbear-cli");
    expect(SKILL_SOURCE.replace(/\/$/, "").endsWith("/skills/sslbear-cli")).toBe(true);
    expect(m![2]!.length).toBeLessThanOrEqual(1024);
    expect(m![2]).not.toMatch(/[<>]/);
  });

  it("文档里的相对链接都指向 skill 内存在的文件", () => {
    for (const [rel, content] of Object.entries(FILES)) {
      for (const [, target] of content.matchAll(/\]\(([^)#]+)(?:#[^)]*)?\)/g)) {
        if (/^https?:/.test(target!)) continue;
        expect(existsSync(resolve(SKILL_SOURCE, dirname(rel), target!)), `${rel} → ${target}`).toBe(true);
      }
    }
  });

  it("文档里提到的长参数都是 CLI 实际支持的", () => {
    const supported = new Set([...longOptions(buildProgram({ env: {}, fetch: fakeFetch(() => undefined), now: () => new Date(), cwd: "/" })), "--help", "--version"]);
    const mentioned = new Set(all.match(/(?<![\w-])--[a-z][a-z-]*/g));
    expect([...mentioned].filter((o) => !supported.has(o))).toEqual([]);
  });

  it("--help 列出的 issue 失败 status、deploy 跳过原因和失败 code，文档里都有处理方法", async () => {
    const issueHelp = (await runCli(["issue", "--help"])).stdout;
    const statuses = [...issueHelp.matchAll(/^ {2}([A-Z][A-Za-z]+) {2,}/gm)].map((m) => m[1]!);
    expect(statuses).toContain("ZoneNotFound");
    const deployHelp = (await runCli(["deploy", "--help"])).stdout;
    const reasons = [...deployHelp.matchAll(/^ {2}([a-z_]+) {2,}/gm)].map((m) => m[1]!);
    expect(reasons).toContain("shared_cert_blocked");
    const codes = ["HttpsStateUnknown", "DomainNotFound", "NotCovered", "CertWithoutCommonName", "HttpsAlreadyEnabled", "HttpsDisabled", "DomainBusy"];
    for (const name of [...statuses, ...reasons, ...codes]) expect(all, name).toContain(`\`${name}\``);
  });

  it("每个支持的 agent 名都能在 --help 里看到，skill 目录随 npm 包发布", async () => {
    const help = (await runCli(["skill", "install", "--help"])).stdout;
    for (const name of Object.keys(SKILL_AGENTS)) expect(help).toContain(name);
    expect(pkg.files).toContain("skills");
  });
});
