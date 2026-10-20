import { describe, expect, it } from "vitest";
import { loadEnvFile, mask, parseDotenv, readAliyun, readTencent } from "../src/lib/env.js";
import { CloudApiError, isRetryable, send, withRetry } from "../src/lib/http.js";
import { renderDomains } from "../src/render.js";
import { displayWidth, renderTable } from "../src/lib/table.js";
import { daysUntil, toIso } from "../src/lib/time.js";
import { xmlBlocks, xmlText } from "../src/lib/xml.js";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

describe("toIso", () => {
  it("无时区的本地时间按北京时间处理", () => {
    expect(toIso("2024-07-02 13:31:09")).toBe("2024-07-02T05:31:09.000Z");
    expect(toIso("2024-07-02")).toBe("2024-07-01T16:00:00.000Z");
    expect(toIso("2024-11-06 08:00:0")).toBe("2024-11-06T00:00:00.000Z");
  });
  it("带时区的 ISO 与 RFC 1123 原样换算", () => {
    expect(toIso("2024-07-02T05:31:09Z")).toBe("2024-07-02T05:31:09.000Z");
    expect(toIso("Mon, 4 May 2048 10:14:51 GMT")).toBe("2048-05-04T10:14:51.000Z");
  });
  it("Unix 纪元及以前的零值时间（如 EdgeOne 申请中的免费证书 0001-01-01T00:00:00Z）视为没有", () => {
    expect(toIso("0001-01-01T00:00:00Z")).toBeUndefined();
    expect(toIso("1970-01-01T00:00:00Z")).toBeUndefined();
    expect(toIso(0)).toBeUndefined();
    expect(toIso("1970-01-01T00:00:01Z")).toBe("1970-01-01T00:00:01.000Z");
  });
  it("秒级与毫秒级时间戳", () => {
    expect(toIso(1719898269)).toBe("2024-07-02T05:31:09.000Z");
    expect(toIso(1719898269000)).toBe("2024-07-02T05:31:09.000Z");
    expect(toIso("1719898269000")).toBe("2024-07-02T05:31:09.000Z");
  });
  it("空值与非法值返回 undefined", () => {
    expect(toIso("")).toBeUndefined();
    expect(toIso(null)).toBeUndefined();
    expect(toIso("not a date")).toBeUndefined();
    expect(toIso("--")).toBeUndefined();
  });
});

describe("daysUntil", () => {
  const now = new Date("2026-10-15T00:00:00Z");
  it("向下取整，过期为负", () => {
    expect(daysUntil("2026-10-15T12:00:00Z", now)).toBe(0);
    expect(daysUntil("2026-11-14T00:00:00Z", now)).toBe(30);
    expect(daysUntil("2026-10-14T00:00:00Z", now)).toBe(-1);
    expect(daysUntil(undefined, now)).toBeUndefined();
  });
});

describe(".env", () => {
  it("解析注释、export 前缀与引号", () => {
    expect(
      parseDotenv(`# comment\nexport A=1\nB="two words"\nC='x#y'\nD=bare # trailing\n\nbad line`),
    ).toEqual({ A: "1", B: "two words", C: "x#y", D: "bare" });
  });
  it("引号后跟注释、值里含 = 与 #、双引号转义", () => {
    expect(
      parseDotenv(
        [
          `S1="abc"  # prod`,
          `S2='sec#ret' # c`,
          `S3=a=b=c`,
          `S4=p#ss`,
          String.raw`S5="say \"hi\" \\ done\n"`,
          `S6=''`,
        ].join("\n"),
      ),
    ).toEqual({ S1: "abc", S2: "sec#ret", S3: "a=b=c", S4: "p#ss", S5: 'say "hi" \\ done\n', S6: "" });
  });
  it("不覆盖已存在的环境变量", () => {
    const dir = mkdtempSync(join(tmpdir(), "sslbear-"));
    const file = join(dir, ".env");
    writeFileSync(file, "A=from-file\nB=from-file\n");
    const env: Record<string, string | undefined> = { A: "from-shell" };
    expect(loadEnvFile(file, env)).toBe(true);
    expect(env).toEqual({ A: "from-shell", B: "from-file" });
    expect(loadEnvFile(join(dir, "missing"), env)).toBe(false);
  });
  it("shell 里设置了某组的任一变量时，整组都不从文件读取", () => {
    const dir = mkdtempSync(join(tmpdir(), "sslbear-"));
    const file = join(dir, ".env");
    writeFileSync(file, "ID_B=b\nSECRET_B=b\nTOKEN=stale\nOTHER=x\n");
    const env: Record<string, string | undefined> = { ID_A: "a" };
    loadEnvFile(file, env, [["ID_A", "ID_B", "SECRET_B", "TOKEN"]]);
    expect(env).toEqual({ ID_A: "a", OTHER: "x" });
  });
});

describe("凭证读取", () => {
  it("阿里云：官方变量名优先，支持别名与 STS", () => {
    expect(readAliyun({})).toEqual({ state: "missing" });
    expect(readAliyun({ ALIYUN_ACCESS_KEY_ID: "id", ALIYUN_ACCESS_KEY_SECRET: "sk" })).toEqual({
      state: "ok",
      credentials: { accessKeyId: "id", accessKeySecret: "sk" },
    });
    expect(
      readAliyun({
        ALIBABA_CLOUD_ACCESS_KEY_ID: "id1",
        ALIYUN_ACCESS_KEY_ID: "id2",
        ALIBABA_CLOUD_ACCESS_KEY_SECRET: "sk",
        ALIBABA_CLOUD_SECURITY_TOKEN: "tok",
      }),
    ).toEqual({ state: "ok", credentials: { accessKeyId: "id1", accessKeySecret: "sk", securityToken: "tok" } });
    expect(readAliyun({ ALIBABA_CLOUD_ACCESS_KEY_ID: "id" })).toMatchObject({
      state: "incomplete",
      missing: ["ALIBABA_CLOUD_ACCESS_KEY_SECRET"],
    });
  });
  it("阿里云：ID / Secret / Token 只从同一个名族取，不跨名族拼凑", () => {
    expect(
      readAliyun({
        ALIBABA_CLOUD_ACCESS_KEY_ID: "id-b",
        ALIYUN_ACCESS_KEY_ID: "id-a",
        ALIYUN_ACCESS_KEY_SECRET: "sk-a",
      }),
    ).toMatchObject({ state: "incomplete", missing: ["ALIBABA_CLOUD_ACCESS_KEY_SECRET"] });
    expect(
      readAliyun({ ALIYUN_ACCESS_KEY_ID: "id-a", ALIYUN_ACCESS_KEY_SECRET: "sk-a", ALIBABA_CLOUD_SECURITY_TOKEN: "stale" }),
    ).toEqual({ state: "ok", credentials: { accessKeyId: "id-a", accessKeySecret: "sk-a" } });
  });
  it("腾讯云：空白值视为未设置", () => {
    expect(readTencent({ TENCENTCLOUD_SECRET_ID: "  ", TENCENTCLOUD_SECRET_KEY: "" })).toEqual({ state: "missing" });
    expect(readTencent({ TENCENTCLOUD_SECRET_KEY: "k" })).toMatchObject({ state: "incomplete", missing: ["TENCENTCLOUD_SECRET_ID"] });
  });
  it("脱敏保留首尾", () => {
    expect(mask("LTAI5tAbCdEfGhIjKlMn")).toBe("LTAI********KlMn");
    expect(mask("short")).toBe("*****");
  });
});

describe("表格", () => {
  it("中文按两列宽对齐", () => {
    expect(displayWidth("阿里云a")).toBe(7);
    expect(renderTable(["云厂商", "域名"], [["腾讯云", "a.com"], ["x", "b.com"]])).toBe(
      "云厂商  域名\n腾讯云  a.com\nx       b.com",
    );
  });
});

describe("xml", () => {
  it("按标签取块与文本", () => {
    const xml = "<R><Cname><Domain>a.com</Domain></Cname><Cname><Domain>b&amp;c.com</Domain></Cname></R>";
    expect(xmlBlocks(xml, "Cname").map((b) => xmlText(b, "Domain"))).toEqual(["a.com", "b&c.com"]);
    expect(xmlText(xml, "Missing")).toBeUndefined();
  });
});

describe("withRetry", () => {
  const ctx = { fetch, timeoutMs: 1000, now: new Date(), env: {}, sleep: async () => {} };
  it("HTTP 429 即使错误码不像限流也重试", async () => {
    let n = 0;
    const r = await withRetry(ctx, async () => {
      if (n++ === 0) throw new CloudApiError("qiniu", "HTTP429", "too many requests", undefined, 429);
      return "ok";
    });
    expect([r, n]).toEqual(["ok", 2]);
  });
  it("其他错误不重试", async () => {
    let n = 0;
    await expect(
      withRetry(ctx, async () => {
        n++;
        throw new CloudApiError("qiniu", "HTTP400", "bad request", undefined, 400);
      }),
    ).rejects.toThrow("bad request");
    expect(n).toBe(1);
  });
});

describe("send", () => {
  it("请求头含换行等非法字符（凭证里混入控制字符）：错误信息不带头部值，不可重试", async () => {
    const ctx = { fetch, timeoutMs: 1000, now: new Date(), env: {} };
    const e = await send(ctx, "cloudflare", "http://127.0.0.1:9/", { headers: { Authorization: "Bearer secret-part\nrest" } }).catch((err: unknown) => err);
    expect(e).toBeInstanceOf(CloudApiError);
    expect(e).toMatchObject({ code: "InvalidRequest" });
    expect((e as Error).message).not.toContain("secret-part");
    expect(isRetryable(e)).toBe(false);
  });
});

describe("renderDomains", () => {
  it("平台默认域名的证书列显示「平台托管」", () => {
    const out = renderDomains([
      { provider: "tencent", service: "vod", domain: "1250000000.vod2.myqcloud.com", https: true, extra: { managed: "platform" } },
      { provider: "tencent", service: "vod", domain: "v.example.com", https: false },
    ]);
    const lines = out.split("\n");
    expect(lines.find((l) => l.includes("vod2.myqcloud.com"))).toContain("平台托管");
    expect(lines.find((l) => l.includes("v.example.com"))).not.toContain("平台托管");
  });
});
