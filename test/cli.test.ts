import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import pkg from "../package.json" with { type: "json" };
import { ALIYUN_ENV, TENCENT_ENV, fakeFetch, runCli, type FakeRequest } from "./helpers.js";

/** 阿里云 CDN 三个域名（89 天 / 17 天 / 无 HTTPS）+ 腾讯云 CDN 一个已过期域名，其余服务都返回空 */
function mixedRoutes(req: FakeRequest) {
  const host = req.url.host;
  if (host === "cdn.aliyuncs.com" && req.action === "DescribeUserDomains") {
    return {
      body: {
        TotalCount: 3,
        Domains: {
          PageData: [
            { DomainName: "api.example.com", SslProtocol: "on", DomainStatus: "online" },
            { DomainName: "img.example.com", SslProtocol: "on", DomainStatus: "online" },
            { DomainName: "plain.example.com", SslProtocol: "off", DomainStatus: "online" },
          ],
        },
      },
    };
  }
  if (host === "cdn.aliyuncs.com" && req.action === "DescribeCdnHttpsDomainList") {
    return {
      body: {
        TotalCount: 2,
        CertInfos: {
          CertInfo: [
            { DomainName: "api.example.com", CertName: "api-2026", CertCommonName: "api.example.com", CertExpireTime: "2027-01-12 08:00:00" },
            { DomainName: "img.example.com", CertName: "img-cert", CertCommonName: "*.cdn-assets.net", CertExpireTime: "2026-11-01 08:00:00" },
          ],
        },
      },
    };
  }
  if (host.endsWith(".aliyuncs.com") && host.startsWith("oss-")) return { body: "<ListAllMyBucketsResult><Buckets></Buckets></ListAllMyBucketsResult>" };
  if (host.endsWith(".aliyuncs.com")) return { body: { TotalCount: 0, Domains: { PageData: [] }, CertInfos: { CertInfo: [] } } };
  if (host === "cdn.tencentcloudapi.com") {
    return {
      body: {
        Response: {
          TotalNumber: 1,
          Domains: [
            { Domain: "static.example.cn", Status: "online", Https: { Switch: "on", CertInfo: { CertName: "static-cert", ExpireTime: "2026-10-12 08:00:00" } } },
          ],
        },
      },
    };
  }
  if (host === "teo.tencentcloudapi.com") return { body: { Response: { TotalCount: 0, Zones: [] } } };
  if (host === "service.cos.myqcloud.com") return { body: "<ListAllMyBucketsResult><Buckets></Buckets></ListAllMyBucketsResult>" };
  if (host === "live.tencentcloudapi.com") return { body: { Response: { AllCount: 0, DomainList: [], TotalNum: 0, LiveDomainCertBindings: [] } } };
  if (host === "vod.tencentcloudapi.com") return { body: { Response: { TotalCount: 0, DomainSet: [], SubAppIdInfoSet: [] } } };
  return undefined;
}

const BOTH = { ...ALIYUN_ENV, ...TENCENT_ENV };

describe("凭证与参数校验", () => {
  it("没有任何凭证时 exit 2 并提示需要的环境变量", async () => {
    const r = await runCli(["domains"]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("ALIBABA_CLOUD_ACCESS_KEY_ID");
    expect(r.stderr).toContain("TENCENTCLOUD_SECRET_ID");
  });

  it("显式指定未配置的云厂商 exit 2", async () => {
    const r = await runCli(["domains", "-p", "tencent", "--json"], { env: ALIYUN_ENV });
    expect(r.code).toBe(2);
    expect(JSON.parse(r.stderr)).toMatchObject({ ok: false, status: "UsageError" });
  });

  it("凭证不完整 exit 2 并指出缺哪个", async () => {
    const r = await runCli(["certs"], { env: { TENCENTCLOUD_SECRET_ID: "x" } });
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("TENCENTCLOUD_SECRET_KEY");
  });

  it("未知云厂商 / 服务、服务与云厂商不匹配、非法天数都 exit 2，且不发请求", async () => {
    const fetch = fakeFetch(() => undefined);
    for (const argv of [
      ["domains", "-p", "aws"],
      ["domains", "-s", "s3"],
      ["domains", "-p", "aliyun", "-s", "teo"],
      ["domains", "-e", "abc"],
      ["domains", "-e", "-1"],
    ]) {
      const r = await runCli(argv, { env: BOTH, fetch });
      expect(r.code, argv.join(" ")).toBe(2);
    }
    expect(fetch.calls).toHaveLength(0);
  });

  it("多余的位置参数（如 -d 后用空格分隔多个域名）exit 2，且不发请求", async () => {
    const fetch = fakeFetch(() => undefined);
    for (const argv of [
      ["domains", "abc", "--json"],
      ["deploy", "--cert", "a.pem", "--key", "b.pem", "-d", "a.example.com", "b.example.com", "--json"],
    ]) {
      const r = await runCli(argv, { env: BOTH, fetch });
      expect(r.code, argv.join(" ")).toBe(2);
      expect(JSON.parse(r.stderr), argv.join(" ")).toMatchObject({ ok: false, status: "UsageError", message: expect.stringContaining("too many arguments") });
    }
    expect(fetch.calls).toHaveLength(0);
  });

  it("--help 与 --version exit 0", async () => {
    expect((await runCli(["--help"])).code).toBe(0);
    const v = await runCli(["--version"]);
    expect(v.code).toBe(0);
    expect(v.stdout.trim()).toBe(pkg.version);
  });

  it("--help 里手工排版的命令说明原样输出，不在句中折行", async () => {
    const r = await runCli(["issue", "--help"]);
    expect(r.stdout).toContain("产出 fullchain.pem + privkey.pem，可直接用于 deploy --cert / --key。\n");
    expect(r.stdout).toContain("即视为同意 Let's Encrypt 订阅协议（https://letsencrypt.org/repository/）。\n");
    expect(r.stdout).toContain("--out 可改；\n    目录 700");
  });
});

describe("domains 汇总", () => {
  it("两家云一起查，按剩余天数升序，无证书的排最后", async () => {
    const r = await runCli(["domains", "--json"], { env: BOTH, fetch: fakeFetch(mixedRoutes) });
    expect(r.code).toBe(0);
    expect(r.json.data.issues).toEqual([]);
    expect(r.json.data.items.map((d: any) => [d.provider, d.domain, d.daysLeft])).toEqual([
      ["tencent", "static.example.cn", -3],
      ["aliyun", "img.example.com", 17],
      ["aliyun", "api.example.com", 89],
      ["aliyun", "plain.example.com", undefined],
    ]);
  });

  it("--expiring-within 只保留 N 天内到期（含已过期）", async () => {
    const r = await runCli(["domains", "-e", "30", "--json"], { env: BOTH, fetch: fakeFetch(mixedRoutes) });
    expect(r.json.data.items.map((d: any) => d.domain)).toEqual(["static.example.cn", "img.example.com"]);
  });

  it("--domain 同时匹配域名和证书通用名", async () => {
    const r = await runCli(["domains", "-d", "CDN-ASSETS", "--json"], { env: BOTH, fetch: fakeFetch(mixedRoutes) });
    expect(r.json.data.items.map((d: any) => d.domain)).toEqual(["img.example.com"]);
  });

  it("只配置一家云时只查这一家", async () => {
    const fetch = fakeFetch(mixedRoutes);
    const r = await runCli(["domains", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(fetch.calls.every((c) => c.url.host.endsWith(".aliyuncs.com"))).toBe(true);
  });

  it("表格输出带汇总行，问题输出到 stderr", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.host === "dcdn.aliyuncs.com") return { status: 403, body: { Code: "DcdnServiceNotFound", Message: "The DCDN service is not activated." } };
      if (req.url.host === "live.aliyuncs.com") return { status: 403, body: { Code: "Forbidden.RAM", Message: "User not authorized", RequestId: "r-9" } };
      return mixedRoutes(req);
    });
    const r = await runCli(["domains", "-p", "aliyun"], { env: BOTH, fetch, now: "2026-10-15T00:00:00Z" });
    expect(r.code).toBe(0);
    const lines = r.stdout.split("\n");
    expect(lines[0]).toMatch(/^云厂商\s+服务\s+域名\s+HTTPS\s+证书\s+到期时间\s+剩余天数$/);
    expect(lines[1]).toMatch(/^阿里云\s+CDN\s+img\.example\.com\s+开启\s+img-cert\s+\d{4}-\d{2}-\d{2}\s+17$/);
    expect(r.stdout).toContain("共 3 个域名，1 个 30 天内到期，1 个未开启 HTTPS");
    expect(r.stderr).toContain("提示：aliyun/dcdn 未开通或无资源（DcdnServiceNotFound）");
    expect(r.stderr).toContain("警告：aliyun/live 查询失败：Forbidden.RAM User not authorized（RequestId: r-9）");
  });

  it("没有符合条件的结果时给出提示", async () => {
    const r = await runCli(["domains", "-p", "aliyun", "-e", "0"], { env: BOTH, fetch: fakeFetch(mixedRoutes) });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("没有 0 天内到期的证书");
  });
});

describe("env 与 .env", () => {
  it("env 脱敏显示 AccessKey ID，Secret 只显示已设置", async () => {
    const r = await runCli(["env", "--json"], {
      env: { ALIYUN_ACCESS_KEY_ID: "LTAI5tAbCdEfGhIjKlMn", ALIYUN_ACCESS_KEY_SECRET: "super-secret-value" },
    });
    expect(r.code).toBe(0);
    expect(r.stdout).not.toContain("super-secret-value");
    expect(r.stdout).not.toContain("LTAI5tAbCdEfGhIjKlMn");
    const [aliyun, tencent] = r.json.data.providers;
    expect(aliyun).toMatchObject({ provider: "aliyun", state: "ok" });
    expect(aliyun.keys).toEqual([
      { name: "ALIYUN_ACCESS_KEY_ID", required: true, set: true, masked: "LTAI********KlMn" },
      { name: "ALIYUN_ACCESS_KEY_SECRET", required: true, set: true },
      { name: "ALIYUN_SECURITY_TOKEN", required: false, set: false },
    ]);
    expect(tencent).toMatchObject({ provider: "tencent", state: "missing" });
    expect(tencent.keys.map((k: any) => k.name)).toEqual(["TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY", "TENCENTCLOUD_SESSION_TOKEN"]);
  });

  it("env 列出所有云厂商：别名族按实际生效的展示，七牛云没有 Token 变量", async () => {
    const r = await runCli(["env", "--json"], { env: { HW_ACCESS_KEY: "hw-ak-0123456789", HW_SECRET_KEY: "hw-sk", QINIU_ACCESS_KEY: "qn-ak" } });
    const byProvider = Object.fromEntries(r.json.data.providers.map((p: any) => [p.provider, p]));
    expect(Object.keys(byProvider)).toEqual(["aliyun", "tencent", "volcengine", "huawei", "baidu", "qiniu"]);
    expect(byProvider.huawei).toMatchObject({ state: "ok" });
    expect(byProvider.huawei.keys.map((k: any) => k.name)).toEqual(["HW_ACCESS_KEY", "HW_SECRET_KEY", "HW_SECURITY_TOKEN"]);
    expect(byProvider.qiniu).toMatchObject({ state: "incomplete" });
    expect(byProvider.qiniu.keys).toEqual([
      { name: "QINIU_ACCESS_KEY", required: true, set: true, masked: "*****" },
      { name: "QINIU_SECRET_KEY", required: true, set: false },
    ]);
    expect(byProvider.volcengine.keys.map((k: any) => k.name)).toEqual(["VOLCENGINE_ACCESS_KEY", "VOLCENGINE_SECRET_KEY", "VOLCENGINE_SESSION_TOKEN"]);
    expect(byProvider.baidu.keys.map((k: any) => k.name)).toEqual(["BAIDUCLOUD_ACCESS_KEY", "BAIDUCLOUD_SECRET_KEY", "BAIDUCLOUD_SESSION_TOKEN"]);
  });

  it("自动加载当前目录 .env", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sslbear-cli-"));
    writeFileSync(join(dir, ".env"), "TENCENTCLOUD_SECRET_ID=from-file-id\nTENCENTCLOUD_SECRET_KEY=from-file-key\n");
    const fetch = fakeFetch((req) => (req.action === "DescribeCertificates" ? { body: { Response: { TotalCount: 0, Certificates: [] } } } : undefined));
    const r = await runCli(["certs", "--json"], { fetch, cwd: dir });
    expect(r.code).toBe(0);
    expect(fetch.calls[0]!.headers.authorization).toContain("Credential=from-file-id/");
    const e = await runCli(["env"], { cwd: dir });
    expect(e.stdout).toContain(`.env 文件：${join(dir, ".env")}`);
  });

  it("shell 里配置了某家云的凭证时，.env 里这家的凭证整组忽略，不拼凑", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sslbear-cli-"));
    writeFileSync(
      join(dir, ".env"),
      "ALIBABA_CLOUD_ACCESS_KEY_ID=file-id\nALIBABA_CLOUD_SECURITY_TOKEN=stale\nTENCENTCLOUD_SECRET_ID=t-id\nTENCENTCLOUD_SECRET_KEY=t-key\n",
    );
    const fetch = fakeFetch((req) => {
      if (req.url.host === "cas.aliyuncs.com") return { body: { TotalCount: 0, CertificateOrderList: [] } };
      if (req.url.host === "ssl.tencentcloudapi.com") return { body: { Response: { TotalCount: 0, Certificates: [] } } };
      return undefined;
    });
    const r = await runCli(["certs", "--json"], {
      env: { ALIYUN_ACCESS_KEY_ID: "shell-id", ALIYUN_ACCESS_KEY_SECRET: "shell-secret" },
      fetch,
      cwd: dir,
    });
    expect(r.code).toBe(0);
    const cas = fetch.calls.find((c) => c.url.host === "cas.aliyuncs.com")!;
    expect(cas.url.searchParams.get("AccessKeyId")).toBe("shell-id");
    expect(cas.url.searchParams.get("SecurityToken")).toBeNull();
    // 腾讯云在 shell 里没有任何变量，照常从 .env 读取
    expect(fetch.calls.some((c) => c.headers.authorization?.includes("Credential=t-id/"))).toBe(true);
  });

  it("当前目录没有 .env 时加载 ~/.sslbear-cli/.env（SSLBEAR_CLI_HOME 可改目录）；当前目录有 .env 时只用它", async () => {
    const home = mkdtempSync(join(tmpdir(), "sslbear-cli-home-"));
    mkdirSync(join(home, ".sslbear-cli"));
    writeFileSync(join(home, ".sslbear-cli/.env"), "QINIU_ACCESS_KEY=home-ak\nQINIU_SECRET_KEY=home-sk\n");
    const fromHome = await runCli(["env", "--json"], { home });
    expect(fromHome.json.data.envFile).toBe(join(home, ".sslbear-cli/.env"));
    expect(fromHome.json.data.providers.find((p: any) => p.provider === "qiniu").state).toBe("ok");

    const custom = mkdtempSync(join(tmpdir(), "sslbear-cli-state-"));
    writeFileSync(join(custom, ".env"), "QINIU_ACCESS_KEY=custom-ak\n");
    const fromCustom = await runCli(["env", "--json"], { home, env: { SSLBEAR_CLI_HOME: custom } });
    expect(fromCustom.json.data.envFile).toBe(join(custom, ".env"));
    expect(fromCustom.json.data.providers.find((p: any) => p.provider === "qiniu").state).toBe("incomplete");

    const cwd = mkdtempSync(join(tmpdir(), "sslbear-cli-"));
    writeFileSync(join(cwd, ".env"), "TENCENTCLOUD_SECRET_ID=cwd-id\n");
    const fromCwd = await runCli(["env", "--json"], { home, cwd });
    expect(fromCwd.json.data.envFile).toBe(join(cwd, ".env"));
    expect(fromCwd.json.data.providers.find((p: any) => p.provider === "qiniu").state).toBe("missing");

    const none = await runCli(["env"], { home: mkdtempSync(join(tmpdir(), "sslbear-cli-home-")) });
    expect(none.stdout).toContain(".env 文件：未加载（当前目录和 ~/.sslbear-cli 下都没有 .env）");
  });

  it("--env-file 指定的文件不存在时 exit 2", async () => {
    const r = await runCli(["env", "--env-file", "nope.env"]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("nope.env");
  });
});

describe("审查发现问题的回归测试", () => {
  it("--json 下参数错误也输出 JSON；无参数运行按参数错误退出", async () => {
    const r = await runCli(["domains", "--json", "--bogus"], { env: BOTH });
    expect(r.code).toBe(2);
    expect(r.stdout).toBe("");
    expect(JSON.parse(r.stderr)).toEqual({ ok: false, status: "UsageError", message: "unknown option '--bogus'" });
    const missing = await runCli(["domains", "-e", "--json"], { env: BOTH });
    expect(missing.code).toBe(2);
    expect(JSON.parse(missing.stderr)).toMatchObject({ ok: false, status: "UsageError" });
    expect((await runCli([])).code).toBe(2);
  });

  it("--timeout 必须在 1~600000 之间", async () => {
    for (const t of ["0", "3000000000", "1.5"]) {
      expect((await runCli(["domains", "--timeout", t], { env: BOTH })).code, t).toBe(2);
    }
  });

  it("重复指定云厂商 / 服务不会重复查询", async () => {
    const fetch = fakeFetch(mixedRoutes);
    const r = await runCli(["domains", "-p", "aliyun,aliyun", "-p", "aliyun", "-s", "cdn,cdn", "--json"], { env: BOTH, fetch });
    expect(r.json.data.items).toHaveLength(3);
    expect(fetch.calls.filter((c) => c.action === "DescribeUserDomains")).toHaveLength(1);
  });

  it("没有任何查询成功时 exit 1；未开通的服务不计入失败数，JSON 里带上全部 issues", async () => {
    const fetch = fakeFetch((req) => {
      const inactive: Record<string, string> = {
        "cdn.aliyuncs.com": "CdnServiceNotFound",
        "dcdn.aliyuncs.com": "DcdnServiceNotFound",
        "live.aliyuncs.com": "LiveServiceNotFound",
        "vod.cn-shanghai.aliyuncs.com": "VodServiceNotFound",
        "esa.cn-hangzhou.aliyuncs.com": "EsaService.NotOpen",
      };
      const code = inactive[req.url.host];
      if (code) return { status: 403, body: { Code: code, Message: "not activated" } };
      return { status: 403, body: "<Error><Code>AccessDenied</Code><Message>denied</Message></Error>" };
    });
    const r = await runCli(["domains", "-p", "aliyun"], { env: BOTH, fetch });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("没有任何查询成功（1 项失败）");
    const j = await runCli(["domains", "-p", "aliyun", "--json"], { env: BOTH, fetch });
    expect(j.code).toBe(1);
    const err = JSON.parse(j.stderr);
    expect(err).toMatchObject({ ok: false, status: "AccessDenied" });
    expect(err.issues.map((i: any) => `${i.service}:${i.kind}`).sort()).toEqual([
      "cdn:inactive",
      "dcdn:inactive",
      "esa:inactive",
      "live:inactive",
      "oss:error",
      "vod:inactive",
    ]);
  });

  it("接口悄悄把 pageSize 截小时，按 total 继续翻页不漏数据", async () => {
    const all = Array.from({ length: 120 }, (_, i) => ({ Domain: `d${i}.example.cn`, Status: "online" }));
    const fetch = fakeFetch((req) => {
      if (req.action !== "DescribeDomainsConfig") return undefined;
      const offset = req.json!.Offset as number;
      return { body: { Response: { TotalNumber: all.length, Domains: all.slice(offset, offset + 50) } } };
    });
    const r = await runCli(["domains", "-p", "tencent", "-s", "cdn", "--json"], { env: BOTH, fetch });
    expect(r.json.data.items).toHaveLength(120);
  });

  it("读取响应体超时按 Timeout 重试", async () => {
    let n = 0;
    const base = fakeFetch(mixedRoutes);
    const fetch = (async (input: any, init?: any) => {
      if (n++ === 0) {
        return {
          status: 200,
          text: async () => {
            throw new DOMException("The operation was aborted due to timeout", "TimeoutError");
          },
        } as unknown as Response;
      }
      return base(input, init);
    }) as typeof globalThis.fetch;
    const r = await runCli(["domains", "-p", "tencent", "-s", "cdn", "--json"], { env: BOTH, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toHaveLength(1);
    expect(n).toBe(2);
  });

  it("未开启 HTTPS 的域名不挂证书、不计入到期统计", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeUserDomains") {
        return { body: { TotalCount: 1, Domains: { PageData: [{ DomainName: "off.example.com", SslProtocol: "off" }] } } };
      }
      if (req.action === "DescribeCdnHttpsDomainList") {
        return { body: { TotalCount: 1, CertInfos: { CertInfo: [{ DomainName: "off.example.com", CertName: "old", CertExpireTime: "2026-01-01 00:00:00" }] } } };
      }
      if (req.url.host.startsWith("oss-")) {
        return { body: "<ListAllMyBucketsResult><Buckets><Bucket><Name>b</Name><Region>cn-hangzhou</Region><ExtranetEndpoint>oss-cn-hangzhou.aliyuncs.com</ExtranetEndpoint></Bucket></Buckets></ListAllMyBucketsResult>" };
      }
      if (req.url.host === "b.oss-cn-hangzhou.aliyuncs.com") {
        return { body: "<ListCnameResult><Cname><Domain>oss-off.example.com</Domain><Certificate><CertId>1</CertId><Status>Disabled</Status><ValidEndDate>Mon, 4 May 2020 10:14:51 GMT</ValidEndDate></Certificate></Cname></ListCnameResult>" };
      }
      if (req.action === "DescribeLiveDomains") return { body: { Response: { AllCount: 1, DomainList: [{ Name: "live-off.example.com", Type: 1, Status: 1 }] } } };
      if (req.action === "DescribeLiveDomainCertBindings") {
        return { body: { Response: { TotalNum: 1, LiveDomainCertBindings: [{ DomainName: "live-off.example.com", Status: 0, CertExpireTime: "2020-01-01 00:00:00" }] } } };
      }
      return undefined;
    });
    const a = await runCli(["domains", "-p", "aliyun", "-s", "cdn,oss", "--json"], { env: BOTH, fetch });
    const t = await runCli(["domains", "-p", "tencent", "-s", "live", "--json"], { env: BOTH, fetch });
    const items = [...a.json.data.items, ...t.json.data.items];
    expect(items.map((d: any) => [d.domain, d.https, d.cert, d.daysLeft])).toEqual([
      ["off.example.com", false, undefined, undefined],
      ["oss-off.example.com", false, undefined, undefined],
      ["live-off.example.com", false, undefined, undefined],
    ]);
    const expiring = await runCli(["domains", "-p", "aliyun", "-s", "cdn,oss", "-e", "30", "--json"], { env: BOTH, fetch });
    expect(expiring.json.data.items).toEqual([]);
  });
});
