import { mkdtempSync, writeFileSync } from "node:fs";
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

  it("--help 与 --version exit 0", async () => {
    expect((await runCli(["--help"])).code).toBe(0);
    const v = await runCli(["--version"]);
    expect(v.code).toBe(0);
    expect(v.stdout.trim()).toBe(pkg.version);
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
    expect(aliyun.keys[0]).toEqual({ name: "ALIBABA_CLOUD_ACCESS_KEY_ID", required: true, source: "ALIYUN_ACCESS_KEY_ID", masked: "LTAI********KlMn" });
    expect(aliyun.keys[1]).toEqual({ name: "ALIBABA_CLOUD_ACCESS_KEY_SECRET", required: true, source: "ALIYUN_ACCESS_KEY_SECRET" });
    expect(tencent).toMatchObject({ provider: "tencent", state: "missing" });
  });

  it("自动加载当前目录 .env，shell 变量优先", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sslbear-cli-"));
    writeFileSync(join(dir, ".env"), "TENCENTCLOUD_SECRET_ID=from-file-id\nTENCENTCLOUD_SECRET_KEY=from-file-key\n");
    const fetch = fakeFetch((req) => (req.action === "DescribeCertificates" ? { body: { Response: { TotalCount: 0, Certificates: [] } } } : undefined));
    const r = await runCli(["certs", "--json"], { env: { TENCENTCLOUD_SECRET_ID: "from-shell" }, fetch, cwd: dir });
    expect(r.code).toBe(0);
    expect(fetch.calls[0]!.headers.authorization).toContain("Credential=from-shell/");
    const e = await runCli(["env"], { cwd: dir });
    expect(e.stdout).toContain(`.env 文件：${join(dir, ".env")}`);
  });

  it("--env-file 指定的文件不存在时 exit 2", async () => {
    const r = await runCli(["env", "--env-file", "nope.env"]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("nope.env");
  });
});
