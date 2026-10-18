import { describe, expect, it } from "vitest";
import { TENCENT_ENV, fakeFetch, runCli, type FakeRequest } from "./helpers.js";

const ok = (data: Record<string, unknown>) => ({ body: { Response: { RequestId: "rid", ...data } } });
const tcError = (Code: string, Message: string) => ({ body: { Response: { RequestId: "rid-err", Error: { Code, Message } } } });

const SSL_CERTS = [
  {
    CertificateId: "ssl-1",
    Alias: "wild",
    Domain: "*.example.com",
    SubjectAltName: ["*.example.com", "example.com"],
    CertBeginTime: "2026-08-01 08:00:00",
    CertEndTime: "2026-10-30 07:59:59",
    Status: 1,
    StatusName: "已通过",
    From: "trustasia",
    ProductZhName: "TrustAsia TLS RSA CA",
  },
];

function sslRoute(req: FakeRequest) {
  if (req.url.host === "ssl.tencentcloudapi.com" && req.action === "DescribeCertificates") {
    return ok({ TotalCount: SSL_CERTS.length, Certificates: SSL_CERTS });
  }
  return undefined;
}

describe("tencent 请求格式", () => {
  it("POST JSON + TC3 签名头，不带 X-TC-Region", async () => {
    const fetch = fakeFetch(sslRoute);
    const r = await runCli(["certs", "-p", "tencent", "--json"], { env: { ...TENCENT_ENV, TENCENTCLOUD_SESSION_TOKEN: "tok" }, fetch });
    expect(r.code).toBe(0);
    const call = fetch.calls[0]!;
    expect(call.method).toBe("POST");
    expect(call.url.href).toBe("https://ssl.tencentcloudapi.com/");
    expect(call.headers["x-tc-version"]).toBe("2019-12-05");
    expect(call.headers["x-tc-region"]).toBeUndefined();
    expect(call.headers["x-tc-token"]).toBe("tok");
    expect(call.headers.authorization).toMatch(
      /^TC3-HMAC-SHA256 Credential=AKIDtest00000000\/\d{4}-\d{2}-\d{2}\/ssl\/tc3_request, SignedHeaders=content-type;host, Signature=[0-9a-f]{64}$/,
    );
    expect(call.json).toEqual({ Offset: 0, Limit: 1000, CertificateType: "SVR" });
  });
});

describe("tencent certs", () => {
  it("SSL 证书：北京时间换算成 UTC，状态取 StatusName", async () => {
    const r = await runCli(["certs", "--json"], { env: TENCENT_ENV, fetch: fakeFetch(sslRoute) });
    expect(r.json.data.items).toEqual([
      {
        provider: "tencent",
        id: "ssl-1",
        name: "wild",
        commonName: "*.example.com",
        sans: ["*.example.com", "example.com"],
        issuer: "TrustAsia TLS RSA CA",
        notBefore: "2026-08-01T00:00:00.000Z",
        notAfter: "2026-10-29T23:59:59.000Z",
        status: "已通过",
        source: "trustasia",
        daysLeft: 14,
      },
    ]);
  });

  it("业务错误以 HTTP 200 + Response.Error 返回", async () => {
    const fetch = fakeFetch(() => tcError("AuthFailure.SecretIdNotFound", "The SecretId is not found"));
    const r = await runCli(["certs", "--json"], { env: TENCENT_ENV, fetch });
    expect(r.code).toBe(1);
    expect(JSON.parse(r.stderr)).toMatchObject({ ok: false, status: "AuthFailure.SecretIdNotFound" });
  });
});

describe("tencent domains", () => {
  it("CDN：Https.CertInfo 直接带到期时间；未开通的服务记为 inactive", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.host === "cdn.tencentcloudapi.com") {
        expect(req.json).toEqual({ Offset: 0, Limit: 100 });
        return ok({
          TotalNumber: 3,
          Domains: [
            {
              Domain: "static.example.cn",
              Status: "online",
              Area: "mainland",
              // 实测 CertName 是证书主域名，Message 才是 SSL 证书的备注名
              Https: { Switch: "on", CertInfo: { CertId: "ssl-9", CertName: "static.example.cn", Message: "static", ExpireTime: "2026-10-12 08:00:00" } },
            },
            { Domain: "dl.example.cn", Status: "offline", Area: "global", Https: null },
            // 平台系统域名：HTTPS 开关开着但没有用户证书（真实响应脱敏）
            {
              Domain: "systemcover-10000001.video.myqcloud.com",
              Status: "online",
              Area: "mainland",
              Cname: "",
              ServiceType: "media",
              Https: { Switch: "on", CertInfo: null, SslStatus: "deployed" },
            },
          ],
        });
      }
      if (req.url.host === "live.tencentcloudapi.com") return tcError("ResourceNotFound.UserNotExist", "用户未注册直播");
      return undefined;
    });
    const r = await runCli(["domains", "-s", "cdn,live", "--json"], { env: TENCENT_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toEqual([
      {
        provider: "tencent",
        service: "cdn",
        domain: "static.example.cn",
        status: "online",
        https: true,
        cert: { id: "ssl-9", name: "static", notAfter: "2026-10-12T00:00:00.000Z" },
        extra: { area: "mainland" },
        daysLeft: -3,
      },
      { provider: "tencent", service: "cdn", domain: "dl.example.cn", status: "offline", https: false, extra: { area: "global" } },
      {
        provider: "tencent",
        service: "cdn",
        domain: "systemcover-10000001.video.myqcloud.com",
        status: "online",
        https: true,
        extra: { area: "mainland", managed: "platform" },
      },
    ]);
    expect(r.json.data.issues).toEqual([
      expect.objectContaining({ service: "live", kind: "inactive", code: "ResourceNotFound.UserNotExist" }),
    ]);
  });

  it("EdgeOne：逐站点查加速域名，多张证书取最早到期", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeZones") return ok({ TotalCount: 2, Zones: [{ ZoneId: "zone-1", ZoneName: "example.io" }, { ZoneId: "zone-2", ZoneName: "broken.io" }] });
      if (req.action === "DescribeAccelerationDomains") {
        if (req.json?.ZoneId === "zone-2") return tcError("InternalError.ProxyServer", "proxy error");
        return ok({
          TotalCount: 2,
          AccelerationDomains: [
            {
              DomainName: "www.example.io",
              DomainStatus: "online",
              Certificate: {
                Mode: "sslcert",
                List: [
                  { CertId: "ecc", Alias: "ecc", ExpireTime: "2027-03-01T00:00:00Z", Status: "deployed" },
                  { CertId: "rsa", Alias: "rsa", ExpireTime: "2026-12-01T00:00:00+00:00", Status: "deployed" },
                ],
              },
            },
            { DomainName: "plain.example.io", DomainStatus: "online", Certificate: { Mode: "disable", List: null } },
          ],
        });
      }
      return undefined;
    });
    const r = await runCli(["domains", "-s", "teo", "--json"], { env: TENCENT_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items[0]).toMatchObject({
      domain: "www.example.io",
      https: true,
      cert: { id: "rsa", notAfter: "2026-12-01T00:00:00.000Z" },
      extra: { zoneId: "zone-1", zone: "example.io", certMode: "sslcert" },
      daysLeft: 47,
    });
    expect(r.json.data.items[1]).toMatchObject({ domain: "plain.example.io", https: false });
    expect(r.json.data.items[1].cert).toBeUndefined();
    expect(r.json.data.issues).toEqual([
      expect.objectContaining({ service: "teo", kind: "error", target: "zone broken.io", code: "InternalError.ProxyServer" }),
    ]);
    // 证书都带 ExpireTime 时不拉 SSL 证书列表
    expect(fetch.calls.some((c) => c.action === "DescribeCertificates")).toBe(false);
  });

  it("EdgeOne：RSA + ECC 双证书时 certs 列出全部，并按 SignAlgo 标出算法", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeZones") return ok({ TotalCount: 1, Zones: [{ ZoneId: "zone-1", ZoneName: "example.io" }] });
      if (req.action === "DescribeAccelerationDomains") {
        return ok({
          TotalCount: 1,
          AccelerationDomains: [
            {
              DomainName: "www.example.io",
              DomainStatus: "online",
              Certificate: {
                Mode: "sslcert",
                List: [
                  { CertId: "ecc", Alias: "ecc", ExpireTime: "2027-03-01T00:00:00Z", SignAlgo: "ECC 256", Status: "deployed" },
                  { CertId: "rsa", Alias: "rsa", ExpireTime: "2026-12-01T00:00:00Z", SignAlgo: "RSA 2048", Status: "deployed" },
                ],
              },
            },
          ],
        });
      }
      return undefined;
    });
    const r = await runCli(["domains", "-s", "teo", "--json"], { env: TENCENT_ENV, fetch });
    expect(r.json.data.items[0]).toMatchObject({
      cert: { id: "rsa", algorithm: "RSA" },
      certs: [
        { id: "rsa", name: "rsa", notAfter: "2026-12-01T00:00:00.000Z", status: "deployed", algorithm: "RSA" },
        { id: "ecc", name: "ecc", notAfter: "2027-03-01T00:00:00.000Z", status: "deployed", algorithm: "ECC" },
      ],
    });
  });

  it("EdgeOne：证书列表只有 CertId 时从 SSL 列表补全后再取最早到期；免费证书模式也算 HTTPS", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeZones") return ok({ TotalCount: 1, Zones: [{ ZoneId: "zone-1", ZoneName: "example.com" }] });
      if (req.action === "DescribeAccelerationDomains") {
        expect(req.json).toEqual({ ZoneId: "zone-1", Offset: 0, Limit: 200 });
        return ok({
          TotalCount: 2,
          AccelerationDomains: [
            // 官方示例里 List 只带 CertId
            { DomainName: "www.example.com", DomainStatus: "online", Certificate: { Mode: "sslcert", List: [{ CertId: "ssl-1" }, { CertId: "ssl-late", ExpireTime: "2027-06-01T00:00:00Z" }] } },
            { DomainName: "free.example.com", DomainStatus: "online", Certificate: { Mode: "eofreecert", List: [{ CertId: "eo-free", ExpireTime: "2026-12-24T15:59:59Z", Status: "deployed" }] } },
          ],
        });
      }
      return sslRoute(req);
    });
    const r = await runCli(["domains", "-s", "teo", "--json"], { env: TENCENT_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toEqual([
      {
        provider: "tencent",
        service: "teo",
        domain: "www.example.com",
        status: "online",
        https: true,
        cert: { id: "ssl-1", name: "wild", commonName: "*.example.com", sans: ["*.example.com", "example.com"], notBefore: "2026-08-01T00:00:00.000Z", notAfter: "2026-10-29T23:59:59.000Z" },
        certs: [
          { id: "ssl-1", name: "wild", commonName: "*.example.com", sans: ["*.example.com", "example.com"], notBefore: "2026-08-01T00:00:00.000Z", notAfter: "2026-10-29T23:59:59.000Z" },
          { id: "ssl-late", notAfter: "2027-06-01T00:00:00.000Z" },
        ],
        extra: { zoneId: "zone-1", zone: "example.com", certMode: "sslcert" },
        daysLeft: 14,
      },
      {
        provider: "tencent",
        service: "teo",
        domain: "free.example.com",
        status: "online",
        https: true,
        cert: { id: "eo-free", notAfter: "2026-12-24T15:59:59.000Z", status: "deployed" },
        extra: { zoneId: "zone-1", zone: "example.com", certMode: "eofreecert" },
        daysLeft: 70,
      },
    ]);
    expect(fetch.calls.filter((c) => c.action === "DescribeCertificates")).toHaveLength(1);
  });

  it("EdgeOne：SSL 列表补全失败只记 issue，域名照常返回", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeZones") return ok({ TotalCount: 1, Zones: [{ ZoneId: "zone-1", ZoneName: "example.com" }] });
      if (req.action === "DescribeAccelerationDomains") {
        return ok({ TotalCount: 1, AccelerationDomains: [{ DomainName: "www.example.com", Certificate: { Mode: "sslcert", List: [{ CertId: "ssl-1" }] } }] });
      }
      if (req.action === "DescribeCertificates") return tcError("UnauthorizedOperation", "no permission");
      return undefined;
    });
    const r = await runCli(["domains", "-s", "teo", "--json"], { env: TENCENT_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toEqual([
      { provider: "tencent", service: "teo", domain: "www.example.com", https: true, cert: { id: "ssl-1" }, extra: { zoneId: "zone-1", zone: "example.com", certMode: "sslcert" } },
    ]);
    expect(r.json.data.issues).toEqual([
      expect.objectContaining({ service: "teo", kind: "error", target: "SSL 证书列表（用于补全到期时间）", code: "UnauthorizedOperation" }),
    ]);
  });

  it("直播：按域名合并证书绑定，缺到期时间的从 SSL 列表补", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeLiveDomains") {
        return ok({
          AllCount: 4,
          DomainList: [
            { Name: "push.example.com", Type: 0, Status: 1 },
            // 平台默认推流域名
            { Name: "12345.livepush.myqcloud.com", Type: 0, Status: 1, BCName: 1, TargetDomain: "12345.livepush.myqcloud.com" },
            { Name: "play.example.com", Type: 1, Status: 1 },
            { Name: "play2.example.com", Type: 1, Status: 0 },
          ],
        });
      }
      if (req.action === "DescribeLiveDomainCertBindings") {
        return ok({
          TotalNum: 2,
          LiveDomainCertBindings: [
            { DomainName: "play.example.com", CertificateAlias: "play", Status: 1, CertExpireTime: "2026-11-20 12:00:00", CloudCertId: "x" },
            { DomainName: "play2.example.com", CertificateAlias: "play2", Status: 1, CloudCertId: "ssl-1" },
          ],
        });
      }
      return sslRoute(req);
    });
    const r = await runCli(["domains", "-s", "live", "--json"], { env: TENCENT_ENV, fetch });
    const byDomain = Object.fromEntries(r.json.data.items.map((d: any) => [d.domain, d]));
    expect(byDomain["push.example.com"]).toEqual({
      provider: "tencent",
      service: "live",
      domain: "push.example.com",
      status: "online",
      https: false,
      extra: { type: "push" },
    });
    expect(byDomain["12345.livepush.myqcloud.com"]).toEqual({
      provider: "tencent",
      service: "live",
      domain: "12345.livepush.myqcloud.com",
      status: "online",
      https: true,
      extra: { type: "push", managed: "platform" },
    });
    expect(byDomain["play.example.com"]).toMatchObject({ https: true, cert: { id: "x", notAfter: "2026-11-20T04:00:00.000Z" } });
    expect(byDomain["play2.example.com"]).toMatchObject({
      status: "offline",
      cert: { id: "ssl-1", name: "play2", commonName: "*.example.com", notAfter: "2026-10-29T23:59:59.000Z" },
      daysLeft: 14,
    });
  });

  it("点播：按应用查询域名，证书 ID 字段为 CloudCertId", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeSubAppIds") {
        return ok({
          TotalCount: 3,
          SubAppIdInfoSet: [
            { SubAppId: 1500001, SubAppIdName: "主应用", Status: "On" },
            { SubAppId: 1500002, SubAppIdName: "test", Status: "Off" },
            { SubAppId: 1500003, SubAppIdName: "gone", Status: "Destroyed" },
          ],
        });
      }
      if (req.action === "DescribeVodDomains") {
        if (req.json?.SubAppId === 1500002) return ok({ TotalCount: 0, DomainSet: [] });
        expect(req.json?.SubAppId).toBe(1500001);
        return ok({
          TotalCount: 2,
          DomainSet: [
            { Domain: "vod.example.com", DeployStatus: "Online", Type: "VOD", HTTPSConfig: { CloudCertId: "ssl-1", CertExpireTime: "2030-01-23T07:25:52Z" } },
            { Domain: "plain.example.com", DeployStatus: "Online", Type: "VOD", HTTPSConfig: null },
          ],
        });
      }
      return undefined;
    });
    const r = await runCli(["domains", "-s", "vod", "--json"], { env: TENCENT_ENV, fetch });
    expect(r.code).toBe(0);
    expect(fetch.calls.filter((c) => c.action === "DescribeVodDomains")).toHaveLength(2);
    // 证书缺名称时会按 ID 拉 SSL 证书列表补名称；拉取失败（这里没有路由）不记 issue，因为到期时间已有
    expect(fetch.calls.filter((c) => c.action === "DescribeCertificates")).toHaveLength(1);
    expect(r.json.data.issues).toEqual([]);
    expect(r.json.data.items).toEqual([
      {
        provider: "tencent",
        service: "vod",
        domain: "vod.example.com",
        status: "Online",
        https: true,
        cert: { id: "ssl-1", notAfter: "2030-01-23T07:25:52.000Z" },
        extra: { type: "VOD", subAppId: "1500001", subApp: "主应用" },
        daysLeft: 1196,
      },
      {
        provider: "tencent",
        service: "vod",
        domain: "plain.example.com",
        status: "Online",
        https: false,
        extra: { type: "VOD", subAppId: "1500001", subApp: "主应用" },
      },
    ]);
  });

  it("点播：证书只有 ID 和到期时间时，从 SSL 证书列表补名称、CN、SAN，到期时间以点播为准", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeSubAppIds") return ok({ TotalCount: 0, SubAppIdInfoSet: [] });
      if (req.action === "DescribeVodDomains") {
        return ok({
          TotalCount: 1,
          DomainSet: [{ Domain: "v.example.com", DeployStatus: "Online", Type: "VOD", HTTPSConfig: { CloudCertId: "ssl-1", CertExpireTime: "2026-10-29T23:59:59Z" } }],
        });
      }
      return sslRoute(req);
    });
    const r = await runCli(["domains", "-s", "vod", "--json"], { env: TENCENT_ENV, fetch });
    expect(r.json.data.items[0].cert).toEqual({
      id: "ssl-1",
      name: "wild",
      commonName: "*.example.com",
      sans: ["*.example.com", "example.com"],
      notBefore: "2026-08-01T00:00:00.000Z",
      notAfter: "2026-10-29T23:59:59.000Z",
      status: "已通过",
    });
  });

  it("点播：TotalCount 含不展示的域名时按页长翻页，同一域名不重复列出；默认分发域名标记为平台域名", async () => {
    // 模拟真实行为：服务端先在完整列表上按 Offset/Limit 切片，再滤掉不展示的域名，TotalCount 仍按完整列表计
    const domain = (Domain: string, HTTPSConfig: unknown = null) => ({ Domain, DeployStatus: "Online", Type: "VOD", HTTPSConfig });
    const lists: Record<number, { hidden?: boolean; d: ReturnType<typeof domain> }[]> = {
      // 主应用：完整列表第 0 条不展示（真实响应：TotalCount=2，DomainSet 只有默认分发域名，Offset=1 时又返回它）
      1250000001: [
        { hidden: true, d: domain("hidden.example.com") },
        { d: domain("1250000001.vod2.myqcloud.com", { CertExpireTime: "2022-11-05T00:00:00Z", CloudCertId: "" }) },
      ],
      // 子应用：45 条、第 3 条不展示，需要翻 3 页
      1500000002: Array.from({ length: 45 }, (_, i) => ({ hidden: i === 3, d: domain(i === 0 ? "1500000002.vod-qcloud.com" : `v${i}.example.com`) })),
    };
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeSubAppIds") {
        return ok({
          TotalCount: 2,
          SubAppIdInfoSet: [
            { SubAppId: 1250000001, SubAppIdName: "PrimaryApplication", Status: "On", IsDefaultApp: true },
            { SubAppId: 1500000002, SubAppIdName: "dev", Status: "On" },
          ],
        });
      }
      if (req.action === "DescribeVodDomains") {
        const { Offset, Limit, SubAppId } = req.json as { Offset: number; Limit: number; SubAppId: number };
        const all = lists[SubAppId]!;
        return ok({ TotalCount: all.length, DomainSet: all.slice(Offset, Offset + Limit).filter((x) => !x.hidden).map((x) => x.d) });
      }
      return undefined;
    });
    const r = await runCli(["domains", "-s", "vod", "--json"], { env: TENCENT_ENV, fetch });
    expect(r.code).toBe(0);
    const offsets = (id: number) => fetch.calls.filter((c) => c.action === "DescribeVodDomains" && c.json?.SubAppId === id).map((c) => c.json?.Offset);
    expect(offsets(1250000001)).toEqual([0]);
    expect(offsets(1500000002)).toEqual([0, 20, 40]);
    const names = r.json.data.items.map((d: any) => d.domain);
    expect(new Set(names).size).toBe(names.length);
    expect(names).toHaveLength(1 + 44);
    expect(r.json.data.items.filter((d: any) => d.extra.managed === "platform").map((d: any) => d.domain)).toEqual([
      "1250000001.vod2.myqcloud.com",
      "1500000002.vod-qcloud.com",
    ]);
    expect(names).not.toContain("v3.example.com");
    expect(r.json.data.items.find((d: any) => d.domain === "1250000001.vod2.myqcloud.com")).toEqual({
      provider: "tencent",
      service: "vod",
      domain: "1250000001.vod2.myqcloud.com",
      status: "Online",
      https: true,
      extra: { type: "VOD", subAppId: "1250000001", subApp: "PrimaryApplication", managed: "platform" },
    });
    expect(r.json.data.items.find((d: any) => d.domain === "v1.example.com")).toMatchObject({ https: false, extra: { subAppId: "1500000002" } });
    expect(r.json.data.items.find((d: any) => d.domain === "v1.example.com").extra.managed).toBeUndefined();
  });

  it("点播：应用列表不可用时退回不带 SubAppId 查询", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeSubAppIds") return tcError("InternalError", "oops");
      if (req.action === "DescribeVodDomains") {
        expect(req.json?.SubAppId).toBeUndefined();
        return ok({ TotalCount: 1, DomainSet: [{ Domain: "old.example.com", DeployStatus: "Online" }] });
      }
      return undefined;
    });
    const r = await runCli(["domains", "-s", "vod", "--json"], { env: TENCENT_ENV, fetch });
    expect(r.json.data.items).toEqual([{ provider: "tencent", service: "vod", domain: "old.example.com", status: "Online", https: false }]);
  });
});
