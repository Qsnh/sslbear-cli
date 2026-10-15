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
          TotalNumber: 2,
          Domains: [
            {
              Domain: "static.example.cn",
              Status: "online",
              Area: "mainland",
              Https: { Switch: "on", CertInfo: { CertId: "ssl-9", CertName: "static", ExpireTime: "2026-10-12 08:00:00" } },
            },
            { Domain: "dl.example.cn", Status: "offline", Area: "global", Https: null },
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
  });

  it("直播：按域名合并证书绑定，缺到期时间的从 SSL 列表补", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeLiveDomains") {
        return ok({
          AllCount: 3,
          DomainList: [
            { Name: "push.example.com", Type: 0, Status: 1 },
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
    expect(fetch.calls.some((c) => c.action === "DescribeCertificates")).toBe(false);
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
