import { describe, expect, it } from "vitest";
import { ALIYUN_ENV, fakeFetch, runCli, type FakeReply, type FakeRequest } from "./helpers.js";

const rpcError = (status: number, Code: string, Message: string) => ({
  status,
  body: { RequestId: "req-1", Code, Message },
});

/** CDN：两个域名，其中一个开了 HTTPS */
function cdnRoutes(req: FakeRequest) {
  if (req.url.host !== "cdn.aliyuncs.com") return undefined;
  if (req.action === "DescribeUserDomains") {
    return {
      body: {
        TotalCount: 2,
        Domains: {
          PageData: [
            { DomainName: "api.example.com", DomainStatus: "online", SslProtocol: "on" },
            { DomainName: "plain.example.com", DomainStatus: "online", SslProtocol: "off" },
          ],
        },
      },
    };
  }
  if (req.action === "DescribeCdnHttpsDomainList") {
    return {
      body: {
        TotalCount: 1,
        CertInfos: {
          CertInfo: [
            {
              DomainName: "api.example.com",
              CertName: "api-cert",
              CertCommonName: "*.example.com",
              CertType: "cas",
              CertStatus: "ok",
              CertStartTime: "2026-08-01 08:00:00",
              CertExpireTime: "2026-11-01 08:00:00",
            },
          ],
        },
      },
    };
  }
  return undefined;
}

describe("aliyun domains", () => {
  it("CDN：域名列表与 HTTPS 证书列表按域名合并，并带上签名参数", async () => {
    const fetch = fakeFetch(cdnRoutes);
    const r = await runCli(["domains", "-p", "aliyun", "-s", "cdn", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.issues).toEqual([]);
    expect(r.json.data.items).toEqual([
      {
        provider: "aliyun",
        service: "cdn",
        domain: "api.example.com",
        status: "online",
        https: true,
        cert: {
          name: "api-cert",
          commonName: "*.example.com",
          notBefore: "2026-08-01T00:00:00.000Z",
          notAfter: "2026-11-01T00:00:00.000Z",
          status: "ok",
        },
        extra: { certType: "cas" },
        daysLeft: 17,
      },
      { provider: "aliyun", service: "cdn", domain: "plain.example.com", status: "online", https: false },
    ]);
    const q = fetch.calls[0]!.url.searchParams;
    expect(q.get("Version")).toBe("2018-05-10");
    expect(q.get("AccessKeyId")).toBe(ALIYUN_ENV.ALIBABA_CLOUD_ACCESS_KEY_ID);
    expect(q.get("SignatureMethod")).toBe("HMAC-SHA1");
    expect(q.get("Signature")).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });

  it("STS 临时凭证带上 SecurityToken", async () => {
    const fetch = fakeFetch(cdnRoutes);
    await runCli(["domains", "-s", "cdn", "--json"], {
      env: { ...ALIYUN_ENV, ALIBABA_CLOUD_SECURITY_TOKEN: "sts-token" },
      fetch,
    });
    expect(fetch.calls.every((c) => c.url.searchParams.get("SecurityToken") === "sts-token")).toBe(true);
  });

  it("翻页直到取完", async () => {
    const all = Array.from({ length: 501 }, (_, i) => ({ DomainName: `d${i}.example.com`, DomainStatus: "online", SslProtocol: "off" }));
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeUserDomains") {
        const page = Number(req.url.searchParams.get("PageNumber"));
        const size = Number(req.url.searchParams.get("PageSize"));
        return { body: { TotalCount: all.length, Domains: { PageData: all.slice((page - 1) * size, page * size) } } };
      }
      if (req.action === "DescribeCdnHttpsDomainList") return rpcError(400, "NoHttpsDomain", "no https domain");
      return undefined;
    });
    const r = await runCli(["domains", "-s", "cdn", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toHaveLength(501);
    expect(r.json.data.issues).toEqual([]);
    expect(fetch.calls.filter((c) => c.action === "DescribeUserDomains")).toHaveLength(2);
    // 没有开启 HTTPS 的域名，不查证书列表
    expect(fetch.calls.filter((c) => c.action === "DescribeCdnHttpsDomainList")).toHaveLength(0);
  });

  it("HTTPS 证书列表无权限时只记 issue，域名照常输出，HTTPS 以域名列表的开关为准", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeCdnHttpsDomainList") {
        return rpcError(403, "Forbidden.RAM", "User not authorized to operate on the specified resource, or this API doesn't support RAM.");
      }
      return cdnRoutes(req);
    });
    const r = await runCli(["domains", "-s", "cdn", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toEqual([
      { provider: "aliyun", service: "cdn", domain: "api.example.com", status: "online", https: true },
      { provider: "aliyun", service: "cdn", domain: "plain.example.com", status: "online", https: false },
    ]);
    expect(r.json.data.issues).toEqual([
      {
        provider: "aliyun",
        service: "cdn",
        target: "HTTPS 证书列表（用于补全证书信息）",
        kind: "error",
        code: "Forbidden.RAM",
        message:
          "User not authorized to operate on the specified resource, or this API doesn't support RAM.（缺少 RAM 权限 cdn:DescribeCdnHttpsDomainList，可授予系统策略 AliyunCDNReadOnlyAccess）",
        requestId: "req-1",
      },
    ]);
  });

  it("没有域名时不查 HTTPS 证书列表", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeUserDomains") return { body: { TotalCount: 0, Domains: { PageData: [] } } };
      if (req.action === "DescribeLiveUserDomains") return { body: { TotalCount: 0, Domains: { PageData: [] } } };
      return undefined;
    });
    const r = await runCli(["domains", "-s", "cdn,live", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data).toEqual({ items: [], issues: [] });
    expect(fetch.calls.map((c) => c.action)).toEqual(["DescribeUserDomains", "DescribeLiveUserDomains"]);
  });

  it("DCDN 未开通记为 inactive，不影响其他服务与退出码", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.host === "dcdn.aliyuncs.com") return rpcError(403, "DcdnServiceNotFound", "The DCDN service is not activated.");
      return cdnRoutes(req);
    });
    const r = await runCli(["domains", "-s", "cdn,dcdn", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toHaveLength(2);
    expect(r.json.data.issues).toEqual([
      {
        provider: "aliyun",
        service: "dcdn",
        kind: "inactive",
        code: "DcdnServiceNotFound",
        message: "The DCDN service is not activated.",
        requestId: "req-1",
      },
    ]);
  });

  it("限流自动重试", async () => {
    let n = 0;
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeUserDomains" && n++ === 0) return rpcError(400, "Throttling.User", "Request was denied due to user flow control.");
      return cdnRoutes(req);
    });
    const r = await runCli(["domains", "-s", "cdn", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toHaveLength(2);
  });

  it("全部查询失败时 exit 1，stderr 输出错误 JSON", async () => {
    const fetch = fakeFetch(() => rpcError(400, "InvalidAccessKeyId.NotFound", "Specified access key is not found."));
    const r = await runCli(["domains", "-s", "cdn,live", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(1);
    expect(r.stdout).toBe("");
    const err = JSON.parse(r.stderr);
    expect(err).toMatchObject({ ok: false, status: "InvalidAccessKeyId.NotFound" });
  });

  it("直播：状态字段为 LiveDomainStatus，证书走批量 HTTPS 列表", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.host !== "live.aliyuncs.com") return undefined;
      if (req.action === "DescribeLiveUserDomains") {
        expect(req.url.searchParams.get("PageSize")).toBe("50");
        return { body: { TotalCount: 1, Domains: { PageData: [{ DomainName: "play.example.com", LiveDomainStatus: "online", LiveDomainType: "liveVideo" }] } } };
      }
      if (req.action === "DescribeLiveHttpsDomainList") {
        return { body: { TotalCount: 1, CertInfos: { CertInfo: [{ DomainName: "play.example.com", CertName: "live", CertExpireTime: "2026-10-10 00:00:00" }] } } };
      }
      return undefined;
    });
    const r = await runCli(["domains", "-s", "live", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.json.data.items[0]).toMatchObject({ domain: "play.example.com", status: "online", https: true, daysLeft: -6 });
  });

  it("直播没有 HTTPS 开关字段：HTTPS 列表查询失败时记 issue，记录标 httpsUnknown；NoHttpsDomain 不算失败", async () => {
    const liveRoutes =
      (httpsReply: FakeReply) =>
      (req: FakeRequest): FakeReply => {
        if (req.action === "DescribeLiveUserDomains") {
          return {
            body: {
              TotalCount: 2,
              Domains: {
                PageData: [
                  { DomainName: "play.example.com", LiveDomainStatus: "online", LiveDomainType: "liveVideo" },
                  { DomainName: "push.example.com", LiveDomainStatus: "online", LiveDomainType: "liveEdge" },
                ],
              },
            },
          };
        }
        if (req.action === "DescribeLiveHttpsDomainList") return httpsReply;
        return undefined;
      };
    const failed = await runCli(["domains", "-s", "live", "--json"], {
      env: ALIYUN_ENV,
      fetch: fakeFetch(liveRoutes(rpcError(403, "Forbidden.RAM", "User not authorized to operate on the specified resource."))),
    });
    expect(failed.code).toBe(0);
    const byDomain = Object.fromEntries(failed.json.data.items.map((d: any) => [d.domain, d]));
    // https 仍填最佳猜测（不在 HTTPS 列表里即 false），但标明无法判断
    expect(byDomain["play.example.com"]).toEqual({
      provider: "aliyun",
      service: "live",
      domain: "play.example.com",
      status: "online",
      https: false,
      extra: { liveDomainType: "liveVideo", httpsUnknown: "true" },
    });
    expect(byDomain["push.example.com"]).toMatchObject({ https: false, extra: { liveDomainType: "liveEdge", httpsUnknown: "true" } });
    expect(failed.json.data.issues).toEqual([
      expect.objectContaining({ service: "live", kind: "error", code: "Forbidden.RAM", target: "HTTPS 证书列表（用于补全证书信息）" }),
    ]);

    const none = await runCli(["domains", "-s", "live", "--json"], {
      env: ALIYUN_ENV,
      fetch: fakeFetch(liveRoutes(rpcError(400, "NoHttpsDomain", "no https domain"))),
    });
    expect(none.json.data.issues).toEqual([]);
    expect(none.json.data.items).toHaveLength(2);
    for (const d of none.json.data.items) {
      expect(d.https).toBe(false);
      expect(d.extra.httpsUnknown).toBeUndefined();
    }
  });

  it("点播：只对开启 HTTPS 的域名查证书，单个域名失败只记 issue", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.host !== "vod.cn-shanghai.aliyuncs.com") return undefined;
      if (req.action === "DescribeVodUserDomains") {
        return {
          body: {
            TotalCount: 3,
            Domains: {
              PageData: [
                { DomainName: "v1.example.com", DomainStatus: "online", SslProtocol: "on" },
                { DomainName: "v2.example.com", DomainStatus: "online", SslProtocol: "on" },
                { DomainName: "v3.example.com", DomainStatus: "offline", SslProtocol: "off" },
              ],
            },
          },
        };
      }
      if (req.action === "DescribeVodDomainCertificateInfo") {
        if (req.url.searchParams.get("DomainName") === "v2.example.com") return rpcError(500, "InternalError", "boom");
        return {
          body: {
            CertInfos: {
              // 真实响应里 CertDomainName 是证书的全部 SAN（逗号分隔）
              CertInfo: [{ CertId: "123", CertName: "vod", CertDomainName: "*.example.com,example.com", CertType: "cas", CertStartTime: "2026-10-01T00:00:00Z", CertExpireTime: "2027-01-01T00:00:00Z", Status: "", ServerCertificateStatus: "on" }],
            },
          },
        };
      }
      return undefined;
    });
    const r = await runCli(["domains", "-s", "vod", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(fetch.calls.filter((c) => c.action === "DescribeVodDomainCertificateInfo")).toHaveLength(2);
    const byDomain = Object.fromEntries(r.json.data.items.map((d: any) => [d.domain, d]));
    expect(byDomain["v1.example.com"].cert).toEqual({
      id: "123",
      name: "vod",
      sans: ["*.example.com", "example.com"],
      notBefore: "2026-10-01T00:00:00.000Z",
      notAfter: "2027-01-01T00:00:00.000Z",
    });
    expect(byDomain["v1.example.com"].extra).toEqual({ certType: "cas" });
    expect(byDomain["v2.example.com"]).toMatchObject({ https: true });
    expect(byDomain["v2.example.com"].cert).toBeUndefined();
    expect(byDomain["v3.example.com"]).toMatchObject({ https: false });
    expect(r.json.data.issues).toEqual([
      expect.objectContaining({ service: "vod", kind: "error", code: "InternalError", target: "v2.example.com" }),
    ]);
  });
});

const ESA_HOST = "esa.cn-hangzhou.aliyuncs.com";

/** ESA：example.com 有五张证书（含一张已过期、一张 ECC），example.net 只有已过期和申请中的证书且不支持 SaaS 域名 */
function esaRoutes(req: FakeRequest) {
  if (req.url.host !== ESA_HOST) return undefined;
  const site = req.url.searchParams.get("SiteId");
  if (req.action === "ListSites") {
    return {
      body: {
        TotalCount: 2,
        Sites: [
          { SiteId: 1001, SiteName: "example.com", Status: "active" },
          { SiteId: 1002, SiteName: "example.net", Status: "pending" },
        ],
      },
    };
  }
  if (req.action === "ListRecords") {
    const records: Record<string, unknown[]> = {
      "1001": [
        { RecordName: "www.example.com", RecordType: "CNAME", Proxied: true },
        { RecordName: "API.example.com", RecordType: "A/AAAA", Proxied: true },
        { RecordName: "deep.a.example.com", RecordType: "CNAME", Proxied: true },
        { RecordName: "*.example.com", RecordType: "CNAME", Proxied: true },
        { RecordName: "admin.example.com", RecordType: "CNAME", Proxied: true },
        { RecordName: "dns-only.example.com", RecordType: "A/AAAA", Proxied: false },
      ],
      "1002": [
        { RecordName: "shop.example.net", RecordType: "CNAME", Proxied: true },
        { RecordName: "new.example.net", RecordType: "CNAME", Proxied: true },
      ],
    };
    return { body: { TotalCount: records[site!]!.length, Records: records[site!] } };
  }
  if (req.action === "ListCertificates") {
    const certs: Record<string, unknown[]> = {
      "1001": [
        { Id: "c-expired", Name: "www-old", Type: "free", Status: "Expired", CommonName: "www.example.com", PubAlg: "RSA", NotBefore: "2026-06-01 00:00:00", NotAfter: "2026-09-01 00:00:00", CreateTime: "2026-06-01 00:00:00" },
        { Id: "c-wild", Name: "wild", Type: "upload", Status: "OK", CommonName: "*.example.com", SAN: "*.example.com,example.com", Issuer: "DigiCert", PubAlg: "RSA", NotBefore: "2026-09-01 12:00:00", NotAfter: "2026-11-30 12:00:00", CreateTime: "2026-09-01 12:30:00" },
        { Id: "c-www-early", Name: "www-early", Type: "upload", Status: "OK", CommonName: "www.example.com", PubAlg: "RSA", NotBefore: "2026-08-01 00:00:00", NotAfter: "2027-08-01 00:00:00", CreateTime: "2026-08-01 00:10:00" },
        { Id: "c-www", Name: "www-new", Type: "cas", Status: "OK", CommonName: "www.example.com", SAN: "www.example.com", PubAlg: "RSA", NotBefore: "2026-10-01 00:00:00", NotAfter: "2027-03-01 00:00:00", CreateTime: "2026-07-01 00:00:00", UpdateTime: "2026-10-01 00:10:00" },
        { Id: "c-api-ecc", Name: "api-ecc", Type: "upload", Status: "OK", CommonName: "api.example.com", PubAlg: "ECDSA", NotBefore: "2026-10-01 00:00:00", NotAfter: "2027-05-01 00:00:00", CreateTime: "2026-10-02 00:00:00" },
      ],
      "1002": [
        { Id: "n-older", Type: "upload", Status: "Expired", CommonName: "shop.example.net", NotAfter: "2026-05-01 00:00:00", CreateTime: "2026-09-01 00:00:00" },
        { Id: "n-old", Type: "upload", Status: "Expired", CommonName: "shop.example.net", NotAfter: "2026-08-01 00:00:00", CreateTime: "2025-08-01 00:00:00" },
        { Id: "n-new", Type: "free", Status: "Applying", CommonName: "new.example.net" },
      ],
    };
    return { body: { TotalCount: certs[site!]!.length, Result: certs[site!] } };
  }
  if (req.action === "ListHttpsBasicConfigurations") {
    // example.net 没有任何 SSL/TLS 配置，按默认开启；example.com 的规则乱序返回，按序号生效
    if (site === "1002") return { body: { TotalCount: 0, Configs: [] } };
    return {
      body: {
        TotalCount: 4,
        Configs: [
          { ConfigType: "global", Https: "on" },
          { ConfigType: "rule", RuleName: "example-on", Sequence: 10, RuleEnable: "on", Rule: '(ends_with(http.host, ".example.com"))', Https: "on" },
          { ConfigType: "rule", RuleName: "admin-off", Sequence: 5, RuleEnable: "on", Rule: '(http.host eq "admin.example.com")', Https: "off" },
          { ConfigType: "rule", RuleName: "disabled", Sequence: 1, RuleEnable: "off", Rule: "true", Https: "off" },
        ],
      },
    };
  }
  if (req.action === "ListCustomHostnames") {
    if (site === "1002") return rpcError(400, "ErrSiteIdNoteEnterprise", "This feature is unavailable because your website is not associated with an Enterprise plan.");
    return {
      body: {
        TotalCount: 2,
        Hostnames: [
          { Hostname: "shop.customer.com", Status: "active", SslFlag: "on", CertType: "free", CertStatus: "OK", CertNotAfter: "2026-12-01T00:00:00Z", RecordName: "origin.example.com" },
          { Hostname: "plain.customer.com", Status: "pending", SslFlag: "off", CertType: "free" },
        ],
      },
    };
  }
  return undefined;
}

describe("aliyun esa", () => {
  it("站点下加速记录按 CN / SAN 匹配站点证书，SaaS 域名取自带的证书信息", async () => {
    const fetch = fakeFetch(esaRoutes);
    const r = await runCli(["domains", "-s", "esa", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.issues).toEqual([]);
    const byDomain = Object.fromEntries(r.json.data.items.map((d: any) => [d.domain, d]));
    expect(Object.keys(byDomain).sort()).toEqual([
      "*.example.com",
      "API.example.com",
      "admin.example.com",
      "deep.a.example.com",
      "new.example.net",
      "plain.customer.com",
      "shop.customer.com",
      "shop.example.net",
      "www.example.com",
    ]);
    // 多张有效证书都匹配时，配置（含原地更新）较晚的生效，即使另一张到期更晚；证书时间按 UTC 解析
    expect(byDomain["www.example.com"]).toEqual({
      provider: "aliyun",
      service: "esa",
      domain: "www.example.com",
      status: "active",
      https: true,
      cert: {
        id: "c-www",
        name: "www-new",
        commonName: "www.example.com",
        sans: ["www.example.com"],
        notBefore: "2026-10-01T00:00:00.000Z",
        notAfter: "2027-03-01T00:00:00.000Z",
        status: "OK",
        algorithm: "RSA",
      },
      extra: { siteId: "1001", site: "example.com", certType: "cas", httpsSwitch: "on", httpsRule: "example-on" },
      daysLeft: 137,
    });
    // 域名大小写不敏感，泛域名证书覆盖一级子域；RSA 与 ECC 证书同时有效时报告先到期的那张，certs 里列出两张并标算法
    expect(byDomain["API.example.com"]).toMatchObject({
      https: true,
      cert: { id: "c-wild", issuer: "DigiCert", sans: ["*.example.com", "example.com"], notAfter: "2026-11-30T12:00:00.000Z", algorithm: "RSA" },
      certs: [
        { id: "c-wild", algorithm: "RSA" },
        { id: "c-api-ecc", algorithm: "ECC" },
      ],
      extra: { certType: "upload" },
      daysLeft: 46,
    });
    expect(byDomain["www.example.com"].certs).toBeUndefined();
    expect(byDomain["*.example.com"]).toMatchObject({ https: true, cert: { id: "c-wild" } });
    // 泛域名证书不覆盖多级子域
    expect(byDomain["deep.a.example.com"]).toEqual({
      provider: "aliyun",
      service: "esa",
      domain: "deep.a.example.com",
      status: "active",
      https: false,
      extra: { siteId: "1001", site: "example.com", httpsSwitch: "on", httpsRule: "example-on" },
    });
    // SSL/TLS 规则关闭了 HTTPS：即使有匹配的有效证书也记为未开启，且不展示证书
    expect(byDomain["admin.example.com"]).toEqual({
      provider: "aliyun",
      service: "esa",
      domain: "admin.example.com",
      status: "active",
      https: false,
      extra: { siteId: "1001", site: "example.com", httpsSwitch: "off", httpsRule: "admin-off" },
    });
    // 没有有效证书时取最近过期的那张；只有申请中的证书时记为未开启 HTTPS，但保留证书状态
    expect(byDomain["shop.example.net"]).toMatchObject({ status: "pending", https: true, cert: { id: "n-old", status: "Expired" }, daysLeft: -75 });
    expect(byDomain["new.example.net"]).toMatchObject({ https: false, cert: { id: "n-new", status: "Applying" }, extra: { httpsSwitch: "on" } });
    expect(byDomain["new.example.net"].extra.httpsRule).toBeUndefined();
    expect(byDomain["new.example.net"].daysLeft).toBeUndefined();
    expect(byDomain["shop.customer.com"]).toEqual({
      provider: "aliyun",
      service: "esa",
      domain: "shop.customer.com",
      status: "active",
      https: true,
      cert: { notAfter: "2026-12-01T00:00:00.000Z", status: "OK" },
      extra: { siteId: "1001", site: "example.com", hostType: "saas", certType: "free" },
      daysLeft: 47,
    });
    expect(byDomain["plain.customer.com"]).toMatchObject({ https: false, extra: { hostType: "saas" } });
    expect(byDomain["plain.customer.com"].cert).toBeUndefined();

    const records = fetch.calls.filter((c) => c.action === "ListRecords");
    expect(records.every((c) => c.url.searchParams.get("Proxied") === "true")).toBe(true);
    expect(fetch.calls[0]!.url.searchParams.get("Version")).toBe("2024-09-10");
  });

  it("站点证书翻页取完后再匹配", async () => {
    const certs = Array.from({ length: 25 }, (_, i) => ({ Id: `c${i}`, Status: "OK", CommonName: `h${i}.example.com`, NotAfter: "2027-01-01 00:00:00" }));
    const fetch = fakeFetch((req) => {
      if (req.action === "ListSites") return { body: { TotalCount: 1, Sites: [{ SiteId: 1001, SiteName: "example.com", Status: "active" }] } };
      if (req.action === "ListRecords") return { body: { TotalCount: 1, Records: [{ RecordName: "h22.example.com", Proxied: true }] } };
      if (req.action === "ListCertificates") {
        const page = Number(req.url.searchParams.get("PageNumber"));
        const size = Number(req.url.searchParams.get("PageSize"));
        return { body: { TotalCount: certs.length, Result: certs.slice((page - 1) * size, page * size) } };
      }
      if (req.action === "ListCustomHostnames") return { body: { TotalCount: 0, Hostnames: [] } };
      if (req.action === "ListHttpsBasicConfigurations") return { body: { TotalCount: 0, Configs: [] } };
      return undefined;
    });
    const r = await runCli(["domains", "-s", "esa", "--json"], { env: ALIYUN_ENV, fetch });
    expect(fetch.calls.filter((c) => c.action === "ListCertificates")).toHaveLength(2);
    expect(r.json.data.items).toEqual([expect.objectContaining({ domain: "h22.example.com", https: true, cert: expect.objectContaining({ id: "c22" }) })]);
  });

  it("SSL/TLS 规则条件无法判断时，命中与否结果不同才记为 partial", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action === "ListSites") return { body: { TotalCount: 1, Sites: [{ SiteId: 1001, SiteName: "example.com", Status: "active" }] } };
      if (req.action === "ListRecords") {
        const records = ["a.example.com", "ab.example.com", "b.example.com", "c.example.com"].map((RecordName) => ({ RecordName, Proxied: true }));
        return { body: { TotalCount: records.length, Records: records } };
      }
      if (req.action === "ListCertificates") {
        return { body: { TotalCount: 1, Result: [{ Id: "w", Status: "OK", CommonName: "*.example.com", NotAfter: "2027-01-01 00:00:00" }] } };
      }
      if (req.action === "ListHttpsBasicConfigurations") {
        return {
          body: {
            TotalCount: 4,
            Configs: [
              { ConfigType: "global", Https: "off" },
              // 列表引用无法判断；对 b、c 来说 starts_with 已为 false，整条规则确定不命中
              { ConfigType: "rule", RuleName: "vip", Sequence: 1, Rule: '(http.host in $vip and starts_with(http.host, "a"))', Https: "on" },
              { ConfigType: "rule", RuleName: "b-on", Sequence: 2, Rule: '(http.host eq "b.example.com")' },
              { ConfigType: "rule", RuleName: "ab-on", Sequence: 3, Rule: '(starts_with(http.host, "ab"))', Https: "on" },
            ],
          },
        };
      }
      if (req.action === "ListCustomHostnames") return { body: { TotalCount: 0, Hostnames: [] } };
      return undefined;
    });
    const r = await runCli(["domains", "-s", "esa", "--json"], { env: ALIYUN_ENV, fetch });
    const byDomain = Object.fromEntries(r.json.data.items.map((d: any) => [d.domain, d]));
    expect(byDomain["a.example.com"]).toMatchObject({ https: true, cert: { id: "w" }, extra: { httpsSwitch: "partial", httpsRule: "vip" } });
    // vip 是否命中无法判断，但不命中时后面的 ab-on 也会开启，结果确定
    expect(byDomain["ab.example.com"]).toMatchObject({ https: true, extra: { httpsSwitch: "on" } });
    expect(byDomain["ab.example.com"].extra.httpsRule).toBeUndefined();
    // 规则未写 Https 时按默认开启
    expect(byDomain["b.example.com"]).toMatchObject({ https: true, extra: { httpsSwitch: "on", httpsRule: "b-on" } });
    expect(byDomain["c.example.com"]).toEqual({
      provider: "aliyun",
      service: "esa",
      domain: "c.example.com",
      status: "active",
      https: false,
      extra: { siteId: "1001", site: "example.com", httpsSwitch: "off" },
    });
  });

  it("查不到 SSL/TLS 配置时记 issue，记录仍按证书输出；有证书的记录 HTTPS 无法判断，标 httpsUnknown", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action === "ListHttpsBasicConfigurations" && req.url.searchParams.get("SiteId") === "1001") {
        return rpcError(403, "NoPermission", "You are not authorized to operate on the specified resource.");
      }
      return esaRoutes(req);
    });
    const r = await runCli(["domains", "-s", "esa", "--json"], { env: ALIYUN_ENV, fetch });
    const byDomain = Object.fromEntries(r.json.data.items.map((d: any) => [d.domain, d]));
    // 有匹配证书的记录：HTTPS 取决于查不到的开关（admin 实际被规则关闭），https 按证书猜测为开启并标 httpsUnknown
    expect(byDomain["admin.example.com"]).toMatchObject({ https: true, cert: { id: "c-wild" }, extra: { httpsUnknown: "true" } });
    expect(byDomain["admin.example.com"].extra.httpsSwitch).toBeUndefined();
    expect(byDomain["www.example.com"].extra.httpsUnknown).toBe("true");
    // 没有匹配的已签发证书：开关怎样都不会提供 HTTPS，https:false 是确定的，不打标记
    expect(byDomain["deep.a.example.com"]).toMatchObject({ https: false });
    expect(byDomain["deep.a.example.com"].extra.httpsUnknown).toBeUndefined();
    expect(byDomain["shop.example.net"].extra.httpsSwitch).toBe("on");
    expect(byDomain["shop.example.net"].extra.httpsUnknown).toBeUndefined();
    expect(byDomain["shop.customer.com"].extra.httpsUnknown).toBeUndefined();
    expect(r.json.data.issues).toEqual([
      expect.objectContaining({ service: "esa", kind: "error", code: "NoPermission", target: "site example.com SSL/TLS 配置" }),
    ]);
  });

  it("单个站点查询失败只记 issue，其余站点照常返回", async () => {
    const fetch = fakeFetch((req) => {
      const site = req.url.searchParams.get("SiteId");
      if (req.action === "ListRecords" && site === "1002") return rpcError(500, "InternalError", "boom");
      if (req.action === "ListCustomHostnames" && site === "1001") return rpcError(400, "InternalException", "saas boom");
      return esaRoutes(req);
    });
    const r = await runCli(["domains", "-s", "esa", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items.map((d: any) => d.domain).sort()).toEqual([
      "*.example.com",
      "API.example.com",
      "admin.example.com",
      "deep.a.example.com",
      "www.example.com",
    ]);
    expect(r.json.data.issues).toEqual([
      expect.objectContaining({ service: "esa", kind: "error", code: "InternalException", target: "site example.com SaaS 域名" }),
      expect.objectContaining({ service: "esa", kind: "error", code: "InternalError", target: "site example.net" }),
    ]);
  });

  it("ESA 未开通记为 inactive", async () => {
    const fetch = fakeFetch((req) => (req.url.host === ESA_HOST ? rpcError(403, "EsaService.NotOpen", "ESA service has not opend.") : undefined));
    const r = await runCli(["domains", "-s", "esa", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toEqual([]);
    expect(r.json.data.issues).toEqual([expect.objectContaining({ service: "esa", kind: "inactive", code: "EsaService.NotOpen" })]);
  });
});

const LIST_BUCKETS = `<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult>
  <Owner><ID>1</ID><DisplayName>1</DisplayName></Owner>
  <Buckets>
    <Bucket>
      <CreationDate>2024-01-01T00:00:00.000Z</CreationDate>
      <ExtranetEndpoint>oss-cn-shanghai.aliyuncs.com</ExtranetEndpoint>
      <Location>oss-cn-shanghai</Location>
      <Name>static-prod</Name>
      <Region>cn-shanghai</Region>
    </Bucket>
    <Bucket>
      <ExtranetEndpoint>oss-cn-beijing.aliyuncs.com</ExtranetEndpoint>
      <Location>oss-cn-beijing</Location>
      <Name>locked</Name>
      <Region>cn-beijing</Region>
    </Bucket>
  </Buckets>
</ListAllMyBucketsResult>`;

const LIST_CNAME = `<?xml version="1.0" encoding="UTF-8"?>
<ListCnameResult>
  <Bucket>static-prod</Bucket>
  <Owner>1</Owner>
  <Cname>
    <Domain>img.example.com</Domain>
    <LastModified>2021-09-15T02:35:07.000Z</LastModified>
    <Status>Enabled</Status>
    <Certificate>
      <Type>CAS</Type>
      <CertId>493****-cn-hangzhou</CertId>
      <Status>Enabled</Status>
      <CreationDate>Wed, 15 Sep 2021 02:35:06 GMT</CreationDate>
      <Fingerprint>DE:01</Fingerprint>
      <ValidStartDate>Wed, 12 Aug 2026 10:14:51 GMT</ValidStartDate>
      <ValidEndDate>Mon, 2 Nov 2026 10:14:51 GMT</ValidEndDate>
    </Certificate>
  </Cname>
  <Cname>
    <Domain>raw.example.com</Domain>
    <Status>Enabled</Status>
  </Cname>
</ListCnameResult>`;

describe("aliyun oss", () => {
  it("列 bucket 后逐个查 CNAME，使用 V4 签名；单个 bucket 无权限只记 issue", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.host === "oss-cn-hangzhou.aliyuncs.com") return { body: LIST_BUCKETS };
      if (req.url.host === "static-prod.oss-cn-shanghai.aliyuncs.com" && req.url.search === "?cname") return { body: LIST_CNAME };
      if (req.url.host === "locked.oss-cn-beijing.aliyuncs.com") {
        return { status: 403, body: "<Error><Code>AccessDenied</Code><Message>denied by bucket policy</Message><RequestId>oss-req</RequestId></Error>" };
      }
      return undefined;
    });
    const r = await runCli(["domains", "-s", "oss", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toEqual([
      {
        provider: "aliyun",
        service: "oss",
        domain: "img.example.com",
        status: "Enabled",
        https: true,
        cert: {
          id: "493****-cn-hangzhou",
          notBefore: "2026-08-12T10:14:51.000Z",
          notAfter: "2026-11-02T10:14:51.000Z",
          status: "Enabled",
        },
        extra: { bucket: "static-prod", region: "cn-shanghai", certType: "CAS" },
        daysLeft: 18,
      },
      {
        provider: "aliyun",
        service: "oss",
        domain: "raw.example.com",
        status: "Enabled",
        https: false,
        extra: { bucket: "static-prod", region: "cn-shanghai" },
      },
    ]);
    expect(r.json.data.issues).toEqual([
      {
        provider: "aliyun",
        service: "oss",
        target: "bucket locked",
        kind: "error",
        code: "AccessDenied",
        message: "denied by bucket policy（可能缺少 RAM 权限 oss:ListCname，可授予系统策略 AliyunOSSReadOnlyAccess）",
        requestId: "oss-req",
      },
    ]);
    const cnameCall = fetch.calls.find((c) => c.url.host.startsWith("static-prod."))!;
    expect(cnameCall.headers.authorization).toMatch(
      /^OSS4-HMAC-SHA256 Credential=LTAItestid0000\/\d{8}\/cn-shanghai\/oss\/aliyun_v4_request,Signature=[0-9a-f]{64}$/,
    );
    expect(cnameCall.headers["x-oss-content-sha256"]).toBe("UNSIGNED-PAYLOAD");
  });

  it("ListBuckets 截断时按 NextMarker 翻页", async () => {
    const page1 = `<ListAllMyBucketsResult><IsTruncated>true</IsTruncated><NextMarker>b1</NextMarker><Buckets><Bucket><Name>b1</Name><Region>cn-hangzhou</Region><ExtranetEndpoint>oss-cn-hangzhou.aliyuncs.com</ExtranetEndpoint></Bucket></Buckets></ListAllMyBucketsResult>`;
    const page2 = `<ListAllMyBucketsResult><Buckets><Bucket><Name>b2</Name><Region>cn-hangzhou</Region><ExtranetEndpoint>oss-cn-hangzhou.aliyuncs.com</ExtranetEndpoint></Bucket></Buckets></ListAllMyBucketsResult>`;
    const fetch = fakeFetch((req) => {
      if (req.url.host === "oss-cn-hangzhou.aliyuncs.com") return { body: req.url.searchParams.get("marker") === "b1" ? page2 : page1 };
      return { body: "<ListCnameResult></ListCnameResult>" };
    });
    const r = await runCli(["domains", "-s", "oss", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(fetch.calls.map((c) => c.url.host)).toEqual([
      "oss-cn-hangzhou.aliyuncs.com",
      "oss-cn-hangzhou.aliyuncs.com",
      "b1.oss-cn-hangzhou.aliyuncs.com",
      "b2.oss-cn-hangzhou.aliyuncs.com",
    ]);
  });
});

describe("aliyun certs", () => {
  it("有效证书与已过期证书两次查询合并去重", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action !== "ListUserCertificateOrder") return undefined;
      expect(req.url.searchParams.get("OrderType")).toBe("CERT");
      if (req.url.searchParams.get("Status") === "EXPIRED") {
        return {
          body: {
            TotalCount: 1,
            CertificateOrderList: [{ CertificateId: 2, Name: "old", CommonName: "old.example.com", EndDate: "2026-09-01", Expired: true, Upload: true }],
          },
        };
      }
      return {
        body: {
          TotalCount: 1,
          CertificateOrderList: [
            {
              CertificateId: 1,
              Name: "wild",
              CommonName: "*.example.com",
              Sans: "*.example.com,example.com",
              Issuer: "DigiCert",
              StartDate: "2026-01-01",
              EndDate: "2027-01-01",
              Expired: false,
              Upload: false,
            },
          ],
        },
      };
    });
    const r = await runCli(["certs", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toEqual([
      {
        provider: "aliyun",
        id: "2",
        name: "old",
        commonName: "old.example.com",
        notAfter: "2026-09-01T15:59:59.000Z",
        status: "EXPIRED",
        source: "upload",
        daysLeft: -44,
      },
      {
        provider: "aliyun",
        id: "1",
        name: "wild",
        commonName: "*.example.com",
        sans: ["*.example.com", "example.com"],
        issuer: "DigiCert",
        notBefore: "2025-12-31T16:00:00.000Z",
        notAfter: "2027-01-01T15:59:59.000Z",
        status: "ISSUED",
        source: "issued",
        daysLeft: 78,
      },
    ]);
  });

  it("有毫秒时间戳 CertStartTime / CertEndTime 时优先使用，不按只有日期的 EndDate 推算", async () => {
    // 真实响应（脱敏）：EndDate 是 UTC 日期，CertEndTime 才是精确到期时刻
    const fetch = fakeFetch((req) => {
      if (req.action !== "ListUserCertificateOrder") return undefined;
      if (req.url.searchParams.get("Status") === "EXPIRED") {
        return {
          body: {
            TotalCount: 1,
            CertificateOrderList: [
              { CertificateId: 11, Name: "utc-eod", CommonName: "a.example.com", Status: "EXPIRED", Expired: true, Upload: true, StartDate: "2024-07-16", EndDate: "2025-07-16", CertStartTime: 1721088000000, CertEndTime: 1752710399000 },
            ],
          },
        };
      }
      return {
        body: {
          TotalCount: 1,
          CertificateOrderList: [
            {
              CertificateId: 27905865,
              Name: "sslbear-test-ec",
              CommonName: "sslbear-test.example.com",
              Sans: "*.sslbear-test.example.com,sslbear-test.example.com",
              Issuer: "Let's Encrypt",
              Status: "ISSUED",
              Expired: false,
              Upload: true,
              StartDate: "2026-10-17",
              EndDate: "2027-01-15",
              CertStartTime: 1792242594000,
              CertEndTime: 1800018593000,
            },
          ],
        },
      };
    });
    const r = await runCli(["certs", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    const byId = Object.fromEntries(r.json.data.items.map((c: any) => [c.id, c]));
    expect(byId["27905865"]).toMatchObject({ notBefore: "2026-10-17T13:09:54.000Z", notAfter: "2027-01-15T13:09:53.000Z", daysLeft: 92, status: "ISSUED" });
    // 按 EndDate 推算会得到 2025-07-16T15:59:59Z，比实际早 8 小时
    expect(byId["11"]).toMatchObject({ notBefore: "2024-07-16T00:00:00.000Z", notAfter: "2025-07-16T23:59:59.000Z", status: "EXPIRED" });
  });
});
