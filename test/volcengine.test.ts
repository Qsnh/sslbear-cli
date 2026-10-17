import { describe, expect, it } from "vitest";
import { fakeFetch, runCli, type FakeRequest } from "./helpers.js";

const VOLC_ENV = { VOLCENGINE_ACCESS_KEY: "AKLTtest0000", VOLCENGINE_SECRET_KEY: "testsecret" };

const ok = (Result: unknown) => ({ body: { ResponseMetadata: { RequestId: "rid" }, Result } });
const volcError = (Code: string, Message: string, status = 200) => ({
  status,
  body: { ResponseMetadata: { RequestId: "rid-err", Error: { CodeN: 1, Code, Message } } },
});

/** fakeFetch 只解析 { 开头的 body；火山引擎 OpenAPI 的 POST body 也是 JSON */
const params = (req: FakeRequest): Record<string, unknown> =>
  req.json ?? Object.fromEntries(Array.from(req.url.searchParams).filter(([k]) => k !== "Action" && k !== "Version"));

const T = (iso: string) => Math.floor(Date.parse(iso) / 1000);

function cdnRoutes(req: FakeRequest) {
  if (req.url.host !== "cdn.volcengineapi.com") return undefined;
  if (req.action === "ListCdnDomains") {
    return ok({
      Total: 3,
      PageNum: 1,
      PageSize: 100,
      Data: [
        { Domain: "www.example.com", Status: "online", HTTPS: true, ServiceType: "web", ServiceRegion: "chinese_mainland", Project: "default" },
        { Domain: "img.example.com", Status: "online", HTTPS: false, ServiceType: "web" },
        { Domain: "*.example.org", Status: "configuring", HTTPS: true, ServiceType: "download" },
      ],
    });
  }
  if (req.action === "ListCdnCertInfo" && req.json?.EncryType === "sm_cert") {
    return ok({
      Total: 1,
      CertInfo: [
        { CertId: "cert-sm2", CertName: "*.example.org", Status: "running", ExpireTime: T("2027-06-01T00:00:00Z"), ConfiguredDomain: "*.example.org" },
      ],
    });
  }
  if (req.action === "ListCdnCertInfo") {
    expect(req.json).toMatchObject({ EncryType: "inter_cert" });
    return ok({
      Total: 3,
      CertInfo: [
        {
          CertId: "cert-ecc",
          CertName: "www.example.com",
          DnsName: "www.example.com, example.com",
          Status: "running",
          EffectiveTime: T("2026-08-01T00:00:00Z"),
          ExpireTime: T("2027-01-01T00:00:00Z"),
          ConfiguredDomain: "www.example.com",
        },
        {
          CertId: "cert-rsa",
          CertName: "www.example.com",
          DnsName: "www.example.com",
          Status: "running",
          EffectiveTime: T("2026-08-01T00:00:00Z"),
          ExpireTime: T("2026-12-01T00:00:00Z"),
          ConfiguredDomain: "www.example.com,img.example.com",
        },
        { CertId: "cert-org", CertName: "*.example.org", Status: "expired", ExpireTime: T("2026-10-01T00:00:00Z"), ConfiguredDomain: "*.example.org" },
      ],
    });
  }
  return undefined;
}

describe("volcengine 请求格式", () => {
  it("POST JSON + HMAC-SHA256 签名头，STS 时带 X-Security-Token 并参与签名", async () => {
    const fetch = fakeFetch(cdnRoutes);
    const r = await runCli(["domains", "-p", "volcengine", "-s", "cdn", "--json"], {
      env: { ...VOLC_ENV, VOLCENGINE_SESSION_TOKEN: "sts-token" },
      fetch,
    });
    expect(r.code).toBe(0);
    const call = fetch.calls.find((c) => c.action === "ListCdnDomains")!;
    expect(call.method).toBe("POST");
    expect(call.url.href).toBe("https://cdn.volcengineapi.com/?Action=ListCdnDomains&Version=2021-03-01");
    expect(call.json).toEqual({ PageNum: 1, PageSize: 100 });
    expect(call.headers["content-type"]).toBe("application/json");
    expect(call.headers["x-date"]).toMatch(/^\d{8}T\d{6}Z$/);
    expect(call.headers["x-content-sha256"]).toMatch(/^[0-9a-f]{64}$/);
    expect(call.headers["x-security-token"]).toBe("sts-token");
    expect(call.headers.authorization).toMatch(
      /^HMAC-SHA256 Credential=AKLTtest0000\/\d{8}\/cn-north-1\/CDN\/request, SignedHeaders=content-type;host;x-content-sha256;x-date;x-security-token, Signature=[0-9a-f]{64}$/,
    );
  });

  it("业务错误以 HTTP 200 + ResponseMetadata.Error 返回", async () => {
    const fetch = fakeFetch(() => volcError("InvalidAccessKey", "The security token[AKLTtest0000] included in the request is invalid."));
    const r = await runCli(["domains", "-s", "cdn", "--json"], { env: VOLC_ENV, fetch });
    expect(r.code).toBe(1);
    expect(JSON.parse(r.stderr)).toMatchObject({ ok: false, status: "InvalidAccessKey" });
  });

  it("FlowLimitExceeded（HTTP 429）自动重试", async () => {
    let n = 0;
    const fetch = fakeFetch((req) => {
      if (req.action === "ListCdnDomains" && n++ === 0) return volcError("FlowLimitExceeded", "Request was rejected", 429);
      return cdnRoutes(req);
    });
    const r = await runCli(["domains", "-s", "cdn", "--json"], { env: VOLC_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toHaveLength(3);
  });

  it("非 JSON 的网关错误按 HTTP 状态报错", async () => {
    const fetch = fakeFetch(() => ({ status: 502, body: "<html>bad gateway</html>" }));
    const r = await runCli(["domains", "-s", "cdn", "--json"], { env: VOLC_ENV, fetch });
    expect(JSON.parse(r.stderr)).toMatchObject({ ok: false, status: "HTTP502" });
  });
});

describe("volcengine cdn", () => {
  it("域名列表与已关联证书（RSA/ECC + 国密）按域名合并，双证书取先到期，未开 HTTPS 不给证书", async () => {
    const r = await runCli(["domains", "-s", "cdn", "--json"], { env: VOLC_ENV, fetch: fakeFetch(cdnRoutes) });
    expect(r.code).toBe(0);
    expect(r.json.data.issues).toEqual([]);
    const byDomain = Object.fromEntries(r.json.data.items.map((d: any) => [d.domain, d]));
    expect(byDomain["www.example.com"]).toEqual({
      provider: "volcengine",
      service: "cdn",
      domain: "www.example.com",
      status: "online",
      https: true,
      cert: {
        id: "cert-rsa",
        commonName: "www.example.com",
        sans: ["www.example.com"],
        notBefore: "2026-08-01T00:00:00.000Z",
        notAfter: "2026-12-01T00:00:00.000Z",
        status: "running",
      },
      extra: { serviceType: "web", serviceRegion: "chinese_mainland", project: "default" },
      daysLeft: 47,
    });
    expect(byDomain["img.example.com"]).toEqual({
      provider: "volcengine",
      service: "cdn",
      domain: "img.example.com",
      status: "online",
      https: false,
      extra: { serviceType: "web" },
    });
    expect(byDomain["*.example.org"]).toMatchObject({ https: true, cert: { id: "cert-org", status: "expired" }, daysLeft: -14 });
  });

  it("翻页直到取完", async () => {
    const all = Array.from({ length: 150 }, (_, i) => ({ Domain: `d${i}.example.com`, Status: "online", HTTPS: false }));
    const fetch = fakeFetch((req) => {
      if (req.action === "ListCdnDomains") {
        const { PageNum, PageSize } = req.json as { PageNum: number; PageSize: number };
        return ok({ Total: all.length, Data: all.slice((PageNum - 1) * PageSize, PageNum * PageSize) });
      }
      if (req.action === "ListCdnCertInfo") return ok({ Total: 0, CertInfo: null, PageNum: 1, PageSize: 100 });
      return undefined;
    });
    const r = await runCli(["domains", "-s", "cdn", "--json"], { env: VOLC_ENV, fetch });
    expect(r.json.data.items).toHaveLength(150);
    expect(fetch.calls.filter((c) => c.action === "ListCdnDomains")).toHaveLength(2);
  });
});

const CERT_CENTER = [
  {
    InstanceId: "cert-wild",
    Tag: "未命名证书",
    CommonName: "*.example.com",
    San: ["*.example.com", "example.com"],
    Issuer: "RapidSSL TLS RSA CA G1",
    NotBefore: "2026-08-01 08:00:00",
    NotAfter: "2026-11-01 07:59:59",
    Status: "Issued",
    InstanceType: "Paid",
  },
  { InstanceId: "cert-pending", Tag: "待验证", CommonName: "new.example.com", Status: "Pending", InstanceType: "Free" },
];

function certCenterRoute(req: FakeRequest) {
  if (req.url.host === "certificate-service.volcengineapi.com" && req.action === "CertificateGetInstanceList") {
    return ok({ PageNumber: 1, PageSize: 100, TotalCount: CERT_CENTER.length, Instances: CERT_CENTER });
  }
  return undefined;
}

describe("volcengine certs", () => {
  it("证书中心：北京时间换算成 UTC，未签发的订单不列出", async () => {
    const fetch = fakeFetch(certCenterRoute);
    const r = await runCli(["certs", "-p", "volcengine", "--json"], { env: VOLC_ENV, fetch });
    expect(r.code).toBe(0);
    const call = fetch.calls[0]!;
    expect(call.method).toBe("POST");
    expect(call.url.href).toBe("https://certificate-service.volcengineapi.com/?Action=CertificateGetInstanceList&Version=2024-10-01");
    expect(call.json).toEqual({ PageNumber: 1, PageSize: 100 });
    expect(call.headers.authorization).toMatch(/Credential=AKLTtest0000\/\d{8}\/cn-beijing\/certificate_service\/request, /);
    expect(r.json.data.items).toEqual([
      {
        provider: "volcengine",
        id: "cert-wild",
        name: "未命名证书",
        commonName: "*.example.com",
        sans: ["*.example.com", "example.com"],
        issuer: "RapidSSL TLS RSA CA G1",
        notBefore: "2026-08-01T00:00:00.000Z",
        notAfter: "2026-10-31T23:59:59.000Z",
        status: "Issued",
        source: "Paid",
        daysLeft: 16,
      },
    ]);
  });

  it("按 PageNumber 翻页", async () => {
    const all = Array.from({ length: 130 }, (_, i) => ({ InstanceId: `cert-${i}`, NotAfter: "2027-01-01 00:00:00", Status: "Issued" }));
    const fetch = fakeFetch((req) => {
      const { PageNumber, PageSize } = req.json as { PageNumber: number; PageSize: number };
      return ok({ TotalCount: all.length, Instances: all.slice((PageNumber - 1) * PageSize, PageNumber * PageSize) });
    });
    const r = await runCli(["certs", "-p", "volcengine", "--json"], { env: VOLC_ENV, fetch });
    expect(r.json.data.items).toHaveLength(130);
    expect(fetch.calls).toHaveLength(2);
  });
});

function dcdnRoutes(req: FakeRequest) {
  if (req.url.host !== "open.volcengineapi.com" || req.action !== "ListDomainConfig") return undefined;
  return ok({
    Total: 4,
    PageNumber: 1,
    PageSize: 1000,
    DomainList: [
      {
        Domain: "a.example.com",
        Status: "Started",
        Scope: "domestic",
        ProjectName: "default",
        Https: {
          EnableHttps: true,
          CertBind: { CertSource: "volc", CertId: "cert-a", CertName: "a 证书", DeployStatus: "Deployed", Expire: "2026-12-20T15:59:59Z" },
        },
      },
      // 证书已绑定但关闭了 HTTPS
      { Domain: "b.example.com", Status: "Started", Https: { EnableHttps: false, CertBind: { CertId: "cert-b", Expire: "2026-10-20T00:00:00Z" } } },
      // 没有 Expire 时从证书中心补全
      { Domain: "www.example.com", Status: "Deploy", Https: { EnableHttps: true, CertBind: { CertSource: "volc", CertId: "cert-wild" } } },
      { Domain: "c.example.com", Status: "Stop", Https: { Http2: false } },
    ],
  });
}

describe("volcengine dcdn", () => {
  it("ListDomainConfig 的 HTTPS 开关与绑定证书；缺到期时间的从证书中心补全", async () => {
    const fetch = fakeFetch((req) => dcdnRoutes(req) ?? certCenterRoute(req));
    const r = await runCli(["domains", "-s", "dcdn", "--json"], { env: VOLC_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.issues).toEqual([]);
    const call = fetch.calls.find((c) => c.action === "ListDomainConfig")!;
    expect(call.url.href).toBe("https://open.volcengineapi.com/?Action=ListDomainConfig&Version=2021-04-01");
    expect(call.json).toEqual({ PageNumber: 1, PageSize: 1000 });
    expect(call.headers.authorization).toMatch(/\/cn-north-1\/dcdn\/request, /);
    const byDomain = Object.fromEntries(r.json.data.items.map((d: any) => [d.domain, d]));
    expect(byDomain["a.example.com"]).toEqual({
      provider: "volcengine",
      service: "dcdn",
      domain: "a.example.com",
      status: "Started",
      https: true,
      cert: { id: "cert-a", name: "a 证书", notAfter: "2026-12-20T15:59:59.000Z" },
      extra: { scope: "domestic", project: "default", certSource: "volc", certDeployStatus: "Deployed" },
      daysLeft: 66,
    });
    expect(byDomain["b.example.com"]).toEqual({ provider: "volcengine", service: "dcdn", domain: "b.example.com", status: "Started", https: false });
    expect(byDomain["www.example.com"]).toMatchObject({
      https: true,
      cert: {
        id: "cert-wild",
        commonName: "*.example.com",
        sans: ["*.example.com", "example.com"],
        notBefore: "2026-08-01T00:00:00.000Z",
        notAfter: "2026-10-31T23:59:59.000Z",
        status: "Issued",
      },
      daysLeft: 16,
    });
    expect(byDomain["c.example.com"]).toMatchObject({ https: false });
    expect(byDomain["c.example.com"].cert).toBeUndefined();
  });

  it("没有 EnableHttps 字段时按是否绑定证书判断；兼容文档里的 DomainConfigs 字段名", async () => {
    const fetch = fakeFetch((req) =>
      req.action === "ListDomainConfig"
        ? ok({ Total: 1, DomainConfigs: [{ Domain: "x.example.com", Https: { CertBind: { CertId: "cert-x", Expire: "2027-01-01T00:00:00Z" } } }] })
        : undefined,
    );
    const r = await runCli(["domains", "-s", "dcdn", "--json"], { env: VOLC_ENV, fetch });
    expect(r.json.data.items).toEqual([
      expect.objectContaining({ domain: "x.example.com", https: true, cert: { id: "cert-x", notAfter: "2027-01-01T00:00:00.000Z" } }),
    ]);
  });

  it("证书中心查询失败只记 issue，域名照常返回", async () => {
    const fetch = fakeFetch((req) =>
      req.action === "CertificateGetInstanceList" ? volcError("AccessDenied", "User is not authorized to perform", 403) : dcdnRoutes(req),
    );
    const r = await runCli(["domains", "-s", "dcdn", "--json"], { env: VOLC_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toHaveLength(4);
    expect(r.json.data.issues).toEqual([
      expect.objectContaining({ provider: "volcengine", service: "dcdn", kind: "error", code: "AccessDenied", target: "证书中心证书列表（用于补全到期时间）" }),
    ]);
  });

  it("产品自定义限流码 ErrTooManyRequests（HTTP 400）自动重试", async () => {
    let n = 0;
    const fetch = fakeFetch((req) => {
      if (req.action === "ListDomainConfig" && n++ === 0) return volcError("ErrTooManyRequests", "Can not process more requests.", 400);
      return dcdnRoutes(req) ?? certCenterRoute(req);
    });
    const r = await runCli(["domains", "-s", "dcdn", "--json"], { env: VOLC_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toHaveLength(4);
    expect(fetch.calls.filter((c) => c.action === "ListDomainConfig")).toHaveLength(2);
  });
});

function liveRoutes(req: FakeRequest) {
  if (req.url.host !== "live.volcengineapi.com") return undefined;
  if (req.action === "ListDomainDetail") {
    return ok({
      Total: 4,
      DomainList: [
        { Domain: "push.example.com", Type: "push", Status: 0, Region: "cn", Vhost: "live.example.com", ProjectName: "default", ChainID: "" },
        { Domain: "pull.example.com", Type: "pull-flv", Status: 0, Region: "cn", Vhost: "live.example.com", ChainID: "chain-ok" },
        { Domain: "old.example.com", Type: "pull-flv", Status: 2, ChainID: "chain-disabled" },
        { Domain: "gone.example.com", Type: "pull-flv", Status: 3, ChainID: "chain-ok" },
      ],
    });
  }
  if (req.action === "ListCertV2") {
    return ok({
      CertList: [
        {
          CertID: "cert-live-1",
          CertName: "*.example.com",
          ChainID: "chain-ok",
          CertDomainList: ["*.example.com", "example.com"],
          NotBefore: "2026-08-01T00:00:00Z",
          NotAfter: "2026-11-30T12:00:00Z",
          Status: "OK",
        },
      ],
    });
  }
  if (req.action === "DescribeCertDetailSecretV2" && req.json?.ChainID === "chain-disabled") {
    return ok({ CertName: "old", ChainID: "chain-disabled", CertDomainList: ["old.example.com"], NotAfter: "2026-10-10T00:00:00Z", Status: "Expire" });
  }
  return undefined;
}

describe("volcengine live", () => {
  it("域名按 ChainID 关联证书；ListCertV2 里没有的证书链逐个补查；已删除域名不列出", async () => {
    const fetch = fakeFetch(liveRoutes);
    const r = await runCli(["domains", "-s", "live", "--json"], { env: VOLC_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.issues).toEqual([]);
    const list = fetch.calls.find((c) => c.action === "ListDomainDetail")!;
    expect(list.url.href).toBe("https://live.volcengineapi.com/?Action=ListDomainDetail&Version=2023-01-01");
    expect(list.json).toEqual({ PageNum: 1, PageSize: 1000 });
    expect(list.headers.authorization).toMatch(/\/cn-north-1\/live\/request, /);
    expect(fetch.calls.find((c) => c.action === "ListCertV2")!.json).toEqual({});
    expect(fetch.calls.filter((c) => c.action === "DescribeCertDetailSecretV2").map((c) => c.json)).toEqual([{ ChainID: "chain-disabled" }]);
    const byDomain = Object.fromEntries(r.json.data.items.map((d: any) => [d.domain, d]));
    expect(Object.keys(byDomain).sort()).toEqual(["old.example.com", "pull.example.com", "push.example.com"]);
    expect(byDomain["push.example.com"]).toEqual({
      provider: "volcengine",
      service: "live",
      domain: "push.example.com",
      status: "normal",
      https: false,
      extra: { type: "push", region: "cn", vhost: "live.example.com", project: "default" },
    });
    expect(byDomain["pull.example.com"]).toMatchObject({
      https: true,
      cert: {
        id: "cert-live-1",
        name: "*.example.com",
        sans: ["*.example.com", "example.com"],
        notBefore: "2026-08-01T00:00:00.000Z",
        notAfter: "2026-11-30T12:00:00.000Z",
        status: "OK",
      },
      daysLeft: 46,
    });
    expect(byDomain["old.example.com"]).toMatchObject({
      status: "disabled",
      https: true,
      cert: { id: "chain-disabled", name: "old", notAfter: "2026-10-10T00:00:00.000Z", status: "Expire" },
      daysLeft: -5,
    });
  });

  it("服务端内部超时 InternalServiceTimeout 自动重试", async () => {
    let n = 0;
    const fetch = fakeFetch((req) => {
      if (req.action === "ListDomainDetail" && n++ === 0) return volcError("InternalServiceTimeout", "Internal Service is timeout. Pls Contact With Admin");
      return liveRoutes(req);
    });
    const r = await runCli(["domains", "-s", "live", "--json"], { env: VOLC_ENV, fetch });
    expect(r.json.data.issues).toEqual([]);
    expect(fetch.calls.filter((c) => c.action === "ListDomainDetail").length).toBeGreaterThan(1);
  });

  it("补查证书链失败只记 issue", async () => {
    const fetch = fakeFetch((req) =>
      req.action === "DescribeCertDetailSecretV2" ? volcError("AccessDenied", "User is not authorized", 403) : liveRoutes(req),
    );
    const r = await runCli(["domains", "-s", "live", "--json"], { env: VOLC_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items.find((d: any) => d.domain === "old.example.com")).toMatchObject({ https: true, cert: { id: "chain-disabled" } });
    expect(r.json.data.issues).toEqual([expect.objectContaining({ service: "live", kind: "error", code: "AccessDenied", target: "证书链 chain-disabled" })]);
  });
});

function vodRoutes(req: FakeRequest) {
  const host = req.url.host;
  if (host === "vod.ap-southeast-1.volcengineapi.com") return volcError("OperationDenied", "操作被拒绝，功能或服务未开通", 403);
  if (host !== "vod.volcengineapi.com") return undefined;
  if (req.action === "ListSpace") {
    return ok([
      { SpaceName: "s1", Region: "cn-north-1", ProjectName: "default", CreatedAt: "2023-01-03 18:09:31", Type: "space" },
      { SpaceName: "s2", Region: "cn-north-1" },
    ]);
  }
  if (req.action === "ListVodDomains" && req.json?.SpaceName === "s1") {
    return ok({
      VodInfo: {
        SpaceName: "s1",
        Total: 2,
        PageNum: 1,
        PageSize: 100,
        Domains: [
          { Domain: "play.example.com", DomainType: "vod_play", Cname: "play.example.com.volcvod.com" },
          { Domain: "img.example.com", DomainType: "vod_image" },
        ],
      },
      DomainInfo: {
        Total: 2,
        PageNum: 1,
        PageSize: 100,
        Data: [
          { Domain: "play.example.com", HTTPS: true, Status: "online", ServiceRegion: "chinese_mainland" },
          { Domain: "img.example.com", HTTPS: false, Status: "online" },
        ],
      },
    });
  }
  if (req.action === "ListVodDomains") return volcError("InvalidParameter.InvalidSpaceName", "space not found", 400);
  if (req.action === "DescribeVodDomainConfig") {
    return ok({
      DomainInfo: {
        DomainConfig: {
          Domain: "play.example.com",
          HTTPS: {
            Switch: true,
            CertInfoList: [
              { CertId: "cert-rsa", CertName: "play.example.com", EffectiveTime: T("2026-09-01T00:00:00Z"), ExpireTime: T("2026-12-01T00:00:00Z") },
              { CertId: "cert-wild", CertName: "*.example.com" },
            ],
          },
        },
      },
      VodInfo: { DomainType: "vod_play" },
    });
  }
  return undefined;
}

describe("volcengine vod", () => {
  it("列空间 → 列域名 → HTTPS 域名读配置；双证书取先到期（缺到期时间的从证书中心补）；柔佛未开通静默跳过", async () => {
    const fetch = fakeFetch((req) => vodRoutes(req) ?? certCenterRoute(req));
    const r = await runCli(["domains", "-s", "vod", "--json"], { env: VOLC_ENV, fetch });
    expect(r.code).toBe(0);
    const space = fetch.calls.find((c) => c.action === "ListSpace" && c.url.host === "vod.volcengineapi.com")!;
    expect(space.method).toBe("GET");
    expect(space.url.href).toBe("https://vod.volcengineapi.com/?Action=ListSpace&Limit=10&Offset=0&Version=2021-01-01");
    expect(space.headers.authorization).toMatch(/\/cn-north-1\/vod\/request, SignedHeaders=host;x-content-sha256;x-date, /);
    const sea = fetch.calls.find((c) => c.url.host === "vod.ap-southeast-1.volcengineapi.com")!;
    expect(sea.headers.authorization).toMatch(/\/ap-southeast-1\/vod\/request, /);
    expect(fetch.calls.find((c) => c.action === "ListVodDomains")!.json).toEqual({ SpaceName: "s1", ListCdnDomainsParam: { PageNum: 1, PageSize: 100 } });
    const configCalls = fetch.calls.filter((c) => c.action === "DescribeVodDomainConfig");
    expect(configCalls.map((c) => c.json)).toEqual([{ SpaceName: "s1", DomainType: "vod_play", DescribeCdnDomainParam: { Domain: "play.example.com" } }]);
    expect(r.json.data.issues).toEqual([
      expect.objectContaining({ service: "vod", kind: "error", code: "InvalidParameter.InvalidSpaceName", target: "空间 s2" }),
    ]);
    const byDomain = Object.fromEntries(r.json.data.items.map((d: any) => [d.domain, d]));
    expect(byDomain["play.example.com"]).toEqual({
      provider: "volcengine",
      service: "vod",
      domain: "play.example.com",
      status: "online",
      https: true,
      cert: {
        id: "cert-wild",
        name: "未命名证书",
        commonName: "*.example.com",
        sans: ["*.example.com", "example.com"],
        issuer: "RapidSSL TLS RSA CA G1",
        notBefore: "2026-08-01T00:00:00.000Z",
        notAfter: "2026-10-31T23:59:59.000Z",
        status: "Issued",
      },
      extra: { space: "s1", region: "cn-north-1", type: "vod_play", serviceRegion: "chinese_mainland" },
      daysLeft: 16,
    });
    expect(byDomain["img.example.com"]).toEqual({
      provider: "volcengine",
      service: "vod",
      domain: "img.example.com",
      status: "online",
      https: false,
      extra: { space: "s1", region: "cn-north-1", type: "vod_image" },
    });
  });

  it("DescribeVodDomainConfig 的 CertName 是证书 CN（不是证书名）：单证书带有效期时不再查证书中心", async () => {
    // 按真实响应脱敏：HTTPS.CertInfo 带 EffectiveTime / ExpireTime / Source，CertName 与 VodInfo.Certificate.CertificateName 都是 CN
    const fetch = fakeFetch((req) => {
      if (req.action === "ListSpace" && req.url.host === "vod.volcengineapi.com") return ok([{ SpaceName: "s1", Region: "cn-north-1" }]);
      if (req.action === "ListSpace") return ok(null);
      if (req.action === "ListVodDomains") {
        return ok({
          VodInfo: { SpaceName: "s1", Total: 1, Domains: [{ Domain: "v.example.com", DomainType: "vod_play", Cname: "v.example.com.bytevdn.com" }] },
          DomainInfo: { Total: 1, Data: [{ Domain: "v.example.com", HTTPS: true, Status: "online", ServiceRegion: "chinese_mainland", ConfigStatus: "FullDeployed" }] },
        });
      }
      if (req.action === "DescribeVodDomainConfig") {
        return ok({
          DomainInfo: {
            DomainConfig: {
              HTTPS: {
                Switch: true,
                CertInfo: {
                  CertId: "cert-ecc",
                  CertName: "v.example.com",
                  Certificate: { Certificate: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n", PrivateKey: null },
                  EffectiveTime: T("2026-10-17T13:09:54Z"),
                  ExpireTime: T("2027-01-15T13:09:53Z"),
                  EncryType: "inter_cert",
                  Source: "cdn_cert_hosting",
                },
                CertInfoList: null,
              },
            },
          },
          VodInfo: { SpaceName: "s1", DomainType: "vod_play", Certificate: { CertificateId: "cert-ecc", CertificateName: "v.example.com", HttpsStatus: "enable" } },
        });
      }
      return undefined;
    });
    const r = await runCli(["domains", "-s", "vod", "--json"], { env: VOLC_ENV, fetch });
    expect(r.json.data.issues).toEqual([]);
    expect(r.json.data.items[0].cert).toEqual({
      id: "cert-ecc",
      commonName: "v.example.com",
      notBefore: "2026-10-17T13:09:54.000Z",
      notAfter: "2027-01-15T13:09:53.000Z",
    });
    expect(fetch.calls.some((c) => c.action === "CertificateGetInstanceList")).toBe(false);
  });

  it("配置里只有 VodInfo.Certificate 时，CertificateName 同样作为 CN，有效期从证书中心补", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action === "ListSpace" && req.url.host === "vod.volcengineapi.com") return ok([{ SpaceName: "s1" }]);
      if (req.action === "ListSpace") return ok(null);
      if (req.action === "ListVodDomains") {
        return ok({ VodInfo: { Total: 1, Domains: [{ Domain: "v.example.com", DomainType: "vod_play" }] }, DomainInfo: { Total: 1, Data: [{ Domain: "v.example.com", HTTPS: true }] } });
      }
      if (req.action === "DescribeVodDomainConfig") return ok({ DomainInfo: { DomainConfig: { HTTPS: { Switch: true } } }, VodInfo: { Certificate: { CertificateId: "cert-wild", CertificateName: "*.example.com" } } });
      return certCenterRoute(req);
    });
    const r = await runCli(["domains", "-s", "vod", "--json"], { env: VOLC_ENV, fetch });
    expect(r.json.data.items[0].cert).toMatchObject({ id: "cert-wild", name: "未命名证书", commonName: "*.example.com", notAfter: "2026-10-31T23:59:59.000Z" });
  });

  it("空间列表按 Offset 翻页", async () => {
    const all = Array.from({ length: 12 }, (_, i) => ({ SpaceName: `s${i}` }));
    const fetch = fakeFetch((req) => {
      if (req.action === "ListSpace" && req.url.host === "vod.volcengineapi.com") {
        const offset = Number(req.url.searchParams.get("Offset"));
        return ok(all.slice(offset, offset + Number(req.url.searchParams.get("Limit"))));
      }
      if (req.action === "ListSpace") return ok(null);
      if (req.action === "ListVodDomains") return ok({ VodInfo: { Total: 0, Domains: [] }, DomainInfo: { Total: 0, Data: [] } });
      return undefined;
    });
    const r = await runCli(["domains", "-s", "vod", "--json"], { env: VOLC_ENV, fetch });
    expect(r.json.data.issues).toEqual([]);
    expect(fetch.calls.filter((c) => c.action === "ListSpace" && c.url.host === "vod.volcengineapi.com").map((c) => c.url.searchParams.get("Offset"))).toEqual(["0", "10"]);
    expect(fetch.calls.filter((c) => c.action === "ListVodDomains")).toHaveLength(12);
  });

  it("点播未开通（OperationDenied）记为 inactive", async () => {
    const fetch = fakeFetch(() => volcError("OperationDenied", "操作被拒绝，功能或服务未开通", 403));
    const r = await runCli(["domains", "-s", "vod", "--json"], { env: VOLC_ENV, fetch });
    expect(r.json.data.issues).toEqual([expect.objectContaining({ service: "vod", kind: "inactive", code: "OperationDenied" })]);
  });
});

/** veImageX 的业务错误：HTTP 200 + 空 Code + 非零 CodeN */
const imagexError = (CodeN: number, Message: string) => ({ body: { ResponseMetadata: { RequestId: "rid-x", Error: { CodeN, Code: "", Message } }, Result: null } });

function imagexRoutes(req: FakeRequest) {
  const q = (k: string) => req.url.searchParams.get(k);
  if (req.url.host === "imagex.ap-southeast-1.volcengineapi.com") {
    if (req.action === "GetAllImageServices") return ok({ Services: [{ ServiceId: "sea1", ServiceName: "sea", ServiceRegion: "mya" }] });
    if (req.action === "GetServiceDomains") return imagexError(601012, "service has no available domain");
    return undefined;
  }
  if (req.url.host !== "imagex.volcengineapi.com") return undefined;
  if (req.action === "GetAllImageServices") {
    return ok({
      Services: [
        { ServiceId: "svc1", ServiceName: "pics", ServiceRegion: "cn", ServiceStatus: "正常" },
        { ServiceId: "svc2", ServiceName: "broken", ServiceRegion: "cn" },
      ],
    });
  }
  if (req.action === "GetServiceDomains" && q("ServiceId") === "svc1") {
    return ok([
      { domain: "img.example.com", status: "正常", is_default: false, https_config: {} },
      { domain: "*.cdn.example.com", status: "正常" },
      { domain: "plain.example.com", status: "正常" },
    ]);
  }
  if (req.action === "GetServiceDomains") return imagexError(601002, "service not found");
  if (req.action === "GetDomainConfig") {
    const domain = q("DomainName");
    if (domain === "img.example.com") return ok({ domain, status: "正常", https_config: { enable_https: true, cert_id: "cert-img" } });
    if (domain === "*.cdn.example.com") return ok({ domain, status: "配置中", https_config: { enable_https: true, cert_id: "cert-wild" } });
    return ok({ domain, status: "正常", https_config: { enable_https: false, cert_id: "cert-old" } });
  }
  if (req.action === "GetImageAllDomainCert") {
    return ok([
      {
        domain: "img.example.com",
        domain_status: "正常",
        cert_id: "cert-img",
        cert_name: "证书域名: img.example.com",
        cert_common_name: "img.example.com",
        cert_not_after: T("2026-12-31T15:59:59Z"),
        san: ["img.example.com"],
      },
    ]);
  }
  return undefined;
}

describe("volcengine imagex", () => {
  it("服务 → 域名 → 逐域名读 HTTPS 开关；证书详情取自域名证书列表，缺失时从证书中心补全", async () => {
    const fetch = fakeFetch((req) => imagexRoutes(req) ?? certCenterRoute(req));
    const r = await runCli(["domains", "-s", "imagex", "--json"], { env: VOLC_ENV, fetch });
    expect(r.code).toBe(0);
    const list = fetch.calls.find((c) => c.action === "GetAllImageServices")!;
    expect(list.method).toBe("GET");
    expect(list.url.href).toBe("https://imagex.volcengineapi.com/?Action=GetAllImageServices&Version=2018-08-01");
    expect(list.headers.authorization).toMatch(/\/cn-north-1\/ImageX\/request, /);
    const wildcard = fetch.calls.find((c) => c.action === "GetDomainConfig" && c.url.searchParams.get("DomainName") === "*.cdn.example.com")!;
    expect(wildcard.url.search).toBe("?Action=GetDomainConfig&DomainName=%2A.cdn.example.com&ServiceId=svc1&Version=2018-08-01");
    // 柔佛服务没有可用域名不算错误；broken 服务查询失败记 issue
    expect(r.json.data.issues).toEqual([expect.objectContaining({ service: "imagex", kind: "error", code: "601002", target: "服务 broken" })]);
    const byDomain = Object.fromEntries(r.json.data.items.map((d: any) => [d.domain, d]));
    expect(byDomain["img.example.com"]).toEqual({
      provider: "volcengine",
      service: "imagex",
      domain: "img.example.com",
      status: "正常",
      https: true,
      cert: {
        id: "cert-img",
        name: "证书域名: img.example.com",
        commonName: "img.example.com",
        sans: ["img.example.com"],
        notAfter: "2026-12-31T15:59:59.000Z",
      },
      extra: { serviceId: "svc1", serviceName: "pics", region: "cn-north-1" },
      daysLeft: 77,
    });
    expect(byDomain["*.cdn.example.com"]).toMatchObject({
      status: "配置中",
      https: true,
      cert: { id: "cert-wild", commonName: "*.example.com", notAfter: "2026-10-31T23:59:59.000Z", status: "Issued" },
    });
    expect(byDomain["plain.example.com"]).toEqual({
      provider: "volcengine",
      service: "imagex",
      domain: "plain.example.com",
      status: "正常",
      https: false,
      extra: { serviceId: "svc1", serviceName: "pics", region: "cn-north-1" },
    });
  });

  it("未开通（HTTP 200 + 空 Code + CodeN 601001）记为 inactive", async () => {
    const fetch = fakeFetch(() => imagexError(601001, "account subscription not found"));
    const r = await runCli(["domains", "-s", "imagex", "--json"], { env: VOLC_ENV, fetch });
    expect(r.json.data.issues).toEqual([expect.objectContaining({ service: "imagex", kind: "inactive", code: "601001" })]);
  });

  it("限流 CodeN 600014 自动重试", async () => {
    let n = 0;
    const fetch = fakeFetch((req) => {
      if (req.action === "GetAllImageServices" && req.url.host === "imagex.volcengineapi.com" && n++ === 0) return imagexError(600014, "too many requests");
      return imagexRoutes(req) ?? certCenterRoute(req);
    });
    const r = await runCli(["domains", "-s", "imagex", "--json"], { env: VOLC_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toHaveLength(3);
  });
});

const tosError = (status: number, Code: string, EC: string) => ({ status, body: { Code, Message: `${Code} message`, RequestId: "tos-rid", HostId: "h", EC } });

function tosRoutes(req: FakeRequest) {
  const host = req.url.host;
  if (host === "tos-cn-beijing.volces.com" && req.url.pathname === "/") {
    return {
      body: {
        Owner: { ID: "2100000000" },
        Buckets: [
          { Name: "b1", Location: "cn-beijing", ExtranetEndpoint: "tos-cn-beijing.volces.com", CreationDate: "2021-08-19T09:16:05.000Z" },
          { Name: "b2", Location: "cn-shanghai", ExtranetEndpoint: "tos-cn-shanghai.volces.com" },
          { Name: "b3", Location: "cn-guangzhou" },
        ],
      },
    };
  }
  if (req.url.search !== "?customdomain") return undefined;
  if (host === "b1.tos-cn-beijing.volces.com") {
    return {
      body: {
        CustomDomainRules: [
          { Domain: "www.example.com", Cname: "b1.tos-cn-beijing.volces.com", Forbidden: false, CertId: "cert-wild", Protocol: "tos", CertStatus: "CertBound" },
          { Domain: "http.example.com", Forbidden: false, CertId: "", Protocol: "tos", CertStatus: "CertUnbound" },
          { Domain: "bad.example.com", Forbidden: true, ForbiddenReason: "DomainUnregistered", CertId: "cert-gone", CertStatus: "CertNotExist" },
          { Domain: "role.example.com", Forbidden: false, ForbiddenReason: "", CertId: "cert-wild", CertStatus: "RoleNotExist", Protocol: "tos" },
          { Domain: "old.example.com", Forbidden: false, ForbiddenReason: "", CertId: "cert-wild", CertStatus: "CertExpired", Protocol: "tos" },
          { Domain: "unknown.example.com", Forbidden: false, ForbiddenReason: "", CertId: "cert-wild", CertStatus: "CertUnknown", Protocol: "tos" },
        ],
      },
    };
  }
  if (host === "b2.tos-cn-shanghai.volces.com") return tosError(404, "NoSuchBucketCustomDomainConfiguration", "0016-00000008");
  if (host === "b3.tos-cn-guangzhou.volces.com") return tosError(404, "NoSuchBucket", "0006-00000001");
  return undefined;
}

describe("volcengine tos", () => {
  it("ListBuckets → 逐桶 ?customdomain（按桶所在地域签名）；绑定证书即 HTTPS（证书已删除 / 跨服务授权失败除外），证书从证书中心补全", async () => {
    const fetch = fakeFetch((req) => tosRoutes(req) ?? certCenterRoute(req));
    const r = await runCli(["domains", "-s", "tos", "--json"], { env: { ...VOLC_ENV, VOLCENGINE_SESSION_TOKEN: "sts" }, fetch });
    expect(r.code).toBe(0);
    const list = fetch.calls[0]!;
    expect(list.url.href).toBe("https://tos-cn-beijing.volces.com/");
    expect(list.headers["x-tos-date"]).toMatch(/^\d{8}T\d{6}Z$/);
    expect(list.headers["x-tos-security-token"]).toBe("sts");
    expect(list.headers.authorization).toMatch(
      /^TOS4-HMAC-SHA256 Credential=AKLTtest0000\/\d{8}\/cn-beijing\/tos\/request,SignedHeaders=host;x-tos-date;x-tos-security-token,Signature=[0-9a-f]{64}$/,
    );
    const b2 = fetch.calls.find((c) => c.url.host === "b2.tos-cn-shanghai.volces.com")!;
    expect(b2.url.href).toBe("https://b2.tos-cn-shanghai.volces.com/?customdomain");
    expect(b2.headers.authorization).toMatch(/\/cn-shanghai\/tos\/request,/);
    // b2 没配自定义域名不算错误；b3 没有 ExtranetEndpoint 时按地域拼 endpoint
    expect(r.json.data.issues).toEqual([
      expect.objectContaining({ service: "tos", kind: "error", code: "NoSuchBucket", message: "NoSuchBucket message（EC 0006-00000001）", target: "bucket b3" }),
    ]);
    const byDomain = Object.fromEntries(r.json.data.items.map((d: any) => [d.domain, d]));
    expect(byDomain["www.example.com"]).toEqual({
      provider: "volcengine",
      service: "tos",
      domain: "www.example.com",
      status: "normal",
      https: true,
      cert: {
        id: "cert-wild",
        name: "未命名证书",
        commonName: "*.example.com",
        sans: ["*.example.com", "example.com"],
        issuer: "RapidSSL TLS RSA CA G1",
        notBefore: "2026-08-01T00:00:00.000Z",
        notAfter: "2026-10-31T23:59:59.000Z",
        status: "CertBound",
      },
      extra: { bucket: "b1", region: "cn-beijing" },
      daysLeft: 16,
    });
    expect(byDomain["http.example.com"]).toEqual({
      provider: "volcengine",
      service: "tos",
      domain: "http.example.com",
      status: "normal",
      https: false,
      extra: { bucket: "b1", region: "cn-beijing" },
    });
    // 证书已删除 / 跨服务授权失败：TOS 实际下发默认证书，记为未开启，证书 ID 与状态放 extra
    expect(byDomain["bad.example.com"]).toEqual({
      provider: "volcengine",
      service: "tos",
      domain: "bad.example.com",
      status: "forbidden",
      https: false,
      extra: { bucket: "b1", region: "cn-beijing", forbiddenReason: "DomainUnregistered", certId: "cert-gone", certStatus: "CertNotExist" },
    });
    expect(byDomain["role.example.com"]).toMatchObject({ https: false, extra: { certId: "cert-wild", certStatus: "RoleNotExist" } });
    expect(byDomain["role.example.com"].cert).toBeUndefined();
    // 已过期 / 状态未知仍按开启处理，照常给出证书
    expect(byDomain["old.example.com"]).toMatchObject({ https: true, cert: { id: "cert-wild", status: "CertExpired", notAfter: "2026-10-31T23:59:59.000Z" } });
    expect(byDomain["unknown.example.com"]).toMatchObject({ https: true, cert: { id: "cert-wild", status: "CertUnknown" } });
  });

  it("未开通 TOS（EC 0003-00000003）记为 inactive；429 限流自动重试", async () => {
    const inactive = await runCli(["domains", "-s", "tos", "--json"], {
      env: VOLC_ENV,
      fetch: fakeFetch(() => tosError(403, "AccessDenied", "0003-00000003")),
    });
    expect(inactive.json.data.issues).toEqual([expect.objectContaining({ service: "tos", kind: "inactive", code: "AccessDenied" })]);

    let n = 0;
    const fetch = fakeFetch((req) => (n++ === 0 ? tosError(429, "ExceedAccountQPSLimit", "0004-00000007") : (tosRoutes(req) ?? certCenterRoute(req))));
    const r = await runCli(["domains", "-s", "tos", "--json"], { env: VOLC_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toHaveLength(6);
  });
});

describe("volcengine 全部服务", () => {
  it("不指定 -s 时查询全部服务", async () => {
    const fetch = fakeFetch((req) => cdnRoutes(req) ?? dcdnRoutes(req) ?? tosRoutes(req) ?? vodRoutes(req) ?? liveRoutes(req) ?? imagexRoutes(req) ?? certCenterRoute(req));
    const r = await runCli(["domains", "-p", "volcengine", "--json"], { env: VOLC_ENV, fetch });
    expect(r.code).toBe(0);
    const services = new Set(r.json.data.items.map((d: any) => d.service));
    expect([...services].sort()).toEqual(["cdn", "dcdn", "imagex", "live", "tos", "vod"]);
    // 证书中心在同一次命令里只拉一次
    expect(fetch.calls.filter((c) => c.action === "CertificateGetInstanceList")).toHaveLength(1);
  });
});
