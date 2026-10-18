import { describe, expect, it } from "vitest";
import { bceAuthorization } from "../src/providers/baidu/sign.js";
import { fakeFetch, runCli, type FakeRequest } from "./helpers.js";

const BAIDU_ENV = { BAIDUCLOUD_ACCESS_KEY: "test-ak-baidu", BAIDUCLOUD_SECRET_KEY: "test-sk-baidu" };

const bceError = (status: number, code: string, message: string) => ({ status, body: { code, message, requestId: "rid-err" } });

const CERTS = [
  {
    certId: "cert-wild000001",
    certName: "wild",
    certCommonName: "*.example.com",
    certDNSNames: "*.example.com,example.com",
    certStartTime: "2026-08-01T00:00:00Z",
    certStopTime: "2026-10-30T23:59:59Z",
    certCreateTime: "2026-08-01T01:00:00Z",
    certUpdateTime: "2026-08-01T01:00:00Z",
    certType: 1,
    resources: [{ serviceName: "opencdn", resourceId: "img.example.com" }],
    status: "IN_USE",
    expired: false,
  },
  {
    certId: "cert-clientca01",
    certName: "client-ca",
    certCommonName: "Example Client CA",
    certStartTime: "2026-01-01T00:00:00Z",
    certStopTime: "2036-01-01T00:00:00Z",
    certType: 2,
    status: "UNUSED",
    expired: false,
  },
];

function certRoute(req: FakeRequest) {
  if (req.url.host === "certificate.baidubce.com" && req.url.pathname === "/v1/certificate/detail") return { body: { certs: CERTS } };
  return undefined;
}

/** 按收到的请求重算签名，校验 URL 上的路径 / 参数与签名时用的一致 */
function expectSigned(req: FakeRequest, ak: string, sk: string) {
  const auth = req.headers.authorization!;
  const timestamp = req.headers["x-bce-date"]!;
  const headers: Record<string, string> = { host: req.url.host, "x-bce-date": timestamp };
  if (req.headers["x-bce-security-token"]) headers["x-bce-security-token"] = req.headers["x-bce-security-token"];
  const expected = bceAuthorization({
    accessKeyId: ak,
    secretAccessKey: sk,
    method: req.method,
    path: decodeURIComponent(req.url.pathname),
    query: Object.fromEntries(req.url.searchParams),
    headers,
    timestamp,
  });
  expect(auth).toBe(expected);
}

describe("baidu 请求格式", () => {
  it("GET + bce-auth-v1 签名头，临时凭证带 x-bce-security-token", async () => {
    const fetch = fakeFetch(certRoute);
    const r = await runCli(["certs", "-p", "baidu", "--json"], { env: { ...BAIDU_ENV, BAIDUCLOUD_SESSION_TOKEN: "sts-token" }, fetch });
    expect(r.code).toBe(0);
    const call = fetch.calls[0]!;
    expect(call.method).toBe("GET");
    expect(call.url.href).toBe("https://certificate.baidubce.com/v1/certificate/detail");
    expect(call.headers["x-bce-date"]).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    expect(call.headers["x-bce-security-token"]).toBe("sts-token");
    expect(call.headers.authorization).toMatch(
      /^bce-auth-v1\/test-ak-baidu\/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\/1800\/host;x-bce-date;x-bce-security-token\/[0-9a-f]{64}$/,
    );
    expectSigned(call, "test-ak-baidu", "test-sk-baidu");
  });

  it("错误响应 {code,message,requestId} 带 HTTP 状态码", async () => {
    const fetch = fakeFetch(() => bceError(403, "IamSignatureInvalid", "IamSignatureInvalid, cause: Could not find credential."));
    const r = await runCli(["certs", "-p", "baidu", "--json"], { env: BAIDU_ENV, fetch });
    expect(r.code).toBe(1);
    expect(JSON.parse(r.stderr)).toMatchObject({ ok: false, status: "IamSignatureInvalid" });
  });

  it("限流（429 或名称像限流的错误码）自动重试", async () => {
    let n = 0;
    const fetch = fakeFetch((req) => {
      n++;
      if (n === 1) return { status: 429, body: "Too Many Requests" };
      if (n === 2) return bceError(400, "RequestRateLimitExceeded", "rate limited");
      return certRoute(req);
    });
    const r = await runCli(["certs", "-p", "baidu", "--json"], { env: BAIDU_ENV, fetch });
    expect(r.code).toBe(0);
    expect(fetch.calls).toHaveLength(3);
    expect(r.json.data.items).toHaveLength(1);
  });
});

describe("baidu certs", () => {
  it("证书管理：UTC 时间、逗号分隔的域名拆成 sans、去掉客户端证书", async () => {
    const r = await runCli(["certs", "-p", "baidu", "--json"], { env: BAIDU_ENV, fetch: fakeFetch(certRoute) });
    expect(r.json.data.items).toEqual([
      {
        provider: "baidu",
        id: "cert-wild000001",
        name: "wild",
        commonName: "*.example.com",
        sans: ["*.example.com", "example.com"],
        notBefore: "2026-08-01T00:00:00.000Z",
        notAfter: "2026-10-30T23:59:59.000Z",
        status: "IN_USE",
        daysLeft: 15,
      },
    ]);
  });
});

/** 第 1 页塞满 100 条不在域名列表里的记录，验证按 count 翻页 */
const FILLER = Array.from({ length: 100 }, (_, i) => ({ domain: `old${i}.example.net`, certId: "cert-x", certType: 1, status: 1 }));

// 实测 HTTPS 域名列表的 certCommonName 装的是证书名，CLI 不用它
const HTTPS_ROWS = [
  // 同一域名 RSA + 国密两张服务端证书，cert 取先到期的；HTTPS 配置里绑定的是 RSA，另一张标为国密
  { domain: "www.example.com", certId: "cert-rsa", certName: "rsa", certCommonName: "rsa", certStartTime: "2026-01-01T00:00:00Z", certStopTime: "2027-01-01T00:00:00Z", certType: 1, status: 1 },
  { domain: "www.example.com", certId: "cert-sm2", certName: "sm2", certCommonName: "sm2", certStartTime: "2026-01-01T00:00:00Z", certStopTime: "2026-12-01T00:00:00Z", certType: 1, status: 1 },
  // 双向认证的客户端证书不算
  { domain: "www.example.com", certId: "cert-clientca01", certName: "client-ca", certStartTime: "2026-01-01T00:00:00Z", certStopTime: "2026-10-20T00:00:00Z", certType: 2, status: 1 },
  // 时间为占位符，从证书管理按 ID 补全
  { domain: "img.example.com", certId: "cert-wild000001", certName: "wild", certCommonName: "-", certStartTime: "-", certStopTime: "-", certType: 1, status: 1 },
  // 平台通用证书，证书管理里没有，不补全
  { domain: "bucket.example.com", certId: "cert-common", certName: "commonCert", certCommonName: "-", certStartTime: "-", certStopTime: "-", certType: 1, status: 1 },
];

function cdnRoute(req: FakeRequest) {
  if (req.url.host !== "cdn.baidubce.com") return undefined;
  if (req.url.pathname === "/v2/user/domains") {
    expect(req.url.searchParams.get("status")).toBe("ALL");
    return {
      body: {
        domains: [
          { domain: "www.example.com", status: "RUNNING" },
          { domain: "img.example.com", status: "RUNNING" },
          { domain: "bucket.example.com", status: "RUNNING" },
          { domain: "plain.example.com", status: "STOPPED" },
        ],
      },
    };
  }
  if (req.url.pathname === "/v2/httpsDomains") {
    const page = req.url.searchParams.get("pageNo");
    expect(req.url.searchParams.get("pageSize")).toBe("100");
    const count = String(FILLER.length + HTTPS_ROWS.length);
    return { body: { count, rows: page === "1" ? FILLER : page === "2" ? HTTPS_ROWS : [] } };
  }
  if (req.url.pathname === "/v2/domain/www.example.com/config" && req.url.search === "?https") {
    return { body: { https: { enabled: true, certId: "cert-rsa", httpRedirect: false, httpsRedirect: false, http2Enabled: true, verifyClient: false } } };
  }
  return undefined;
}

describe("baidu domains", () => {
  it("CDN：域名列表与 HTTPS 域名列表合并，多证书取最早到期并区分国密，缺到期时间的从证书管理补", async () => {
    const fetch = fakeFetch((req) => cdnRoute(req) ?? certRoute(req));
    const r = await runCli(["domains", "-p", "baidu", "-s", "cdn", "--json"], { env: BAIDU_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.issues).toEqual([]);
    const byDomain = Object.fromEntries(r.json.data.items.map((d: any) => [d.domain, d]));
    expect(byDomain["www.example.com"]).toEqual({
      provider: "baidu",
      service: "cdn",
      domain: "www.example.com",
      status: "RUNNING",
      https: true,
      cert: {
        id: "cert-sm2",
        name: "sm2",
        notBefore: "2026-01-01T00:00:00.000Z",
        notAfter: "2026-12-01T00:00:00.000Z",
        status: "1",
        algorithm: "SM2",
      },
      certs: [
        { id: "cert-rsa", name: "rsa", notBefore: "2026-01-01T00:00:00.000Z", notAfter: "2027-01-01T00:00:00.000Z", status: "1" },
        { id: "cert-sm2", name: "sm2", notBefore: "2026-01-01T00:00:00.000Z", notAfter: "2026-12-01T00:00:00.000Z", status: "1", algorithm: "SM2" },
      ],
      daysLeft: 47,
    });
    // 只有多证书的域名才查 HTTPS 配置
    expect(fetch.calls.filter((c) => c.url.pathname.endsWith("/config")).map((c) => c.url.pathname)).toEqual(["/v2/domain/www.example.com/config"]);
    expect(byDomain["img.example.com"]).toEqual({
      provider: "baidu",
      service: "cdn",
      domain: "img.example.com",
      status: "RUNNING",
      https: true,
      cert: {
        id: "cert-wild000001",
        name: "wild",
        commonName: "*.example.com",
        sans: ["*.example.com", "example.com"],
        notBefore: "2026-08-01T00:00:00.000Z",
        notAfter: "2026-10-30T23:59:59.000Z",
        status: "1",
      },
      daysLeft: 15,
    });
    expect(byDomain["bucket.example.com"]).toMatchObject({ https: true, cert: { id: "cert-common", name: "commonCert", status: "1" } });
    expect(byDomain["bucket.example.com"].daysLeft).toBeUndefined();
    expect(byDomain["plain.example.com"]).toEqual({ provider: "baidu", service: "cdn", domain: "plain.example.com", status: "STOPPED", https: false });
    // 填充页里的域名不在域名列表中，不输出
    expect(r.json.data.items).toHaveLength(4);
    const httpsPages = fetch.calls.filter((c) => c.url.pathname === "/v2/httpsDomains").map((c) => c.url.searchParams.get("pageNo"));
    expect(httpsPages).toEqual(["1", "2"]);
    // 证书管理只拉一次
    expect(fetch.calls.filter((c) => c.url.host === "certificate.baidubce.com")).toHaveLength(1);
  });

  it("证书管理补全失败只记 issue，域名照常返回", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.host === "certificate.baidubce.com") return bceError(403, "AccessDenied", "Access denied.");
      return cdnRoute(req);
    });
    const r = await runCli(["domains", "-p", "baidu", "--json"], { env: BAIDU_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toHaveLength(4);
    const img = r.json.data.items.find((d: any) => d.domain === "img.example.com");
    expect(img).toMatchObject({ https: true, cert: { id: "cert-wild000001", name: "wild" } });
    expect(img.cert.notAfter).toBeUndefined();
    expect(r.json.data.issues).toEqual([
      expect.objectContaining({ provider: "baidu", service: "cdn", kind: "error", code: "AccessDenied", target: "证书管理列表（用于补全到期时间）" }),
    ]);
  });

  it("没有 HTTPS 域名时不查证书管理", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.pathname === "/v2/user/domains") return { body: { domains: [{ domain: "a.example.com", status: "RUNNING" }] } };
      if (req.url.pathname === "/v2/httpsDomains") return { body: { count: 0, rows: [] } };
      return undefined;
    });
    const r = await runCli(["domains", "-p", "baidu", "--json"], { env: BAIDU_ENV, fetch });
    expect(r.json.data.items).toEqual([{ provider: "baidu", service: "cdn", domain: "a.example.com", status: "RUNNING", https: false }]);
    expect(fetch.calls.map((c) => c.url.pathname).sort()).toEqual(["/v2/httpsDomains", "/v2/user/domains"]);
  });

  it("CDN 未开通（OptInRequired）记为 inactive", async () => {
    const fetch = fakeFetch(() => bceError(403, "OptInRequired", "A subscription for the service is required."));
    const r = await runCli(["domains", "-p", "baidu", "--json"], { env: BAIDU_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toEqual([]);
    expect(r.json.data.issues).toEqual([expect.objectContaining({ provider: "baidu", service: "cdn", kind: "inactive", code: "OptInRequired" })]);
  });

  it("入口接口失败整个服务记为失败", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.pathname === "/v2/user/domains") return bceError(403, "AccessDenied", "Access denied.");
      return cdnRoute(req);
    });
    const r = await runCli(["domains", "-p", "baidu", "--json"], { env: BAIDU_ENV, fetch });
    expect(r.code).toBe(1);
  });
});

describe("baidu CDN：HTTPS 列表接口失败的处理", () => {
  /** 按真实账号响应改写：证书管理列表（ECC + RSA 两张同域名证书） */
  const LE_CERTS = [
    {
      certId: "cert-ecc0000001",
      certName: "test-ec",
      certCommonName: "test.example.com",
      certType: 1,
      certStartTime: "2026-10-17T13:09:54Z",
      certStopTime: "2027-01-15T13:09:53Z",
      canReplace: false,
      certDNSNames: "*.test.example.com,test.example.com",
      resources: [{ serviceName: "opencdn", resourceId: "on.test.example.com" }],
      status: "IN_USE",
      expired: false,
      certCreateTime: "2026-10-17T14:15:35Z",
      // 实测 certUpdateTime 是北京时间却带 Z，CLI 不使用该字段
      certUpdateTime: "2026-10-17T22:15:35Z",
    },
    {
      certId: "cert-rsa0000001",
      certName: "test-rsa",
      certCommonName: "test.example.com",
      certType: 1,
      certStartTime: "2026-10-17T13:10:09Z",
      certStopTime: "2027-01-15T13:10:08Z",
      canReplace: false,
      certDNSNames: "*.test.example.com,test.example.com",
      resources: [],
      status: "UNUSED",
      expired: false,
      certCreateTime: "2026-10-17T14:15:36Z",
      certUpdateTime: "2026-10-17T22:15:35Z",
    },
  ];

  /** 实测：未开通 CDN 的账号 /v2/httpsDomains 无论带什么参数都返回 500 且响应体为空 */
  const EMPTY_500 = { status: 500, body: "" };

  const HTTPS_CONFIG: Record<string, unknown> = {
    // 开启 HTTPS 并绑定证书
    "on.test.example.com": { https: { enabled: true, certId: "cert-ecc0000001", httpRedirect: false, httpsRedirect: false, http2Enabled: true, verifyClient: false, sslProtocols: ["TLSv1.2", "TLSv1.3"] } },
    // 关闭 HTTPS 但证书仍绑定着（PUT enabled=false 不会解绑证书）
    "bound-off.test.example.com": { https: { enabled: false, certId: "cert-rsa0000001", httpRedirect: false, httpsRedirect: false, http2Enabled: true, verifyClient: false } },
    // 从未配置 HTTPS
    "off.test.example.com": { https: { enabled: false, httpRedirect: false, httpsRedirect: false, http2Enabled: true, verifyClient: false } },
  };

  function route(req: FakeRequest) {
    if (req.url.host === "certificate.baidubce.com" && req.url.pathname === "/v1/certificate/detail") return { body: { certs: LE_CERTS } };
    if (req.url.host !== "cdn.baidubce.com") return undefined;
    if (req.url.pathname === "/v2/user/domains") {
      return {
        body: {
          domains: [
            { domain: "on.test.example.com", status: "RUNNING" },
            { domain: "bound-off.test.example.com", status: "RUNNING" },
            { domain: "off.test.example.com", status: "STOPPED" },
            { domain: "broken.test.example.com", status: "RUNNING" },
          ],
        },
      };
    }
    if (req.url.pathname === "/v2/httpsDomains") return EMPTY_500;
    const m = /^\/v2\/domain\/([^/]+)\/config$/.exec(req.url.pathname);
    if (m && req.url.searchParams.has("https")) {
      const cfg = HTTPS_CONFIG[m[1]!];
      return cfg ? { body: cfg } : bceError(500, "InternalError", "We encountered an internal error. Please try again.");
    }
    return undefined;
  }

  it("没有域名时不调 HTTPS 列表接口（未开通 CDN 的账号该接口 500），也不报错", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.pathname === "/v2/user/domains") return { body: { domains: [] } };
      if (req.url.pathname === "/v2/httpsDomains") return EMPTY_500;
      return undefined;
    });
    const r = await runCli(["domains", "-p", "baidu", "--json"], { env: BAIDU_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data).toEqual({ items: [], issues: [] });
    expect(fetch.calls.map((c) => c.url.pathname)).toEqual(["/v2/user/domains"]);
  });

  it("HTTPS 列表接口 500 时退回逐域名查 HTTPS 配置：enabled 才算 HTTPS，证书从证书管理补全，单域名失败只记 issue", async () => {
    const fetch = fakeFetch(route);
    const r = await runCli(["domains", "-p", "baidu", "--json"], { env: BAIDU_ENV, fetch, now: "2026-10-17T14:20:00Z" });
    expect(r.code).toBe(0);
    const byDomain = Object.fromEntries(r.json.data.items.map((d: any) => [d.domain, d]));
    expect(byDomain["on.test.example.com"]).toEqual({
      provider: "baidu",
      service: "cdn",
      domain: "on.test.example.com",
      status: "RUNNING",
      https: true,
      cert: {
        id: "cert-ecc0000001",
        name: "test-ec",
        commonName: "test.example.com",
        sans: ["*.test.example.com", "test.example.com"],
        notBefore: "2026-10-17T13:09:54.000Z",
        notAfter: "2027-01-15T13:09:53.000Z",
      },
      daysLeft: 89,
    });
    expect(byDomain["bound-off.test.example.com"]).toEqual({ provider: "baidu", service: "cdn", domain: "bound-off.test.example.com", status: "RUNNING", https: false });
    expect(byDomain["off.test.example.com"]).toEqual({ provider: "baidu", service: "cdn", domain: "off.test.example.com", status: "STOPPED", https: false });
    expect(byDomain["broken.test.example.com"]).toEqual({ provider: "baidu", service: "cdn", domain: "broken.test.example.com", status: "RUNNING", https: false });
    // 批量接口失败已由逐域名查询兜底，不单独报；只有查不到的那个域名记 issue
    expect(r.json.data.issues).toEqual([
      expect.objectContaining({ provider: "baidu", service: "cdn", kind: "error", code: "InternalError", target: "domain broken.test.example.com HTTPS 配置" }),
    ]);
    // URL 上 https 只写参数名（与官方 SDK 一致），签名按 https= 计算
    const configCalls = fetch.calls.filter((c) => c.url.pathname.endsWith("/config"));
    expect(configCalls).toHaveLength(4);
    expect(configCalls[0]!.url.search).toBe("?https");
    expectSigned(configCalls[0]!, "test-ak-baidu", "test-sk-baidu");
    // 证书管理只拉一次
    expect(fetch.calls.filter((c) => c.url.host === "certificate.baidubce.com")).toHaveLength(1);
  });

  it("空响应体的错误在 message 里标明", async () => {
    const fetch = fakeFetch((req) => (req.url.pathname === "/v2/user/domains" ? EMPTY_500 : undefined));
    const r = await runCli(["domains", "-p", "baidu", "--json"], { env: BAIDU_ENV, fetch });
    expect(r.code).toBe(1);
    expect(JSON.parse(r.stderr)).toMatchObject({ ok: false, status: "HTTP500", issues: [expect.objectContaining({ code: "HTTP500", message: "HTTP 500（响应体为空）" })] });
  });

  it("CDNNotActivated（实测未开通 CDN 时的错误码，HTTP 500）记为 inactive", async () => {
    const fetch = fakeFetch(() => bceError(500, "CDNNotActivated", "please activate/open CDN first by BCE console"));
    const r = await runCli(["domains", "-p", "baidu", "--json"], { env: BAIDU_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.issues).toEqual([expect.objectContaining({ provider: "baidu", service: "cdn", kind: "inactive", code: "CDNNotActivated" })]);
  });
});

describe("baidu CDN 证书通用名", () => {
  it("HTTPS 域名列表的 certCommonName 实为证书名：通用名与 SAN 从证书管理补全，有效期以 CDN 为准", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.pathname === "/v2/user/domains") return { body: { domains: [{ domain: "img.example.com", status: "RUNNING" }] } };
      if (req.url.pathname === "/v2/httpsDomains") {
        return {
          body: {
            count: 1,
            rows: [{ domain: "img.example.com", certId: "cert-wild000001", certName: "wild", certCommonName: "wild", certStartTime: "2026-08-01T00:00:00Z", certStopTime: "2026-10-30T23:59:59Z", certType: 1, status: 1 }],
          },
        };
      }
      return certRoute(req);
    });
    const r = await runCli(["domains", "-p", "baidu", "--json"], { env: BAIDU_ENV, fetch });
    expect(r.json.data.items[0].cert).toEqual({
      id: "cert-wild000001",
      name: "wild",
      commonName: "*.example.com",
      sans: ["*.example.com", "example.com"],
      notBefore: "2026-08-01T00:00:00.000Z",
      notAfter: "2026-10-30T23:59:59.000Z",
      status: "1",
    });
    expect(r.json.data.issues).toEqual([]);
  });

  it("只缺通用名时证书管理拉取失败不记 issue", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.pathname === "/v2/user/domains") return { body: { domains: [{ domain: "img.example.com", status: "RUNNING" }] } };
      if (req.url.pathname === "/v2/httpsDomains") {
        return { body: { count: 1, rows: [{ domain: "img.example.com", certId: "cert-x", certName: "x", certStopTime: "2026-10-30T23:59:59Z", certType: 1, status: 1 }] } };
      }
      if (req.url.host === "certificate.baidubce.com") return bceError(403, "AccessDenied", "denied");
      return undefined;
    });
    const r = await runCli(["domains", "-p", "baidu", "--json"], { env: BAIDU_ENV, fetch });
    expect(r.json.data.items[0]).toMatchObject({ https: true, cert: { id: "cert-x", name: "x", notAfter: "2026-10-30T23:59:59.000Z" } });
    expect(r.json.data.issues).toEqual([]);
  });
});
