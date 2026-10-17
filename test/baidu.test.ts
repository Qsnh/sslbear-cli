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

const HTTPS_ROWS = [
  // 同一域名 RSA + 国密两张服务端证书，取先到期的
  { domain: "www.example.com", certId: "cert-rsa", certName: "rsa", certCommonName: "www.example.com", certStartTime: "2026-01-01T00:00:00Z", certStopTime: "2027-01-01T00:00:00Z", certType: 1, status: 1 },
  { domain: "www.example.com", certId: "cert-sm2", certName: "sm2", certCommonName: "www.example.com", certStartTime: "2026-01-01T00:00:00Z", certStopTime: "2026-12-01T00:00:00Z", certType: 1, status: 1 },
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
  return undefined;
}

describe("baidu domains", () => {
  it("CDN：域名列表与 HTTPS 域名列表合并，多证书取最早到期，缺到期时间的从证书管理补", async () => {
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
        commonName: "www.example.com",
        notBefore: "2026-01-01T00:00:00.000Z",
        notAfter: "2026-12-01T00:00:00.000Z",
        status: "1",
      },
      daysLeft: 47,
    });
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
