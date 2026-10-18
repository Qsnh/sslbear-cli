import { describe, expect, it } from "vitest";
import { qboxAuthorization, qiniuAuthorization } from "../src/providers/qiniu/sign.js";
import { fakeFetch, runCli, type FakeRequest } from "./helpers.js";

const QINIU_ENV = { QINIU_ACCESS_KEY: "qiniu-test-ak", QINIU_SECRET_KEY: "qiniu-test-sk" };

const T = (iso: string) => Math.floor(Date.parse(iso) / 1000);
const pathOf = (req: FakeRequest) => req.url.pathname + req.url.search;

/** 证书列表条目，按真实响应形态脱敏（uid 为假值） */
const cert = (o: { certid: string; name: string; common_name: string; dnsnames: string[]; not_before: number; not_after: number }) => ({
  ...o,
  uid: 1000000001,
  create_time: o.not_before + 3600,
  orderid: "",
  product_short_name: "",
  product_type: o.dnsnames.length > 1 ? "multiple" : "single",
  cert_type: "DV",
  encrypt: "RSA",
  encryptParameter: "",
  enable: false,
  child_order_id: "",
  state: "",
  auto_renew: false,
  renewable: false,
});

const CERTS = [
  cert({
    certid: "cert-www",
    name: "www-2026",
    common_name: "www.example.com",
    dnsnames: ["www.example.com", "example.com"],
    not_before: T("2026-08-01T00:00:00Z"),
    not_after: T("2026-11-01T00:00:00Z"),
  }),
  cert({
    certid: "cert-wild",
    name: "wild",
    common_name: "*.example.com",
    dnsnames: ["*.example.com"],
    not_before: T("2026-07-01T00:00:00Z"),
    not_after: T("2026-10-20T00:00:00Z"),
  }),
];

/**
 * 证书列表（按真实账号实测的行为）：成功时 code 为 0；marker 是偏移量，非空页返回 offset + limit，
 * 取完也不会返回空 marker，而是下一页返回空列表与原 marker（如 2 张证书、limit=100：先 "100"，再 [] + "100"）
 */
function sslRoute(req: FakeRequest, certs: unknown[] = CERTS) {
  if (req.url.host !== "fusion.qiniuapi.com" || req.url.pathname !== "/sslcert") return undefined;
  const offset = Number(req.url.searchParams.get("marker") || 0);
  const limit = Number(req.url.searchParams.get("limit") || 100);
  const page = certs.slice(offset, offset + limit);
  return { body: { code: 0, error: "", certs: page, marker: String(page.length ? offset + limit : offset) } };
}

const DOMAIN_MARKER = "MTc2NTM3MTY5NDE1MzAwMDAwMA==";

function cdnRoute(req: FakeRequest) {
  if (req.url.host !== "api.qiniu.com") return undefined;
  if (req.url.pathname === "/domain") {
    if (req.url.searchParams.get("marker") === "") {
      return {
        body: {
          domains: [
            { name: "www.example.com", type: "normal", protocol: "https", product: "cdn", geoCover: "china", operatingState: "success" },
            { name: "img.example.com", type: "normal", protocol: "http", product: "cdn", geoCover: "global", operatingState: "success" },
            // 新建 bucket 时七牛自动分配的测试域名（真实账号里见到的形态）
            { name: "abc123xyz.hd-bkt.clouddn.com", type: "test", protocol: "http", product: "cdn", platform: "web", geoCover: "china", operatingState: "success" },
          ],
          marker: DOMAIN_MARKER,
        },
      };
    }
    if (req.url.searchParams.get("marker") === DOMAIN_MARKER) {
      return {
        body: {
          domains: [
            { name: ".example.com", type: "wildcard", protocol: "https", geoCover: "foreign", operatingState: "offlined" },
            { name: "broken.example.com", type: "normal", protocol: "https", operatingState: "success" },
            { name: "other.example.com", type: "normal", protocol: "https", operatingState: "success" },
          ],
          marker: "",
        },
      };
    }
  }
  if (req.url.pathname === "/domain/www.example.com") {
    return { body: { name: "www.example.com", protocol: "https", product: "cdn", https: { certId: "cert-www", forceHttps: true, http2Enable: true } } };
  }
  if (req.url.pathname === "/domain/.example.com") {
    return { body: { name: ".example.com", protocol: "https", product: "dcdn", https: { certId: "cert-wild", forceHttps: false, http2Enable: false } } };
  }
  if (req.url.pathname === "/domain/broken.example.com") return { status: 404, body: { code: 404001, error: "无此域名" } };
  if (req.url.pathname === "/domain/other.example.com") {
    return { body: { name: "other.example.com", protocol: "https", https: { certId: "cert-gone" } } };
  }
  return undefined;
}

describe("qiniu 请求格式", () => {
  it("域名管理走 api.qiniu.com + Qiniu 鉴权（签 Content-Type 与 X-Qiniu-Date）", async () => {
    const fetch = fakeFetch((req) => (req.url.pathname === "/domain" ? { body: { domains: [], marker: "" } } : undefined));
    const r = await runCli(["domains", "-p", "qiniu", "--json"], { env: QINIU_ENV, fetch });
    expect(r.code).toBe(0);
    const call = fetch.calls[0]!;
    expect(call.method).toBe("GET");
    expect(call.url.href).toBe("https://api.qiniu.com/domain?marker=&limit=1000");
    expect(call.headers["content-type"]).toBe("application/x-www-form-urlencoded");
    expect(call.headers["x-qiniu-date"]).toMatch(/^\d{8}T\d{6}Z$/);
    expect(call.headers.authorization).toBe(
      qiniuAuthorization({
        accessKey: "qiniu-test-ak",
        secretKey: "qiniu-test-sk",
        method: "GET",
        host: "api.qiniu.com",
        pathWithQuery: "/domain?marker=&limit=1000",
        contentType: "application/x-www-form-urlencoded",
        headers: { "X-Qiniu-Date": call.headers["x-qiniu-date"]! },
      }),
    );
    expect(call.headers.authorization).toMatch(/^Qiniu qiniu-test-ak:[A-Za-z0-9_-]{27}=$/);
  });

  it("证书管理走 fusion.qiniuapi.com + QBox 鉴权（只签路径 + query）", async () => {
    const fetch = fakeFetch(sslRoute);
    const r = await runCli(["certs", "-p", "qiniu", "--json"], { env: QINIU_ENV, fetch });
    expect(r.code).toBe(0);
    const call = fetch.calls[0]!;
    expect(call.url.href).toBe("https://fusion.qiniuapi.com/sslcert?marker=&limit=100");
    expect(call.headers.authorization).toBe(
      qboxAuthorization({ accessKey: "qiniu-test-ak", secretKey: "qiniu-test-sk", pathWithQuery: "/sslcert?marker=&limit=100" }),
    );
    expect(call.headers["x-qiniu-date"]).toBeUndefined();
    expect(fetch.calls[1]!.url.search).toBe("?marker=100&limit=100");
    expect(fetch.calls).toHaveLength(2);
  });
});

describe("qiniu certs", () => {
  it("按 marker 翻页；not_before / not_after 为 Unix 秒", async () => {
    const r = await runCli(["certs", "--json"], { env: QINIU_ENV, fetch: fakeFetch(sslRoute) });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toEqual([
      {
        provider: "qiniu",
        id: "cert-wild",
        name: "wild",
        commonName: "*.example.com",
        sans: ["*.example.com"],
        notBefore: "2026-07-01T00:00:00.000Z",
        notAfter: "2026-10-20T00:00:00.000Z",
        algorithm: "RSA",
        daysLeft: 5,
      },
      {
        provider: "qiniu",
        id: "cert-www",
        name: "www-2026",
        commonName: "www.example.com",
        sans: ["www.example.com", "example.com"],
        notBefore: "2026-08-01T00:00:00.000Z",
        notAfter: "2026-11-01T00:00:00.000Z",
        algorithm: "RSA",
        daysLeft: 17,
      },
    ]);
  });

  it("超过一页（limit 100）时按偏移量 marker 继续取，取到空页为止", async () => {
    const many = Array.from({ length: 150 }, (_, i) =>
      cert({ certid: `c${i}`, name: `c${i}`, common_name: `c${i}.example.com`, dnsnames: [`c${i}.example.com`], not_before: T("2026-08-01T00:00:00Z"), not_after: T("2026-11-01T00:00:00Z") }),
    );
    const fetch = fakeFetch((req) => sslRoute(req, many));
    const r = await runCli(["certs", "--json"], { env: QINIU_ENV, fetch });
    expect(r.code).toBe(0);
    expect(fetch.calls.map((c) => c.url.search)).toEqual(["?marker=&limit=100", "?marker=100&limit=100", "?marker=200&limit=100"]);
    expect(new Set(r.json.data.items.map((c: any) => c.id)).size).toBe(150);
  });

  it("鉴权失败：HTTP 401 + {error, error_code}", async () => {
    const fetch = fakeFetch(() => ({ status: 401, body: { error: "bad token", error_code: "BadToken" } }));
    const r = await runCli(["certs", "--json"], { env: QINIU_ENV, fetch });
    expect(r.code).toBe(1);
    expect(JSON.parse(r.stderr)).toMatchObject({ ok: false, status: "BadToken", message: expect.stringContaining("bad token") });
  });

  it("业务错误：{code, error}，错误码取 code（403001 无操作权限，不重试）", async () => {
    const fetch = fakeFetch(() => ({ status: 403, body: { code: 403001, error: "permission denied" } }));
    const r = await runCli(["certs", "--json"], { env: QINIU_ENV, fetch });
    expect(r.code).toBe(1);
    expect(JSON.parse(r.stderr)).toMatchObject({ ok: false, status: "403001" });
    expect(fetch.calls).toHaveLength(1);
  });

  it("成功响应的业务码：0（证书列表）、200（写接口）或缺省都算成功", async () => {
    for (const code of [0, 200, undefined]) {
      const fetch = fakeFetch((req) =>
        req.url.pathname === "/sslcert" ? { body: { code, error: "", certs: req.url.searchParams.get("marker") ? [] : CERTS, marker: "100" } } : undefined,
      );
      const r = await runCli(["certs", "--json"], { env: QINIU_ENV, fetch });
      expect(r.code).toBe(0);
      expect(r.json.data.items).toHaveLength(2);
      expect(r.json.data.issues).toEqual([]);
    }
  });

  it("HTTP 200 但带其他业务码视为失败", async () => {
    const fetch = fakeFetch(() => ({ body: { code: 400401, error: "无此证书" } }));
    const r = await runCli(["certs", "--json"], { env: QINIU_ENV, fetch });
    expect(JSON.parse(r.stderr)).toMatchObject({ ok: false, status: "400401", message: "没有任何查询成功：qiniu/cert 400401 无此证书" });
  });

  it("限流（403024 单用户 QPS 超限 / 403022 全局 QPS 超限 / HTTP 573 / 429）记为 Throttling 并重试", async () => {
    for (const reply of [
      { status: 403, body: { code: 403024, error: "too many requests" } },
      { status: 403, body: { code: 403022, error: "global qps exceeded" } },
      { status: 573, body: { error: "frequency limited" } },
      { status: 429, body: "Too Many Requests" },
    ]) {
      let n = 0;
      const fetch = fakeFetch((req) => (++n === 1 ? reply : sslRoute(req)));
      const r = await runCli(["certs", "--json"], { env: QINIU_ENV, fetch });
      expect(r.code).toBe(0);
      expect(r.json.data.items).toHaveLength(2);
      expect(fetch.calls).toHaveLength(3);
    }
    for (const code of [403024, 403022]) {
      const fetch = fakeFetch(() => ({ status: 403, body: { code, error: "too many requests" } }));
      const r = await runCli(["certs", "--json"], { env: QINIU_ENV, fetch });
      expect(fetch.calls).toHaveLength(3);
      expect(JSON.parse(r.stderr)).toMatchObject({ status: "Throttling", message: expect.stringContaining(String(code)) });
    }
  });

  it("纯文本错误响应（路径不存在）", async () => {
    const r = await runCli(["certs", "--json"], { env: QINIU_ENV, fetch: fakeFetch(() => undefined) });
    expect(JSON.parse(r.stderr)).toMatchObject({ ok: false, status: "HTTP404" });
  });
});

describe("qiniu domains", () => {
  it("CDN：按 marker 翻页，仅对开启 HTTPS 的域名查详情，证书从证书列表补全，不列七牛测试域名", async () => {
    const fetch = fakeFetch((req) => cdnRoute(req) ?? sslRoute(req));
    const r = await runCli(["domains", "-p", "qiniu", "-s", "cdn", "--json"], { env: QINIU_ENV, fetch });
    expect(r.code).toBe(0);
    // 第二页的 marker 含 =，需编码后发送（签名用同一个串）
    expect(fetch.calls.map(pathOf)).toContain(`/domain?marker=${encodeURIComponent(DOMAIN_MARKER)}&limit=1000`);
    expect(fetch.calls.some((c) => c.url.pathname === "/domain/img.example.com")).toBe(false);
    // 证书列表只拉一次（两页）
    expect(fetch.calls.filter((c) => c.url.pathname === "/sslcert")).toHaveLength(2);

    const byDomain = Object.fromEntries(r.json.data.items.map((d: any) => [d.domain, d]));
    expect(byDomain["www.example.com"]).toEqual({
      provider: "qiniu",
      service: "cdn",
      domain: "www.example.com",
      status: "success",
      https: true,
      cert: {
        id: "cert-www",
        name: "www-2026",
        commonName: "www.example.com",
        sans: ["www.example.com", "example.com"],
        notBefore: "2026-08-01T00:00:00.000Z",
        notAfter: "2026-11-01T00:00:00.000Z",
        // 证书算法来自证书列表的 encrypt：同期签发的 RSA / ECC 两张靠它区分（决策表的 already_current）
        algorithm: "RSA",
      },
      extra: { type: "normal", product: "cdn", geoCover: "china" },
      daysLeft: 17,
    });
    expect(byDomain["img.example.com"]).toEqual({
      provider: "qiniu",
      service: "cdn",
      domain: "img.example.com",
      status: "success",
      https: false,
      extra: { type: "normal", product: "cdn", geoCover: "global" },
    });
    // 七牛分配的测试域名不列出
    expect(byDomain["abc123xyz.hd-bkt.clouddn.com"]).toBeUndefined();
    expect(r.json.data.items).toHaveLength(5);
    // 已下线的泛域名照常列出
    expect(byDomain[".example.com"]).toMatchObject({
      status: "offlined",
      https: true,
      cert: { id: "cert-wild", notAfter: "2026-10-20T00:00:00.000Z" },
      extra: { type: "wildcard", product: "dcdn", geoCover: "foreign" },
      daysLeft: 5,
    });
    // 证书列表里找不到的证书只保留 ID
    expect(byDomain["other.example.com"]).toMatchObject({ https: true, cert: { id: "cert-gone" } });
    expect(byDomain["other.example.com"].daysLeft).toBeUndefined();
    // 单个域名详情失败：记 issue，域名按列表信息返回；拿不到证书 ID，标 httpsUnknown（部署时不能按查询结果处理）
    expect(byDomain["broken.example.com"]).toEqual({
      provider: "qiniu",
      service: "cdn",
      domain: "broken.example.com",
      status: "success",
      https: true,
      extra: { type: "normal", httpsUnknown: "true" },
    });
    expect(r.json.data.issues).toEqual([
      expect.objectContaining({ provider: "qiniu", service: "cdn", kind: "error", target: "domain broken.example.com", code: "404001", message: "无此域名" }),
    ]);
  });

  it("处理中的域名列表里的 protocol 还是旧值（实测 sslize 后列表仍为 http），照常查详情，按详情（已提交的配置）输出", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.pathname === "/domain") {
        return {
          body: {
            domains: [
              { name: "a.example.com", type: "normal", protocol: "http", operatingState: "processing", operationType: "sslize" },
              { name: "b.example.com", type: "normal", protocol: "http", operatingState: "success", operationType: "unsslize" },
            ],
            marker: "",
          },
        };
      }
      if (req.url.pathname === "/domain/a.example.com") {
        return { body: { name: "a.example.com", protocol: "https", operatingState: "processing", https: { certId: "cert-www", forceHttps: false, http2Enable: true } } };
      }
      return sslRoute(req);
    });
    const r = await runCli(["domains", "-p", "qiniu", "--json"], { env: QINIU_ENV, fetch });
    const byDomain = Object.fromEntries(r.json.data.items.map((d: any) => [d.domain, d]));
    expect(byDomain["a.example.com"]).toMatchObject({ status: "processing", https: true, cert: { id: "cert-www", notAfter: "2026-11-01T00:00:00.000Z" } });
    // 不在处理中的 HTTP 域名仍不查详情
    expect(byDomain["b.example.com"]).toMatchObject({ status: "success", https: false });
    expect(fetch.calls.some((c) => c.url.pathname === "/domain/b.example.com")).toBe(false);
  });

  it("详情里 protocol 为 http 时不计证书（绑了证书但未开启 HTTPS）", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.pathname === "/domain") return { body: { domains: [{ name: "a.example.com", operatingState: "success" }], marker: "" } };
      if (req.url.pathname === "/domain/a.example.com") return { body: { name: "a.example.com", protocol: "http", https: { certId: "cert-www" } } };
      return sslRoute(req);
    });
    const r = await runCli(["domains", "-p", "qiniu", "--json"], { env: QINIU_ENV, fetch });
    expect(r.json.data.items).toEqual([{ provider: "qiniu", service: "cdn", domain: "a.example.com", status: "success", https: false }]);
    expect(fetch.calls.some((c) => c.url.pathname === "/sslcert")).toBe(false);
  });

  it("列表没给 protocol 且详情查询失败时 https 按 false 输出，但标 httpsUnknown", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.pathname === "/domain") return { body: { domains: [{ name: "a.example.com", type: "normal", operatingState: "success" }], marker: "" } };
      if (req.url.pathname === "/domain/a.example.com") return { status: 500, body: { code: 500000, error: "internal error" } };
      return undefined;
    });
    const r = await runCli(["domains", "-p", "qiniu", "--json"], { env: QINIU_ENV, fetch });
    expect(r.json.data.items).toEqual([
      { provider: "qiniu", service: "cdn", domain: "a.example.com", status: "success", https: false, extra: { type: "normal", httpsUnknown: "true" } },
    ]);
    expect(r.json.data.issues).toEqual([expect.objectContaining({ target: "domain a.example.com", code: "500000" })]);
  });

  it("证书列表失败只记 issue，域名照常返回", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.host === "fusion.qiniuapi.com") return { status: 403, body: { code: 403001, error: "no permission" } };
      return cdnRoute(req);
    });
    const r = await runCli(["domains", "-p", "qiniu", "--json"], { env: QINIU_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items.find((d: any) => d.domain === "www.example.com")).toMatchObject({ https: true, cert: { id: "cert-www" } });
    expect(r.json.data.issues).toContainEqual(
      expect.objectContaining({ kind: "error", target: "SSL 证书列表（用于补全到期时间）", code: "403001" }),
    );
  });

  it("域名列表失败即该服务失败（七牛没有「未开通」错误，记为 error）", async () => {
    const fetch = fakeFetch(() => ({ status: 401, body: { error: "bad token", error_code: "BadToken" } }));
    const r = await runCli(["domains", "-p", "qiniu", "--json"], { env: QINIU_ENV, fetch });
    expect(r.code).toBe(1);
    expect(JSON.parse(r.stderr)).toMatchObject({
      ok: false,
      status: "BadToken",
      issues: [expect.objectContaining({ provider: "qiniu", service: "cdn", kind: "error", code: "BadToken" })],
    });
  });
});
