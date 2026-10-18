import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { loadLocalCert, type LocalCert } from "../src/deploy/cert.js";
import { executeDeploy, planDeploy } from "../src/deploy/run.js";
import { CloudApiError, type Fetch, type QueryContext } from "../src/lib/http.js";
import { qiniu } from "../src/providers/qiniu/index.js";
import { qboxAuthorization, qiniuAuthorization } from "../src/providers/qiniu/sign.js";
import type { DeployInput } from "../src/providers/registry.js";
import type { DomainRecord } from "../src/types.js";
import { fakeFetch, type FakeReply, type FakeRequest } from "./helpers.js";

const FIX = fileURLToPath(new URL("./fixtures/deploy/", import.meta.url));
const NOW = new Date("2026-10-15T00:00:00Z");
const load = (cert: string, key: string) => loadLocalCert(readFileSync(join(FIX, cert), "utf8"), readFileSync(join(FIX, key), "utf8"), NOW);
/** CN example.com，SAN example.com、*.example.com，2026-01-01 至 2027-01-01 */
const RSA = load("rsa-fullchain.pem", "rsa-key.pem");
/** 与 RSA 同 CN、同 SAN、同起止时间，只有算法不同 */
const ECC = load("ecc-fullchain.pem", "ecc-key.pem");

const ENV = { QINIU_ACCESS_KEY: "qiniu-test-ak", QINIU_SECRET_KEY: "qiniu-test-sk" };
const CREDS = { accessKeyId: "qiniu-test-ak", secretAccessKey: "qiniu-test-sk" };
const ctxOf = (fetch: Fetch): QueryContext => ({ env: ENV, fetch, now: NOW, timeoutMs: 1000, sleep: async () => {} });

const T = (iso: string) => Math.floor(Date.parse(iso) / 1000);
const pathOf = (req: FakeRequest) => req.url.pathname + req.url.search;
const cdn = qiniu.services.find((s) => s.key === "cdn")!;
const deployer = cdn.deployer!;

/** 证书列表条目，按真实响应形态（见 qiniu.test.ts） */
const sslcert = (o: { certid: string; name?: string; common_name?: string; dnsnames?: string[]; not_before?: number; not_after?: number; encrypt?: string }) => ({
  name: o.certid,
  common_name: "example.com",
  dnsnames: ["*.example.com", "example.com"],
  not_before: T("2026-01-01T00:00:00Z"),
  not_after: T("2027-01-01T00:00:00Z"),
  encrypt: "RSA",
  uid: 1000000001,
  create_time: T("2026-01-01T01:00:00Z"),
  product_type: "multiple_wildcard",
  enable: false,
  state: "",
  ...o,
});

/** 证书列表：marker 是偏移量，取完后下一页返回空列表与原 marker */
function sslListRoute(req: FakeRequest, certs: unknown[]): FakeReply {
  if (req.method !== "GET" || req.url.host !== "fusion.qiniuapi.com" || req.url.pathname !== "/sslcert") return undefined;
  const offset = Number(req.url.searchParams.get("marker") || 0);
  const page = certs.slice(offset, offset + 100);
  return { body: { code: 0, error: "", certs: page, marker: String(page.length ? offset + 100 : offset) } };
}

const isUpload = (req: FakeRequest) => req.method === "POST" && req.url.host === "fusion.qiniuapi.com" && req.url.pathname === "/sslcert";

describe("qiniu uploadCertificate", () => {
  it("查重命中：同算法、同起止时间、同 CN、同 SAN（顺序无关）即复用，不上传", async () => {
    const fetch = fakeFetch((req) =>
      sslListRoute(req, [
        sslcert({ certid: "ecc-twin", encrypt: "ECDSA" }),
        sslcert({ certid: "other-time", not_after: T("2027-01-01T00:00:01Z") }),
        sslcert({ certid: "other-san", dnsnames: ["example.com"] }),
        sslcert({ certid: "same", dnsnames: ["example.com", "*.example.com"] }),
      ]),
    );
    const r = await qiniu.uploadCertificate!(ctxOf(fetch), CREDS, RSA);
    expect(r).toEqual({ id: "same", reused: true });
    expect(fetch.calls.some(isUpload)).toBe(false);

    const ecc = await qiniu.uploadCertificate!(ctxOf(fetch), CREDS, ECC);
    expect(ecc).toEqual({ id: "ecc-twin", reused: true });
  });

  it("查重未命中：POST fusion /sslcert，QBox 只签路径，JSON 体带 name / common_name / pri / ca，PEM 不上 URL", async () => {
    const fetch = fakeFetch((req) => {
      if (isUpload(req)) return { body: { certID: "new-cert" } };
      return sslListRoute(req, [
        // 同 CN / SAN、到期只差几秒的另一算法证书（真实账号里同批签发的 RSA / ECC 就是这样），不能当成同一张
        sslcert({ certid: "ecc-twin", encrypt: "ECDSA" }),
        // 到期差 1 天的同名 RSA 证书也不是同一张
        sslcert({ certid: "rsa-next-day", not_before: T("2026-01-02T00:00:00Z"), not_after: T("2027-01-02T00:00:00Z") }),
      ]);
    });
    const r = await qiniu.uploadCertificate!(ctxOf(fetch), CREDS, RSA);
    expect(r).toEqual({ id: "new-cert", reused: false });

    const uploads = fetch.calls.filter(isUpload);
    expect(uploads).toHaveLength(1);
    const call = uploads[0]!;
    expect(call.url.href).toBe("https://fusion.qiniuapi.com/sslcert");
    expect(call.headers["content-type"]).toBe("application/json");
    expect(call.headers.authorization).toBe(qboxAuthorization({ accessKey: "qiniu-test-ak", secretKey: "qiniu-test-sk", pathWithQuery: "/sslcert" }));
    expect(call.json).toEqual({ name: "sslbear-example.com-20270101", common_name: "example.com", pri: RSA.keyPem, ca: RSA.certPem });
    expect(call.url.href).not.toContain("PRIVATE");
  });

  it("证书名：CN 里的 * 换成 _；超长时截短 CN 部分，保留到期日；没有 CN 时用第一个 SAN", async () => {
    const names: string[] = [];
    const fetch = fakeFetch((req) => {
      if (isUpload(req)) {
        names.push(req.json!.name as string);
        return { body: { certID: `id-${names.length}` } };
      }
      return sslListRoute(req, []);
    });
    const long = `${"a".repeat(70)}.example.com`;
    const variants: LocalCert[] = [
      { ...RSA, commonName: "*.example.com" },
      { ...RSA, commonName: long, sans: [long] },
      { ...RSA, commonName: undefined, sans: ["*.example.org", "example.org"] },
    ];
    for (const cert of variants) await qiniu.uploadCertificate!(ctxOf(fetch), CREDS, cert);
    expect(names[0]).toBe("sslbear-_.example.com-20270101");
    expect(names[1]).toHaveLength(64);
    expect(names[1]).toMatch(/^sslbear-a+-20270101$/);
    expect(names[2]).toBe("sslbear-_.example.org-20270101");
    expect(fetch.calls.filter(isUpload)[2]!.json!.common_name).toBe("*.example.org");
  });

  it("上传超时后重试先重新查重：上次其实已传成功时复用，不会传出两份", async () => {
    let stored = false;
    const inner = fakeFetch((req) => {
      if (isUpload(req)) {
        stored = true;
        return { body: { certID: "new-cert" } };
      }
      return sslListRoute(req, stored ? [sslcert({ certid: "new-cert" })] : []);
    });
    let timedOut = false;
    const fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const res = await inner(input, init);
      // 服务端已经收下证书，但响应没在超时前回来
      if (init?.method === "POST" && !timedOut) {
        timedOut = true;
        throw Object.assign(new Error("The operation was aborted due to timeout"), { name: "TimeoutError" });
      }
      return res;
    }) as Fetch;
    const r = await qiniu.uploadCertificate!(ctxOf(fetch), CREDS, RSA);
    expect(r).toEqual({ id: "new-cert", reused: true });
    expect(inner.calls.filter(isUpload)).toHaveLength(1);
  });

  it("上传被拒：抛 CloudApiError，带七牛错误码，不重试", async () => {
    const fetch = fakeFetch((req) => (isUpload(req) ? { status: 400, body: { code: 400323, error: "证书链验证失败" } } : sslListRoute(req, [])));
    const err = await qiniu.uploadCertificate!(ctxOf(fetch), CREDS, RSA).catch((e) => e);
    expect(err).toBeInstanceOf(CloudApiError);
    expect(err).toMatchObject({ provider: "qiniu", code: "400323", message: "证书链验证失败" });
    expect(fetch.calls.filter(isUpload)).toHaveLength(1);
  });

  it("响应里没有证书 ID 视为失败", async () => {
    const fetch = fakeFetch((req) => (isUpload(req) ? { body: { code: 200 } } : sslListRoute(req, [])));
    await expect(qiniu.uploadCertificate!(ctxOf(fetch), CREDS, RSA)).rejects.toMatchObject({ code: "InvalidResponse" });
  });

  it("查重用的证书列表失败时不上传", async () => {
    const fetch = fakeFetch((req) => (isUpload(req) ? { body: { certID: "x" } } : { status: 403, body: { code: 403022, error: "no permission" } }));
    await expect(qiniu.uploadCertificate!(ctxOf(fetch), CREDS, RSA)).rejects.toMatchObject({ code: "403022" });
    expect(fetch.calls.some(isUpload)).toBe(false);
  });
});

const record = (domain: string, r: Partial<DomainRecord> = {}): DomainRecord => ({
  provider: "qiniu",
  service: "cdn",
  domain,
  status: "success",
  https: true,
  cert: { id: "cert-old", notAfter: "2026-10-20T00:00:00.000Z" },
  extra: { type: "normal", product: "cdn" },
  ...r,
});

const input = (id = "new-cert"): DeployInput & { uploads: number } => {
  const i = {
    cert: RSA,
    uploads: 0,
    certId: async () => {
      i.uploads++;
      return id;
    },
  };
  return i;
};

/** 校验 api.qiniu.com 写请求的 Qiniu 鉴权：JSON 请求体参与签名 */
function expectSigned(call: FakeRequest) {
  expect(call.headers["content-type"]).toBe("application/json");
  expect(call.headers["x-qiniu-date"]).toMatch(/^\d{8}T\d{6}Z$/);
  expect(call.headers.authorization).toBe(
    qiniuAuthorization({
      accessKey: "qiniu-test-ak",
      secretKey: "qiniu-test-sk",
      method: call.method,
      host: "api.qiniu.com",
      pathWithQuery: pathOf(call),
      contentType: "application/json",
      headers: { "X-Qiniu-Date": call.headers["x-qiniu-date"]! },
      body: call.body,
    }),
  );
}

describe("qiniu cdn deployer", () => {
  it("update：先读域名详情，PUT httpsconf 只换 certId，强制跳转 / HTTP/2 / TLS 版本原样带回", async () => {
    for (const https of [
      { certId: "cert-old", forceHttps: true, http2Enable: false, tlsVersions: "TLSv1.2/TLSv1.3" },
      { certId: "cert-old", forceHttps: false, http2Enable: true },
    ]) {
      const fetch = fakeFetch((req) => {
        if (req.method === "GET" && req.url.pathname === "/domain/www.example.com") {
          return { body: { name: "www.example.com", protocol: "https", operatingState: "success", https } };
        }
        if (req.method === "PUT" && req.url.pathname === "/domain/www.example.com/httpsconf") return { body: { code: 200 } };
        return undefined;
      });
      const i = input();
      const out = await deployer.apply(ctxOf(fetch), CREDS, { records: [record("www.example.com")], mode: "update" }, i);
      expect(out).toEqual({ certId: "new-cert" });
      expect(i.uploads).toBe(1);
      expect(fetch.calls.map((c) => `${c.method} ${c.url.host}${pathOf(c)}`)).toEqual([
        "GET api.qiniu.com/domain/www.example.com",
        "PUT api.qiniu.com/domain/www.example.com/httpsconf",
      ]);
      const put = fetch.calls[1]!;
      const { certId: _old, ...rest } = https;
      expect(put.json).toEqual({ certId: "new-cert", ...rest });
      expectSigned(put);
    }
  });

  it("update：详情里没有 forceHttps / http2Enable 时不传（七牛对未传项保留原值），不会按 false 覆盖", async () => {
    const fetch = fakeFetch((req) => {
      if (req.method === "GET") return { body: { name: "www.example.com", protocol: "https", https: { certId: "cert-old" } } };
      if (req.method === "PUT") return { body: { code: 200 } };
      return undefined;
    });
    await deployer.apply(ctxOf(fetch), CREDS, { records: [record("www.example.com")], mode: "update" }, input());
    expect(fetch.calls[1]!.json).toEqual({ certId: "new-cert" });
  });

  it("update：域名已绑着这张证书时不再提交", async () => {
    const fetch = fakeFetch((req) =>
      req.method === "GET" ? { body: { name: "www.example.com", protocol: "https", https: { certId: "new-cert", forceHttps: false, http2Enable: true } } } : undefined,
    );
    const out = await deployer.apply(ctxOf(fetch), CREDS, { records: [record("www.example.com")], mode: "update" }, input());
    expect(out).toEqual({ certId: "new-cert", note: expect.stringContaining("已绑定") });
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET"]);
  });

  it("deploy：PUT sslize 开启 HTTPS（不强制跳转、HTTP/2 开启），不读详情；写接口空响应体也算成功", async () => {
    const fetch = fakeFetch((req) => (req.method === "PUT" && req.url.pathname === "/domain/img.example.com/sslize" ? { body: "" } : undefined));
    const out = await deployer.apply(ctxOf(fetch), CREDS, { records: [record("img.example.com", { https: false, cert: undefined })], mode: "deploy" }, input());
    expect(out).toEqual({ certId: "new-cert" });
    expect(fetch.calls).toHaveLength(1);
    const put = fetch.calls[0]!;
    expect(put.url.href).toBe("https://api.qiniu.com/domain/img.example.com/sslize");
    expect(put.json).toEqual({ certId: "new-cert", forceHttps: false, http2Enable: true });
    expectSigned(put);
  });

  it("泛域名（七牛写作 .example.com）原样放进路径", async () => {
    const fetch = fakeFetch((req) => {
      if (req.method === "GET") return { body: { name: ".example.com", type: "wildcard", protocol: "https", https: { certId: "cert-old", forceHttps: false, http2Enable: false } } };
      return { body: { code: 200 } };
    });
    await deployer.apply(ctxOf(fetch), CREDS, { records: [record(".example.com", { extra: { type: "wildcard" } })], mode: "update" }, input());
    expect(fetch.calls.map(pathOf)).toEqual(["/domain/.example.com", "/domain/.example.com/httpsconf"]);
    expect(fetch.calls[1]!.json).toEqual({ certId: "new-cert", forceHttps: false, http2Enable: false });
  });

  it("七牛拒绝修改（如域名处理中）时原样抛出错误码与信息", async () => {
    const fetch = fakeFetch((req) =>
      req.method === "GET"
        ? { body: { name: "www.example.com", protocol: "https", operatingState: "processing", https: { certId: "cert-old", forceHttps: false, http2Enable: true } } }
        : { status: 400, body: { code: 400030, error: "正在处理中" } },
    );
    const err = await deployer.apply(ctxOf(fetch), CREDS, { records: [record("www.example.com")], mode: "update" }, input()).catch((e) => e);
    expect(err).toBeInstanceOf(CloudApiError);
    expect(err).toMatchObject({ code: "400030", message: "正在处理中" });
  });

  it("unsupported：泛子域名的 HTTPS 配置继承所属泛域名", () => {
    expect(deployer.unsupported!(record("a.example.com", { extra: { type: "pan" } }), "update")).toMatch(/泛子域名/);
    expect(deployer.unsupported!(record("a.example.com", { https: false, extra: { type: "pan" } }), "deploy")).toMatch(/泛子域名/);
    expect(deployer.unsupported!(record("a.example.com"), "update")).toBeUndefined();
    expect(deployer.unsupported!(record(".example.com", { extra: { type: "wildcard" } }), "update")).toBeUndefined();
  });
});

describe("qiniu deploy（planDeploy + executeDeploy）", () => {
  const LATER = T("2026-12-01T00:00:00Z"); // 剩 47 天

  function route(certs: unknown[]) {
    return (req: FakeRequest): FakeReply => {
      if (req.url.host === "fusion.qiniuapi.com") {
        if (isUpload(req)) return { body: { certID: "new-cert" } };
        return sslListRoute(req, certs);
      }
      if (req.method === "GET" && req.url.pathname === "/domain") {
        return {
          body: {
            domains: [
              { name: "www.example.com", type: "normal", protocol: "https", product: "cdn", operatingState: "success" },
              { name: "img.example.com", type: "normal", protocol: "http", product: "cdn", operatingState: "success" },
              { name: ".example.com", type: "wildcard", protocol: "https", product: "dcdn", operatingState: "success" },
              { name: "p.example.com", type: "pan", protocol: "https", product: "cdn", operatingState: "success" },
              { name: "other.org", type: "normal", protocol: "https", product: "cdn", operatingState: "success" },
            ],
            marker: "",
          },
        };
      }
      const details: Record<string, unknown> = {
        "www.example.com": { https: { certId: "cert-due", forceHttps: true, http2Enable: true } },
        ".example.com": { https: { certId: "cert-later", forceHttps: false, http2Enable: false } },
        "p.example.com": { https: { certId: "cert-due", forceHttps: false, http2Enable: true } },
        "other.org": { https: { certId: "cert-other", forceHttps: false, http2Enable: true } },
      };
      const m = /^\/domain\/([^/]+)(\/\w+)?$/.exec(req.url.pathname);
      if (req.method === "GET" && m && !m[2] && details[m[1]!]) return { body: { name: m[1], protocol: "https", ...(details[m[1]!] as object) } };
      if (req.method === "PUT" && m && (m[2] === "/httpsconf" || m[2] === "/sslize")) return { body: { code: 200 } };
      return undefined;
    };
  }

  const CERTS = [
    sslcert({ certid: "cert-due", not_before: T("2026-07-20T00:00:00Z"), not_after: T("2026-10-20T00:00:00Z") }),
    sslcert({ certid: "cert-later", not_after: LATER }),
    sslcert({ certid: "cert-other", common_name: "other.org", dnsnames: ["other.org"], not_after: LATER }),
  ];

  it("点名的域名：快到期的更新、没开 HTTPS 的部署；证书只上传一次；未点名的不动", async () => {
    const fetch = fakeFetch(route(CERTS));
    const ctx = ctxOf(fetch);
    const plan = await planDeploy(ctx, RSA, { providers: ["qiniu"], domains: ["www.example.com", "img.example.com", "p.example.com"], force: false, dryRun: false });
    const report = await executeDeploy(ctx, RSA, plan);

    expect(report.results).toEqual([
      expect.objectContaining({ domain: "img.example.com", action: "deployed", after: { id: "new-cert", notAfter: RSA.notAfter } }),
      expect.objectContaining({ domain: "p.example.com", action: "skipped", reason: "unsupported" }),
      expect.objectContaining({ domain: "www.example.com", action: "updated", before: expect.objectContaining({ id: "cert-due", daysLeft: 5 }) }),
    ]);
    expect(report.uploads).toEqual([{ provider: "qiniu", certId: "new-cert", reused: false }]);
    expect(fetch.calls.filter(isUpload)).toHaveLength(1);

    const writes = fetch.calls.filter((c) => c.method === "PUT").map((c) => [pathOf(c), c.json]);
    expect(writes).toEqual(
      expect.arrayContaining([
        ["/domain/www.example.com/httpsconf", { certId: "new-cert", forceHttps: true, http2Enable: true }],
        ["/domain/img.example.com/sslize", { certId: "new-cert", forceHttps: false, http2Enable: true }],
      ]),
    );
    expect(writes).toHaveLength(2);
  });

  it("未点名：未到期的泛域名需确认、没开 HTTPS 的跳过；--force 后泛域名也更新", async () => {
    const fetch = fakeFetch(route(CERTS));
    const ctx = ctxOf(fetch);
    const report = await executeDeploy(ctx, RSA, await planDeploy(ctx, RSA, { providers: ["qiniu"], force: false, dryRun: false }));
    const by = Object.fromEntries(report.results.map((r) => [r.domain, r]));
    expect(by[".example.com"]).toMatchObject({ action: "skipped", reason: "not_due", needsConfirm: true });
    expect(by["img.example.com"]).toMatchObject({ action: "skipped", reason: "https_off" });
    expect(by["www.example.com"]).toMatchObject({ action: "updated" });
    expect(by["other.org"]).toBeUndefined();

    const fetch2 = fakeFetch(route(CERTS));
    const ctx2 = ctxOf(fetch2);
    const forced = await executeDeploy(ctx2, RSA, await planDeploy(ctx2, RSA, { providers: ["qiniu"], domains: [".example.com"], force: true, dryRun: false }));
    expect(forced.results).toEqual([expect.objectContaining({ domain: ".example.com", action: "updated" })]);
    expect(fetch2.calls.filter((c) => c.method === "PUT").map((c) => [pathOf(c), c.json])).toEqual([
      ["/domain/.example.com/httpsconf", { certId: "new-cert", forceHttps: false, http2Enable: false }],
    ]);
  });

  it("七牛报错时该域名记为 failed，错误码与信息原样上报，私钥不出现在输出里", async () => {
    const base = route(CERTS);
    const fetch = fakeFetch((req) =>
      req.method === "PUT" ? { status: 400, body: { code: 400030, error: `正在处理中 ${RSA.keyPem}` } } : base(req),
    );
    const ctx = ctxOf(fetch);
    const report = await executeDeploy(ctx, RSA, await planDeploy(ctx, RSA, { providers: ["qiniu"], domains: ["www.example.com"], force: false, dryRun: false }));
    expect(report.results).toEqual([expect.objectContaining({ domain: "www.example.com", action: "failed", code: "400030", retryable: false })]);
    expect(report.results[0]!.message).toMatch(/^正在处理中/);
    expect(JSON.stringify(report)).not.toContain(RSA.keyPem.split("\n")[1]);
  });
});
