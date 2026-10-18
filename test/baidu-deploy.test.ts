import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { loadLocalCert, type LocalCert } from "../src/deploy/cert.js";
import { executeDeploy, planDeploy, type DeployOptions } from "../src/deploy/run.js";
import { CloudApiError, type QueryContext } from "../src/lib/http.js";
import { baidu } from "../src/providers/baidu/index.js";
import { bceAuthorization } from "../src/providers/baidu/sign.js";
import { queryDomains } from "../src/query.js";
import { fakeFetch, type FakeReply, type FakeRequest } from "./helpers.js";

const FIX = fileURLToPath(new URL("./fixtures/deploy/", import.meta.url));
const NOW = new Date("2026-10-15T00:00:00Z");
const CERT = loadLocalCert(readFileSync(join(FIX, "rsa-fullchain.pem"), "utf8"), readFileSync(join(FIX, "rsa-key.pem"), "utf8"), NOW);
const [LEAF, CA] = CERT.certPem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)!;
const KEY_LINE = CERT.keyPem.split("\n")[1]!;

const BAIDU_ENV = { BAIDUCLOUD_ACCESS_KEY: "test-ak-baidu", BAIDUCLOUD_SECRET_KEY: "test-sk-baidu" };
const CREDS = { accessKeyId: "test-ak-baidu", secretAccessKey: "test-sk-baidu" };

const DUE = "2026-10-25T00:00:00Z"; // 剩 10 天
const LATER = "2026-12-01T00:00:00Z"; // 剩 47 天
const NEW_ID = "cert-new00000001";

const colonHex = (hex: string) => hex.toUpperCase().match(/../g)!.join(":");
const SHA256 = colonHex(CERT.fingerprint);
const SHA1 = new X509Certificate(LEAF!).fingerprint;
const OTHER_SHA256 = colonHex("ab".repeat(32));

const bceError = (status: number, code: string, message: string) => ({ status, body: { code, message, requestId: "rid-err" } });

interface CertDetail {
  certId: string;
  certName: string;
  certCommonName?: string;
  certDNSNames?: string;
  certStartTime?: string;
  certStopTime?: string;
  certType?: number;
}

const detail = (id: string, r: Partial<CertDetail> = {}): CertDetail => ({
  certId: id,
  certName: id,
  certCommonName: "example.com",
  certDNSNames: "example.com,*.example.com",
  certStartTime: "2026-01-01T00:00:00Z",
  certStopTime: "2027-01-01T00:00:00Z",
  certType: 1,
  ...r,
});

interface HttpsRow {
  domain: string;
  certId: string;
  certName?: string;
  certStartTime?: string;
  certStopTime?: string;
  certType?: number;
  status?: number;
}

interface Api {
  domains?: { domain: string; status: string }[];
  httpsRows?: HttpsRow[];
  /** GET /v2/domain/{domain}/config?https 的响应；值为 FakeReply 时原样返回（模拟报错） */
  config?: Record<string, unknown>;
  certs?: CertDetail[];
  /** GET /v1/certificate/{certId} 的响应 */
  meta?: Record<string, unknown>;
  upload?: FakeReply;
}

/** 模拟百度智能云 CDN 与证书管理接口 */
function baiduApi(api: Api) {
  return fakeFetch((req): FakeReply => {
    const { host, pathname } = req.url;
    if (host === "certificate.baidubce.com") {
      if (req.method === "GET" && pathname === "/v1/certificate/detail") return { body: { certs: api.certs ?? [] } };
      if (req.method === "POST" && pathname === "/v1/certificate") return api.upload ?? { body: { certId: NEW_ID, certName: req.json?.certName } };
      const m = /^\/v1\/certificate\/([^/]+)$/.exec(pathname);
      if (req.method === "GET" && m) {
        const meta = api.meta?.[m[1]!];
        return meta ? { body: meta } : bceError(404, "ResourceNotFound", "Resource not found.");
      }
      return undefined;
    }
    if (host !== "cdn.baidubce.com") return undefined;
    if (pathname === "/v2/user/domains") return { body: { domains: api.domains ?? [] } };
    if (pathname === "/v2/httpsDomains") {
      const rows = api.httpsRows ?? [];
      return { body: { count: String(rows.length), rows: req.url.searchParams.get("pageNo") === "1" ? rows : [] } };
    }
    const m = /^\/v2\/domain\/([^/]+)\/config$/.exec(pathname);
    if (m && req.url.search === "?https") {
      if (req.method === "PUT") return { body: { status: "RUNNING" } };
      const cfg = api.config?.[m[1]!];
      if (cfg && typeof cfg === "object" && "status" in cfg) return cfg as FakeReply;
      return cfg ? { body: cfg } : bceError(404, "NoSuchDomain", "domain not found");
    }
    return undefined;
  });
}

function ctxOf(fetch: ReturnType<typeof baiduApi>): QueryContext {
  return { env: BAIDU_ENV, fetch, now: NOW, timeoutMs: 1000, sleep: async () => {} };
}

async function deploy(api: Api, opts: Partial<DeployOptions> = {}) {
  const fetch = baiduApi(api);
  const ctx = ctxOf(fetch);
  const plan = await planDeploy(ctx, CERT, { providers: ["baidu"], force: false, dryRun: false, ...opts });
  const report = await executeDeploy(ctx, CERT, plan);
  return { report, fetch, byDomain: Object.fromEntries(report.results.map((r) => [r.domain, r])) };
}

const puts = (fetch: { calls: FakeRequest[] }) => fetch.calls.filter((c) => c.method === "PUT");
const posts = (fetch: { calls: FakeRequest[] }) => fetch.calls.filter((c) => c.method === "POST");

/** 按收到的请求重算签名：路径、参数、Content-Type 都要与签名时一致 */
function expectSigned(req: FakeRequest) {
  const timestamp = req.headers["x-bce-date"]!;
  const headers: Record<string, string> = { host: req.url.host, "x-bce-date": timestamp };
  if (req.headers["content-type"]) headers["content-type"] = req.headers["content-type"];
  const expected = bceAuthorization({
    accessKeyId: CREDS.accessKeyId,
    secretAccessKey: CREDS.secretAccessKey,
    method: req.method,
    path: decodeURIComponent(req.url.pathname),
    query: Object.fromEntries(req.url.searchParams),
    headers,
    timestamp,
  });
  expect(req.headers.authorization).toBe(expected);
}

describe("baidu uploadCertificate", () => {
  const upload = (api: Api, cert: LocalCert = CERT) => {
    const fetch = baiduApi(api);
    return { fetch, result: baidu.uploadCertificate!(ctxOf(fetch), CREDS, cert) };
  };

  it("证书管理里没有同一张证书时上传：叶子、证书链、私钥分开放在 JSON 请求体里", async () => {
    const { fetch, result } = upload({
      certs: [
        detail("cert-other", { certCommonName: "other.org", certDNSNames: "other.org" }),
        // 同 CN、同 SAN，但到期时间差超过 48 小时
        detail("cert-older", { certStopTime: "2026-12-01T00:00:00Z" }),
        // 同 CN、同到期时间，但 SAN 不同
        detail("cert-nowild", { certDNSNames: "example.com" }),
      ],
    });
    await expect(result).resolves.toEqual({ id: NEW_ID, reused: false });
    const post = posts(fetch);
    expect(post).toHaveLength(1);
    expect(post[0]!.url.href).toBe("https://certificate.baidubce.com/v1/certificate");
    expect(post[0]!.json).toEqual({
      certName: "sslbear-example.com-20270101",
      certServerData: LEAF,
      certPrivateData: CERT.keyPem.trim(),
      certLinkData: CA,
      certType: 1,
    });
    expect(post[0]!.headers["content-type"]).toBe("application/json;charset=utf-8");
    expectSigned(post[0]!);
    // 不是候选的证书不查指纹
    expect(fetch.calls.filter((c) => /^\/v1\/certificate\/cert-/.test(c.url.pathname))).toEqual([]);
    for (const c of fetch.calls) expect(c.url.href).not.toContain(encodeURIComponent(KEY_LINE).slice(0, 20));
  });

  it("同 CN、同 SAN（不分大小写和顺序）、到期时间相差 48 小时内且指纹一致时复用，不上传", async () => {
    const { fetch, result } = upload({
      certs: [detail("cert-same", { certCommonName: "Example.com", certDNSNames: "*.EXAMPLE.com,example.com", certStopTime: "2026-12-31T08:00:00Z" })],
      meta: { "cert-same": { certId: "cert-same", certName: "mine", certFingerprint: SHA256 } },
    });
    await expect(result).resolves.toEqual({ id: "cert-same", reused: true });
    expect(posts(fetch)).toEqual([]);
  });

  it("同名同到期的另一张证书（如 ECC 版本）指纹不一致时不复用，取指纹一致的那张（指纹可以是 SHA-1）", async () => {
    const { fetch, result } = upload({
      certs: [detail("cert-ecc"), detail("cert-rsa")],
      meta: { "cert-ecc": { certFingerprint: OTHER_SHA256 }, "cert-rsa": { certFingerprint: SHA1.replace(/:/g, "").toLowerCase() } },
    });
    await expect(result).resolves.toEqual({ id: "cert-rsa", reused: true });
    expect(posts(fetch)).toEqual([]);
  });

  it("候选证书的指纹都不一致时上传新证书", async () => {
    const { fetch, result } = upload({ certs: [detail("cert-ecc")], meta: { "cert-ecc": { certFingerprint: OTHER_SHA256 } } });
    await expect(result).resolves.toEqual({ id: NEW_ID, reused: false });
    expect(posts(fetch)).toHaveLength(1);
  });

  it("接口不给指纹或格式认不出时，按 CN + 到期时间 + SAN 判定为同一张", async () => {
    for (const meta of [{ certId: "cert-same" }, { certFingerprint: "not-a-hex-digest" }]) {
      const { fetch, result } = upload({ certs: [detail("cert-same")], meta: { "cert-same": meta } });
      await expect(result).resolves.toEqual({ id: "cert-same", reused: true });
      expect(posts(fetch)).toEqual([]);
    }
  });

  it("证书名：* 换成 _，不允许的字符换成 _，超长时截断通用名保证不超过 65 个字符", async () => {
    const long: LocalCert = { ...CERT, commonName: `*.${"a".repeat(60)}.example.com` };
    const { fetch, result } = upload({}, long);
    await result;
    const name = posts(fetch)[0]!.json!.certName as string;
    expect(name).toMatch(/^sslbear-_\.a+-20270101$/);
    expect(name).toHaveLength(65);
    expect(name).toMatch(/^[a-zA-Z][a-zA-Z0-9\-/_.]{2,64}$/);

    const odd: LocalCert = { ...CERT, commonName: "例子 test.example.com" };
    const r2 = upload({}, odd);
    await r2.result;
    expect(posts(r2.fetch)[0]!.json!.certName).toBe("sslbear-___test.example.com-20270101");

    // 没有 CN 时用第一个 SAN
    const { commonName: _, ...noCn } = CERT;
    const r3 = upload({}, noCn as LocalCert);
    await r3.result;
    expect(posts(r3.fetch)[0]!.json!.certName).toBe("sslbear-example.com-20270101");
  });

  it("上传失败抛 CloudApiError，错误信息里没有私钥", async () => {
    const { result } = upload({ upload: bceError(400, "PrivateKeyParameterInvalid", "私钥解析异常") });
    const err = await result.catch((e) => e);
    expect(err).toBeInstanceOf(CloudApiError);
    expect(err).toMatchObject({ provider: "baidu", code: "PrivateKeyParameterInvalid", requestId: "rid-err" });
    expect(err.message).not.toContain(KEY_LINE);
  });

  it("上传成功但响应里没有 certId 时报错", async () => {
    const { result } = upload({ upload: { body: {} } });
    await expect(result).rejects.toMatchObject({ code: "InvalidResponse" });
  });
});

describe("baidu CDN 部署", () => {
  const FULL_HTTPS = {
    enabled: true,
    certId: "cert-old",
    httpRedirect: true,
    httpRedirectCode: 301,
    httpsRedirect: false,
    noRedirectedUAs: ["spider"],
    http2Enabled: false,
    verifyClient: false,
    sslProtocols: ["TLSv1.2", "TLSv1.3"],
  };

  it("更新：先读 HTTPS 配置，只换 certId，跳转 / HTTP2 / TLS 版本等其他配置原样写回", async () => {
    const { report, fetch, byDomain } = await deploy({
      domains: [{ domain: "www.example.com", status: "RUNNING" }],
      httpsRows: [{ domain: "www.example.com", certId: "cert-old", certName: "old", certStartTime: "2026-01-01T00:00:00Z", certStopTime: DUE, certType: 1, status: 1 }],
      config: { "www.example.com": { https: FULL_HTTPS } },
    });
    expect(byDomain["www.example.com"]).toMatchObject({ action: "updated", after: { id: NEW_ID, notAfter: CERT.notAfter } });
    expect(report.uploads).toEqual([{ provider: "baidu", certId: NEW_ID, reused: false }]);
    const put = puts(fetch);
    expect(put).toHaveLength(1);
    expect(put[0]!.url.href).toBe("https://cdn.baidubce.com/v2/domain/www.example.com/config?https");
    expect(put[0]!.json).toEqual({ https: { ...FULL_HTTPS, certId: NEW_ID } });
    expect(put[0]!.headers["content-type"]).toBe("application/json;charset=utf-8");
    expectSigned(put[0]!);
    // 先读后写
    const order = fetch.calls.filter((c) => c.url.pathname === "/v2/domain/www.example.com/config").map((c) => c.method);
    expect(order).toEqual(["GET", "PUT"]);
  });

  it("读回的配置里值为 null 的字段、空的 TLS 版本列表不写回", async () => {
    const { fetch } = await deploy({
      domains: [{ domain: "www.example.com", status: "RUNNING" }],
      httpsRows: [{ domain: "www.example.com", certId: "cert-old", certStopTime: DUE, certType: 1, status: 1 }],
      config: { "www.example.com": { https: { enabled: true, certId: "cert-old", httpRedirect: false, httpRedirectCode: null, sslProtocols: [] } } },
    });
    expect(puts(fetch)[0]!.json).toEqual({ https: { enabled: true, certId: NEW_ID, httpRedirect: false } });
  });

  it("部署：点名的未开启 HTTPS 域名开启 HTTPS 并绑定新证书（关闭时仍绑着的旧证书一并换掉），未点名的不动", async () => {
    const off = { enabled: false, certId: "cert-old", httpRedirect: false, httpsRedirect: false, http2Enabled: true, verifyClient: false };
    const { fetch, byDomain } = await deploy(
      {
        domains: [
          { domain: "bound-off.example.com", status: "RUNNING" },
          { domain: "off.example.com", status: "RUNNING" },
        ],
        httpsRows: [],
        config: { "bound-off.example.com": { https: off }, "off.example.com": { https: { enabled: false } } },
      },
      { domains: ["bound-off.example.com"] },
    );
    expect(byDomain["bound-off.example.com"]).toMatchObject({ action: "deployed", after: { id: NEW_ID } });
    expect(byDomain["off.example.com"]).toBeUndefined();
    const put = puts(fetch);
    expect(put).toHaveLength(1);
    expect(put[0]!.url.pathname).toBe("/v2/domain/bound-off.example.com/config");
    expect(put[0]!.json).toEqual({ https: { ...off, enabled: true, certId: NEW_ID } });
  });

  it("未点名的未开启 HTTPS 域名跳过（https_off），不上传证书", async () => {
    const { fetch, byDomain } = await deploy({ domains: [{ domain: "off.example.com", status: "RUNNING" }], httpsRows: [] });
    expect(byDomain["off.example.com"]).toMatchObject({ action: "skipped", reason: "https_off" });
    expect(puts(fetch)).toEqual([]);
    expect(posts(fetch)).toEqual([]);
  });

  it("更新时读到 HTTPS 已被关闭则不写入，记为失败（不能悄悄开启 HTTPS）", async () => {
    const { fetch, byDomain } = await deploy({
      domains: [{ domain: "www.example.com", status: "RUNNING" }],
      httpsRows: [{ domain: "www.example.com", certId: "cert-old", certStopTime: DUE, certType: 1, status: 1 }],
      config: { "www.example.com": { https: { ...FULL_HTTPS, enabled: false } } },
    });
    expect(byDomain["www.example.com"]).toMatchObject({ action: "failed", code: "HttpsDisabled", retryable: false });
    expect(puts(fetch)).toEqual([]);
  });

  it("写配置失败记为 failed，带错误码与 RequestId", async () => {
    const fetch = baiduApi({
      domains: [{ domain: "www.example.com", status: "RUNNING" }],
      httpsRows: [{ domain: "www.example.com", certId: "cert-old", certStopTime: DUE, certType: 1, status: 1 }],
      config: { "www.example.com": { https: FULL_HTTPS } },
    });
    const failing = Object.assign(
      (async (input: string | URL | Request, init?: RequestInit) => {
        if (init?.method === "PUT") return new Response(JSON.stringify({ code: "InvalidArgument", message: "bad cert", requestId: "rid-put" }), { status: 400 });
        return fetch(input, init);
      }) as typeof fetch,
      { calls: fetch.calls },
    );
    const ctx = ctxOf(failing);
    const plan = await planDeploy(ctx, CERT, { providers: ["baidu"], force: false, dryRun: false });
    const report = await executeDeploy(ctx, CERT, plan);
    expect(report.results).toEqual([
      expect.objectContaining({ domain: "www.example.com", action: "failed", code: "InvalidArgument", requestId: "rid-put", retryable: false }),
    ]);
  });

  describe("国际证书 + 国密证书", () => {
    const api = (config: unknown): Api => ({
      domains: [{ domain: "www.example.com", status: "RUNNING" }],
      httpsRows: [
        { domain: "www.example.com", certId: "cert-intl", certName: "intl", certStartTime: "2026-01-01T00:00:00Z", certStopTime: LATER, certType: 1, status: 1 },
        { domain: "www.example.com", certId: "cert-sm2", certName: "sm2", certStartTime: "2026-01-01T00:00:00Z", certStopTime: DUE, certType: 1, status: 1 },
      ],
      config: { "www.example.com": config },
    });

    it("查询层：HTTPS 配置里绑定的是国际证书，其余标为国密（SM2），certs 列出全部", async () => {
      const fetch = baiduApi(api({ https: { ...FULL_HTTPS, certId: "cert-intl" } }));
      const r = await queryDomains(ctxOf(fetch), { providers: ["baidu"] });
      expect(r.issues).toEqual([]);
      expect(r.items[0]).toMatchObject({
        domain: "www.example.com",
        https: true,
        cert: { id: "cert-sm2", algorithm: "SM2" },
        certs: [{ id: "cert-intl", notAfter: "2026-12-01T00:00:00.000Z" }, { id: "cert-sm2", algorithm: "SM2" }],
      });
      expect(r.items[0]!.certs![0]!.algorithm).toBeUndefined();
    });

    it("按国际证书的到期时间决策：国密证书快到期也不触发更新", async () => {
      const { fetch, byDomain } = await deploy(api({ https: { ...FULL_HTTPS, certId: "cert-intl" } }));
      expect(byDomain["www.example.com"]).toMatchObject({ action: "skipped", reason: "not_due", needsConfirm: true, before: { id: "cert-intl", daysLeft: 47 } });
      expect(puts(fetch)).toEqual([]);
    });

    it("--force 时只换 HTTPS 配置里的国际证书，国密配置不碰", async () => {
      const { fetch, byDomain } = await deploy(api({ https: { ...FULL_HTTPS, certId: "cert-intl" } }), { force: true });
      expect(byDomain["www.example.com"]).toMatchObject({ action: "updated", before: { id: "cert-intl" } });
      const put = puts(fetch);
      expect(put).toHaveLength(1);
      expect(put[0]!.json).toEqual({ https: { ...FULL_HTTPS, certId: NEW_ID } });
    });

    it("查不到 HTTPS 配置、无法区分哪张是国密证书时记 issue，该域名不处理（unsupported）", async () => {
      const { report, fetch, byDomain } = await deploy(api(bceError(500, "InternalError", "internal error")), { force: true });
      expect(report.issues).toEqual([expect.objectContaining({ provider: "baidu", service: "cdn", code: "InternalError", target: "domain www.example.com HTTPS 配置（用于区分国密证书）" })]);
      expect(byDomain["www.example.com"]).toMatchObject({ action: "skipped", reason: "unsupported" });
      expect(byDomain["www.example.com"]!.message).toContain("国密");
      expect(puts(fetch)).toEqual([]);
    });
  });
});
