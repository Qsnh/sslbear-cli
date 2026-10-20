import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { loadLocalCert, type LocalCert } from "../src/deploy/cert.js";
import { executeDeploy, planDeploy } from "../src/deploy/run.js";
import type { AccessKeyCredentials } from "../src/lib/env.js";
import { CloudApiError, type QueryContext } from "../src/lib/http.js";
import { xmlText } from "../src/lib/xml.js";
import { cdn } from "../src/providers/huawei/cdn.js";
import { certName } from "../src/providers/huawei/common.js";
import { huawei } from "../src/providers/huawei/index.js";
import { live } from "../src/providers/huawei/live.js";
import { obs } from "../src/providers/huawei/obs.js";
import { apigAuthorization, obsAuthorization, obsStringToSign } from "../src/providers/huawei/sign.js";
import type { DeployInput, Warn } from "../src/providers/registry.js";
import type { DomainRecord } from "../src/types.js";
import { fakeFetch, type FakeReply, type FakeRequest } from "./helpers.js";

const FIX = fileURLToPath(new URL("./fixtures/deploy/", import.meta.url));
const NOW = new Date("2026-10-15T00:00:00Z");
/** RSA 叶子 + 测试 CA，SAN example.com / *.example.com，2026-01-01 ~ 2027-01-01 */
const CERT = loadLocalCert(readFileSync(join(FIX, "rsa-fullchain.pem"), "utf8"), readFileSync(join(FIX, "rsa-key.pem"), "utf8"), NOW);
const [LEAF, CA] = CERT.certPem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)!;
/** 叶子证书 DER 的 SHA-1（华为 SCM 证书详情里的 fingerprint 格式：40 位小写十六进制） */
const SHA1 = "615ddd5906497891d0f54186e4f7724befd7fdb2";
const NAME = "sslbear-example.com-20270101";

/** 旧证书：ECC，CN=static.example.cn，2026-10-30T12:00Z 到期（剩 15 天） */
const OLD_ECC_PEM = `-----BEGIN CERTIFICATE-----
MIIBuTCCAV6gAwIBAgICA+kwCgYIKoZIzj0EAwIwPjELMAkGA1UEBhMCQ04xFTAT
BgNVBAoMDFNTTEJlYXIgVGVzdDEYMBYGA1UEAwwPU1NMQmVhciBUZXN0IENBMB4X
DTI2MDgwMTAwMDAwMFoXDTI2MTAzMDEyMDAwMFowHDEaMBgGA1UEAwwRc3RhdGlj
LmV4YW1wbGUuY24wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATYB6OAhcBEGYiJ
rW+CS7q+wpkDKMW5fPzLj4Iz9Dif7Wfqb4tET8E7/+jeMHi7PDnL7LnjfeJ5RKUT
aVEJbOdOo24wbDAqBgNVHREEIzAhghFzdGF0aWMuZXhhbXBsZS5jboIMKi5leGFt
cGxlLmNuMB0GA1UdDgQWBBQxnR5IJlOtoG0zm5H4Jkelr5ba8DAfBgNVHSMEGDAW
gBSD/qY8HtmVcak93hHepeRXj/yIejAKBggqhkjOPQQDAgNJADBGAiEApFVJ983b
Oja9jZZrd3EPQ0E8HR14OSgzTWsnqv2F/eYCIQCPKYysKoQF+ZnDAVNspTubMzl+
FVpsdHx69n1p/1krsA==
-----END CERTIFICATE-----`;

const HUAWEI_ENV = { HUAWEICLOUD_SDK_AK: "HWtestak000000000000", HUAWEICLOUD_SDK_SK: "testsk" };
const CREDS: AccessKeyCredentials = { accessKeyId: HUAWEI_ENV.HUAWEICLOUD_SDK_AK, secretAccessKey: HUAWEI_ENV.HUAWEICLOUD_SDK_SK };

const SCM_HOST = "scm.cn-north-4.myhuaweicloud.com";
const CDN_HOST = "cdn.myhuaweicloud.com";
const LIVE_HOST = "live.cn-north-4.myhuaweicloud.com";

function ctxOf(route: (req: FakeRequest) => FakeReply) {
  const fetch = fakeFetch(route);
  const ctx: QueryContext = { env: HUAWEI_ENV, fetch, now: NOW, timeoutMs: 1000, sleep: async () => {} };
  return { ctx, fetch };
}

/** 不需要上传证书的服务调用 certId() 即视为错误 */
function pemOnly(): DeployInput & { certId: ReturnType<typeof vi.fn> } {
  return { cert: CERT, certId: vi.fn(async () => Promise.reject(new Error("不应上传证书"))) };
}

function viaScm(id = "scs-new"): DeployInput & { certId: ReturnType<typeof vi.fn> } {
  return { cert: CERT, certId: vi.fn(async () => id) };
}

/** CCM 导入没有 CN、只有 SAN 的证书（如 Let's Encrypt 短期证书）时的真实报错：HTTP 400 SCM.0009 */
const scmNoDomain = () => new CloudApiError("huawei", "SCM.0009", "No domain name is bonded with the certificate. Failed to upload the certificate.", undefined, 400);

/** 上传到 CCM 失败 */
function scmRejects(error: Error = scmNoDomain()): DeployInput & { certId: ReturnType<typeof vi.fn> } {
  return { cert: CERT, certId: vi.fn(async () => Promise.reject(error)) };
}

const apigError = (status: number, code: string, msg: string) => ({ status, body: { error_code: code, error_msg: msg, request_id: `rid-${code}` } });
const noWarn: Warn = (e) => {
  throw e;
};

/** 按实际发出的请求重算 API 网关签名（含请求体） */
function expectApigSigned(call: FakeRequest, extraHeaders: Record<string, string> = {}) {
  expect(call.headers.authorization).toBe(
    apigAuthorization({
      accessKeyId: CREDS.accessKeyId,
      secretAccessKey: CREDS.secretAccessKey,
      method: call.method,
      path: decodeURIComponent(call.url.pathname),
      query: Object.fromEntries(call.url.searchParams),
      headers: { Host: call.url.host, "X-Sdk-Date": call.headers["x-sdk-date"]!, ...extraHeaders },
      body: call.body,
    }),
  );
}

function expectNoKeyInUrl(calls: FakeRequest[]) {
  const keyLine = CERT.keyPem.split("\n")[1]!;
  for (const c of calls) {
    expect(c.url.href).not.toContain("PRIVATE");
    expect(decodeURIComponent(c.url.href)).not.toContain(keyLine);
  }
}

describe("huawei 证书命名", () => {
  const cert = (o: Partial<LocalCert>) => ({ ...CERT, ...o }) as LocalCert;

  it("sslbear-<CN>-<到期日>，* 换成 _，其余不允许的字符换成 _", () => {
    expect(certName(CERT)).toBe(NAME);
    expect(certName(cert({ commonName: "*.Example.com" }))).toBe("sslbear-_.Example.com-20270101");
    expect(certName(cert({ commonName: "a b/c.example.com" }))).toBe("sslbear-a_b_c.example.com-20270101");
  });

  it("没有 CN 时取第一个 SAN；超长时截断 CN 部分，总长不超过 63", () => {
    expect(certName(cert({ commonName: undefined, sans: ["*.a.example.com", "a.example.com"] }))).toBe("sslbear-_.a.example.com-20270101");
    const long = certName(cert({ commonName: `${"x".repeat(80)}.example.com` }));
    expect(long).toHaveLength(63);
    expect(long).toMatch(/^sslbear-x+-20270101$/);
  });
});

describe("huawei uploadCertificate（云证书管理服务 CCM / SCM）", () => {
  const listed = [
    // 同名但到期时间不同：不是同一张
    { id: "scs0000000000001", name: "old", domain: "example.com", sans: "*.example.com", expire_time: "2026-06-01 08:00:00.0", status: "UPLOAD" },
    // CN / SAN / 到期时间（北京时间）都相同，但指纹不同：换了私钥重签的另一张
    { id: "scs0000000000002", name: "rekeyed", domain: "example.com", sans: "*.example.com", expire_time: "2027-01-01 08:00:00.0", status: "UPLOAD" },
    { id: "scs0000000000003", name: "same", domain: "example.com", sans: "*.example.com", expire_time: "2027-01-01 08:00:00.0", status: "UPLOAD" },
    // SAN 不同
    { id: "scs0000000000004", name: "fewer", domain: "example.com", sans: null, expire_time: "2027-01-01 08:00:00.0", status: "UPLOAD" },
    { id: "scs0000000000005", name: "more", domain: "www.example.com", sans: "example.com;*.example.com", expire_time: "2027-01-01 08:00:00.0", status: "ISSUED" },
  ];

  function scm(certificates: unknown[], details: Record<string, unknown> = {}, onImport?: (req: FakeRequest) => FakeReply) {
    return (req: FakeRequest): FakeReply => {
      if (req.url.host !== SCM_HOST) return undefined;
      if (req.method === "GET" && req.url.pathname === "/v3/scm/certificates") return { body: { total_count: certificates.length, certificates } };
      const detail = /^\/v3\/scm\/certificates\/(scs\d+)$/.exec(req.url.pathname)?.[1];
      if (req.method === "GET" && detail && details[detail]) return { body: details[detail] };
      if (req.method === "POST" && req.url.pathname === "/v3/scm/certificates/import") return onImport?.(req);
      return undefined;
    };
  }

  it("查重命中：CN、SAN、到期时间都相同的候选再按证书详情的 SHA-1 指纹确认，复用指纹相同的那张、不上传", async () => {
    const { ctx, fetch } = ctxOf(
      scm(listed, {
        scs0000000000002: { id: "scs0000000000002", fingerprint: "1111111111111111111111111111111111111111" },
        scs0000000000003: { id: "scs0000000000003", fingerprint: SHA1.toUpperCase() },
      }),
    );
    await expect(huawei.uploadCertificate!(ctx, CREDS, CERT)).resolves.toEqual({ id: "scs0000000000003", reused: true });
    expect(fetch.calls.map((c) => `${c.method} ${c.url.pathname}`)).toEqual([
      "GET /v3/scm/certificates",
      "GET /v3/scm/certificates/scs0000000000002",
      "GET /v3/scm/certificates/scs0000000000003",
    ]);
  });

  it("证书详情没有指纹、或指纹格式认不出时按不是同一张处理，照常导入（同 CN、同 SAN、到期只差几秒的另一张证书不能复用）", async () => {
    for (const detail of [{ id: "scs0000000000003" }, { id: "scs0000000000003", fingerprint: null }, { id: "scs0000000000003", fingerprint: "" }, { id: "scs0000000000003", fingerprint: "sha1:unknown" }]) {
      const { ctx, fetch } = ctxOf(
        scm([{ ...listed[2], expire_time: "2027-01-01 08:00:05.0" }], { scs0000000000003: detail }, () => ({ body: { certificate_id: "scs1600313391074" } })),
      );
      await expect(huawei.uploadCertificate!(ctx, CREDS, CERT)).resolves.toEqual({ id: "scs1600313391074", reused: false });
      expect(fetch.calls.filter((c) => c.method === "POST")).toHaveLength(1);
    }
  });

  it("详情给的是 SHA-256 指纹（64 位十六进制）时按 SHA-256 比对", async () => {
    const same = ctxOf(scm([listed[2]], { scs0000000000003: { fingerprint: CERT.fingerprint.toUpperCase().replace(/(..)(?!$)/g, "$1:") } }));
    await expect(huawei.uploadCertificate!(same.ctx, CREDS, CERT)).resolves.toEqual({ id: "scs0000000000003", reused: true });
    const other = ctxOf(scm([listed[2]], { scs0000000000003: { fingerprint: "a".repeat(64) } }, () => ({ body: { certificate_id: "scs1600313391074" } })));
    await expect(huawei.uploadCertificate!(other.ctx, CREDS, CERT)).resolves.toEqual({ id: "scs1600313391074", reused: false });
  });

  /** 模拟请求超时：服务端可能已经处理了这次请求 */
  const timeout = (): never => {
    throw Object.assign(new Error("The operation was aborted due to timeout"), { name: "TimeoutError" });
  };
  const call = (c: FakeRequest) => `${c.method} ${c.url.pathname}`;

  it("导入超时（服务端其实已导入成功）：导入请求不原样重发，下一轮重新拉列表查重，查到即复用", async () => {
    const stored: unknown[] = [];
    const { ctx, fetch } = ctxOf(
      scm(stored, { scs1600313391074: { id: "scs1600313391074", fingerprint: SHA1 } }, () => {
        stored.push({ id: "scs1600313391074", name: NAME, domain: "example.com", sans: "*.example.com", expire_time: "2027-01-01 08:00:00.0", status: "UPLOAD" });
        return timeout();
      }),
    );
    await expect(huawei.uploadCertificate!(ctx, CREDS, CERT)).resolves.toEqual({ id: "scs1600313391074", reused: true });
    expect(fetch.calls.map(call)).toEqual([
      "GET /v3/scm/certificates",
      "POST /v3/scm/certificates/import",
      "GET /v3/scm/certificates",
      "GET /v3/scm/certificates/scs1600313391074",
    ]);
  });

  it("导入一直限流：每轮先重新查重再导入一次，最多 3 轮", async () => {
    const { ctx, fetch } = ctxOf(scm([], {}, () => apigError(429, "APIGW.0308", "The throttling threshold has been reached")));
    await expect(huawei.uploadCertificate!(ctx, CREDS, CERT)).rejects.toMatchObject({ code: "APIGW.0308" });
    expect(fetch.calls.map(call)).toEqual(Array.from({ length: 3 }, () => ["GET /v3/scm/certificates", "POST /v3/scm/certificates/import"]).flat());
  });

  it("查重不用缓存：同一次命令里已拉过证书列表，上传前仍重新拉取", async () => {
    const stored: unknown[] = [];
    const { ctx, fetch } = ctxOf(scm(stored, { scs0000000000003: { fingerprint: SHA1 } }, () => ({ body: { certificate_id: "scs1600313391074" } })));
    await expect(huawei.listCertificates(ctx, CREDS)).resolves.toEqual([]);
    stored.push(listed[2]);
    await expect(huawei.uploadCertificate!(ctx, CREDS, CERT)).resolves.toEqual({ id: "scs0000000000003", reused: true });
    expect(fetch.calls.map(call)).toEqual(["GET /v3/scm/certificates", "GET /v3/scm/certificates", "GET /v3/scm/certificates/scs0000000000003"]);
  });

  it("查重未命中：POST 导入，叶子证书与证书链分开传，私钥只在请求体里，请求体参与签名", async () => {
    const { ctx, fetch } = ctxOf(
      scm(listed, { scs0000000000002: { fingerprint: "1111111111111111111111111111111111111111" }, scs0000000000003: { fingerprint: "2222222222222222222222222222222222222222" } }, () => ({
        body: { certificate_id: "scs1600313391074" },
      })),
    );
    await expect(huawei.uploadCertificate!(ctx, { ...CREDS, securityToken: "tok" }, CERT)).resolves.toEqual({ id: "scs1600313391074", reused: false });
    const post = fetch.calls.find((c) => c.method === "POST")!;
    expect(post.url.href).toBe(`https://${SCM_HOST}/v3/scm/certificates/import`);
    expect(post.json).toEqual({ name: NAME, certificate: `${LEAF}\n`, certificate_chain: `${CA}\n`, private_key: CERT.keyPem, duplicate_check: false });
    expect(post.headers["content-type"]).toBe("application/json");
    expect(post.headers.authorization).toMatch(/SignedHeaders=host;x-sdk-date;x-security-token,/);
    expectApigSigned(post, { "X-Security-Token": "tok" });
    expectNoKeyInUrl(fetch.calls);
  });

  it("导入失败抛 CloudApiError（错误码、RequestId），不可重试的错误不再重来，错误信息里没有私钥", async () => {
    const { ctx, fetch } = ctxOf(scm([], {}, () => apigError(400, "SCM.0016", "Certificate content is invalid.")));
    const err = await huawei.uploadCertificate!(ctx, CREDS, CERT).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CloudApiError);
    expect(err).toMatchObject({ code: "SCM.0016", requestId: "rid-SCM.0016" });
    expect(fetch.calls.filter((c) => c.method === "POST")).toHaveLength(1);
    expect(String((err as Error).message)).not.toContain("PRIVATE KEY");
  });

  it("导入成功但没返回证书 ID 时报错", async () => {
    const { ctx } = ctxOf(scm([], {}, () => ({ body: {} })));
    await expect(huawei.uploadCertificate!(ctx, CREDS, CERT)).rejects.toMatchObject({ code: "InvalidResponse" });
  });
});

const cdnRecord = (r: Partial<DomainRecord> = {}): DomainRecord => ({
  provider: "huawei",
  service: "cdn",
  domain: "www.example.com",
  https: true,
  cert: { name: "old", notAfter: "2026-10-30T12:00:00.000Z" },
  ...r,
});

function cdnRoute(https: Record<string, unknown>, domain = "www.example.com") {
  return (req: FakeRequest): FakeReply => {
    if (req.url.host !== CDN_HOST || req.url.pathname !== `/v1.1/cdn/configuration/domains/${domain}/configs`) return undefined;
    if (req.method === "GET") {
      return { body: { configs: { business_type: "web", https, force_redirect: { status: "on", type: "https", redirect_code: 301 }, hsts: { status: "on", max_age: 63072000 } } } };
    }
    // 真实接口为 204 无响应体
    if (req.method === "PUT") return { body: "" };
    return undefined;
  };
}

const newIntl = { certificate_type: "server", certificate_source: 0, certificate_name: NAME, certificate_value: CERT.certPem, private_key: CERT.keyPem };

describe("huawei cdn deployer", () => {
  it("update：先读全量配置，只改 https 里的证书字段，HTTP/2、TLS 版本、OCSP 原样带回，强制跳转 / HSTS 不发送；直接传 PEM，不上传证书", async () => {
    const { ctx, fetch } = ctxOf(
      cdnRoute({
        https_status: "on",
        certificate_type: "server",
        certificate_source: 0,
        certificate_name: "old",
        certificate_value: OLD_ECC_PEM,
        expire_time: Date.parse("2026-10-30T12:00:00Z"),
        http2_status: "on",
        tls_version: "TLSv1.2,TLSv1.3",
        ocsp_stapling_status: "on",
      }),
    );
    const input = pemOnly();
    await expect(cdn.deployer!.apply(ctx, CREDS, { records: [cdnRecord()], mode: "update" }, input)).resolves.toEqual({});
    expect(input.certId).not.toHaveBeenCalled();
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET", "PUT"]);
    for (const c of fetch.calls) expect(Object.fromEntries(c.url.searchParams)).toEqual({ enterprise_project_id: "all" });
    const put = fetch.calls[1]!;
    expect(put.json).toEqual({
      configs: {
        https: { https_status: "on", http2_status: "on", tls_version: "TLSv1.2,TLSv1.3", ocsp_stapling_status: "on", ...newIntl },
      },
    });
    expectApigSigned(put);
    expectNoKeyInUrl(fetch.calls);
  });

  it("无权限（CDN.0004，原文带授权项）时报错写出缺少的 IAM 权限与系统策略", async () => {
    const action = "cdn:configuration:modifyHttpsConf";
    const msg = `User: iam::0000:user:dev is not authorized to perform: ${action} on resource: cdn::0000:domain:www.example.com because no identity-based policy allows the ${action} action.`;
    const { ctx } = ctxOf((req) =>
      req.method === "PUT" ? { status: 403, body: { error: { error_code: "CDN.0004", error_msg: msg } } } : cdnRoute({ https_status: "on", certificate_type: "server" })(req),
    );
    await expect(cdn.deployer!.apply(ctx, CREDS, { records: [cdnRecord()], mode: "update" }, pemOnly())).rejects.toMatchObject({
      code: "CDN.0004",
      message: `${msg}（缺少 IAM 权限 ${action}，可授予系统策略 CDNDomainConfigurationPolicy，旧版 IAM 授予 CDN DomainConfiguration）`,
    });
  });

  it("deploy：原先未开启 HTTPS，开启并配置国际证书（读不到的 HTTPS 子项不发送）", async () => {
    const { ctx, fetch } = ctxOf(cdnRoute({ https_status: "off" }));
    await cdn.deployer!.apply(ctx, CREDS, { records: [cdnRecord({ https: false, cert: undefined })], mode: "deploy" }, pemOnly());
    expect(fetch.calls[1]!.json).toEqual({ configs: { https: { https_status: "on", ...newIntl } } });
  });

  it("双证书：保留 CCM 托管的国密证书，用 certificates 同时传新国际证书与原国密证书", async () => {
    const { ctx, fetch } = ctxOf(
      cdnRoute({
        https_status: "on",
        certificate_type: "server",
        certificate_source: 0,
        certificate_name: "old",
        certificate_value: OLD_ECC_PEM,
        http2_status: "off",
        tls_version: "TLSv1.2",
        certificates: [
          { certificate_type: "server", certificate_source: 0, certificate_name: "old", certificate_value: OLD_ECC_PEM, expire_time: 1 },
          { certificate_type: "server_sm", certificate_source: 2, scm_certificate_id: "scs0000000000099", certificate_name: "gm", certificate_value: "", enc_certificate_value: "", expire_time: 2 },
        ],
      }),
    );
    await cdn.deployer!.apply(ctx, CREDS, { records: [cdnRecord()], mode: "update" }, pemOnly());
    expect(fetch.calls[1]!.json).toEqual({
      configs: {
        https: {
          https_status: "on",
          http2_status: "off",
          tls_version: "TLSv1.2",
          certificates: [newIntl, { certificate_type: "server_sm", certificate_source: 2, scm_certificate_id: "scs0000000000099", certificate_name: "gm" }],
        },
      },
    });
  });

  it("国密证书是自有上传的（读不到私钥，无法保留）：不写入，报错", async () => {
    const { ctx, fetch } = ctxOf(
      cdnRoute({
        https_status: "on",
        certificates: [
          { certificate_type: "server", certificate_source: 0, certificate_name: "old", certificate_value: OLD_ECC_PEM },
          { certificate_type: "server_sm", certificate_source: 0, certificate_name: "gm", certificate_value: "-----BEGIN CERTIFICATE-----" },
        ],
      }),
    );
    await expect(cdn.deployer!.apply(ctx, CREDS, { records: [cdnRecord()], mode: "update" }, pemOnly())).rejects.toMatchObject({ code: "SmCertNotPreservable" });
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET"]);
  });

  it("双证书：读回的 CCM 国密证书没有证书名称时不写入（不省掉该字段），报错说明原因", async () => {
    for (const name of [{}, { certificate_name: "" }, { certificate_name: null }]) {
      const { ctx, fetch } = ctxOf(
        cdnRoute({
          https_status: "on",
          certificates: [
            { certificate_type: "server", certificate_source: 0, certificate_name: "old", certificate_value: OLD_ECC_PEM },
            { certificate_type: "server_sm", certificate_source: 2, scm_certificate_id: "scs0000000000099", ...name },
          ],
        }),
      );
      const err = await cdn.deployer!.apply(ctx, CREDS, { records: [cdnRecord()], mode: "update" }, pemOnly()).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(CloudApiError);
      expect(err).toMatchObject({ code: "SmCertNotPreservable", message: expect.stringContaining("没有证书名称") });
      expect((err as Error).message).toContain("scs0000000000099");
      expect(fetch.calls.map((c) => c.method)).toEqual(["GET"]);
    }
  });

  it("deploy 模式：读到 HTTPS 其实已开启（与查询时不同）时不写入，报 HttpsAlreadyEnabled", async () => {
    const { ctx, fetch } = ctxOf(cdnRoute({ https_status: "on", certificate_type: "server", certificate_source: 0, certificate_name: "old", certificate_value: OLD_ECC_PEM }));
    await expect(cdn.deployer!.apply(ctx, CREDS, { records: [cdnRecord({ https: false, cert: undefined })], mode: "deploy" }, pemOnly())).rejects.toMatchObject({
      code: "HttpsAlreadyEnabled",
      message: "该域名的 HTTPS 已开启（与查询时不同），未做修改；请重新执行，按更新规则判断",
    });
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET"]);
  });

  it("update 模式：读到 HTTPS 已关闭（与查询时不同）时不写入，报 HttpsDisabled，不会把 HTTPS 重新打开", async () => {
    const { ctx, fetch } = ctxOf(cdnRoute({ https_status: "off", certificate_name: "stale" }));
    await expect(cdn.deployer!.apply(ctx, CREDS, { records: [cdnRecord()], mode: "update" }, pemOnly())).rejects.toMatchObject({ code: "HttpsDisabled" });
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET"]);
  });

  it("deploy 模式：配置里没有 https 或 https_status 为 off 时照常开启", async () => {
    for (const configs of [{}, { https: null }, { https: {} }, { https: { https_status: "off", certificate_name: "stale" } }]) {
      const { ctx, fetch } = ctxOf((req) => (req.method === "GET" ? { body: { configs } } : { body: "" }));
      await cdn.deployer!.apply(ctx, CREDS, { records: [cdnRecord({ https: false, cert: undefined })], mode: "deploy" }, pemOnly());
      expect(fetch.calls.map((c) => c.method)).toEqual(["GET", "PUT"]);
    }
  });

  it("unsupported：查询时已知国密证书为自有上传的域名不更新；其余支持", () => {
    const u = cdn.deployer!.unsupported!;
    expect(u(cdnRecord({ extra: { smCertSource: "user" } }), "update")).toContain("国密");
    expect(u(cdnRecord({ extra: { smCertSource: "scm" } }), "update")).toBeUndefined();
    expect(u(cdnRecord(), "update")).toBeUndefined();
    expect(u(cdnRecord({ https: false }), "deploy")).toBeUndefined();
  });

  it("泛域名：路径里的 * 按签名规则编码为 %2A", async () => {
    const { ctx, fetch } = ctxOf((req) => {
      if (req.url.pathname !== "/v1.1/cdn/configuration/domains/%2A.example.com/configs") return undefined;
      return req.method === "GET" ? { body: { configs: { https: { https_status: "on" } } } } : { body: "" };
    });
    await cdn.deployer!.apply(ctx, CREDS, { records: [cdnRecord({ domain: "*.example.com" })], mode: "update" }, pemOnly());
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET", "PUT"]);
    for (const c of fetch.calls) expectApigSigned(c);
  });

  it("写接口业务错误（HTTP 200 + {error}）抛 CloudApiError", async () => {
    const { ctx } = ctxOf((req) => {
      if (req.method === "GET") return cdnRoute({ https_status: "on" })(req);
      return { body: { error: { error_code: "CDN.0163", error_msg: "The certificate is invalid." } } };
    });
    await expect(cdn.deployer!.apply(ctx, CREDS, { records: [cdnRecord()], mode: "update" }, pemOnly())).rejects.toMatchObject({ code: "CDN.0163" });
  });
});

describe("huawei cdn 查询：双证书", () => {
  const route = (req: FakeRequest): FakeReply => {
    if (req.url.host !== CDN_HOST) return undefined;
    if (req.url.pathname === "/v1.0/cdn/domains") {
      return { body: { total: 1, domains: [{ domain_name: "www.example.com", domain_status: "online", business_type: "web", service_area: "mainland_china", https_status: 3 }] } };
    }
    if (req.url.pathname === "/v1.0/cdn/domains/https-certificate-info") {
      return {
        body: {
          total: 1,
          https: [
            {
              domain_name: "www.example.com",
              cert_name: "gm",
              certificate_type: 2,
              https_status: 3,
              certificates: [
                { certificate_type: "server", certificate_source: 0, certificate_name: "old-ecc", certificate_value: OLD_ECC_PEM, expire_time: Date.parse("2026-10-30T12:00:00Z") },
                // 国密证书先到期，域名的 cert 是它；新证书要换的是国际证书
                { certificate_type: "server_sm", certificate_source: 2, certificate_name: "gm", certificate_value: "", expire_time: Date.parse("2026-10-20T00:00:00Z") },
              ],
            },
          ],
        },
      };
    }
    if (req.url.pathname === "/v1.1/cdn/configuration/domains/www.example.com/configs") {
      return cdnRoute({
        https_status: "on",
        certificates: [
          { certificate_type: "server", certificate_source: 0, certificate_name: "old-ecc", certificate_value: OLD_ECC_PEM },
          { certificate_type: "server_sm", certificate_source: 2, scm_certificate_id: "scs0000000000099", certificate_name: "gm" },
        ],
      })(req);
    }
    return undefined;
  };

  it("list 给出全部证书（国际在前）并标注算法，国密证书来源记在 extra.smCertSource", async () => {
    const { ctx } = ctxOf(route);
    const [rec] = await cdn.list(ctx, CREDS, noWarn);
    expect(rec).toMatchObject({
      https: true,
      cert: { name: "gm", notAfter: "2026-10-20T00:00:00.000Z", algorithm: "SM2" },
      certs: [
        { name: "old-ecc", commonName: "static.example.cn", notAfter: "2026-10-30T12:00:00.000Z", algorithm: "ECC" },
        { name: "gm", notAfter: "2026-10-20T00:00:00.000Z", algorithm: "SM2" },
      ],
      extra: { certSource: "scm", smCertSource: "scm" },
    });
  });

  it("planDeploy + executeDeploy：按国际证书的到期时间决定更新，国密证书保留", async () => {
    const { ctx, fetch } = ctxOf(route);
    const plan = await planDeploy(ctx, CERT, { providers: ["huawei"], services: ["cdn"], force: false, dryRun: false });
    const report = await executeDeploy(ctx, CERT, plan);
    expect(report.results).toEqual([
      expect.objectContaining({ provider: "huawei", service: "cdn", domain: "www.example.com", action: "updated", before: expect.objectContaining({ name: "old-ecc", daysLeft: 15 }) }),
    ]);
    expect(report.uploads).toEqual([]);
    const put = fetch.calls.find((c) => c.method === "PUT")!;
    expect((put.json as any).configs.https.certificates[1]).toEqual({ certificate_type: "server_sm", certificate_source: 2, scm_certificate_id: "scs0000000000099", certificate_name: "gm" });
  });
});

const liveRecord = (r: Partial<DomainRecord> = {}): DomainRecord => ({
  provider: "huawei",
  service: "live",
  domain: "play.example.com",
  https: true,
  cert: { notAfter: "2026-10-30T12:00:00.000Z" },
  extra: { region: "cn-north-4", projectId: "p-bj4", type: "pull" },
  ...r,
});

function liveRoute(current: Record<string, unknown>, domain = "play.example.com") {
  return (req: FakeRequest): FakeReply => {
    if (req.url.host !== LIVE_HOST || req.url.pathname !== "/v1/p-bj4/guard/https-cert" || req.url.searchParams.get("domain") !== domain) return undefined;
    if (req.method === "GET") return { body: current };
    if (req.method === "PUT") return { body: "" };
    return undefined;
  };
}

describe("huawei live deployer", () => {
  it("update：先读当前 HTTPS 配置，强制跳转原样带回；证书用 CCM 证书 ID 绑定（tls_certificate.source = scm）", async () => {
    const { ctx, fetch } = ctxOf(
      liveRoute({ certificate_format: "PEM", certificate: OLD_ECC_PEM, certificate_key: "", force_redirect: true, gm_certificate: {}, tls_certificate: { certificate: OLD_ECC_PEM } }),
    );
    const input = viaScm();
    await expect(live.deployer!.apply(ctx, CREDS, { records: [liveRecord()], mode: "update" }, input)).resolves.toEqual({ certId: "scs-new" });
    expect(input.certId).toHaveBeenCalledTimes(1);
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET", "PUT"]);
    const put = fetch.calls[1]!;
    expect(Object.fromEntries(put.url.searchParams)).toEqual({ domain: "play.example.com" });
    expect(put.headers["x-project-id"]).toBe("p-bj4");
    expect(put.json).toEqual({ certificate_format: "PEM", force_redirect: true, tls_certificate: { source: "scm", cert_id: "scs-new" } });
    expectApigSigned(put, { "X-Project-Id": "p-bj4" });
  });

  it("deploy：原先没有证书，配置证书即开启 HTTPS", async () => {
    const { ctx, fetch } = ctxOf(liveRoute({ certificate_format: "", certificate: "", certificate_key: "", force_redirect: false, gm_certificate: {}, tls_certificate: {} }));
    await live.deployer!.apply(ctx, CREDS, { records: [liveRecord({ https: false, cert: undefined })], mode: "deploy" }, viaScm());
    expect(fetch.calls[1]!.json).toEqual({ certificate_format: "PEM", force_redirect: false, tls_certificate: { source: "scm", cert_id: "scs-new" } });
  });

  it("双证书：CCM 托管的国密证书按证书 ID 原样带回", async () => {
    const { ctx, fetch } = ctxOf(
      liveRoute({
        certificate_format: "PEM",
        force_redirect: false,
        gm_certificate: { source: "scm", cert_id: "scs-gm", cert_name: "gm", sign_certificate: "-----BEGIN CERTIFICATE-----x", enc_certificate: "-----BEGIN CERTIFICATE-----y" },
        tls_certificate: { source: "user", certificate: OLD_ECC_PEM },
      }),
    );
    await live.deployer!.apply(ctx, CREDS, { records: [liveRecord()], mode: "update" }, viaScm());
    expect(fetch.calls[1]!.json).toEqual({
      certificate_format: "PEM",
      force_redirect: false,
      tls_certificate: { source: "scm", cert_id: "scs-new" },
      gm_certificate: { source: "scm", cert_id: "scs-gm", cert_name: "gm" },
    });
  });

  it("国密证书是自有上传的：不上传、不写入，报错", async () => {
    const { ctx, fetch } = ctxOf(liveRoute({ force_redirect: false, gm_certificate: { source: "user", sign_certificate: "-----BEGIN CERTIFICATE-----x" }, tls_certificate: {} }));
    const input = viaScm();
    await expect(live.deployer!.apply(ctx, CREDS, { records: [liveRecord()], mode: "update" }, input)).rejects.toMatchObject({ code: "SmCertNotPreservable" });
    expect(input.certId).not.toHaveBeenCalled();
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET"]);
  });

  it("deploy 模式：读到已配置证书（HTTPS 其实已开启）时不上传、不写入，报 HttpsAlreadyEnabled", async () => {
    for (const current of [
      { certificate_format: "PEM", certificate: OLD_ECC_PEM, force_redirect: false, gm_certificate: {}, tls_certificate: { certificate: OLD_ECC_PEM } },
      { force_redirect: false, tls_certificate: { source: "scm", cert_id: "scs-old" } },
      { certificate: OLD_ECC_PEM },
      { gm_certificate: { source: "scm", cert_id: "scs-gm", cert_name: "gm" }, tls_certificate: {} },
    ]) {
      const { ctx, fetch } = ctxOf(liveRoute(current));
      const input = viaScm();
      await expect(live.deployer!.apply(ctx, CREDS, { records: [liveRecord({ https: false, cert: undefined })], mode: "deploy" }, input)).rejects.toMatchObject({
        code: "HttpsAlreadyEnabled",
        message: "该域名的 HTTPS 已开启（与查询时不同），未做修改；请重新执行，按更新规则判断",
      });
      expect(input.certId).not.toHaveBeenCalled();
      expect(fetch.calls.map((c) => c.method)).toEqual(["GET"]);
    }
  });

  it("update 模式：读到没有任何证书（HTTPS 已被关闭）时不上传、不写入，报 HttpsDisabled", async () => {
    const { ctx, fetch } = ctxOf(liveRoute({ force_redirect: false, tls_certificate: {} }));
    const input = viaScm();
    await expect(live.deployer!.apply(ctx, CREDS, { records: [liveRecord()], mode: "update" }, input)).rejects.toMatchObject({ code: "HttpsDisabled" });
    expect(input.certId).not.toHaveBeenCalled();
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET"]);
  });

  it("extra 里没有项目 ID 时按地域从 IAM 项目列表取", async () => {
    const { ctx, fetch } = ctxOf((req) => {
      if (req.url.host === "iam.myhuaweicloud.com") return { body: { projects: [{ id: "p-bj4", name: "cn-north-4" }] } };
      return liveRoute({ force_redirect: false, tls_certificate: { source: "scm", cert_id: "scs-old" } })(req);
    });
    await live.deployer!.apply(ctx, CREDS, { records: [liveRecord({ extra: { region: "cn-north-4", type: "pull" } })], mode: "update" }, viaScm());
    expect(fetch.calls.map((c) => `${c.method} ${c.url.host}`)).toEqual(["GET iam.myhuaweicloud.com", `GET ${LIVE_HOST}`, `PUT ${LIVE_HOST}`]);
  });

  it("unsupported：推流域名；国密证书为自有上传的播放域名", () => {
    const u = live.deployer!.unsupported!;
    expect(u(liveRecord({ https: false, extra: { region: "cn-north-4", type: "push" } }), "deploy")).toContain("推流域名");
    expect(u(liveRecord({ extra: { region: "cn-north-4", type: "pull", smCertSource: "user" } }), "update")).toContain("国密");
    expect(u(liveRecord(), "update")).toBeUndefined();
  });

  it("CCM 不接受没有 CN 的证书（SCM.0009）：改为直接传 PEM（tls_certificate.source = user），结果带说明；国密证书照常带回", async () => {
    const { ctx, fetch } = ctxOf(
      liveRoute({ certificate_format: "PEM", force_redirect: true, gm_certificate: { source: "scm", cert_id: "scs-gm", cert_name: "gm" }, tls_certificate: { certificate: OLD_ECC_PEM } }),
    );
    const input = scmRejects();
    const outcome = await live.deployer!.apply(ctx, CREDS, { records: [liveRecord()], mode: "update" }, input);
    expect(outcome.certId).toBeUndefined();
    expect(outcome.note).toMatch(/SCM\.0009/);
    expect(outcome.note).toContain("certs");
    const put = fetch.calls.find((c) => c.method === "PUT")!;
    expect(put.json).toEqual({
      certificate_format: "PEM",
      force_redirect: true,
      tls_certificate: { source: "user", certificate: CERT.certPem, certificate_key: CERT.keyPem },
      gm_certificate: { source: "scm", cert_id: "scs-gm", cert_name: "gm" },
    });
    expectApigSigned(put, { "X-Project-Id": "p-bj4" });
    expectNoKeyInUrl(fetch.calls);
  });

  it("上传到 CCM 的其他失败照常报错，不改为直接传 PEM、不写入", async () => {
    const { ctx, fetch } = ctxOf(liveRoute({ force_redirect: false, tls_certificate: { certificate: OLD_ECC_PEM } }));
    const input = scmRejects(new CloudApiError("huawei", "SCM.0016", "Access denied", "rid-scm", 403));
    await expect(live.deployer!.apply(ctx, CREDS, { records: [liveRecord()], mode: "update" }, input)).rejects.toMatchObject({ code: "SCM.0016" });
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET"]);
  });

  it("写接口失败抛 CloudApiError", async () => {
    const current = { force_redirect: false, tls_certificate: { source: "scm", cert_id: "scs-old" } };
    const { ctx } = ctxOf((req) => (req.method === "PUT" ? apigError(400, "LIVE.100011001", "Request Illegal") : liveRoute(current)(req)));
    await expect(live.deployer!.apply(ctx, CREDS, { records: [liveRecord()], mode: "update" }, viaScm())).rejects.toMatchObject({
      code: "LIVE.100011001",
      requestId: "rid-LIVE.100011001",
    });
  });
});

describe("huawei live 查询与部署全流程", () => {
  function route(onImport: () => FakeReply) {
    return (req: FakeRequest): FakeReply => {
      const path = req.url.pathname;
      if (req.url.host === "iam.myhuaweicloud.com") return { body: { projects: [{ id: "p-bj4", name: "cn-north-4" }] } };
      if (req.url.host === SCM_HOST) {
        if (req.method === "GET" && path === "/v3/scm/certificates") return { body: { total_count: 0, certificates: [] } };
        if (req.method === "POST" && path === "/v3/scm/certificates/import") return onImport();
        return undefined;
      }
      if (req.url.host !== LIVE_HOST) return undefined;
      if (path === "/v1/p-bj4/domain") {
        return {
          body: {
            total: 2,
            domain_info: [
              { domain: "play.example.com", domain_type: "pull", status: "on" },
              { domain: "push.example.com", domain_type: "push", status: "on" },
            ],
          },
        };
      }
      if (path === "/v2/p-bj4/certificates") {
        return {
          body: {
            total: 2,
            certificates_info: [
              { play_domain: "play.example.com", cert_type: 0, source: "user", expire_time: "2026-10-30T04:00:00Z" },
              { play_domain: "play.example.com", cert_type: 1, gm_cert_type: 1, source: "scm", cert_id: "scs-gm", cert_name: "gm", expire_time: "2027-02-28T16:00:00Z" },
            ],
          },
        };
      }
      return liveRoute({
        certificate_format: "PEM",
        force_redirect: true,
        gm_certificate: { source: "scm", cert_id: "scs-gm", cert_name: "gm" },
        tls_certificate: { source: "user", certificate: OLD_ECC_PEM },
      })(req);
    };
  }

  it("list：extra 补项目 ID 与国密证书来源，全部证书标注算法（国际证书在前）", async () => {
    const { ctx } = ctxOf(route(() => undefined));
    const items = await live.list(ctx, CREDS, noWarn);
    const play = items.find((d) => d.domain === "play.example.com")!;
    expect(play).toMatchObject({
      https: true,
      cert: { commonName: "static.example.cn", notAfter: "2026-10-30T12:00:00.000Z", algorithm: "ECC" },
      certs: [
        { commonName: "static.example.cn", algorithm: "ECC" },
        { id: "scs-gm", name: "gm", notAfter: "2027-03-01T00:00:00.000Z", algorithm: "SM2" },
      ],
      extra: { region: "cn-north-4", projectId: "p-bj4", type: "pull", certSource: "user", smCertSource: "scm" },
    });
    expect(items.find((d) => d.domain === "push.example.com")!.extra).toEqual({ region: "cn-north-4", projectId: "p-bj4", type: "push" });
  });

  it("planDeploy + executeDeploy：上传到 CCM 后绑定播放域名，推流域名跳过 unsupported", async () => {
    const { ctx, fetch } = ctxOf(route(() => ({ body: { certificate_id: "scs1600313391074" } })));
    const plan = await planDeploy(ctx, CERT, { providers: ["huawei"], services: ["live"], force: false, dryRun: false });
    const report = await executeDeploy(ctx, CERT, plan);
    expect(report.results).toEqual([
      expect.objectContaining({ domain: "play.example.com", action: "updated", after: { id: "scs1600313391074", notAfter: CERT.notAfter } }),
      expect.objectContaining({ domain: "push.example.com", action: "skipped", reason: "unsupported", message: expect.stringContaining("推流域名") }),
    ]);
    expect(report.uploads).toEqual([{ provider: "huawei", certId: "scs1600313391074", reused: false }]);
    expect(fetch.calls.find((c) => c.method === "PUT")!.json).toEqual({
      certificate_format: "PEM",
      force_redirect: true,
      tls_certificate: { source: "scm", cert_id: "scs1600313391074" },
      gm_certificate: { source: "scm", cert_id: "scs-gm", cert_name: "gm" },
    });
    expectNoKeyInUrl(fetch.calls);
  });

  it("planDeploy + executeDeploy：CCM 拒收没有 CN 的证书（SCM.0009）时直接传 PEM 完成更新，没有上传记录，结果说明原因", async () => {
    const { ctx, fetch } = ctxOf(route(() => apigError(400, "SCM.0009", "No domain name is bonded with the certificate. Failed to upload the certificate.")));
    const plan = await planDeploy(ctx, CERT, { providers: ["huawei"], services: ["live"], force: false, dryRun: false });
    const report = await executeDeploy(ctx, CERT, plan);
    expect(report.results[0]).toEqual(
      expect.objectContaining({ domain: "play.example.com", action: "updated", after: { notAfter: CERT.notAfter }, message: expect.stringContaining("SCM.0009") }),
    );
    expect(report.uploads).toEqual([]);
    expect(fetch.calls.filter((c) => c.method === "POST")).toHaveLength(1);
    expect(fetch.calls.find((c) => c.method === "PUT")!.json).toMatchObject({ tls_certificate: { source: "user", certificate: CERT.certPem, certificate_key: CERT.keyPem } });
  });
});

const obsRecord = (r: Partial<DomainRecord> = {}): DomainRecord => ({
  provider: "huawei",
  service: "obs",
  domain: "img.example.com",
  https: true,
  cert: { id: "scs0000000000011", name: "old", notAfter: "2026-10-30T12:00:00.000Z" },
  extra: { bucket: "static-prod", region: "cn-east-3", certType: "server" },
  ...r,
});

const BUCKET_HOST = "static-prod.obs.cn-east-3.myhuaweicloud.com";

describe("huawei obs deployer", () => {
  it("update：SetBucketCustomdomain 只设置服务端证书（CertificateType=server，国密 / 客户端证书不动），带 CCM 证书 ID 与 PEM、Content-MD5，OBS 签名", async () => {
    const { ctx, fetch } = ctxOf((req) => (req.url.host === BUCKET_HOST && req.method === "PUT" ? { body: "" } : undefined));
    const input = viaScm();
    await expect(obs.deployer!.apply(ctx, { ...CREDS, securityToken: "tok" }, { records: [obsRecord()], mode: "update" }, input)).resolves.toEqual({ certId: "scs-new" });
    expect(fetch.calls).toHaveLength(1);
    const put = fetch.calls[0]!;
    expect(put.method).toBe("PUT");
    expect(put.url.pathname).toBe("/");
    expect(put.url.search).toBe("?customdomain=img.example.com");
    expect(put.headers["content-type"]).toBe("application/xml");
    expect(put.headers["content-md5"]).toBe(createHash("md5").update(put.body).digest("base64"));
    expect(put.headers["x-obs-security-token"]).toBe("tok");
    expect(put.headers.authorization).toBe(
      obsAuthorization(
        CREDS.accessKeyId,
        CREDS.secretAccessKey,
        obsStringToSign(
          "PUT",
          { "content-md5": put.headers["content-md5"]!, "content-type": "application/xml", "x-obs-date": put.headers["x-obs-date"]!, "x-obs-security-token": "tok" },
          "/static-prod/?customdomain=img.example.com",
        ),
      ),
    );
    expect(put.body).toMatch(/^<CustomDomainConfiguration>.*<\/CustomDomainConfiguration>$/s);
    expect(xmlText(put.body, "Name")).toBe(NAME);
    expect(xmlText(put.body, "CertificateId")).toBe("scs-new");
    expect(xmlText(put.body, "Certificate")).toBe(CERT.certPem.trim());
    expect(xmlText(put.body, "PrivateKey")).toBe(CERT.keyPem.trim());
    expect(xmlText(put.body, "CertificateType")).toBe("server");
    expect(put.body).not.toContain("DeleteCertificate");
    expectNoKeyInUrl(fetch.calls);
  });

  it("deploy：没有证书的自定义域名绑定服务端证书即支持 HTTPS（请求与 update 相同）", async () => {
    const { ctx, fetch } = ctxOf((req) => (req.url.host === BUCKET_HOST && req.method === "PUT" ? { body: "" } : undefined));
    await obs.deployer!.apply(ctx, CREDS, { records: [obsRecord({ https: false, cert: undefined, extra: { bucket: "static-prod", region: "cn-east-3" } })], mode: "deploy" }, viaScm());
    expect(xmlText(fetch.calls[0]!.body, "CertificateType")).toBe("server");
  });

  it("CCM 不接受没有 CN 的证书（SCM.0009）：不带 CertificateId、直接传 PEM（OBS 自动生成证书 ID），结果带说明", async () => {
    const { ctx, fetch } = ctxOf((req) => (req.url.host === BUCKET_HOST && req.method === "PUT" ? { body: "" } : undefined));
    const outcome = await obs.deployer!.apply(ctx, CREDS, { records: [obsRecord()], mode: "update" }, scmRejects());
    expect(outcome.certId).toBeUndefined();
    expect(outcome.note).toMatch(/SCM\.0009/);
    const put = fetch.calls[0]!;
    expect(put.body).not.toContain("CertificateId");
    expect(xmlText(put.body, "Name")).toBe(NAME);
    expect(xmlText(put.body, "Certificate")).toBe(CERT.certPem.trim());
    expect(xmlText(put.body, "PrivateKey")).toBe(CERT.keyPem.trim());
    expect(xmlText(put.body, "CertificateType")).toBe("server");
    expectNoKeyInUrl(fetch.calls);
  });

  it("上传到 CCM 的其他失败照常报错，不写入", async () => {
    const { ctx, fetch } = ctxOf((req) => (req.url.host === BUCKET_HOST && req.method === "PUT" ? { body: "" } : undefined));
    const input = scmRejects(new CloudApiError("huawei", "SCM.0016", "Access denied", "rid-scm", 403));
    await expect(obs.deployer!.apply(ctx, CREDS, { records: [obsRecord()], mode: "update" }, input)).rejects.toMatchObject({ code: "SCM.0016" });
    expect(fetch.calls).toHaveLength(0);
  });

  it("失败抛 CloudApiError（XML 错误体）；extra 缺 bucket / region 时报错且不上传", async () => {
    const { ctx } = ctxOf(() => ({ status: 403, body: "<Error><Code>AccessDenied</Code><Message>Access Denied</Message><RequestId>obs-rid</RequestId></Error>" }));
    await expect(obs.deployer!.apply(ctx, CREDS, { records: [obsRecord()], mode: "update" }, viaScm())).rejects.toMatchObject({
      code: "AccessDenied",
      requestId: "obs-rid",
      message: "Access Denied（可能缺少 IAM 权限 obs:bucket:putBucketCustomDomainConfiguration，可授予系统策略 OBSFullAccessPolicy，旧版 IAM 授予 OBS Administrator）",
    });
    const input = viaScm();
    await expect(obs.deployer!.apply(ctx, CREDS, { records: [obsRecord({ extra: {} })], mode: "update" }, input)).rejects.toThrow(/bucket/);
    expect(input.certId).not.toHaveBeenCalled();
  });

  it("list：服务端证书 + 国密证书时给出全部证书，国密标 SM2", async () => {
    const { ctx } = ctxOf((req) => {
      if (req.url.host === "obs.cn-north-4.myhuaweicloud.com") {
        return { body: "<ListAllMyBucketsResult><Buckets><Bucket><Name>static-prod</Name><Location>cn-east-3</Location></Bucket></Buckets></ListAllMyBucketsResult>" };
      }
      if (req.url.host === BUCKET_HOST) {
        return {
          body:
            "<ListBucketCustomDomainsResult>" +
            "<Domains><DomainName>img.example.com</DomainName><CertName>rsa</CertName><CertificateId>000001A14A3ABD8282E7B4974512770A</CertificateId><CertificateType>server</CertificateType><ExpiredTime>2027-03-13T10:22:05.912Z</ExpiredTime></Domains>" +
            "<Domains><DomainName>img.example.com</DomainName><CertName>sm2</CertName><CertificateId>000001A14A3ABD8282E7B4974512770B</CertificateId><CertificateType>server_sm</CertificateType><ExpiredTime>2026-11-13T10:22:05.912Z</ExpiredTime></Domains>" +
            "</ListBucketCustomDomainsResult>",
        };
      }
      return undefined;
    });
    const [rec] = await obs.list(ctx, CREDS, noWarn);
    expect(rec).toEqual({
      provider: "huawei",
      service: "obs",
      domain: "img.example.com",
      https: true,
      cert: { id: "000001A14A3ABD8282E7B4974512770B", name: "sm2", notAfter: "2026-11-13T10:22:05.912Z", algorithm: "SM2" },
      certs: [
        { id: "000001A14A3ABD8282E7B4974512770A", name: "rsa", notAfter: "2027-03-13T10:22:05.912Z" },
        { id: "000001A14A3ABD8282E7B4974512770B", name: "sm2", notAfter: "2026-11-13T10:22:05.912Z", algorithm: "SM2" },
      ],
      extra: { bucket: "static-prod", region: "cn-east-3", certType: "server_sm" },
    });
  });
});
