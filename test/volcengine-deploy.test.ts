import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { loadLocalCert, type LocalCert } from "../src/deploy/cert.js";
import { executeDeploy, planDeploy } from "../src/deploy/run.js";
import { CloudApiError, type QueryContext } from "../src/lib/http.js";
import { certName, keyAlgorithm, pemAlgorithm } from "../src/providers/volcengine/common.js";
import { volcengine } from "../src/providers/volcengine/index.js";
import type { DeployInput, DeployTarget } from "../src/providers/registry.js";
import type { DomainRecord } from "../src/types.js";
import { fakeFetch, type FakeReply, type FakeRequest } from "./helpers.js";

const FIX = fileURLToPath(new URL("./fixtures/deploy/", import.meta.url));
const read = (f: string) => readFileSync(join(FIX, f), "utf8");
const NOW = new Date("2026-10-15T00:00:00Z");
const RSA = loadLocalCert(read("rsa-fullchain.pem"), read("rsa-key.pem"), NOW);
const ECC = loadLocalCert(read("ecc-fullchain.pem"), read("ecc-key.pem"), NOW);
const CREDS = { accessKeyId: "AKLTtest0000", secretAccessKey: "testsecret" };
const VOLC_ENV = { VOLCENGINE_ACCESS_KEY: "AKLTtest0000", VOLCENGINE_SECRET_KEY: "testsecret" };

const ok = (Result: unknown) => ({ body: { ResponseMetadata: { RequestId: "rid" }, Result } });
const volcError = (Code: string, Message: string, status = 200) => ({
  status,
  body: { ResponseMetadata: { RequestId: "rid-err", Error: { CodeN: 1, Code, Message } } },
});

function setup(route: (req: FakeRequest) => FakeReply) {
  const fetch = fakeFetch(route);
  const ctx: QueryContext = { env: VOLC_ENV, fetch, now: NOW, timeoutMs: 1000, sleep: async () => {} };
  return { fetch, ctx };
}

const deployer = (key: string) => volcengine.services.find((s) => s.key === key)!.deployer!;

function input(cert: LocalCert = RSA, id = "cert-new"): DeployInput & { uploads: () => number } {
  let n = 0;
  return { cert, certId: async () => (n++, id), uploads: () => n };
}

const rec = (service: string, domain: string, r: Partial<DomainRecord> = {}): DomainRecord => ({
  provider: "volcengine",
  service,
  domain,
  https: true,
  ...r,
});
const target = (record: DomainRecord, mode: DeployTarget["mode"] = record.https ? "update" : "deploy"): DeployTarget => ({ records: [record], mode });

/** 请求里不能把 PEM / 私钥放在 URL 上 */
const noPemInUrl = (fetch: { calls: FakeRequest[] }) => {
  for (const c of fetch.calls) expect(decodeURIComponent(c.url.href)).not.toMatch(/BEGIN|PRIVATE/);
};

describe("volcengine 证书名与算法", () => {
  it("证书名 sslbear-<CN，* 换成 _>-<到期日>，超长截断 CN 部分", () => {
    expect(certName(RSA)).toBe("sslbear-example.com-20270101");
    expect(certName({ ...RSA, commonName: "*.example.com" })).toBe("sslbear-_.example.com-20270101");
    const long = certName({ ...RSA, commonName: "a-very-long-subdomain-name.example.com" }, 40);
    expect(long).toBe("sslbear-a-very-long-subdomain-n-20270101");
    expect(long.length).toBe(40);
  });

  it("证书中心的 CertificateKeyAlgorithm 与 PEM 公钥类型换算成 RSA / ECC / SM2", () => {
    expect(keyAlgorithm("RSA 2048")).toBe("RSA");
    expect(keyAlgorithm("EC 256")).toBe("ECC");
    expect(keyAlgorithm("ECC 384")).toBe("ECC");
    expect(keyAlgorithm("SM2 256")).toBe("SM2");
    expect(keyAlgorithm("")).toBeUndefined();
    expect(pemAlgorithm(RSA.certPem)).toBe("RSA");
    expect(pemAlgorithm(ECC.certPem)).toBe("ECC");
    expect(pemAlgorithm("not a pem")).toBeUndefined();
  });
});

describe("volcengine uploadCertificate（证书中心）", () => {
  it("ImportCertificate 上传：PEM 在 JSON 请求体里，不允许重复上传，证书名带 CN 与到期日", async () => {
    const { fetch, ctx } = setup((req) => (req.action === "ImportCertificate" ? ok({ InstanceId: "cert-up", RepeatId: "" }) : undefined));
    const r = await volcengine.uploadCertificate!(ctx, CREDS, RSA);
    expect(r).toEqual({ id: "cert-up", reused: false });
    expect(fetch.calls).toHaveLength(1);
    const call = fetch.calls[0]!;
    expect(call.method).toBe("POST");
    expect(call.url.href).toBe("https://certificate-service.volcengineapi.com/?Action=ImportCertificate&Version=2024-10-01");
    expect(call.headers.authorization).toMatch(/\/cn-beijing\/certificate_service\/request, /);
    expect(call.json).toEqual({
      Tag: "sslbear-example.com-20270101",
      Repeatable: false,
      CertificateInfo: { CertificateChain: RSA.certPem.trim(), PrivateKey: RSA.keyPem.trim() },
    });
    noPemInUrl(fetch);
  });

  it("证书中心已有同指纹的证书时返回 RepeatId，记为复用", async () => {
    const { ctx } = setup((req) => (req.action === "ImportCertificate" ? ok({ InstanceId: "", RepeatId: "cert-old" }) : undefined));
    expect(await volcengine.uploadCertificate!(ctx, CREDS, RSA)).toEqual({ id: "cert-old", reused: true });
  });

  it("上传失败抛 CloudApiError（带错误码与 RequestId）", async () => {
    const { ctx } = setup(() => volcError("NotMatch.KeyPair", "公私钥不匹配", 400));
    const e = await volcengine.uploadCertificate!(ctx, CREDS, RSA).catch((x) => x);
    expect(e).toBeInstanceOf(CloudApiError);
    expect(e).toMatchObject({ code: "NotMatch.KeyPair", requestId: "rid-err" });
  });

  it("响应里既没有 InstanceId 也没有 RepeatId 时报错", async () => {
    const { ctx } = setup(() => ok({}));
    await expect(volcengine.uploadCertificate!(ctx, CREDS, RSA)).rejects.toMatchObject({ code: "InvalidResponse" });
  });
});

describe("volcengine cdn 部署", () => {
  const route = (DeployResult: unknown[]) => (req: FakeRequest) => (req.action === "BatchDeployCert" ? ok({ DeployResult }) : undefined);

  it("更新：BatchDeployCert 只换证书（单证书不带 CertId2）", async () => {
    const { fetch, ctx } = setup(route([{ Domain: "www.example.com", Status: "success" }]));
    const record = rec("cdn", "www.example.com", { cert: { id: "cert-old", notAfter: "2026-10-25T00:00:00.000Z" } });
    const out = await deployer("cdn").apply(ctx, CREDS, target(record), input());
    expect(out).toEqual({ certId: "cert-new" });
    expect(fetch.calls).toHaveLength(1);
    expect(fetch.calls[0]!.url.href).toBe("https://cdn.volcengineapi.com/?Action=BatchDeployCert&Version=2021-03-01");
    expect(fetch.calls[0]!.json).toEqual({ CertId: "cert-new", Domain: "www.example.com" });
  });

  it("部署：没开 HTTPS 的域名关联证书即开启 HTTPS", async () => {
    const { fetch, ctx } = setup(route([{ Domain: "img.example.com", Status: "success" }]));
    await deployer("cdn").apply(ctx, CREDS, target(rec("cdn", "img.example.com", { https: false })), input());
    expect(fetch.calls[0]!.json).toEqual({ CertId: "cert-new", Domain: "img.example.com" });
  });

  it("双证书只换同算法那张，另一张作为 CertId2 保留", async () => {
    const certs = [
      { id: "cert-rsa", algorithm: "RSA" as const, notAfter: "2026-10-25T00:00:00.000Z" },
      { id: "cert-ecc", algorithm: "ECC" as const, notAfter: "2026-11-25T00:00:00.000Z" },
    ];
    const record = rec("cdn", "www.example.com", { cert: certs[0], certs });
    const rsa = setup(route([{ Domain: "www.example.com", Status: "success" }]));
    await deployer("cdn").apply(rsa.ctx, CREDS, target(record), input(RSA));
    expect(rsa.fetch.calls[0]!.json).toEqual({ CertId: "cert-new", CertId2: "cert-ecc", Domain: "www.example.com" });
    const ecc = setup(route([{ Domain: "www.example.com", Status: "success" }]));
    await deployer("cdn").apply(ecc.ctx, CREDS, target(record), input(ECC));
    expect(ecc.fetch.calls[0]!.json).toEqual({ CertId: "cert-new", CertId2: "cert-rsa", Domain: "www.example.com" });
  });

  it("国密证书原样保留", async () => {
    const certs = [
      { id: "cert-rsa", algorithm: "RSA" as const, notAfter: "2026-10-25T00:00:00.000Z" },
      { id: "cert-sm2", algorithm: "SM2" as const, notAfter: "2026-10-20T00:00:00.000Z" },
    ];
    const { fetch, ctx } = setup(route([{ Domain: "www.example.com", Status: "success" }]));
    await deployer("cdn").apply(ctx, CREDS, target(rec("cdn", "www.example.com", { cert: certs[1], certs })), input(RSA));
    expect(fetch.calls[0]!.json).toEqual({ CertId: "cert-new", CertId2: "cert-sm2", Domain: "www.example.com" });
  });

  it("域名上超过两张证书时不改、也不上传", async () => {
    const certs = [
      { id: "cert-rsa", algorithm: "RSA" as const },
      { id: "cert-ecc", algorithm: "ECC" as const },
      { id: "cert-sm2", algorithm: "SM2" as const },
    ];
    const { fetch, ctx } = setup(route([]));
    const inp = input(RSA);
    await expect(deployer("cdn").apply(ctx, CREDS, target(rec("cdn", "www.example.com", { cert: certs[0], certs })), inp)).rejects.toMatchObject({
      code: "TooManyCerts",
    });
    expect(inp.uploads()).toBe(0);
    expect(fetch.calls).toHaveLength(0);
  });

  it("DeployResult 标为失败时报错，带上失败原因", async () => {
    const { ctx } = setup(route([{ Domain: "www.example.com", Status: "fail", ErrorMsg: "域名与证书不匹配" }]));
    await expect(deployer("cdn").apply(ctx, CREDS, target(rec("cdn", "www.example.com")), input())).rejects.toMatchObject({
      code: "DeployCertFailed",
      message: expect.stringContaining("域名与证书不匹配"),
    });
  });

  it("双证书但查不到证书算法时不处理", () => {
    const certs = [{ id: "a", notAfter: "2026-10-25T00:00:00.000Z" }, { id: "b", algorithm: "ECC" as const }];
    expect(deployer("cdn").unsupported!(rec("cdn", "www.example.com", { cert: certs[0], certs }), "update")).toMatch(/算法/);
    expect(deployer("cdn").unsupported!(rec("cdn", "www.example.com", { cert: certs[0] }), "update")).toBeUndefined();
  });

  it("planDeploy + executeDeploy：双证书域名按同算法那张判断并只换它，上传只做一次", async () => {
    const T = (iso: string) => Math.floor(Date.parse(iso) / 1000);
    const { fetch, ctx } = setup((req) => {
      if (req.action === "ListCdnDomains") {
        return ok({ Total: 2, Data: [{ Domain: "www.example.com", HTTPS: true }, { Domain: "a.example.com", HTTPS: true }] });
      }
      if (req.action === "ListCdnCertInfo" && req.json?.EncryType === "sm_cert") return ok({ Total: 0, CertInfo: [] });
      if (req.action === "ListCdnCertInfo") {
        return ok({
          Total: 2,
          CertInfo: [
            { CertId: "cert-rsa", ExpireTime: T("2026-10-25T00:00:00Z"), ConfiguredDomain: "www.example.com,a.example.com" },
            { CertId: "cert-ecc", ExpireTime: T("2027-03-01T00:00:00Z"), ConfiguredDomain: "www.example.com" },
          ],
        });
      }
      if (req.action === "CertificateGetInstanceList") {
        return ok({
          TotalCount: 2,
          Instances: [
            { InstanceId: "cert-rsa", NotAfter: "2026-10-25 08:00:00", Status: "Issued", CertificateKeyAlgorithm: "RSA 2048" },
            { InstanceId: "cert-ecc", NotAfter: "2027-03-01 08:00:00", Status: "Issued", CertificateKeyAlgorithm: "EC 256" },
          ],
        });
      }
      if (req.action === "ImportCertificate") return ok({ InstanceId: "cert-new" });
      if (req.action === "BatchDeployCert") return ok({ DeployResult: [{ Domain: req.json?.Domain, Status: "success" }] });
      return undefined;
    });
    const plan = await planDeploy(ctx, RSA, { providers: ["volcengine"], services: ["cdn"], force: false, dryRun: false });
    const www = plan.report.results.find((r) => r.domain === "www.example.com");
    expect(www).toMatchObject({ action: "would_update", before: { id: "cert-rsa", algorithm: "RSA", daysLeft: 10 } });
    const report = await executeDeploy(ctx, RSA, plan);
    expect(report.results.map((r) => [r.domain, r.action])).toEqual([
      ["a.example.com", "updated"],
      ["www.example.com", "updated"],
    ]);
    expect(report.uploads).toEqual([{ provider: "volcengine", certId: "cert-new", reused: false }]);
    expect(fetch.calls.filter((c) => c.action === "ImportCertificate")).toHaveLength(1);
    const deploys = fetch.calls.filter((c) => c.action === "BatchDeployCert").map((c) => c.json);
    expect(deploys).toContainEqual({ CertId: "cert-new", CertId2: "cert-ecc", Domain: "www.example.com" });
    expect(deploys).toContainEqual({ CertId: "cert-new", Domain: "a.example.com" });
    noPemInUrl(fetch);
  });
});

describe("volcengine dcdn 部署", () => {
  it("更新 / 部署都用 CreateCertBind 绑定证书中心证书（绑定即开启 HTTPS）", async () => {
    const { fetch, ctx } = setup((req) => (req.action === "CreateCertBind" ? ok({}) : undefined));
    const out = await deployer("dcdn").apply(ctx, CREDS, target(rec("dcdn", "a.example.com", { cert: { id: "cert-old" } })), input());
    expect(out).toEqual({ certId: "cert-new" });
    await deployer("dcdn").apply(ctx, CREDS, target(rec("dcdn", "b.example.com", { https: false })), input());
    const [update, deploy] = fetch.calls;
    expect(update!.url.href).toBe("https://open.volcengineapi.com/?Action=CreateCertBind&Version=2021-04-01");
    expect(update!.headers.authorization).toMatch(/\/cn-north-1\/dcdn\/request, /);
    expect(update!.json).toEqual({ CertSource: "volc", CertId: "cert-new", DomainNames: ["a.example.com"] });
    expect(deploy!.json).toEqual({ CertSource: "volc", CertId: "cert-new", DomainNames: ["b.example.com"] });
  });

  it("返回 Success=false 时报错", async () => {
    const { ctx } = setup(() => ok({ Success: false }));
    await expect(deployer("dcdn").apply(ctx, CREDS, target(rec("dcdn", "a.example.com")), input())).rejects.toBeInstanceOf(CloudApiError);
  });
});

describe("volcengine tos 部署", () => {
  const rules = [
    { Domain: "www.example.com", Cname: "b1.tos-cn-shanghai.volces.com", Forbidden: false, CertId: "cert-old", Protocol: "s3", CertStatus: "CertBound" },
    { Domain: "http.example.com", Forbidden: false, CertId: "", Protocol: "tos", CertStatus: "CertUnbound" },
  ];
  const route = (req: FakeRequest): FakeReply => {
    if (req.url.host !== "b1.tos-cn-shanghai.volces.com" || req.url.search !== "?customdomain") return undefined;
    if (req.method === "GET") return { body: { CustomDomainRules: rules } };
    if (req.method === "PUT") return { status: 200, body: "" };
    return undefined;
  };
  const extra = { bucket: "b1", region: "cn-shanghai" };

  it("更新：先读出该域名的规则，只换 CertId，访问协议原样带回", async () => {
    const { fetch, ctx } = setup(route);
    const out = await deployer("tos").apply(ctx, CREDS, target(rec("tos", "www.example.com", { extra, cert: { id: "cert-old" } })), input());
    expect(out).toEqual({ certId: "cert-new" });
    const [get, put] = fetch.calls;
    expect(get!.method).toBe("GET");
    expect(put!.method).toBe("PUT");
    expect(put!.url.href).toBe("https://b1.tos-cn-shanghai.volces.com/?customdomain");
    expect(put!.json).toEqual({ CustomDomainRule: { Domain: "www.example.com", CertId: "cert-new", Protocol: "s3" } });
    expect(put!.headers["content-type"]).toBe("application/json");
    expect(put!.headers["x-tos-content-sha256"]).toBe(createHash("sha256").update(put!.body).digest("hex"));
    expect(put!.headers["content-md5"]).toBe(createHash("md5").update(put!.body).digest("base64"));
    expect(put!.headers.authorization).toMatch(
      /^TOS4-HMAC-SHA256 Credential=AKLTtest0000\/\d{8}\/cn-shanghai\/tos\/request,SignedHeaders=content-type;host;x-tos-content-sha256;x-tos-date,Signature=[0-9a-f]{64}$/,
    );
  });

  it("部署：没绑证书的自定义域名绑定证书（TOS 绑证书即 HTTPS）", async () => {
    const { fetch, ctx } = setup(route);
    await deployer("tos").apply(ctx, CREDS, target(rec("tos", "http.example.com", { https: false, extra })), input());
    expect(fetch.calls[1]!.json).toEqual({ CustomDomainRule: { Domain: "http.example.com", CertId: "cert-new", Protocol: "tos" } });
  });

  it("桶上已没有该域名时报错，不新建域名", async () => {
    const { fetch, ctx } = setup(route);
    await expect(deployer("tos").apply(ctx, CREDS, target(rec("tos", "gone.example.com", { extra })), input())).rejects.toMatchObject({
      code: "DomainNotFound",
    });
    expect(fetch.calls.filter((c) => c.method === "PUT")).toHaveLength(0);
  });

  it("PUT 失败按 TOS 错误体报错", async () => {
    const { ctx } = setup((req) =>
      req.method === "PUT" ? { status: 400, body: { Code: "InvalidArgument", Message: "cert not match", RequestId: "tos-rid", EC: "0016-00000010" } } : route(req),
    );
    await expect(deployer("tos").apply(ctx, CREDS, target(rec("tos", "www.example.com", { extra })), input())).rejects.toMatchObject({
      code: "InvalidArgument",
      requestId: "tos-rid",
    });
  });

  it("跨服务授权失败（RoleNotExist）时不处理：绑定的证书 TOS 读不到", () => {
    const record = rec("tos", "role.example.com", { https: false, extra: { ...extra, certId: "cert-old", certStatus: "RoleNotExist" } });
    expect(deployer("tos").unsupported!(record, "deploy")).toMatch(/跨服务授权/);
    expect(deployer("tos").unsupported!(rec("tos", "x.example.com", { https: false, extra: { ...extra, certStatus: "CertNotExist" } }), "deploy")).toBeUndefined();
  });
});

describe("volcengine vod 部署", () => {
  const config = (HTTPS: unknown) => ok({ DomainInfo: { DomainConfig: { Domain: "v.example.com", HTTPS } }, VodInfo: { DomainType: "vod_play" } });
  const extra = { space: "s1", region: "cn-north-1", type: "vod_play" };

  function routes(HTTPS: unknown, host = "vod.volcengineapi.com") {
    return (req: FakeRequest): FakeReply => {
      if (req.url.host !== host) return undefined;
      if (req.action === "DescribeVodDomainConfig") return config(HTTPS);
      if (req.action === "UpdateVodDomainConfig") return ok(null);
      return undefined;
    };
  }

  it("更新：先读 HTTPS 配置，只换证书 ID，HTTP/2、TLS、强制跳转、HSTS、OCSP 原样带回，不回传证书内容", async () => {
    const { fetch, ctx } = setup(
      routes({
        Switch: true,
        CertInfo: {
          CertId: "cert-old",
          CertName: "v.example.com",
          Certificate: { Certificate: RSA.certPem, PrivateKey: null },
          EffectiveTime: 1760000000,
          ExpireTime: 1790000000,
          EncryType: "inter_cert",
          Source: "volc_cert_center",
        },
        CertInfoList: null,
        CertCheck: { Switch: false, CertInfoList: null },
        DisableHttp: false,
        ForcedRedirect: { EnableForcedRedirect: true, StatusCode: "301" },
        HTTP2: true,
        Hsts: { Subdomain: "exclude", Switch: true, Ttl: 100 },
        OCSP: true,
        TlsVersion: ["tlsv1.2", "tlsv1.3"],
      }),
    );
    const record = rec("vod", "v.example.com", { extra, cert: { id: "cert-old" } });
    expect(await deployer("vod").apply(ctx, CREDS, target(record), input())).toEqual({ certId: "cert-new" });
    const [describe, update] = fetch.calls;
    expect(describe!.json).toEqual({ SpaceName: "s1", DomainType: "vod_play", DescribeCdnDomainParam: { Domain: "v.example.com" } });
    expect(update!.url.href).toBe("https://vod.volcengineapi.com/?Action=UpdateVodDomainConfig&Version=2026-01-01");
    expect(update!.json).toEqual({
      SpaceName: "s1",
      DomainType: "vod_play",
      UpdateCdnConfigParam: {
        Domain: "v.example.com",
        HTTPS: {
          Switch: true,
          CertInfo: { CertId: "cert-new" },
          CertCheck: { Switch: false },
          DisableHttp: false,
          ForcedRedirect: { EnableForcedRedirect: true, StatusCode: "301" },
          HTTP2: true,
          Hsts: { Subdomain: "exclude", Switch: true, Ttl: 100 },
          OCSP: true,
          TlsVersion: ["tlsv1.2", "tlsv1.3"],
        },
      },
    });
    expect(update!.body).not.toContain("BEGIN CERTIFICATE");
  });

  it("部署：打开 HTTPS 开关并绑定证书，其余配置照读出的值带回", async () => {
    const { fetch, ctx } = setup(routes({ Switch: false, HTTP2: false, TlsVersion: ["tlsv1.1", "tlsv1.2", "tlsv1.3"] }));
    await deployer("vod").apply(ctx, CREDS, target(rec("vod", "v.example.com", { https: false, extra })), input());
    expect(fetch.calls[1]!.json).toMatchObject({
      UpdateCdnConfigParam: { Domain: "v.example.com", HTTPS: { Switch: true, CertInfo: { CertId: "cert-new" }, HTTP2: false, TlsVersion: ["tlsv1.1", "tlsv1.2", "tlsv1.3"] } },
    });
  });

  it("双证书只换同算法那张，用 CertInfoList 保留另一张", async () => {
    const { fetch, ctx } = setup(
      routes({ Switch: true, CertInfo: null, CertInfoList: [{ CertId: "cert-rsa", EncryType: "inter_cert" }, { CertId: "cert-ecc", EncryType: "inter_cert" }], HTTP2: true }),
    );
    const certs = [
      { id: "cert-rsa", algorithm: "RSA" as const, notAfter: "2026-10-25T00:00:00.000Z" },
      { id: "cert-ecc", algorithm: "ECC" as const, notAfter: "2026-11-25T00:00:00.000Z" },
    ];
    await deployer("vod").apply(ctx, CREDS, target(rec("vod", "v.example.com", { extra, cert: certs[0], certs })), input(ECC));
    expect(fetch.calls[1]!.json).toMatchObject({
      UpdateCdnConfigParam: { HTTPS: { Switch: true, CertInfoList: [{ CertId: "cert-new" }, { CertId: "cert-rsa" }], HTTP2: true } },
    });
    expect((fetch.calls[1]!.json as any).UpdateCdnConfigParam.HTTPS.CertInfo).toBeUndefined();
  });

  it("柔佛地域的空间走 ap-southeast-1 的 endpoint", async () => {
    const { fetch, ctx } = setup(routes({ Switch: true, CertInfo: { CertId: "cert-old" } }, "vod.ap-southeast-1.volcengineapi.com"));
    await deployer("vod").apply(ctx, CREDS, target(rec("vod", "v.example.com", { extra: { ...extra, region: "ap-southeast-1" } })), input());
    expect(fetch.calls.map((c) => c.action)).toEqual(["DescribeVodDomainConfig", "UpdateVodDomainConfig"]);
    expect(fetch.calls[1]!.headers.authorization).toMatch(/\/ap-southeast-1\/vod\/request, /);
  });

  it("缺域名类型 / 空间时不处理；双证书查不到算法时不处理", () => {
    expect(deployer("vod").unsupported!(rec("vod", "v.example.com", { extra: { space: "s1", region: "cn-north-1" } }), "update")).toMatch(/域名类型/);
    const certs = [{ id: "a" }, { id: "b" }];
    expect(deployer("vod").unsupported!(rec("vod", "v.example.com", { extra, certs }), "update")).toMatch(/算法/);
    expect(deployer("vod").unsupported!(rec("vod", "v.example.com", { extra }), "update")).toBeUndefined();
  });
});

describe("volcengine live 部署", () => {
  const leafOf = (cert: LocalCert) => cert.certPem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/)![0];

  function routes(certList: unknown[] = [], details: Record<string, LocalCert> = {}) {
    return (req: FakeRequest): FakeReply => {
      if (req.url.host !== "live.volcengineapi.com") return undefined;
      if (req.action === "ListCertV2") return ok({ CertList: certList });
      if (req.action === "DescribeCertDetailSecretV2") {
        const c = details[req.json?.ChainID as string];
        return c ? ok({ ChainID: req.json?.ChainID, SSL: { Chain: [leafOf(c)], KeyType: "rsa" } }) : volcError("ResourceNotFound", "not found", 404);
      }
      if (req.action === "CreateCert") return ok({ ChainID: "chain-new", UseWay: "https" });
      if (req.action === "BindCert") return ok(null);
      return undefined;
    };
  }

  it("直播用自己的证书管理：没有同一张证书时 CreateCert 上传 PEM（项目与域名一致），再 BindCert 开启 HTTPS", async () => {
    const { fetch, ctx } = setup(routes([{ ChainID: "chain-other", NotAfter: "2026-12-01T00:00:00Z", ProjectName: "default" }]));
    const push = rec("live", "push.example.com", { extra: { type: "push", project: "proj1" }, cert: { id: "chain-old" } });
    const inp = input();
    expect(await deployer("live").apply(ctx, CREDS, target(push), inp)).toEqual({ certId: "chain-new" });
    expect(inp.uploads()).toBe(0);
    const create = fetch.calls.find((c) => c.action === "CreateCert")!;
    expect(create.url.href).toBe("https://live.volcengineapi.com/?Action=CreateCert&Version=2023-01-01");
    expect(create.json).toEqual({
      CertName: "sslbear-example.com-20270101",
      UseWay: "https",
      ProjectName: "proj1",
      Rsa: { Pubkey: RSA.certPem, Prikey: RSA.keyPem },
    });
    expect(fetch.calls.find((c) => c.action === "BindCert")!.json).toEqual({ Domain: "push.example.com", ChainID: "chain-new", HTTPS: true });
    // 到期时间不同的证书不必查详情
    expect(fetch.calls.some((c) => c.action === "DescribeCertDetailSecretV2")).toBe(false);
    noPemInUrl(fetch);
  });

  it("直播证书管理里已有同指纹的证书时复用其 ChainID；同到期时间的另一张（ECC）不误用", async () => {
    const list = [
      { ChainID: "chain-ecc", NotAfter: "2027-01-01T00:00:00Z", ProjectName: "default" },
      { ChainID: "chain-rsa", NotAfter: "2027-01-01T00:00:00Z", ProjectName: "default" },
      { ChainID: "chain-rsa-other-project", NotAfter: "2027-01-01T00:00:00Z", ProjectName: "proj2" },
    ];
    const { fetch, ctx } = setup(routes(list, { "chain-ecc": ECC, "chain-rsa": RSA, "chain-rsa-other-project": RSA }));
    const pull = rec("live", "pull.example.com", { https: false, extra: { type: "pull-flv", project: "default" } });
    const out = await deployer("live").apply(ctx, CREDS, target(pull), input(RSA));
    // 拉流域名开启 HTTPS 时 HTTP/2、TLS 版本取直播默认值，结果里提示
    expect(out).toEqual({ certId: "chain-rsa", note: expect.stringMatching(/HTTP\/2.*TLS/) });
    expect(fetch.calls.some((c) => c.action === "CreateCert")).toBe(false);
    expect(fetch.calls.filter((c) => c.action === "DescribeCertDetailSecretV2").map((c) => c.json?.ChainID)).toEqual(["chain-ecc", "chain-rsa"]);
    expect(fetch.calls.find((c) => c.action === "BindCert")!.json).toEqual({ Domain: "pull.example.com", ChainID: "chain-rsa", HTTPS: true });
  });

  it("同一次运行内同一项目只上传一次", async () => {
    const { fetch, ctx } = setup(routes());
    const a = rec("live", "a.example.com", { https: false, extra: { type: "pull-flv", project: "default" } });
    const b = rec("live", "b.example.com", { extra: { type: "push", project: "default" } });
    await Promise.all([deployer("live").apply(ctx, CREDS, target(a), input()), deployer("live").apply(ctx, CREDS, target(b), input())]);
    expect(fetch.calls.filter((c) => c.action === "CreateCert")).toHaveLength(1);
    expect(fetch.calls.filter((c) => c.action === "BindCert")).toHaveLength(2);
  });

  it("planDeploy + executeDeploy：推流域名更新、拉流域名更新记为 unsupported；不上传到证书中心", async () => {
    const { fetch, ctx } = setup((req) => {
      if (req.action === "ListDomainDetail") {
        return ok({
          Total: 2,
          DomainList: [
            { Domain: "push.example.com", Type: "push", Status: 0, ProjectName: "default", ChainID: "chain-old" },
            { Domain: "pull.example.com", Type: "pull-flv", Status: 0, ProjectName: "default", ChainID: "chain-old" },
          ],
        });
      }
      if (req.action === "ListCertV2") return ok({ CertList: [{ ChainID: "chain-old", NotAfter: "2026-10-25T00:00:00Z", ProjectName: "default" }] });
      return routes()(req);
    });
    const plan = await planDeploy(ctx, RSA, { providers: ["volcengine"], services: ["live"], force: false, dryRun: false });
    const report = await executeDeploy(ctx, RSA, plan);
    expect(report.results).toEqual([
      expect.objectContaining({ domain: "pull.example.com", action: "skipped", reason: "unsupported", message: expect.stringMatching(/HTTP\/2/) }),
      expect.objectContaining({ domain: "push.example.com", action: "updated", after: { id: "chain-new", notAfter: RSA.notAfter } }),
    ]);
    expect(report.uploads).toEqual([]);
    expect(fetch.calls.filter((c) => c.action === "BindCert").map((c) => c.json)).toEqual([{ Domain: "push.example.com", ChainID: "chain-new", HTTPS: true }]);
  });

  it("推流域名可以部署 / 更新；拉流域名可以部署，更新不处理（BindCert 会重置 HTTP/2 与 TLS 版本且读不到原值）", () => {
    const live = deployer("live");
    expect(live.unsupported!(rec("live", "push.example.com", { extra: { type: "push" } }), "update")).toBeUndefined();
    expect(live.unsupported!(rec("live", "push.example.com", { https: false, extra: { type: "push" } }), "deploy")).toBeUndefined();
    expect(live.unsupported!(rec("live", "pull.example.com", { https: false, extra: { type: "pull-flv" } }), "deploy")).toBeUndefined();
    expect(live.unsupported!(rec("live", "pull.example.com", { extra: { type: "pull-flv" } }), "update")).toMatch(/HTTP\/2/);
  });
});

describe("volcengine imagex 部署", () => {
  const extra = { serviceId: "svc1", serviceName: "pics", region: "cn-north-1" };

  it("更新：UpdateImageBatchDomainCert 只关联证书", async () => {
    const { fetch, ctx } = setup((req) => (req.action === "UpdateImageBatchDomainCert" ? ok({}) : undefined));
    const out = await deployer("imagex").apply(ctx, CREDS, target(rec("imagex", "img.example.com", { extra, cert: { id: "cert-old" } })), input());
    expect(out).toEqual({ certId: "cert-new" });
    const call = fetch.calls[0]!;
    expect(call.method).toBe("POST");
    expect(call.url.href).toBe("https://imagex.volcengineapi.com/?Action=UpdateImageBatchDomainCert&Version=2018-08-01");
    expect(call.headers.authorization).toMatch(/\/cn-north-1\/ImageX\/request, /);
    expect(call.json).toEqual({ cert_id: "cert-new", domain: "img.example.com" });
  });

  it("柔佛地域走 ap-southeast-1 的 endpoint", async () => {
    const { fetch, ctx } = setup((req) => (req.action === "UpdateImageBatchDomainCert" ? ok({}) : undefined));
    await deployer("imagex").apply(ctx, CREDS, target(rec("imagex", "img.example.com", { extra: { ...extra, region: "ap-southeast-1" } })), input());
    expect(fetch.calls[0]!.url.host).toBe("imagex.ap-southeast-1.volcengineapi.com");
    expect(fetch.calls[0]!.headers.authorization).toMatch(/\/ap-southeast-1\/ImageX\/request, /);
  });

  it("部署：先读域名配置，UpdateHttps 开启 HTTPS 并绑定证书（ServiceId 在 query、配置在 JSON 体）", async () => {
    const { fetch, ctx } = setup((req) => {
      if (req.action === "GetDomainConfig") return ok({ domain: "img.example.com", https_config: { enable_https: false, enable_http2: true, force_https: false } });
      if (req.action === "UpdateHttps") return ok({});
      return undefined;
    });
    const out = await deployer("imagex").apply(ctx, CREDS, target(rec("imagex", "img.example.com", { https: false, extra })), input());
    expect(out).toEqual({ certId: "cert-new", note: expect.stringMatching(/TLS.*OCSP/) });
    const [get, update] = fetch.calls;
    expect(get!.url.search).toBe("?Action=GetDomainConfig&DomainName=img.example.com&ServiceId=svc1&Version=2018-08-01");
    expect(update!.method).toBe("POST");
    expect(update!.url.href).toBe("https://imagex.volcengineapi.com/?Action=UpdateHttps&ServiceId=svc1&Version=2018-08-01");
    expect(update!.json).toEqual({
      domain: "img.example.com",
      https: { enable_https: true, cert_id: "cert-new", enable_http2: true, enable_ocsp: false, tls_versions: ["tlsv1.1", "tlsv1.2", "tlsv1.3"] },
    });
  });

  it("部署时原先开着强制跳转 HTTPS 的照样带上", async () => {
    const { fetch, ctx } = setup((req) => {
      if (req.action === "GetDomainConfig") return ok({ https_config: { enable_https: false, enable_http2: false, force_https: true } });
      if (req.action === "UpdateHttps") return ok({});
      return undefined;
    });
    await deployer("imagex").apply(ctx, CREDS, target(rec("imagex", "img.example.com", { https: false, extra })), input());
    expect(fetch.calls[1]!.json).toMatchObject({
      https: { enable_http2: false, enable_force_redirect: true, force_redirect_type: "http2https", force_redirect_code: "301" },
    });
  });
});

describe("volcengine 查询层为双证书补全算法", () => {
  const T = (iso: string) => Math.floor(Date.parse(iso) / 1000);

  it("点播：CertInfoList 的证书按 PEM 识别算法，列出全部证书", async () => {
    const { ctx } = setup((req) => {
      if (req.action === "ListSpace" && req.url.host === "vod.volcengineapi.com") return ok([{ SpaceName: "s1" }]);
      if (req.action === "ListSpace") return ok(null);
      if (req.action === "ListVodDomains") {
        return ok({ VodInfo: { Total: 1, Domains: [{ Domain: "v.example.com", DomainType: "vod_play" }] }, DomainInfo: { Total: 1, Data: [{ Domain: "v.example.com", HTTPS: true }] } });
      }
      if (req.action === "DescribeVodDomainConfig") {
        return ok({
          DomainInfo: {
            DomainConfig: {
              HTTPS: {
                Switch: true,
                CertInfoList: [
                  { CertId: "cert-rsa", ExpireTime: T("2026-10-25T00:00:00Z"), EncryType: "inter_cert", Certificate: { Certificate: RSA.certPem } },
                  { CertId: "cert-ecc", ExpireTime: T("2027-03-01T00:00:00Z"), EncryType: "inter_cert", Certificate: { Certificate: ECC.certPem } },
                ],
              },
            },
          },
        });
      }
      return undefined;
    });
    const [record] = await volcengine.services.find((s) => s.key === "vod")!.list(ctx, CREDS, () => {});
    expect(record!.cert).toMatchObject({ id: "cert-rsa", algorithm: "RSA" });
    expect(record!.certs).toEqual([
      expect.objectContaining({ id: "cert-rsa", algorithm: "RSA", notAfter: "2026-10-25T00:00:00.000Z" }),
      expect.objectContaining({ id: "cert-ecc", algorithm: "ECC", notAfter: "2027-03-01T00:00:00.000Z" }),
    ]);
  });
});
