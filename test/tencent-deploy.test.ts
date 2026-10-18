import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { loadLocalCert, type LocalCert } from "../src/deploy/cert.js";
import { executeDeploy, planDeploy } from "../src/deploy/run.js";
import { CloudApiError, type Fetch, type QueryContext } from "../src/lib/http.js";
import type { DeployInput, DeployTarget } from "../src/providers/registry.js";
import { tencent } from "../src/providers/tencent/index.js";
import { cosAuthorization } from "../src/providers/tencent/sign.js";
import type { DomainRecord } from "../src/types.js";
import { TENCENT_ENV, fakeFetch, type FakeReply, type FakeRequest } from "./helpers.js";

const FIX = fileURLToPath(new URL("./fixtures/deploy/", import.meta.url));
const NOW = new Date("2026-10-15T00:00:00Z");
const load = (name: string) => readFileSync(join(FIX, name), "utf8");
const RSA = loadLocalCert(load("rsa-fullchain.pem"), load("rsa-key.pem"), NOW);
const ECC = loadLocalCert(load("ecc-fullchain.pem"), load("ecc-key.pem"), NOW);
const CREDS = { secretId: "AKIDtest00000000", secretKey: "testkey" };

const ctxOf = (fetch: Fetch): QueryContext => ({ fetch, timeoutMs: 1000, now: NOW, env: TENCENT_ENV, sleep: async () => {} });
const ok = (data: Record<string, unknown> = {}) => ({ body: { Response: { RequestId: "rid", ...data } } });
const tcError = (Code: string, Message: string) => ({ body: { Response: { RequestId: "rid-err", Error: { Code, Message } } } });

const deployer = (key: string) => tencent.services.find((s) => s.key === key)!.deployer!;
const rec = (service: string, domain: string, r: Partial<DomainRecord> = {}): DomainRecord => ({ provider: "tencent", service, domain, https: true, ...r });
const inputOf = (cert: LocalCert = RSA, id = "new-cert"): DeployInput => ({ cert, certId: async () => id });
const apply = (key: string, route: (req: FakeRequest) => FakeReply, target: DeployTarget, input = inputOf()) => {
  const fetch = fakeFetch(route);
  return { fetch, result: deployer(key).apply(ctxOf(fetch), CREDS, target, input) };
};

const upload = (fetch: Fetch, cert: LocalCert = RSA) => tencent.uploadCertificate!(ctxOf(fetch), CREDS, cert);

describe("tencent uploadCertificate（SSL 证书）", () => {
  const sslList = (...ids: string[]) =>
    ok({ TotalCount: ids.length, Certificates: ids.map((id) => ({ CertificateId: id, Alias: id, Domain: "example.com", CertEndTime: "2027-01-01 08:00:00" })) });

  it("UploadCertificate 带完整证书链与私钥，Repeatable=false 让服务端按指纹查重；未重复时返回新证书 ID", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeCertificates") return sslList("other-1");
      return req.action === "UploadCertificate" ? ok({ CertificateId: "new-1", RepeatCertId: "" }) : undefined;
    });
    expect(await upload(fetch)).toEqual({ id: "new-1", reused: false });
    expect(fetch.calls.map((c) => c.action)).toEqual(["DescribeCertificates", "UploadCertificate"]);
    const call = fetch.calls[1]!;
    expect(call.url.href).toBe("https://ssl.tencentcloudapi.com/");
    expect(call.method).toBe("POST");
    expect(call.headers["x-tc-version"]).toBe("2019-12-05");
    expect(call.json).toEqual({
      CertificatePublicKey: RSA.certPem,
      CertificatePrivateKey: RSA.keyPem,
      CertificateType: "SVR",
      Alias: "sslbear-example.com-20270101",
      Repeatable: false,
    });
  });

  it("同指纹证书已存在：返回 RepeatCertId 并标记 reused", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeCertificates") return sslList("old-9");
      return req.action === "UploadCertificate" ? ok({ CertificateId: "", RepeatCertId: "old-9" }) : undefined;
    });
    expect(await upload(fetch)).toEqual({ id: "old-9", reused: true });
  });

  it("实测查重命中时 RepeatCertId 为空、CertificateId 直接是已有证书的 ID：按上传前的证书列表判断为复用", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeCertificates") return sslList("other-1", "old-9");
      return req.action === "UploadCertificate" ? ok({ CertificateId: "old-9", RepeatCertId: "" }) : undefined;
    });
    expect(await upload(fetch)).toEqual({ id: "old-9", reused: true });
  });

  it("查询阶段已拉过 SSL 证书列表时直接用它判断，不再重复拉取", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeCertificates") return sslList("old-9");
      return req.action === "UploadCertificate" ? ok({ CertificateId: "old-9", RepeatCertId: "" }) : undefined;
    });
    const ctx = ctxOf(fetch);
    await tencent.listCertificates!(ctx, CREDS);
    expect(await tencent.uploadCertificate!(ctx, CREDS, RSA)).toEqual({ id: "old-9", reused: true });
    expect(fetch.calls.map((c) => c.action)).toEqual(["DescribeCertificates", "UploadCertificate"]);
  });

  it("SSL 证书列表拉取失败（如没有只读权限）时照常上传，无法判断是否复用，按新上传报告", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeCertificates") return tcError("UnauthorizedOperation", "no permission");
      return req.action === "UploadCertificate" ? ok({ CertificateId: "old-9", RepeatCertId: "" }) : undefined;
    });
    expect(await upload(fetch)).toEqual({ id: "old-9", reused: false });
    expect(fetch.calls.map((c) => c.action)).toEqual(["DescribeCertificates", "UploadCertificate"]);
  });

  it("超时后自动重试不会重复建证书：重发的仍是 Repeatable=false，首次已建成时按指纹命中同一张，仍报告为新上传", async () => {
    // 模拟首个上传请求在服务端已建成证书、客户端却超时：重发时服务端查重命中刚建成的那张（实测 CertificateId 即其 ID）
    let created = false;
    const inner = fakeFetch((req) => {
      if (req.action === "DescribeCertificates") return sslList("other-1");
      if (req.action !== "UploadCertificate") return undefined;
      if (created) return ok({ CertificateId: "new-1", RepeatCertId: "" });
      created = true;
      return ok({ CertificateId: "new-1", RepeatCertId: "" });
    });
    let uploads = 0;
    const fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const res = await inner(input, init);
      const isUpload = (init?.headers as Record<string, string> | undefined)?.["X-TC-Action"] === "UploadCertificate";
      if (isUpload && uploads++ === 0) throw Object.assign(new Error("The operation was aborted due to timeout"), { name: "TimeoutError" });
      return res;
    }) as Fetch;
    expect(await upload(fetch)).toEqual({ id: "new-1", reused: false });
    const sent = inner.calls.filter((c) => c.action === "UploadCertificate");
    expect(sent).toHaveLength(2);
    expect(sent.map((c) => c.json?.Repeatable)).toEqual([false, false]);
    expect(sent[1]!.body).toBe(sent[0]!.body);
  });

  it("证书名里的 * 换成 _；没有 CN 时用第一个 SAN", async () => {
    const fetch = fakeFetch(() => ok({ CertificateId: "x" }));
    await upload(fetch, { ...RSA, commonName: "*.example.com" });
    await upload(fetch, { ...RSA, commonName: undefined, sans: ["*.a.example.com", "a.example.com"] });
    const aliases = fetch.calls.filter((c) => c.action === "UploadCertificate").map((c) => c.json?.Alias);
    expect(aliases).toEqual(["sslbear-_.example.com-20270101", "sslbear-_.a.example.com-20270101"]);
  });

  it("上传失败抛 CloudApiError，带错误码与 RequestId", async () => {
    const fetch = fakeFetch(() => tcError("FailedOperation.CertificateInvalid", "证书内容不合法"));
    const err = await upload(fetch).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CloudApiError);
    expect(err).toMatchObject({ code: "FailedOperation.CertificateInvalid", requestId: "rid-err" });
  });

  it("响应里既没有新证书 ID 也没有重复证书 ID 时报错", async () => {
    const fetch = fakeFetch(() => ok({ CertificateId: "", RepeatCertId: "" }));
    await expect(upload(fetch)).rejects.toMatchObject({ code: "InvalidResponse" });
  });
});

describe("tencent cdn 部署", () => {
  const HTTPS_OFF = {
    Switch: "off",
    Http2: "on",
    OcspStapling: "off",
    VerifyClient: "off",
    Spdy: "off",
    CertInfo: null,
    ClientCertInfo: null,
    Hsts: { Switch: "on", MaxAge: 600, IncludeSubDomains: "off" },
    TlsVersion: ["TLSv1.2", "TLSv1.3"],
    SslStatus: "closed",
  };
  const describeReply = (https: unknown, extra: Record<string, unknown> = {}) =>
    ok({ TotalNumber: 1, Domains: [{ Domain: "www.example.com", Status: "online", Https: https, HttpsBilling: { Switch: "on" }, ...extra }] });

  it("update：ModifyDomainConfig 只改 Https.CertInfo.CertId 这一叶子节点，其他 HTTPS 配置不动", async () => {
    const { fetch, result } = apply("cdn", (req) => (req.action === "ModifyDomainConfig" ? ok() : undefined), {
      mode: "update",
      records: [rec("cdn", "www.example.com")],
    });
    expect(await result).toEqual({ certId: "new-cert" });
    expect(fetch.calls).toHaveLength(1);
    expect(fetch.calls[0]!.url.host).toBe("cdn.tencentcloudapi.com");
    expect(fetch.calls[0]!.json).toEqual({ Domain: "www.example.com", Route: "Https.CertInfo.CertId", Value: JSON.stringify({ update: "new-cert" }) });
  });

  it("deploy：先按域名读出 Https 配置，开启 HTTPS 并换上证书，HTTP/2、HSTS、TLS 版本等原样带回", async () => {
    const { fetch, result } = apply(
      "cdn",
      (req) => {
        if (req.action === "DescribeDomainsConfig") return describeReply(HTTPS_OFF);
        if (req.action === "UpdateDomainConfig") return ok();
        return undefined;
      },
      { mode: "deploy", records: [rec("cdn", "www.example.com", { https: false })] },
    );
    expect(await result).toEqual({ certId: "new-cert" });
    expect(fetch.calls.map((c) => c.action)).toEqual(["DescribeDomainsConfig", "UpdateDomainConfig"]);
    expect(fetch.calls[0]!.json).toEqual({ Offset: 0, Limit: 100, Filters: [{ Name: "domain", Value: ["www.example.com"] }] });
    expect(fetch.calls[1]!.json).toEqual({
      Domain: "www.example.com",
      Https: {
        Switch: "on",
        Http2: "on",
        OcspStapling: "off",
        VerifyClient: "off",
        Spdy: "off",
        Hsts: { Switch: "on", MaxAge: 600, IncludeSubDomains: "off" },
        TlsVersion: ["TLSv1.2", "TLSv1.3"],
        CertInfo: { CertId: "new-cert" },
      },
    });
  });

  it("deploy：已配置的客户端证书（双向认证）原样带回，只带可写字段", async () => {
    const https = {
      ...HTTPS_OFF,
      VerifyClient: "on",
      ClientCertInfo: { Certificate: "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n", CertName: "ca", ExpireTime: "2030-01-01 00:00:00", DeployTime: "2026-01-01 00:00:00" },
    };
    const { fetch, result } = apply("cdn", (req) => (req.action === "DescribeDomainsConfig" ? describeReply(https) : ok()), {
      mode: "deploy",
      records: [rec("cdn", "www.example.com", { https: false })],
    });
    await result;
    expect(fetch.calls[1]!.json?.Https).toMatchObject({
      VerifyClient: "on",
      ClientCertInfo: { Certificate: "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n", CertName: "ca" },
    });
  });

  it("deploy：Https 配置为空时只传开关与证书", async () => {
    const { fetch, result } = apply("cdn", (req) => (req.action === "DescribeDomainsConfig" ? describeReply(null) : ok()), {
      mode: "deploy",
      records: [rec("cdn", "www.example.com", { https: false })],
    });
    await result;
    expect(fetch.calls[1]!.json?.Https).toEqual({ Switch: "on", CertInfo: { CertId: "new-cert" } });
  });

  it("deploy：HTTPS 服务（HttpsBilling）关着时照常部署，但提示 HTTPS 请求会被拦截", async () => {
    const { result } = apply(
      "cdn",
      (req) => (req.action === "DescribeDomainsConfig" ? describeReply(HTTPS_OFF, { HttpsBilling: { Switch: "off" } }) : ok()),
      { mode: "deploy", records: [rec("cdn", "www.example.com", { https: false })] },
    );
    expect((await result).note).toContain("HTTPS 服务");
  });

  it("deploy：写之前读到 HTTPS 已开启（与查询时不同）时不上传、不写配置，报 HttpsAlreadyEnabled", async () => {
    let uploaded = 0;
    const input: DeployInput = { cert: RSA, certId: async () => (uploaded++, "new-cert") };
    const https = { ...HTTPS_OFF, Switch: "on", CertInfo: { CertId: "other", Message: "other", ExpireTime: "2027-06-01 08:00:00" }, SslStatus: "deployed" };
    const { fetch, result } = apply(
      "cdn",
      (req) => (req.action === "DescribeDomainsConfig" ? describeReply(https) : ok()),
      { mode: "deploy", records: [rec("cdn", "www.example.com", { https: false })] },
      input,
    );
    const err = await result.catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CloudApiError);
    expect(err).toMatchObject({
      provider: "tencent",
      code: "HttpsAlreadyEnabled",
      message: "该域名的 HTTPS 已开启（与查询时不同），未做修改；请重新执行，按更新规则判断",
    });
    expect(fetch.calls.map((c) => c.action)).toEqual(["DescribeDomainsConfig"]);
    expect(uploaded).toBe(0);
  });

  it("deploy：查不到该域名时报错，不写配置", async () => {
    const { fetch, result } = apply("cdn", (req) => (req.action === "DescribeDomainsConfig" ? ok({ TotalNumber: 0, Domains: [] }) : ok()), {
      mode: "deploy",
      records: [rec("cdn", "www.example.com", { https: false })],
    });
    await expect(result).rejects.toMatchObject({ code: "DomainNotFound" });
    expect(fetch.calls.map((c) => c.action)).toEqual(["DescribeDomainsConfig"]);
  });
});

describe("tencent teo（EdgeOne）部署", () => {
  const extra = { zoneId: "zone-1", zone: "example.io", certMode: "sslcert" };
  const rsa = { id: "old-rsa", notAfter: "2026-10-20T00:00:00.000Z", algorithm: "RSA" as const };
  const ecc = { id: "old-ecc", notAfter: "2027-03-01T00:00:00.000Z", algorithm: "ECC" as const };
  const run = (record: DomainRecord, mode: DeployTarget["mode"], input = inputOf()) =>
    apply("teo", (req) => (req.action === "ModifyHostsCertificate" ? ok() : undefined), { mode, records: [record] }, input);

  it("update：RSA + ECC 双证书时只换同算法那张，另一张原样保留；不传客户端 / 回源证书配置", async () => {
    const { fetch, result } = run(rec("teo", "www.example.io", { cert: rsa, certs: [rsa, ecc], extra }), "update");
    expect(await result).toEqual({ certId: "new-cert" });
    expect(fetch.calls).toHaveLength(1);
    expect(fetch.calls[0]!.url.host).toBe("teo.tencentcloudapi.com");
    expect(fetch.calls[0]!.headers["x-tc-version"]).toBe("2022-09-01");
    expect(fetch.calls[0]!.json).toEqual({
      ZoneId: "zone-1",
      Hosts: ["www.example.io"],
      Mode: "sslcert",
      ServerCertInfo: [{ CertId: "old-ecc" }, { CertId: "new-cert" }],
    });
  });

  it("update：新证书是 ECC 时保留 RSA 那张", async () => {
    const { fetch, result } = run(rec("teo", "www.example.io", { cert: rsa, certs: [rsa, ecc], extra }), "update", inputOf(ECC));
    await result;
    expect(fetch.calls[0]!.json?.ServerCertInfo).toEqual([{ CertId: "old-rsa" }, { CertId: "new-cert" }]);
  });

  it("update：只有一张另一算法的证书时把它当作旧证书替换", async () => {
    const { fetch, result } = run(rec("teo", "www.example.io", { cert: ecc, extra }), "update");
    await result;
    expect(fetch.calls[0]!.json?.ServerCertInfo).toEqual([{ CertId: "new-cert" }]);
  });

  it("update：国密证书永远保留", async () => {
    const sm2 = { id: "old-sm2", notAfter: "2027-03-01T00:00:00.000Z", algorithm: "SM2" as const };
    const { fetch, result } = run(rec("teo", "www.example.io", { cert: rsa, certs: [rsa, sm2], extra }), "update");
    await result;
    expect(fetch.calls[0]!.json?.ServerCertInfo).toEqual([{ CertId: "old-sm2" }, { CertId: "new-cert" }]);
  });

  it("update：免费证书模式改为 SSL 托管证书，只挂新证书", async () => {
    const free = { id: "eo-free", notAfter: "2026-10-20T00:00:00.000Z" };
    const { fetch, result } = run(rec("teo", "www.example.io", { cert: free, extra: { ...extra, certMode: "eofreecert" } }), "update");
    await result;
    expect(fetch.calls[0]!.json).toMatchObject({ Mode: "sslcert", ServerCertInfo: [{ CertId: "new-cert" }] });
  });

  it("deploy：未配置证书的域名改为 sslcert 模式并挂上新证书", async () => {
    const { fetch, result } = run(rec("teo", "plain.example.io", { https: false, extra: { ...extra, certMode: "disable" } }), "deploy");
    await result;
    expect(fetch.calls[0]!.json).toEqual({ ZoneId: "zone-1", Hosts: ["plain.example.io"], Mode: "sslcert", ServerCertInfo: [{ CertId: "new-cert" }] });
  });

  it("unsupported：挂了多张证书但有证书查不到算法时不处理（无法判断该换哪张）", () => {
    const unknown = { id: "x", notAfter: "2027-03-01T00:00:00.000Z" };
    const d = deployer("teo");
    expect(d.unsupported?.(rec("teo", "a.example.io", { cert: rsa, certs: [rsa, unknown], extra }), "update")).toContain("算法");
    expect(d.unsupported?.(rec("teo", "a.example.io", { cert: rsa, certs: [rsa, ecc], extra }), "update")).toBeUndefined();
    expect(d.unsupported?.(rec("teo", "a.example.io", { cert: unknown, extra }), "update")).toBeUndefined();
  });
});

describe("tencent cos 部署", () => {
  const HOST = "static-1250000000.cos.ap-shanghai.myqcloud.com";
  const extra = { bucket: "static-1250000000", region: "ap-shanghai", type: "REST" };
  const BODY =
    "<DomainCertificate><CertificateInfo><CertType>CustomCert</CertType><CustomCert><CertId>new-cert</CertId></CustomCert></CertificateInfo>" +
    "<DomainList><DomainName>img.example.com</DomainName></DomainList></DomainCertificate>";

  for (const mode of ["update", "deploy"] as const) {
    it(`${mode}：PUT Bucket domaincertificate 用 SSL 证书 ID 绑定（绑定即开启 HTTPS），请求体签 Content-MD5`, async () => {
      const { fetch, result } = apply("cos", (req) => (req.method === "PUT" ? { body: "" } : undefined), {
        mode,
        records: [rec("cos", "img.example.com", { https: mode === "update", extra })],
      });
      expect(await result).toEqual({ certId: "new-cert" });
      expect(fetch.calls).toHaveLength(1);
      const call = fetch.calls[0]!;
      expect(call.method).toBe("PUT");
      expect(call.url.href).toBe(`https://${HOST}/?domaincertificate`);
      expect(call.body).toBe(BODY);
      const md5 = createHash("md5").update(BODY).digest("base64");
      expect(call.headers["content-md5"]).toBe(md5);
      expect(call.headers["content-type"]).toBe("application/xml");
      const [start, end] = /q-sign-time=(\d+);(\d+)/.exec(call.headers.authorization!)!.slice(1).map(Number) as [number, number];
      expect(call.headers.authorization).toBe(
        cosAuthorization({
          secretId: CREDS.secretId,
          secretKey: CREDS.secretKey,
          method: "PUT",
          path: "/",
          query: { domaincertificate: "" },
          headers: { host: HOST, "content-md5": md5, "content-type": "application/xml" },
          start,
          end,
        }),
      );
    });
  }

  it("域名里的 XML 特殊字符转义", async () => {
    const { fetch, result } = apply("cos", () => ({ body: "" }), { mode: "update", records: [rec("cos", "a&b.example.com", { extra })] });
    await result;
    expect(fetch.calls[0]!.body).toContain("<DomainName>a&amp;b.example.com</DomainName>");
  });

  it("失败时按 COS 的 XML 错误抛 CloudApiError", async () => {
    const err = `<Error><Code>InvalidArgument</Code><Message>cert not match domain</Message><RequestId>req-1</RequestId></Error>`;
    const { result } = apply("cos", () => ({ status: 400, body: err }), { mode: "update", records: [rec("cos", "img.example.com", { extra })] });
    await expect(result).rejects.toMatchObject({ code: "InvalidArgument", requestId: "req-1", httpStatus: 400 });
  });

  it("缺 bucket / region 时报错，不发请求", async () => {
    const { fetch, result } = apply("cos", () => ({ body: "" }), { mode: "update", records: [rec("cos", "img.example.com", { extra: { type: "REST" } })] });
    await expect(result).rejects.toThrow(/bucket/);
    expect(fetch.calls).toHaveLength(0);
  });
});

describe("tencent live 部署", () => {
  const OK = ok({ MismatchedDomainNames: [], Errors: [] });
  const run = (mode: DeployTarget["mode"], reply: FakeReply = OK) =>
    apply("live", (req) => (req.action === "ModifyLiveDomainCertBindings" ? reply : undefined), {
      mode,
      records: [rec("live", "play.example.com", { https: mode === "update", extra: { type: "play" } })],
    });

  it("update：ModifyLiveDomainCertBindings 用 SSL 证书 ID 绑定，HTTPS 启用状态保持不变（Status=-1）", async () => {
    const { fetch, result } = run("update");
    expect(await result).toEqual({ certId: "new-cert" });
    expect(fetch.calls).toHaveLength(1);
    expect(fetch.calls[0]!.url.host).toBe("live.tencentcloudapi.com");
    expect(fetch.calls[0]!.headers["x-tc-version"]).toBe("2018-08-01");
    expect(fetch.calls[0]!.json).toEqual({ DomainInfos: [{ DomainName: "play.example.com", Status: -1 }], CloudCertId: "new-cert" });
  });

  it("deploy：绑定证书并启用 HTTPS（Status=1）", async () => {
    const { fetch, result } = run("deploy");
    await result;
    expect(fetch.calls[0]!.json).toEqual({ DomainInfos: [{ DomainName: "play.example.com", Status: 1 }], CloudCertId: "new-cert" });
  });

  it("接口受理但该域名在 Errors 里：按其错误码失败", async () => {
    const { result } = run("update", ok({ MismatchedDomainNames: [], Errors: [{ DomainName: "play.example.com", Code: "FailedOperation.DomainNotExist", Message: "域名不存在" }] }));
    await expect(result).rejects.toMatchObject({ code: "FailedOperation.DomainNotExist", message: expect.stringContaining("域名不存在"), requestId: "rid" });
  });

  it("域名与证书不匹配（MismatchedDomainNames）时失败", async () => {
    const { result } = run("update", ok({ MismatchedDomainNames: ["play.example.com"], Errors: [] }));
    await expect(result).rejects.toMatchObject({ code: "CertDomainMismatch" });
  });

  it("unsupported：推流域名不能绑定证书", () => {
    const d = deployer("live");
    expect(d.unsupported?.(rec("live", "push.example.com", { https: false, extra: { type: "push" } }), "deploy")).toContain("推流域名");
    expect(d.unsupported?.(rec("live", "play.example.com", { extra: { type: "play" } }), "update")).toBeUndefined();
  });
});

describe("tencent vod 部署", () => {
  const run = (mode: DeployTarget["mode"], extra: Record<string, string> = { type: "VOD", subAppId: "1500000002" }) =>
    apply("vod", (req) => (req.action === "SetVodDomainCertificate" ? ok() : undefined), {
      mode,
      records: [rec("vod", "v.example.com", { https: mode === "update", extra })],
    });

  for (const mode of ["update", "deploy"] as const) {
    it(`${mode}：SetVodDomainCertificate(Operation=Set) 带 SubAppId，设置即开启 HTTPS`, async () => {
      const { fetch, result } = run(mode);
      expect(await result).toEqual({ certId: "new-cert" });
      expect(fetch.calls).toHaveLength(1);
      expect(fetch.calls[0]!.url.host).toBe("vod.tencentcloudapi.com");
      expect(fetch.calls[0]!.headers["x-tc-version"]).toBe("2018-07-17");
      expect(fetch.calls[0]!.json).toEqual({ Domain: "v.example.com", Operation: "Set", CertID: "new-cert", SubAppId: 1500000002 });
    });
  }

  it("老账号没有应用 ID 时不带 SubAppId", async () => {
    const { fetch, result } = run("update", { type: "VOD" });
    await result;
    expect(fetch.calls[0]!.json).toEqual({ Domain: "v.example.com", Operation: "Set", CertID: "new-cert" });
  });

  it("unsupported：EdgeOne 分发的域名、锁定中的域名", () => {
    const d = deployer("vod");
    expect(d.unsupported?.(rec("vod", "eo.example.com", { extra: { type: "EdgeOne" } }), "update")).toContain("EdgeOne");
    expect(d.unsupported?.(rec("vod", "v.example.com", { status: "Locked", extra: { type: "VOD" } }), "update")).toContain("锁定");
    expect(d.unsupported?.(rec("vod", "v.example.com", { status: "Online", extra: { type: "VOD" } }), "update")).toBeUndefined();
  });
});

describe("tencent 经编排层部署（planDeploy + executeDeploy）", () => {
  const WRITES = new Set(["UploadCertificate", "ModifyDomainConfig", "UpdateDomainConfig", "ModifyLiveDomainCertBindings"]);
  const route = (req: FakeRequest): FakeReply => {
    switch (req.action) {
      case "DescribeDomainsConfig":
        return ok({
          TotalNumber: 2,
          Domains: [
            { Domain: "due.example.com", Status: "online", Https: { Switch: "on", CertInfo: { CertId: "old-cdn", Message: "old", ExpireTime: "2026-10-25 08:00:00" } } },
            { Domain: "off.example.com", Status: "online", Https: { Switch: "off", CertInfo: null } },
          ],
        });
      case "DescribeLiveDomains":
        return ok({ AllCount: 2, DomainList: [{ Name: "push.example.com", Type: 0, Status: 1 }, { Name: "play.example.com", Type: 1, Status: 1 }] });
      case "DescribeLiveDomainCertBindings":
        return ok({ TotalNum: 1, LiveDomainCertBindings: [{ DomainName: "play.example.com", CertificateAlias: "old", Status: 1, CertExpireTime: "2026-10-30 08:00:00", CloudCertId: "old-live" }] });
      case "UploadCertificate":
        return ok({ CertificateId: "new-1", RepeatCertId: "" });
      case "ModifyDomainConfig":
        return ok();
      case "ModifyLiveDomainCertBindings":
        return ok({ MismatchedDomainNames: [], Errors: [] });
    }
    return undefined;
  };

  it("多个服务共用一次上传；到期的更新、推流域名 unsupported、未开 HTTPS 的跳过", async () => {
    const fetch = fakeFetch(route);
    const ctx = ctxOf(fetch);
    const plan = await planDeploy(ctx, RSA, { providers: ["tencent"], services: ["cdn", "live"], force: false, dryRun: false });
    const report = await executeDeploy(ctx, RSA, plan);
    expect(report.results.map((r) => [r.service, r.domain, r.action, r.reason])).toEqual([
      ["cdn", "due.example.com", "updated", undefined],
      ["cdn", "off.example.com", "skipped", "https_off"],
      ["live", "play.example.com", "updated", undefined],
      ["live", "push.example.com", "skipped", "unsupported"],
    ]);
    expect(report.results[0]!.after).toEqual({ id: "new-1", notAfter: RSA.notAfter });
    expect(report.uploads).toEqual([{ provider: "tencent", certId: "new-1", reused: false }]);
    expect(fetch.calls.filter((c) => c.action === "UploadCertificate")).toHaveLength(1);
    expect(fetch.calls.find((c) => c.action === "ModifyDomainConfig")!.json).toMatchObject({ Domain: "due.example.com", Route: "Https.CertInfo.CertId" });
    expect(fetch.calls.find((c) => c.action === "ModifyLiveDomainCertBindings")!.json).toMatchObject({ CloudCertId: "new-1" });
  });

  it("--dry-run 不上传、不写配置", async () => {
    const fetch = fakeFetch(route);
    const plan = await planDeploy(ctxOf(fetch), RSA, { providers: ["tencent"], services: ["cdn", "live"], force: false, dryRun: true });
    expect(plan.report.results.filter((r) => r.action === "would_update").map((r) => r.domain)).toEqual(["due.example.com", "play.example.com"]);
    expect(fetch.calls.filter((c) => WRITES.has(c.action ?? ""))).toEqual([]);
  });
});
