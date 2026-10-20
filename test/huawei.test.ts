import { describe, expect, it } from "vitest";
import { apigAuthorization, obsAuthorization, obsStringToSign } from "../src/providers/huawei/sign.js";
import { fakeFetch, runCli, type FakeRequest } from "./helpers.js";

const HUAWEI_ENV = { HUAWEICLOUD_SDK_AK: "HWtestak000000000000", HUAWEICLOUD_SDK_SK: "testsk" };

/** openssl 生成的测试证书：CN=static.example.cn，SAN 含 *.example.cn，由 SSLBear Test CA 签发，有效期 2026-08-01 ~ 2026-10-30T12:00Z */
const LEAF_PEM = `-----BEGIN CERTIFICATE-----
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

const apigError = (status: number, code: string, msg: string) => ({ status, body: { error_code: code, error_msg: msg, request_id: `rid-${code}` } });

const SCM_CERTS = [
  {
    id: "scs1554192131150",
    name: "wild",
    domain: "*.example.cn",
    sans: "example.cn;static.example.cn",
    type: "DV_SSL_CERT",
    brand: "GEOTRUST",
    expire_time: "2026-10-30 12:00:00.0",
    status: "ISSUED",
  },
  { id: "scs1554192131151", name: "uploaded", domain: "up.example.cn", sans: "", expire_time: "2026-12-01 08:00:00.0", status: "UPLOAD" },
];

function scmRoute(req: FakeRequest) {
  if (req.url.host === "scm.cn-north-4.myhuaweicloud.com" && req.url.pathname === "/v3/scm/certificates") {
    return { body: { total_count: SCM_CERTS.length, certificates: SCM_CERTS } };
  }
  return undefined;
}

const byDomain = (items: any[]) => Object.fromEntries(items.map((d) => [d.domain, d]));

describe("huawei 请求格式", () => {
  it("API 网关：GET + SDK-HMAC-SHA256，Host / X-Sdk-Date / X-Security-Token 参与签名", async () => {
    const fetch = fakeFetch(scmRoute);
    const r = await runCli(["certs", "-p", "huawei", "--json"], { env: { ...HUAWEI_ENV, HUAWEICLOUD_SDK_SECURITY_TOKEN: "tok" }, fetch });
    expect(r.code).toBe(0);
    const call = fetch.calls[0]!;
    expect(call.method).toBe("GET");
    expect(call.url.pathname).toBe("/v3/scm/certificates");
    expect(Object.fromEntries(call.url.searchParams)).toEqual({ limit: "50", offset: "0", expired_days_since: "1095" });
    expect(call.headers["x-security-token"]).toBe("tok");
    expect(call.headers["content-type"]).toBe("application/json");
    expect(call.headers["x-sdk-date"]).toMatch(/^\d{8}T\d{6}Z$/);
    expect(call.headers.authorization).toMatch(
      /^SDK-HMAC-SHA256 Access=HWtestak000000000000, SignedHeaders=host;x-sdk-date;x-security-token, Signature=[0-9a-f]{64}$/,
    );
    // 按实际发出的请求重算签名，确认签名用的路径、查询串与发送的一致
    expect(call.headers.authorization).toBe(
      apigAuthorization({
        accessKeyId: HUAWEI_ENV.HUAWEICLOUD_SDK_AK,
        secretAccessKey: HUAWEI_ENV.HUAWEICLOUD_SDK_SK,
        method: "GET",
        path: call.url.pathname,
        query: Object.fromEntries(call.url.searchParams),
        headers: { Host: call.url.host, "X-Sdk-Date": call.headers["x-sdk-date"]!, "X-Security-Token": "tok" },
      }),
    );
  });

  it("无权限时报错写出缺少的 IAM 权限与可授予的系统策略（新旧两版 IAM）", async () => {
    const denied = (action: string, resource: string) =>
      `User: iam::0000:user:dev is not authorized to perform: ${action} on resource: ${resource} because no identity-based policy allows the ${action} action.`;
    const fetch = fakeFetch((req) =>
      req.url.pathname === "/v3/scm/certificates" ? apigError(403, "SCM.4002", `Permission denied. Policy does not allow action to be performed${denied("scm:cert:list", "scm:cn-north-4:0000:cert:*")}`) : undefined,
    );
    const r = await runCli(["certs", "-p", "huawei", "--json"], { env: HUAWEI_ENV, fetch });
    expect(r.code).toBe(1);
    expect(JSON.parse(r.stderr).issues).toEqual([
      expect.objectContaining({
        code: "SCM.4002",
        message: expect.stringMatching(/scm:cert:list action\.（缺少 IAM 权限 scm:cert:list，可授予系统策略 SCMReadOnlyPolicy，旧版 IAM 授予 SCM ReadOnlyAccess）$/),
      }),
    ]);
  });

  it("别名 HW_ACCESS_KEY / HW_SECRET_KEY 也可用", async () => {
    const fetch = fakeFetch(scmRoute);
    const r = await runCli(["certs", "-p", "huawei", "--json"], { env: { HW_ACCESS_KEY: "HWalias0000000000000", HW_SECRET_KEY: "s" }, fetch });
    expect(r.code).toBe(0);
    expect(fetch.calls[0]!.headers.authorization).toMatch(/^SDK-HMAC-SHA256 Access=HWalias0000000000000, SignedHeaders=host;x-sdk-date,/);
  });
});

describe("huawei certs", () => {
  it("SCM 证书：北京时间（带小数秒）换算成 UTC，附加域名按分号拆分并补上主域名，上传的证书来源记为 upload", async () => {
    const r = await runCli(["certs", "--json"], { env: HUAWEI_ENV, fetch: fakeFetch(scmRoute) });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toEqual([
      {
        provider: "huawei",
        id: "scs1554192131150",
        name: "wild",
        commonName: "*.example.cn",
        sans: ["*.example.cn", "example.cn", "static.example.cn"],
        issuer: "GEOTRUST",
        notAfter: "2026-10-30T04:00:00.000Z",
        status: "ISSUED",
        source: "DV_SSL_CERT",
        daysLeft: 15,
      },
      {
        provider: "huawei",
        id: "scs1554192131151",
        name: "uploaded",
        commonName: "up.example.cn",
        sans: ["up.example.cn"],
        notAfter: "2026-12-01T00:00:00.000Z",
        status: "UPLOAD",
        source: "upload",
        daysLeft: 47,
      },
    ]);
  });

  it("按条目偏移分页，以 total_count 为准", async () => {
    const all = Array.from({ length: 51 }, (_, i) => ({ id: `scs${String(i).padStart(13, "0")}`, domain: `d${i}.example.cn`, status: "ISSUED" }));
    const fetch = fakeFetch((req) => {
      const offset = Number(req.url.searchParams.get("offset"));
      return { body: { total_count: all.length, certificates: all.slice(offset, offset + 50) } };
    });
    const r = await runCli(["certs", "-p", "huawei", "--json"], { env: HUAWEI_ENV, fetch });
    expect(r.json.data.items).toHaveLength(51);
    expect(fetch.calls.map((c) => c.url.searchParams.get("offset"))).toEqual(["0", "50"]);
  });

  it("错误体 {error_code, error_msg, request_id}；网关限流 APIGW.0308（HTTP 429）自动重试", async () => {
    const failed = await runCli(["certs", "-p", "huawei", "--json"], {
      env: HUAWEI_ENV,
      fetch: fakeFetch(() => apigError(401, "APIGW.0301", "Incorrect IAM authentication information: Unauthorized")),
    });
    expect(failed.code).toBe(1);
    expect(JSON.parse(failed.stderr)).toMatchObject({
      ok: false,
      status: "APIGW.0301",
      issues: [expect.objectContaining({ service: "cert", kind: "error", code: "APIGW.0301", requestId: "rid-APIGW.0301" })],
    });

    let n = 0;
    const fetch = fakeFetch((req) => (n++ === 0 ? apigError(429, "APIGW.0308", "The throttling threshold has been reached") : scmRoute(req)));
    const r = await runCli(["certs", "-p", "huawei", "--json"], { env: HUAWEI_ENV, fetch });
    expect(r.code).toBe(0);
    expect(fetch.calls).toHaveLength(2);
    expect(r.json.data.items).toHaveLength(2);
  });
});

describe("huawei cdn", () => {
  it("域名列表 + HTTPS 证书列表合并：开关以域名列表为准，解析 PEM 证书，多张证书取最早到期", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.host !== "cdn.myhuaweicloud.com") return undefined;
      if (req.url.pathname === "/v1.0/cdn/domains") {
        return {
          body: {
            total: 4,
            domains: [
              { domain_name: "static.example.cn", domain_status: "online", business_type: "web", service_area: "mainland_china", https_status: 1 },
              // 实测开启 HTTPS 的域名 https_status 为 2 / 3，不只是文档写的 1
              { domain_name: "dual.example.cn", domain_status: "online", business_type: "web", service_area: "mainland_china", https_status: 3 },
              { domain_name: "dl.example.cn", domain_status: "offline", business_type: "download", service_area: "global", https_status: 0 },
              { domain_name: "img.example.cn", domain_status: "online", business_type: "web", service_area: "mainland_china", https_status: 1 },
            ],
          },
        };
      }
      if (req.url.pathname === "/v1.0/cdn/domains/https-certificate-info") {
        return {
          body: {
            total: 5,
            https: [
              {
                // 真实响应在外层字段之外还带 certificates 数组；双证书时外层只描述其中一张
                domain_name: "dual.example.cn",
                cert_name: "dual-rsa",
                certificate: LEAF_PEM,
                private_key: "",
                certificate_type: 0,
                expiration_time: Date.parse("2026-10-30T12:00:00Z"),
                https_status: 3,
                certificates: [
                  { certificate_type: "server", certificate_source: 0, certificate_name: "dual-rsa", certificate_value: LEAF_PEM, private_key: "", expire_time: Date.parse("2026-10-30T12:00:00Z") },
                  { certificate_type: "server_sm", certificate_source: 2, certificate_name: "dual-sm2", certificate_value: "", expire_time: Date.parse("2026-10-25T00:00:00Z") },
                ],
              },
              {
                domain_name: "static.example.cn",
                cert_name: "static-sm2",
                certificate: null,
                certificate_type: 2,
                expiration_time: Date.parse("2027-01-01T00:00:00Z"),
                https_status: 1,
              },
              {
                domain_name: "static.example.cn",
                cert_name: "static-rsa",
                certificate: LEAF_PEM,
                private_key: null,
                certificate_type: 0,
                expiration_time: Date.parse("2026-10-30T12:00:00Z"),
                https_status: 1,
              },
              { domain_name: "dl.example.cn", cert_name: "dl", certificate: "", certificate_type: 0, expiration_time: Date.parse("2026-10-20T00:00:00Z"), https_status: 0 },
              {
                domain_name: "img.example.cn",
                cert_name: "img",
                certificate: "-----BEGIN CERTIFICATE-----XX-----END CERTIFICATE-----",
                certificate_type: 2,
                expiration_time: Date.parse("2026-11-20T00:00:00Z"),
                https_status: 1,
              },
            ],
          },
        };
      }
      return undefined;
    });
    const r = await runCli(["domains", "-p", "huawei", "-s", "cdn", "--json"], { env: HUAWEI_ENV, fetch });
    expect(r.code).toBe(0);
    for (const call of fetch.calls) {
      expect(call.url.searchParams.get("enterprise_project_id")).toBe("all");
      expect(call.url.searchParams.get("page_number")).toBe("1");
    }
    expect(fetch.calls.map((c) => c.url.searchParams.get("page_size")).sort()).toEqual(["1000", "10000"]);
    const items = byDomain(r.json.data.items);
    expect(items["static.example.cn"]).toEqual({
      provider: "huawei",
      service: "cdn",
      domain: "static.example.cn",
      status: "online",
      https: true,
      cert: {
        name: "static-rsa",
        commonName: "static.example.cn",
        sans: ["static.example.cn", "*.example.cn"],
        issuer: "SSLBear Test CA",
        notBefore: "2026-08-01T00:00:00.000Z",
        notAfter: "2026-10-30T12:00:00.000Z",
        algorithm: "ECC",
      },
      // 多张证书时列出全部：算法已知的国际证书在前（取不到 PEM 的那张算法未知）
      certs: [
        {
          name: "static-rsa",
          commonName: "static.example.cn",
          sans: ["static.example.cn", "*.example.cn"],
          issuer: "SSLBear Test CA",
          notBefore: "2026-08-01T00:00:00.000Z",
          notAfter: "2026-10-30T12:00:00.000Z",
          algorithm: "ECC",
        },
        { name: "static-sm2", notAfter: "2027-01-01T00:00:00.000Z" },
      ],
      extra: { businessType: "web", serviceArea: "mainland_china", certSource: "user" },
      daysLeft: 15,
    });
    // HTTPS 关闭的域名即使绑过证书也不给出 cert
    expect(items["dl.example.cn"]).toEqual({
      provider: "huawei",
      service: "cdn",
      domain: "dl.example.cn",
      status: "offline",
      https: false,
      extra: { businessType: "download", serviceArea: "global" },
    });
    // certificates 数组里的国密证书先到期；certificates 的证书类型标出国密证书
    expect(items["dual.example.cn"]).toMatchObject({
      https: true,
      cert: { name: "dual-sm2", notAfter: "2026-10-25T00:00:00.000Z", algorithm: "SM2" },
      certs: [
        { name: "dual-rsa", notAfter: "2026-10-30T12:00:00.000Z", algorithm: "ECC" },
        { name: "dual-sm2", algorithm: "SM2" },
      ],
      extra: { certSource: "scm", smCertSource: "scm" },
      daysLeft: 10,
    });
    // PEM 解析失败时退回接口给的毫秒时间戳
    expect(items["img.example.cn"]).toMatchObject({
      https: true,
      cert: { name: "img", notAfter: "2026-11-20T00:00:00.000Z" },
      extra: { certSource: "scm" },
      daysLeft: 36,
    });
  });

  it("CDN 未开通（HTTP 200 + {error:{error_code}}）与 OBS 未注册（NotSignedUp）记为 inactive", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.host === "cdn.myhuaweicloud.com") {
        return { status: 200, body: { error: { error_code: "CDN.0114", error_msg: "The billing mode has not been configured." } } };
      }
      if (req.url.host === "obs.cn-north-4.myhuaweicloud.com") {
        return {
          status: 403,
          body: '<?xml version="1.0" encoding="UTF-8"?><Error><Code>NotSignedUp</Code><Message>Your account is not signed up for OBS.</Message><RequestId>obs-rid</RequestId></Error>',
        };
      }
      return undefined;
    });
    const r = await runCli(["domains", "-p", "huawei", "-s", "cdn,obs", "--json"], { env: HUAWEI_ENV, fetch });
    expect(r.json.data.items).toEqual([]);
    expect(r.json.data.issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ service: "cdn", kind: "inactive", code: "CDN.0114" }),
        expect.objectContaining({ service: "obs", kind: "inactive", code: "NotSignedUp", requestId: "obs-rid" }),
      ]),
    );
  });
});

const PROJECTS = [
  { id: "p-bj4", name: "cn-north-4", enabled: true },
  { id: "p-bj1", name: "cn-north-1", enabled: true },
  { id: "p-sh1", name: "cn-east-3", enabled: true },
  { id: "p-bj4-sub", name: "cn-north-4_sub", enabled: true },
  { id: "p-sg", name: "ap-southeast-3", enabled: true },
  { id: "p-mos", name: "MOS", enabled: true },
];

function iamRoute(req: FakeRequest, projects: { id: string; name: string; enabled?: boolean }[] = PROJECTS) {
  if (req.url.host === "iam.myhuaweicloud.com" && req.url.pathname === "/v3/auth/projects") return { body: { projects } };
  return undefined;
}

describe("huawei live", () => {
  it("按 IAM 项目逐地域查询：合并证书列表、多证书取最早到期、按 ID 从 SCM 补全，未使用的地域静默跳过", async () => {
    const fetch = fakeFetch((req) => {
      const iam = iamRoute(req) ?? scmRoute(req);
      if (iam) return iam;
      const path = req.url.pathname;
      if (req.url.host === "live.cn-north-4.myhuaweicloud.com") {
        if (path === "/v1/p-bj4/domain") {
          return {
            body: {
              total: 4,
              domain_info: [
                { domain: "play.example.cn", domain_type: "pull", status: "on", region: "cn-north-4", service_area: "mainland_china" },
                { domain: "push.example.cn", domain_type: "push", status: "on", region: "cn-north-4" },
                { domain: "play2.example.cn", domain_type: "pull", status: "off", region: "cn-north-4" },
                { domain: "play3.example.cn", domain_type: "pull", status: "on", region: "cn-north-4" },
              ],
            },
          };
        }
        if (path === "/v2/p-bj4/certificates") {
          return {
            body: {
              total: 3,
              certificates_info: [
                // 国密证书与国际证书各一条，取先到期的国际证书；列表时间按真实响应比证书有效期早 8 小时
                { play_domain: "play.example.cn", cert_type: 1, gm_cert_type: 1, source: "scm", cert_id: "scs-gm", cert_name: "gm", start_time: "2026-02-28T16:00:00Z", expire_time: "2027-02-28T16:00:00Z" },
                { play_domain: "play.example.cn", cert_type: 0, gm_cert_type: 0, source: "user", cert_name: "", cert_id: "", start_time: "2026-07-31T16:00:00Z", expire_time: "2026-10-30T04:00:00Z" },
                // 缺到期时间且取不到 PEM，按证书 ID 从 SCM 补全
                { play_domain: "play2.example.cn", cert_type: 0, source: "scm", cert_id: "scs1554192131150", cert_name: "wild" },
              ],
            },
          };
        }
        if (path === "/v1/p-bj4/guard/https-cert") {
          const domain = req.url.searchParams.get("domain");
          // 真实响应：国际证书在 certificate 与 tls_certificate.certificate 各一份，私钥为空串
          if (domain === "play.example.cn") {
            return { body: { certificate_format: "PEM", certificate: LEAF_PEM, certificate_key: "", force_redirect: false, gm_certificate: {}, tls_certificate: { certificate: LEAF_PEM } } };
          }
          if (domain === "play2.example.cn") return { body: { certificate_format: "", certificate: "", certificate_key: "", gm_certificate: {}, tls_certificate: {} } };
        }
      }
      if (req.url.host === "live.cn-north-1.myhuaweicloud.com") return apigError(400, "LIVE.100011009", "The requested user does not exist.");
      if (req.url.host === "live.cn-east-3.myhuaweicloud.com") return apigError(500, "LIVE.100011005", "Server internal error");
      if (req.url.host === "live.ap-southeast-3.myhuaweicloud.com") {
        if (path === "/v1/p-sg/domain") {
          return {
            body: {
              total: 2,
              domain_info: [
                { domain: "play.example.cn", domain_type: "pull", status: "on" },
                { domain: "sg.example.com", domain_type: "pull", status: "on" },
              ],
            },
          };
        }
        // 列表接口报资源不存在等同没有数据
        if (path === "/v2/p-sg/certificates") return apigError(404, "LIVE.103011019", "The resource to access is not exists");
      }
      return undefined;
    });
    const r = await runCli(["domains", "-p", "huawei", "-s", "live", "--json"], { env: HUAWEI_ENV, fetch });
    expect(r.code).toBe(0);
    // 只查有项目的直播地域，子项目与 MOS 不查；ap-southeast-2 没有项目
    expect(new Set(fetch.calls.map((c) => c.url.host))).toEqual(
      new Set([
        "iam.myhuaweicloud.com",
        "live.cn-north-4.myhuaweicloud.com",
        "live.cn-north-1.myhuaweicloud.com",
        "live.cn-east-3.myhuaweicloud.com",
        "live.ap-southeast-3.myhuaweicloud.com",
        "scm.cn-north-4.myhuaweicloud.com",
      ]),
    );
    const liveCall = fetch.calls.find((c) => c.url.pathname === "/v2/p-bj4/certificates")!;
    expect(liveCall.headers["x-project-id"]).toBe("p-bj4");
    expect(liveCall.headers.authorization).toMatch(/SignedHeaders=host;x-project-id;x-sdk-date,/);
    expect(Object.fromEntries(liveCall.url.searchParams)).toEqual({ offset: "0", limit: "100" });
    // 只对证书列表里出现的播放域名取证书内容，每个域名一次
    expect(
      fetch.calls
        .filter((c) => c.url.pathname.endsWith("/guard/https-cert"))
        .map((c) => `${c.url.host} ${c.url.searchParams.get("domain")}`)
        .sort(),
    ).toEqual(["live.cn-north-4.myhuaweicloud.com play.example.cn", "live.cn-north-4.myhuaweicloud.com play2.example.cn"]);

    const items = r.json.data.items;
    expect(items.filter((d: any) => d.domain === "play.example.cn")).toHaveLength(1);
    const map = byDomain(items);
    expect(map["play.example.cn"]).toEqual({
      provider: "huawei",
      service: "live",
      domain: "play.example.cn",
      status: "on",
      https: true,
      // 时间、CN、SAN、签发者都取自 PEM（证书真实有效期 2026-08-01 ~ 2026-10-30T12:00Z）
      cert: {
        commonName: "static.example.cn",
        sans: ["static.example.cn", "*.example.cn"],
        issuer: "SSLBear Test CA",
        notBefore: "2026-08-01T00:00:00.000Z",
        notAfter: "2026-10-30T12:00:00.000Z",
        algorithm: "ECC",
      },
      // 国际 + 国密双证书时列出全部，国际证书在前
      certs: [
        {
          commonName: "static.example.cn",
          sans: ["static.example.cn", "*.example.cn"],
          issuer: "SSLBear Test CA",
          notBefore: "2026-08-01T00:00:00.000Z",
          notAfter: "2026-10-30T12:00:00.000Z",
          algorithm: "ECC",
        },
        { id: "scs-gm", name: "gm", notBefore: "2026-03-01T00:00:00.000Z", notAfter: "2027-03-01T00:00:00.000Z", algorithm: "SM2" },
      ],
      extra: { region: "cn-north-4", projectId: "p-bj4", type: "pull", serviceArea: "mainland_china", certSource: "user", smCertSource: "scm" },
      daysLeft: 15,
    });
    expect(map["push.example.cn"]).toEqual({
      provider: "huawei",
      service: "live",
      domain: "push.example.cn",
      status: "on",
      https: false,
      extra: { region: "cn-north-4", projectId: "p-bj4", type: "push" },
    });
    expect(map["play2.example.cn"]).toMatchObject({
      status: "off",
      https: true,
      cert: {
        id: "scs1554192131150",
        name: "wild",
        commonName: "*.example.cn",
        sans: ["*.example.cn", "example.cn", "static.example.cn"],
        notAfter: "2026-10-30T04:00:00.000Z",
        status: "ISSUED",
      },
      extra: { certSource: "scm" },
      daysLeft: 15,
    });
    expect(map["play3.example.cn"]).toMatchObject({ https: false });
    expect(map["play3.example.cn"].cert).toBeUndefined();
    expect(map["sg.example.com"]).toMatchObject({ https: false, extra: { region: "ap-southeast-3", type: "pull" } });
    expect(r.json.data.issues).toEqual([
      expect.objectContaining({ service: "live", kind: "error", target: "region cn-east-3", code: "LIVE.100011005", requestId: "rid-LIVE.100011005" }),
    ]);
  });

  it("所有地域都报直播用户不存在时记为 inactive；服务自定义的限流错误码会重试", async () => {
    const onlyBj4 = [{ id: "p-bj4", name: "cn-north-4" }];
    const inactive = await runCli(["domains", "-p", "huawei", "-s", "live", "--json"], {
      env: HUAWEI_ENV,
      fetch: fakeFetch((req) => iamRoute(req, onlyBj4) ?? apigError(400, "LIVE.100011009", "The requested user does not exist.")),
    });
    expect(inactive.json.data.issues).toEqual([expect.objectContaining({ service: "live", kind: "inactive", code: "LIVE.100011009" })]);
    expect(inactive.json.data.issues[0].target).toBeUndefined();

    let n = 0;
    const fetch = fakeFetch((req) => {
      const iam = iamRoute(req, onlyBj4);
      if (iam) return iam;
      if (req.url.pathname === "/v1/p-bj4/domain") {
        if (n++ === 0) return apigError(500, "LIVE.100011007", "The number of concurrent API requests exceeds the upper limit.");
        return { body: { total: 1, domain_info: [{ domain: "play.example.cn", domain_type: "pull", status: "on" }] } };
      }
      if (req.url.pathname === "/v2/p-bj4/certificates") return { body: { total: 0, certificates_info: [] } };
      return undefined;
    });
    const r = await runCli(["domains", "-p", "huawei", "-s", "live", "--json"], { env: HUAWEI_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.issues).toEqual([]);
    expect(r.json.data.items).toEqual([expect.objectContaining({ domain: "play.example.cn", https: false })]);
    expect(fetch.calls.filter((c) => c.url.pathname === "/v1/p-bj4/domain")).toHaveLength(2);
  });

  it("证书列表的 offset 是页码（从 0 开始）；取证书内容失败时记 issue，到期时间用证书列表的并补回 8 小时", async () => {
    const onlyBj4 = [{ id: "p-bj4", name: "cn-north-4" }];
    const listed = [
      ...Array.from({ length: 100 }, (_, i) => ({ play_domain: `gone${i}.example.cn`, cert_type: 0, source: "user", expire_time: "2026-12-01T00:00:00Z" })),
      { play_domain: "a.example.cn", cert_type: 0, source: "scm", cert_id: "scs-a", cert_name: "a", start_time: "2026-09-30T16:00:00Z", expire_time: "2026-12-30T16:00:00Z" },
    ];
    const fetch = fakeFetch((req) => {
      const iam = iamRoute(req, onlyBj4);
      if (iam) return iam;
      const path = req.url.pathname;
      if (path === "/v1/p-bj4/domain") {
        return { body: { total: 2, domain_info: [{ domain: "a.example.cn", domain_type: "pull", status: "on" }, { domain: "push.example.cn", domain_type: "push", status: "on" }] } };
      }
      if (path === "/v2/p-bj4/certificates") {
        const page = Number(req.url.searchParams.get("offset"));
        const limit = Number(req.url.searchParams.get("limit"));
        // 真实接口：offset * limit 超出总数时报 page too large
        if (page * limit >= listed.length) return apigError(400, "LIVE.100011001", "page too large");
        return { body: { total: listed.length, certificates_info: listed.slice(page * limit, (page + 1) * limit) } };
      }
      if (path === "/v1/p-bj4/guard/https-cert") return apigError(403, "LIVE.100011003", "Permission denied");
      return undefined;
    });
    const r = await runCli(["domains", "-p", "huawei", "-s", "live", "--json"], { env: HUAWEI_ENV, fetch });
    expect(r.code).toBe(0);
    expect(fetch.calls.filter((c) => c.url.pathname === "/v2/p-bj4/certificates").map((c) => c.url.searchParams.get("offset"))).toEqual(["0", "1"]);
    // 不在域名列表里的播放域名不取证书内容
    expect(fetch.calls.filter((c) => c.url.pathname === "/v1/p-bj4/guard/https-cert").map((c) => c.url.searchParams.get("domain"))).toEqual(["a.example.cn"]);
    expect(byDomain(r.json.data.items)["a.example.cn"]).toEqual({
      provider: "huawei",
      service: "live",
      domain: "a.example.cn",
      status: "on",
      https: true,
      cert: { id: "scs-a", name: "a", notBefore: "2026-10-01T00:00:00.000Z", notAfter: "2026-12-31T00:00:00.000Z" },
      extra: { region: "cn-north-4", projectId: "p-bj4", type: "pull", certSource: "scm" },
      daysLeft: 77,
    });
    expect(r.json.data.issues).toEqual([
      expect.objectContaining({ service: "live", kind: "error", target: "domain a.example.cn HTTPS 证书内容（到期时间改用证书列表）", code: "LIVE.100011003" }),
    ]);
  });

  it("查询失败导致国际证书缺到期时间（取证书内容失败且列表没给时间、SCM 补全失败）时标 httpsUnknown；只缺国密证书的到期时间不标", async () => {
    const onlyBj4 = [{ id: "p-bj4", name: "cn-north-4" }];
    const fetch = fakeFetch((req) => {
      const iam = iamRoute(req, onlyBj4);
      if (iam) return iam;
      if (req.url.host === "scm.cn-north-4.myhuaweicloud.com") return apigError(403, "SCM.0403", "Permission denied");
      const path = req.url.pathname;
      if (path === "/v1/p-bj4/domain") {
        const names = ["nopem", "timed", "scm", "gm", "ok"];
        return { body: { total: names.length, domain_info: names.map((n) => ({ domain: `${n}.example.cn`, domain_type: "pull", status: "on" })) } };
      }
      if (path === "/v2/p-bj4/certificates") {
        return {
          body: {
            total: 6,
            certificates_info: [
              // 取证书内容失败、列表也没给时间
              { play_domain: "nopem.example.cn", cert_type: 0, source: "user" },
              // 取证书内容失败，但列表给了时间
              { play_domain: "timed.example.cn", cert_type: 0, source: "user", expire_time: "2026-12-30T16:00:00Z" },
              // 没有 PEM 也没有时间，要从 SCM 补全，SCM 失败
              { play_domain: "scm.example.cn", cert_type: 0, source: "scm", cert_id: "scs1554192131150", cert_name: "wild" },
              // 国际证书齐全，只有国密证书缺时间
              { play_domain: "gm.example.cn", cert_type: 0, source: "user", expire_time: "2026-12-30T16:00:00Z" },
              { play_domain: "gm.example.cn", cert_type: 1, gm_cert_type: 1, source: "scm", cert_id: "scs1554192131151", cert_name: "gm" },
              { play_domain: "ok.example.cn", cert_type: 0, source: "user" },
            ],
          },
        };
      }
      if (path === "/v1/p-bj4/guard/https-cert") {
        const domain = req.url.searchParams.get("domain");
        if (domain === "nopem.example.cn" || domain === "timed.example.cn") return apigError(500, "LIVE.100011005", "Server internal error");
        if (domain === "ok.example.cn") return { body: { tls_certificate: { certificate: LEAF_PEM } } };
        return { body: { tls_certificate: {}, gm_certificate: {} } };
      }
      return undefined;
    });
    const r = await runCli(["domains", "-p", "huawei", "-s", "live", "--json"], { env: HUAWEI_ENV, fetch });
    expect(r.code).toBe(0);
    const map = byDomain(r.json.data.items);
    expect(map["nopem.example.cn"]).toMatchObject({ https: true, extra: { httpsUnknown: "true" } });
    expect(map["scm.example.cn"]).toMatchObject({ https: true, cert: { id: "scs1554192131150" }, extra: { httpsUnknown: "true" } });
    for (const d of ["timed.example.cn", "gm.example.cn", "ok.example.cn"]) {
      expect(map[d].https).toBe(true);
      expect(map[d].extra.httpsUnknown).toBeUndefined();
    }
    expect(r.json.data.issues.map((i: any) => i.code).sort()).toEqual(["LIVE.100011005", "LIVE.100011005", "SCM.0403"]);
  });

  it("账号下没有直播地域的项目时报错", async () => {
    const r = await runCli(["domains", "-p", "huawei", "-s", "live", "--json"], {
      env: HUAWEI_ENV,
      fetch: fakeFetch((req) => iamRoute(req, [{ id: "p-gz", name: "cn-south-1" }])),
    });
    expect(r.code).toBe(1);
    expect(JSON.parse(r.stderr)).toMatchObject({ status: "ProjectNotFound" });
  });
});

const LIST_BUCKETS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ListAllMyBucketsResult xmlns="http://obs.cn-north-4.myhuaweicloud.com/doc/2015-06-30/">
  <Owner><ID>783fc6652cf246c096ea836694f71855</ID></Owner>
  <Buckets>
    <Bucket><Name>static-prod</Name><CreationDate>2018-06-21T09:15:01.032Z</CreationDate><Location>cn-east-3</Location><BucketType>OBJECT</BucketType></Bucket>
    <Bucket><Name>plain</Name><CreationDate>2018-06-22T03:56:33.700Z</CreationDate><Location>cn-north-4</Location><BucketType>OBJECT</BucketType></Bucket>
    <Bucket><Name>locked</Name><CreationDate>2018-06-22T03:56:33.700Z</CreationDate><Location>cn-south-1</Location><BucketType>OBJECT</BucketType></Bucket>
  </Buckets>
</ListAllMyBucketsResult>`;

const CUSTOM_DOMAINS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ListBucketCustomDomainsResult xmlns="http://obs.cn-north-4.myhuaweicloud.com/doc/2015-06-30/">
  <Domains><DomainName>cdn.example.cn</DomainName><CreateTime>2019-03-13T10:22:05.912Z</CreateTime><CertName>rsa</CertName><CertificateId>scs0000000000011</CertificateId><CertificateType>server</CertificateType><ExpiredTime>2027-03-13T10:22:05.912Z</ExpiredTime></Domains>
  <Domains><DomainName>cdn.example.cn</DomainName><CreateTime>2019-03-13T10:22:05.912Z</CreateTime><CertName>sm2</CertName><CertificateId>scs0000000000012</CertificateId><CertificateType>server_sm</CertificateType><ExpiredTime>2026-11-13T10:22:05.912Z</ExpiredTime></Domains>
  <Domains><DomainName>mtls.example.cn</DomainName><CreateTime>2019-03-13T10:22:05.912Z</CreateTime><CertName>ca</CertName><CertificateId>scs0000000000013</CertificateId><CertificateType>client</CertificateType></Domains>
  <Domains><DomainName>http.example.cn</DomainName><CreateTime>2019-03-13T10:22:05.912Z</CreateTime></Domains>
  <Domains><DomainName>old.example.cn</DomainName><CreateTime>2019-03-13T10:22:05.912Z</CreateTime><CertificateId>scs1554192131150</CertificateId></Domains>
  <Domains><DomainName>ccm.example.cn</DomainName><CreateTime>2026-10-17T14:19:01.094Z</CreateTime><CertName>wild</CertName><CertificateId>scs1554192131150</CertificateId><CertificateType>server</CertificateType><ExpiredTime>2026-10-30T04:00:00.000Z</ExpiredTime></Domains>
  <Domains><DomainName>own.example.cn</DomainName><CreateTime>2026-10-17T14:18:46.022Z</CreateTime><CertName>own</CertName><CertificateId>000001A14A3ABD8282E7B4974512770A</CertificateId><CertificateType>server</CertificateType><ExpiredTime>2027-01-15T13:09:53.000Z</ExpiredTime></Domains>
</ListBucketCustomDomainsResult>`;

describe("huawei obs", () => {
  it("先列桶再逐桶查自定义域名：服务端证书才算 HTTPS，多证书取最早到期，单桶失败 warn，缺到期时间从 SCM 补全", async () => {
    const fetch = fakeFetch((req) => {
      const scm = scmRoute(req);
      if (scm) return scm;
      if (req.url.host === "obs.cn-north-4.myhuaweicloud.com") return { body: LIST_BUCKETS };
      if (req.url.host === "static-prod.obs.cn-east-3.myhuaweicloud.com" && req.url.search === "?customdomain") return { body: CUSTOM_DOMAINS };
      if (req.url.host === "plain.obs.cn-north-4.myhuaweicloud.com") {
        return { status: 404, body: "<Error><Code>NoSuchCustomDomain</Code><Message>The specified customdomain does not exist</Message></Error>" };
      }
      if (req.url.host === "locked.obs.cn-south-1.myhuaweicloud.com") {
        return { status: 403, body: "<Error><Code>AccessDenied</Code><Message>Access Denied</Message><RequestId>obs-req</RequestId></Error>" };
      }
      return undefined;
    });
    const r = await runCli(["domains", "-p", "huawei", "-s", "obs", "--json"], { env: { ...HUAWEI_ENV, HUAWEICLOUD_SDK_SECURITY_TOKEN: "tok" }, fetch });
    expect(r.code).toBe(0);
    const map = byDomain(r.json.data.items);
    expect(Object.keys(map).sort()).toEqual(["ccm.example.cn", "cdn.example.cn", "http.example.cn", "mtls.example.cn", "old.example.cn", "own.example.cn"]);
    expect(map["cdn.example.cn"]).toEqual({
      provider: "huawei",
      service: "obs",
      domain: "cdn.example.cn",
      https: true,
      cert: { id: "scs0000000000012", name: "sm2", notAfter: "2026-11-13T10:22:05.912Z", algorithm: "SM2" },
      certs: [
        { id: "scs0000000000011", name: "rsa", notAfter: "2027-03-13T10:22:05.912Z" },
        { id: "scs0000000000012", name: "sm2", notAfter: "2026-11-13T10:22:05.912Z", algorithm: "SM2" },
      ],
      extra: { bucket: "static-prod", region: "cn-east-3", certType: "server_sm" },
      daysLeft: 29,
    });
    // 只绑了客户端 CA 证书、没绑证书的域名都不算 HTTPS
    expect(map["mtls.example.cn"]).toEqual({
      provider: "huawei",
      service: "obs",
      domain: "mtls.example.cn",
      https: false,
      extra: { bucket: "static-prod", region: "cn-east-3" },
    });
    expect(map["http.example.cn"]).toMatchObject({ https: false });
    expect(map["old.example.cn"]).toMatchObject({
      https: true,
      cert: { id: "scs1554192131150", name: "wild", commonName: "*.example.cn", notAfter: "2026-10-30T04:00:00.000Z" },
      daysLeft: 15,
    });
    // 绑定 CCM 证书（scs 开头的 ID）的域名从证书列表补 CN / SAN；自有证书自动生成的 ID 不在列表里，保持原样
    expect(map["ccm.example.cn"].cert).toEqual({
      id: "scs1554192131150",
      name: "wild",
      commonName: "*.example.cn",
      sans: ["*.example.cn", "example.cn", "static.example.cn"],
      issuer: "GEOTRUST",
      notAfter: "2026-10-30T04:00:00.000Z",
      status: "ISSUED",
    });
    expect(map["own.example.cn"].cert).toEqual({ id: "000001A14A3ABD8282E7B4974512770A", name: "own", notAfter: "2027-01-15T13:09:53.000Z" });
    expect(r.json.data.issues).toEqual([
      expect.objectContaining({
        service: "obs",
        kind: "error",
        target: "bucket locked",
        code: "AccessDenied",
        requestId: "obs-req",
        // OBS 的拒绝原文不说缺哪个权限（也可能是桶策略），按接口推断；只读系统策略不含读自定义域名
        message: "Access Denied（可能缺少 IAM 权限 obs:bucket:getBucketCustomDomainConfiguration，需用自定义策略授予）",
      }),
    ]);

    const list = fetch.calls.find((c) => c.url.host === "obs.cn-north-4.myhuaweicloud.com")!;
    expect(list.headers["x-obs-bucket-type"]).toBe("OBJECT");
    const cname = fetch.calls.find((c) => c.url.host === "static-prod.obs.cn-east-3.myhuaweicloud.com")!;
    expect(cname.url.pathname).toBe("/");
    expect(cname.headers.date).toBeUndefined();
    expect(cname.headers["x-obs-date"]).toMatch(/^\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} GMT$/);
    expect(cname.headers["x-obs-security-token"]).toBe("tok");
    expect(cname.headers.authorization).toBe(
      obsAuthorization(
        HUAWEI_ENV.HUAWEICLOUD_SDK_AK,
        HUAWEI_ENV.HUAWEICLOUD_SDK_SK,
        obsStringToSign("GET", { "x-obs-date": cname.headers["x-obs-date"]!, "x-obs-security-token": "tok" }, "/static-prod/?customdomain"),
      ),
    );
    expect(list.headers.authorization).toBe(
      obsAuthorization(
        HUAWEI_ENV.HUAWEICLOUD_SDK_AK,
        HUAWEI_ENV.HUAWEICLOUD_SDK_SK,
        obsStringToSign("GET", { "x-obs-date": list.headers["x-obs-date"]!, "x-obs-bucket-type": "OBJECT", "x-obs-security-token": "tok" }, "/"),
      ),
    );
  });

  it("SCM 补全失败：缺到期时间的服务端证书所在域名标 httpsUnknown，只缺 CN / 只缺国密证书时间的不标", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.host === "scm.cn-north-4.myhuaweicloud.com") return apigError(403, "SCM.0403", "Permission denied");
      if (req.url.host === "obs.cn-north-4.myhuaweicloud.com") {
        return { body: "<ListAllMyBucketsResult><Buckets><Bucket><Name>static-prod</Name><Location>cn-east-3</Location></Bucket></Buckets></ListAllMyBucketsResult>" };
      }
      if (req.url.host === "static-prod.obs.cn-east-3.myhuaweicloud.com") {
        return {
          body:
            CUSTOM_DOMAINS.replace("</ListBucketCustomDomainsResult>", "") +
            "<Domains><DomainName>gm.example.cn</DomainName><CertName>rsa</CertName><CertificateId>scs0000000000021</CertificateId><CertificateType>server</CertificateType><ExpiredTime>2027-03-13T10:22:05.912Z</ExpiredTime></Domains>" +
            "<Domains><DomainName>gm.example.cn</DomainName><CertName>sm2</CertName><CertificateId>scs0000000000022</CertificateId><CertificateType>server_sm</CertificateType></Domains>" +
            "</ListBucketCustomDomainsResult>",
        };
      }
      return undefined;
    });
    const r = await runCli(["domains", "-p", "huawei", "-s", "obs", "--json"], { env: HUAWEI_ENV, fetch });
    expect(r.code).toBe(0);
    const map = byDomain(r.json.data.items);
    expect(map["old.example.cn"]).toMatchObject({ https: true, cert: { id: "scs1554192131150" }, extra: { bucket: "static-prod", httpsUnknown: "true" } });
    for (const d of ["ccm.example.cn", "cdn.example.cn", "own.example.cn", "http.example.cn", "gm.example.cn"]) expect(map[d].extra.httpsUnknown).toBeUndefined();
    expect(r.json.data.issues).toEqual([expect.objectContaining({ service: "obs", kind: "error", code: "SCM.0403" })]);
  });

  it("ListBuckets 按 NextMarker 翻页；SlowDown（HTTP 503）自动重试", async () => {
    const page1 = `<ListAllMyBucketsResult><IsTruncated>true</IsTruncated><NextMarker>b1</NextMarker><Buckets><Bucket><Name>b1</Name><Location>cn-north-4</Location></Bucket></Buckets></ListAllMyBucketsResult>`;
    const page2 = `<ListAllMyBucketsResult><Buckets><Bucket><Name>b2</Name><Location>cn-north-4</Location></Bucket></Buckets></ListAllMyBucketsResult>`;
    let slow = true;
    const fetch = fakeFetch((req) => {
      if (req.url.host === "obs.cn-north-4.myhuaweicloud.com") return { body: req.url.searchParams.get("marker") === "b1" ? page2 : page1 };
      if (req.url.host === "b2.obs.cn-north-4.myhuaweicloud.com" && slow) {
        slow = false;
        return { status: 503, body: "<Error><Code>SlowDown</Code><Message>Please reduce your request rate.</Message></Error>" };
      }
      return { body: "<ListBucketCustomDomainsResult><Domains><DomainName>a.example.cn</DomainName></Domains></ListBucketCustomDomainsResult>" };
    });
    const r = await runCli(["domains", "-p", "huawei", "-s", "obs", "--json"], { env: HUAWEI_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.issues).toEqual([]);
    expect(fetch.calls.map((c) => c.url.host)).toEqual([
      "obs.cn-north-4.myhuaweicloud.com",
      "obs.cn-north-4.myhuaweicloud.com",
      "b1.obs.cn-north-4.myhuaweicloud.com",
      "b2.obs.cn-north-4.myhuaweicloud.com",
      "b2.obs.cn-north-4.myhuaweicloud.com",
    ]);
    expect(r.json.data.items.map((d: any) => d.extra.bucket).sort()).toEqual(["b1", "b2"]);
  });
});
