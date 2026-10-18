import { createPrivateKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadLocalCert, type LocalCert } from "../src/deploy/cert.js";
import { executeDeploy, planDeploy, type DeployOptions } from "../src/deploy/run.js";
import type { AliyunCredentials } from "../src/lib/env.js";
import { CloudApiError, type QueryContext } from "../src/lib/http.js";
import { aliyun } from "../src/providers/aliyun/index.js";
import { rpcSignature } from "../src/providers/aliyun/sign.js";
import type { DeployInput, DeployTarget } from "../src/providers/registry.js";
import type { DomainRecord } from "../src/types.js";
import { ALIYUN_ENV, fakeFetch, type FakeReply, type FakeRequest } from "./helpers.js";

const FIX = fileURLToPath(new URL("./fixtures/deploy/", import.meta.url));
const NOW = new Date("2026-10-15T00:00:00Z");
const CERT = loadLocalCert(readFileSync(join(FIX, "rsa-fullchain.pem"), "utf8"), readFileSync(join(FIX, "rsa-key.pem"), "utf8"), NOW);
const ECC = loadLocalCert(readFileSync(join(FIX, "ecc-fullchain.pem"), "utf8"), readFileSync(join(FIX, "ecc-key.pem"), "utf8"), NOW);
const CREDS: AliyunCredentials = { accessKeyId: ALIYUN_ENV.ALIBABA_CLOUD_ACCESS_KEY_ID, accessKeySecret: ALIYUN_ENV.ALIBABA_CLOUD_ACCESS_KEY_SECRET };
const KEY_LINE = CERT.keyPem.split("\n")[1]!;
const NAME = "sslbear-example.com-20270101";

const CAS_HOST = "cas.aliyuncs.com";
const ESA_HOST = "esa.cn-hangzhou.aliyuncs.com";

const rpcError = (status: number, Code: string, Message: string) => ({ status, body: { RequestId: "req-1", Code, Message } });

function context(route: (req: FakeRequest) => FakeReply) {
  const fetch = fakeFetch(route);
  const ctx: QueryContext = { env: { ...ALIYUN_ENV }, fetch, now: NOW, timeoutMs: 1000, sleep: async () => {} };
  return { ctx, fetch };
}

/** POST 表单体里的业务参数 */
const form = (req: FakeRequest) => Object.fromEntries(new URLSearchParams(req.body));

const calls = (fetch: { calls: FakeRequest[] }, action: string) => fetch.calls.filter((c) => c.action === action);

/** 签名覆盖 URL 上的公共参数与表单体里的业务参数，方法为 POST */
function expectSignedPost(req: FakeRequest) {
  expect(req.method).toBe("POST");
  expect(req.headers["content-type"]).toBe("application/x-www-form-urlencoded");
  const query = Object.fromEntries(req.url.searchParams);
  const { Signature, ...rest } = query;
  expect(rpcSignature({ ...rest, ...form(req) }, CREDS.accessKeySecret, "POST")).toBe(Signature);
}

/** 证书与私钥 PEM 只在请求体里 */
function expectNoPemInUrl(fetch: { calls: FakeRequest[] }) {
  for (const c of fetch.calls) {
    expect(c.url.href).not.toContain("PRIVATE");
    expect(c.url.href).not.toContain("CERTIFICATE");
    expect(decodeURIComponent(c.url.href)).not.toContain(KEY_LINE);
  }
}

function input(id = "9001", cert: LocalCert = CERT): DeployInput & { requested: () => number } {
  let n = 0;
  return {
    cert,
    certId: async () => {
      n++;
      return id;
    },
    requested: () => n,
  };
}

const service = (key: string) => aliyun.services.find((s) => s.key === key)!;

function rec(service: string, domain: string, r: Partial<DomainRecord> = {}): DomainRecord {
  return { provider: "aliyun", service, domain, https: true, cert: { name: "old", notAfter: "2026-10-25T00:00:00.000Z" }, ...r };
}

const target = (records: DomainRecord[], mode: DeployTarget["mode"] = "update"): DeployTarget => ({ records, mode });

/** 数字证书管理服务里的一张证书（ListUserCertificateOrder，OrderType=CERT） */
function order(o: Record<string, unknown>) {
  return { CertificateId: 1, Name: "other", CommonName: "other.org", Sans: "other.org", Upload: true, EndDate: "2027-01-01", CertEndTime: Date.parse("2027-01-01T00:00:00Z"), ...o };
}

function casRoutes(orders: unknown[][], uploadReply: FakeReply = { body: { CertId: 9001, RequestId: "r" } }) {
  let listed = 0;
  return (req: FakeRequest): FakeReply => {
    if (req.url.host !== CAS_HOST) return undefined;
    if (req.action === "ListUserCertificateOrder") {
      const list = orders[Math.min(listed++, orders.length - 1)]!;
      return { body: { TotalCount: list.length, CertificateOrderList: list } };
    }
    if (req.action === "UploadUserCertificate") return uploadReply;
    if (req.action === "GetUserCertificateDetail") return { body: { Id: Number(req.url.searchParams.get("CertId")), Name: NAME } };
    return undefined;
  };
}

describe("aliyun 上传证书到数字证书管理服务", () => {
  it("已有同指纹（Sha2）的证书时复用，不再上传", async () => {
    const { ctx, fetch } = context(
      casRoutes([[order({ CertificateId: 111, Sha2: "AA".repeat(32) }), order({ CertificateId: 222, Name: "mine", Sha2: CERT.fingerprint.toUpperCase() })]]),
    );
    expect(await aliyun.uploadCertificate!(ctx, CREDS, CERT)).toEqual({ id: "222", reused: true });
    expect(calls(fetch, "UploadUserCertificate")).toHaveLength(0);
    const list = calls(fetch, "ListUserCertificateOrder")[0]!.url.searchParams;
    expect(list.get("OrderType")).toBe("CERT");
    expect(list.get("Version")).toBe("2020-04-07");
  });

  /** 与 CERT 序列号、签发者、起止时间都一致的证书服务记录（没给指纹） */
  const sameSerial = (o: Record<string, unknown> = {}) =>
    order({
      SerialNo: "1a2b3c",
      Issuer: "sslbear test CA",
      CertStartTime: Date.parse("2026-01-01T00:00:00Z"),
      CertEndTime: Date.parse("2027-01-01T00:00:00Z"),
      ...o,
    });

  it("列表没给指纹时按序列号 + 签发者 + 起止时间复用（序列号前导零、大小写不同也算同一张）", async () => {
    const { ctx, fetch } = context(
      casRoutes([
        [
          // 同序列号但起止时间不同、签发者不同：别的 CA 签的另一张证书
          sameSerial({ CertificateId: 111, EndDate: "2027-06-01", CertEndTime: Date.parse("2027-06-01T00:00:00Z") }),
          sameSerial({ CertificateId: 112, Issuer: "Other CA" }),
          // 只有日期、没有精确起止时间：无法确认，不复用
          sameSerial({ CertificateId: 113, CertStartTime: undefined, CertEndTime: undefined }),
          // 给了指纹就只认指纹：指纹不同即使序列号等都相同也不是同一张
          sameSerial({ CertificateId: 114, Sha2: "AA".repeat(32) }),
          sameSerial({ CertificateId: 222, SerialNo: "001A2B3C" }),
        ],
      ]),
    );
    expect(await aliyun.uploadCertificate!(ctx, CREDS, CERT)).toEqual({ id: "222", reused: true });
    expect(calls(fetch, "UploadUserCertificate")).toHaveLength(0);
  });

  it("签发者按证书签发者 DN 的 CN 或 O 比对（证书服务返回的是组织名，如 Let's Encrypt）", async () => {
    const { ctx } = context(casRoutes([[sameSerial({ CertificateId: 222, Issuer: "SSLBEAR TEST CA" })]]));
    expect(await aliyun.uploadCertificate!(ctx, CREDS, CERT)).toEqual({ id: "222", reused: true });
  });

  it("没有指纹和序列号时不复用：同 CN、同 SAN、同起止时间的另一张证书（如 RSA / ECC 两张）照常上传", async () => {
    // ECC 与 RSA 测试证书 CN、SAN、起止时间完全相同，只有密钥和序列号不同
    const rsaOrder = order({
      CertificateId: 222,
      Name: "rsa",
      CommonName: "example.com",
      Sans: CERT.sans.join(","),
      CertStartTime: Date.parse(CERT.notBefore),
      CertEndTime: Date.parse(CERT.notAfter),
    });
    for (const cert of [ECC, CERT]) {
      const { ctx, fetch } = context(casRoutes([[rsaOrder]]));
      expect(await aliyun.uploadCertificate!(ctx, CREDS, cert)).toEqual({ id: "9001", reused: false });
      expect(calls(fetch, "UploadUserCertificate")).toHaveLength(1);
    }
  });

  it("未命中：POST 表单上传，证书名带 CN 与到期日，PEM 和私钥不出现在 URL 上", async () => {
    const { ctx, fetch } = context(casRoutes([[order({ CertificateId: 111, Sha2: "AA".repeat(32) })]]));
    expect(await aliyun.uploadCertificate!(ctx, CREDS, CERT)).toEqual({ id: "9001", reused: false });
    const [up] = calls(fetch, "UploadUserCertificate");
    expect(up!.url.host).toBe(CAS_HOST);
    expect(up!.url.searchParams.get("Version")).toBe("2020-04-07");
    expectSignedPost(up!);
    expect(form(up!)).toMatchObject({ Name: NAME, Cert: CERT.certPem });
    expect(form(up!).ClientToken).toMatch(/\S/);
    expectNoPemInUrl(fetch);
  });

  it("私钥转成阿里云要求的传统格式上传（RSA 为 PKCS#1、ECC 为 SEC1），内容不变", async () => {
    const pkcs8 = (pem: string) => createPrivateKey(pem).export({ type: "pkcs8", format: "pem" });
    expect(CERT.keyPem).toContain("BEGIN PRIVATE KEY");
    for (const [cert, header] of [
      [CERT, "-----BEGIN RSA PRIVATE KEY-----"],
      [ECC, "-----BEGIN EC PRIVATE KEY-----"],
    ] as const) {
      const { ctx, fetch } = context(casRoutes([[]]));
      await aliyun.uploadCertificate!(ctx, CREDS, cert);
      const key = form(calls(fetch, "UploadUserCertificate")[0]!).Key!;
      expect(key.startsWith(header)).toBe(true);
      expect(pkcs8(key)).toBe(pkcs8(cert.keyPem));
    }
  });

  it("上传报错回显了私钥时，转换格式后的私钥内容也被隐藏", async () => {
    const converted = createPrivateKey(CERT.keyPem).export({ type: "pkcs1", format: "pem" }) as string;
    const line = converted.split("\n")[1]!;
    const { ctx } = context(casRoutes([[]], rpcError(400, "InvalidParameter", `bad Key=${converted} (${encodeURIComponent(line)})`)));
    const err = (await aliyun.uploadCertificate!(ctx, CREDS, CERT).catch((e: unknown) => e)) as CloudApiError;
    expect(err).toBeInstanceOf(CloudApiError);
    expect(err.code).toBe("InvalidParameter");
    expect(err.message).toContain("[私钥已隐藏]");
    expect(err.message).not.toContain(line);
    expect(err.message).not.toContain(encodeURIComponent(line));
  });

  it("证书名：* 换成 _，超长截断到 63 个字符；同名已被另一张证书占用时加指纹后缀", async () => {
    const wild = { ...CERT, commonName: "*.example.com" };
    const a = context(casRoutes([[]]));
    await aliyun.uploadCertificate!(a.ctx, CREDS, wild);
    expect(form(calls(a.fetch, "UploadUserCertificate")[0]!).Name).toBe("sslbear-_.example.com-20270101");

    const long = { ...CERT, commonName: `${"a".repeat(60)}.example.com` };
    const b = context(casRoutes([[]]));
    await aliyun.uploadCertificate!(b.ctx, CREDS, long);
    const name = form(calls(b.fetch, "UploadUserCertificate")[0]!).Name!;
    expect(name).toHaveLength(63);
    expect(name).toMatch(/^sslbear-a+-20270101$/);

    const c = context(casRoutes([[order({ CertificateId: 111, Name: NAME, Sha2: "AA".repeat(32) })]]));
    await aliyun.uploadCertificate!(c.ctx, CREDS, CERT);
    expect(form(calls(c.fetch, "UploadUserCertificate")[0]!).Name).toBe(`${NAME}-${CERT.fingerprint.slice(0, 8)}`);
  });

  it("上传遇到可重试错误时先重新查重：上一次其实已传成功就直接复用，不会传出两份", async () => {
    const { ctx, fetch } = context(
      casRoutes([[], [order({ CertificateId: 444, Name: NAME, Sha2: CERT.fingerprint })]], { status: 503, body: { Code: "ServiceUnavailable", Message: "busy", RequestId: "r" } }),
    );
    expect(await aliyun.uploadCertificate!(ctx, CREDS, CERT)).toEqual({ id: "444", reused: true });
    expect(calls(fetch, "UploadUserCertificate")).toHaveLength(1);
    expect(calls(fetch, "ListUserCertificateOrder")).toHaveLength(2);
  });

  it("重试时沿用同一个 ClientToken（接口幂等）", async () => {
    let n = 0;
    const cas = casRoutes([[]]);
    const { ctx, fetch } = context((req) => {
      if (req.action === "UploadUserCertificate" && n++ === 0) return { status: 503, body: { Code: "ServiceUnavailable", Message: "busy" } };
      return cas(req);
    });
    expect(await aliyun.uploadCertificate!(ctx, CREDS, CERT)).toEqual({ id: "9001", reused: false });
    const tokens = calls(fetch, "UploadUserCertificate").map((c) => form(c).ClientToken);
    expect(tokens).toHaveLength(2);
    expect(tokens[0]).toBe(tokens[1]);
  });

  it("上传失败抛 CloudApiError", async () => {
    const { ctx } = context(casRoutes([[]], rpcError(400, "NameRepeat", "name exists")));
    const err = await aliyun.uploadCertificate!(ctx, CREDS, CERT).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CloudApiError);
    expect(err).toMatchObject({ code: "NameRepeat", requestId: "req-1" });
  });
});

describe("aliyun CDN / DCDN deployer", () => {
  const cases = [
    { key: "cdn", host: "cdn.aliyuncs.com", version: "2018-05-10", action: "SetCdnDomainSSLCertificate" },
    { key: "dcdn", host: "dcdn.aliyuncs.com", version: "2018-01-15", action: "SetDcdnDomainSSLCertificate" },
  ];

  it.each(cases)("$key 更新：只调 $action 按 CAS 证书 ID 换证书，不读写其他 HTTPS 配置", async ({ key, host, version, action }) => {
    const { ctx, fetch } = context((req) => (req.url.host === host && req.action === action ? { body: { RequestId: "r" } } : undefined));
    const out = await service(key).deployer!.apply(ctx, CREDS, target([rec(key, "a.example.com")]), input());
    expect(out).toEqual({ certId: "9001" });
    expect(fetch.calls).toHaveLength(1);
    const [call] = fetch.calls;
    expect(call!.url.searchParams.get("Version")).toBe(version);
    expectSignedPost(call!);
    expect(form(call!)).toEqual({ DomainName: "a.example.com", SSLProtocol: "on", CertType: "cas", CertId: "9001", CertRegion: "cn-hangzhou" });
  });

  it.each(cases)("$key 部署：没开 HTTPS 的域名同一接口开启 HTTPS", async ({ key, action }) => {
    const { ctx, fetch } = context((req) => (req.action === action ? { body: { RequestId: "r" } } : undefined));
    await service(key).deployer!.apply(ctx, CREDS, target([rec(key, "b.example.com", { https: false, cert: undefined })], "deploy"), input());
    expect(form(fetch.calls[0]!)).toMatchObject({ DomainName: "b.example.com", SSLProtocol: "on", CertType: "cas", CertId: "9001" });
  });

  it("接口报错原样抛出 CloudApiError", async () => {
    const { ctx } = context(() => rpcError(400, "InvalidDomain.NotFound", "domain not found"));
    await expect(service("cdn").deployer!.apply(ctx, CREDS, target([rec("cdn", "a.example.com")]), input())).rejects.toMatchObject({
      code: "InvalidDomain.NotFound",
    });
  });
});

describe("aliyun 直播 deployer", () => {
  const live = service("live");

  it("查询时带上域名类型；推流域名不能配 HTTPS，记为不支持", async () => {
    const { ctx } = context((req) => {
      if (req.action === "DescribeLiveUserDomains") {
        return {
          body: {
            TotalCount: 2,
            Domains: {
              PageData: [
                { DomainName: "push.example.com", LiveDomainStatus: "online", LiveDomainType: "liveEdge" },
                { DomainName: "play.example.com", LiveDomainStatus: "online", LiveDomainType: "liveVideo" },
              ],
            },
          },
        };
      }
      if (req.action === "DescribeLiveHttpsDomainList") return { body: { TotalCount: 0, CertInfos: { CertInfo: [] } } };
      return undefined;
    });
    const [push, play] = await live.list(ctx, CREDS, () => {});
    expect(push!.extra).toEqual({ liveDomainType: "liveEdge" });
    expect(play!.extra).toEqual({ liveDomainType: "liveVideo" });
    expect(live.deployer!.unsupported!(push!, "deploy")).toContain("推流域名");
    expect(live.deployer!.unsupported!(play!, "deploy")).toBeUndefined();
  });

  it("播流域名按 CAS 证书名绑定（接口没有证书 ID 参数），证书名只查一次且不取回证书与私钥内容", async () => {
    const cas = casRoutes([[]]);
    const { ctx, fetch } = context((req) => (req.action === "SetLiveDomainCertificate" ? { body: { RequestId: "r" } } : cas(req)));
    const records = ["p1.example.com", "p2.example.com"].map((d) => rec("live", d, { extra: { liveDomainType: "liveVideo" } }));
    for (const r of records) expect(await live.deployer!.apply(ctx, CREDS, target([r]), input())).toEqual({ certId: "9001" });

    const detail = calls(fetch, "GetUserCertificateDetail");
    expect(detail).toHaveLength(1);
    expect(detail[0]!.url.searchParams.get("CertId")).toBe("9001");
    expect(detail[0]!.url.searchParams.get("CertFilter")).toBe("true");
    const sets = calls(fetch, "SetLiveDomainCertificate");
    expect(sets.map((c) => c.url.host)).toEqual(["live.aliyuncs.com", "live.aliyuncs.com"]);
    expectSignedPost(sets[0]!);
    expect(form(sets[0]!)).toEqual({ DomainName: "p1.example.com", SSLProtocol: "on", CertType: "cas", CertName: NAME });
  });
});

describe("aliyun 点播 deployer", () => {
  it("上海接入点 SetVodDomainSSLCertificate，带 CAS 证书 ID 与证书名", async () => {
    const cas = casRoutes([[]]);
    const { ctx, fetch } = context((req) => (req.action === "SetVodDomainSSLCertificate" ? { body: { RequestId: "r" } } : cas(req)));
    const out = await service("vod").deployer!.apply(ctx, CREDS, target([rec("vod", "v.example.com", { https: false })], "deploy"), input());
    expect(out).toEqual({ certId: "9001" });
    const [set] = calls(fetch, "SetVodDomainSSLCertificate");
    expect(set!.url.host).toBe("vod.cn-shanghai.aliyuncs.com");
    expect(set!.url.searchParams.get("Version")).toBe("2017-03-21");
    expectSignedPost(set!);
    expect(form(set!)).toEqual({ DomainName: "v.example.com", SSLProtocol: "on", CertType: "cas", CertId: "9001", CertName: NAME, CertRegion: "cn-hangzhou" });
  });
});

describe("aliyun OSS deployer", () => {
  const oss = service("oss");
  const ossRoute = (req: FakeRequest): FakeReply => (req.method === "POST" && req.url.search === "?cname&comp=add" ? { body: "" } : undefined);

  it("更新：PutCname 只带证书配置（CAS 证书 ID 加地域后缀），Force 覆盖当前证书", async () => {
    const { ctx, fetch } = context(ossRoute);
    const record = rec("oss", "img.example.com", { cert: { id: "1234-cn-hangzhou", notAfter: "2026-10-25T00:00:00.000Z" }, extra: { bucket: "b1", region: "cn-beijing" } });
    expect(await oss.deployer!.apply(ctx, CREDS, target([record]), input())).toEqual({ certId: "9001-cn-hangzhou" });
    expect(fetch.calls).toHaveLength(1);
    const [put] = fetch.calls;
    expect(put!.url.host).toBe("b1.oss-cn-beijing.aliyuncs.com");
    expect(put!.headers["content-type"]).toBe("application/xml");
    expect(put!.headers.authorization).toMatch(/^OSS4-HMAC-SHA256 Credential=LTAItestid0000\/\d{8}\/cn-beijing\/oss\/aliyun_v4_request,Signature=[0-9a-f]{64}$/);
    expect(put!.body.replace(/\s+/g, "")).toContain(
      "<BucketCnameConfiguration><Cname><Domain>img.example.com</Domain><CertificateConfiguration><CertId>9001-cn-hangzhou</CertId><Force>true</Force></CertificateConfiguration></Cname></BucketCnameConfiguration>",
    );
  });

  it("部署：没有证书的自定义域名同样绑定证书即开启 HTTPS", async () => {
    const { ctx, fetch } = context(ossRoute);
    const record = rec("oss", "img.example.com", { https: false, cert: undefined, extra: { bucket: "b1", region: "cn-hangzhou" } });
    await oss.deployer!.apply(ctx, CREDS, target([record], "deploy"), input());
    const body = fetch.calls[0]!.body.replace(/\s+/g, "");
    expect(body).toContain("<Domain>img.example.com</Domain><CertificateConfiguration><CertId>9001-cn-hangzhou</CertId><Force>true</Force></CertificateConfiguration>");
  });

  it("OSS 报错解析 XML 错误码", async () => {
    const { ctx } = context(() => ({
      status: 403,
      body: "<Error><Code>AccessDenied</Code><Message>denied</Message><RequestId>oss-req</RequestId></Error>",
    }));
    const record = rec("oss", "img.example.com", { extra: { bucket: "b1", region: "cn-hangzhou" } });
    await expect(oss.deployer!.apply(ctx, CREDS, target([record]), input())).rejects.toMatchObject({ code: "AccessDenied", requestId: "oss-req" });
  });
});

describe("aliyun ESA deployer", () => {
  const esa = service("esa");
  const site = { siteId: "1001", site: "example.com" };
  const saas = { ...site, hostType: "saas", hostnameId: "77", recordId: "88" };

  it("普通记录按站点共享证书；没开 HTTPS 的普通记录不支持部署，SaaS 域名逐个处理", () => {
    const d = esa.deployer!;
    const normal = rec("esa", "a.example.com", { extra: site });
    expect(d.sharedScope!(normal)).toBe("1001");
    expect(d.unsupported!(normal, "update")).toBeUndefined();
    expect(d.unsupported!({ ...normal, https: false }, "deploy")).toContain("SSL/TLS 规则");
    const custom = rec("esa", "shop.customer.com", { extra: saas });
    expect(d.sharedScope!(custom)).toBeUndefined();
    expect(d.unsupported!({ ...custom, https: false }, "deploy")).toBeUndefined();
  });

  it("sharedScope：站点证书会影响到的普通记录都归入站点——开着 HTTPS 的，以及没开 HTTPS 但 SSL/TLS 开关不是 off 的", () => {
    const d = esa.deployer!;
    const off = (httpsSwitch?: string) =>
      rec("esa", "a.example.com", { https: false, cert: undefined, extra: { ...site, ...(httpsSwitch && { httpsSwitch }) } });
    expect(d.sharedScope!(rec("esa", "a.example.com", { extra: { ...site, httpsSwitch: "on" } }))).toBe("1001");
    // 开关开着 / partial / 查不到：只是还没有匹配的已签发证书，站点一加上覆盖它的证书就会开始提供 HTTPS
    expect(d.sharedScope!(off("on"))).toBe("1001");
    expect(d.sharedScope!(off("partial"))).toBe("1001");
    expect(d.sharedScope!(off())).toBe("1001");
    // 开关为 off：加证书也不会开启 HTTPS，不受影响
    expect(d.sharedScope!(off("off"))).toBeUndefined();
    // SaaS 域名的证书在域名自身上
    expect(d.sharedScope!(rec("esa", "shop.customer.com", { https: false, cert: undefined, extra: { ...saas, httpsSwitch: "on" } }))).toBeUndefined();
  });

  function esaWriteRoutes(siteCerts: unknown[]) {
    return (req: FakeRequest): FakeReply => {
      if (req.url.host !== ESA_HOST) return undefined;
      if (req.action === "ListCertificates") return { body: { TotalCount: siteCerts.length, Result: siteCerts } };
      if (req.action === "SetCertificate") return { body: { Id: "esa-new", RequestId: "r" } };
      if (req.action === "UpdateCustomHostname") return { body: { RequestId: "r" } };
      return undefined;
    };
  }

  it("站点：同一站点的一组记录只往站点设置一次 CAS 证书（新增，不删旧证书）", async () => {
    const { ctx, fetch } = context(esaWriteRoutes([{ Id: "old", Type: "upload", PubAlg: "RSA", FingerprintSha256: "aa".repeat(32), CasId: "123" }]));
    const records = ["a.example.com", "b.example.com"].map((d) => rec("esa", d, { extra: site }));
    expect(await esa.deployer!.apply(ctx, CREDS, target(records), input())).toEqual({ certId: "esa-new" });
    expect(calls(fetch, "ListCertificates")[0]!.url.searchParams.get("SiteId")).toBe("1001");
    const sets = calls(fetch, "SetCertificate");
    expect(sets).toHaveLength(1);
    expectSignedPost(sets[0]!);
    expect(form(sets[0]!)).toEqual({ SiteId: "1001", Type: "cas", CasId: "9001", Region: "cn-hangzhou" });
    expect(fetch.calls.map((c) => c.action)).toEqual(["ListCertificates", "SetCertificate"]);
  });

  it("站点上已有同一张证书时原地更新它（带 Id），不重复添加", async () => {
    const { ctx, fetch } = context(esaWriteRoutes([{ Id: "same", Type: "upload", PubAlg: "RSA", FingerprintSha256: CERT.fingerprint.toUpperCase() }]));
    await esa.deployer!.apply(ctx, CREDS, target([rec("esa", "a.example.com", { extra: site })]), input());
    expect(form(calls(fetch, "SetCertificate")[0]!)).toEqual({ SiteId: "1001", Type: "cas", CasId: "9001", Region: "cn-hangzhou", Id: "same" });
  });

  /** 站点证书列表与 SetCertificate 的回复按调用次序依次返回（取完后重复最后一个） */
  function esaSeqRoutes(lists: unknown[][], replies: FakeReply[]) {
    let listed = 0;
    let set = 0;
    return (req: FakeRequest): FakeReply => {
      if (req.url.host !== ESA_HOST) return undefined;
      if (req.action === "ListCertificates") {
        const list = lists[Math.min(listed++, lists.length - 1)]!;
        return { body: { TotalCount: list.length, Result: list } };
      }
      if (req.action === "SetCertificate") return replies[Math.min(set++, replies.length - 1)];
      return undefined;
    };
  }
  const busy: FakeReply = { status: 503, body: { Code: "ServiceUnavailable", Message: "busy", RequestId: "r" } };
  const added: FakeReply = { body: { Id: "esa-new", RequestId: "r" } };
  /** 站点上的「同一张证书」：上一轮新增其实已成功时重新列出能看到它 */
  const mine = (o: Record<string, unknown> = {}) => ({ Id: "esa-mine", Type: "cas", PubAlg: "RSA", FingerprintSha256: CERT.fingerprint.toUpperCase(), CasId: "9001", ...o });
  const siteRecords = () => [rec("esa", "a.example.com", { extra: site })];
  const setForms = (fetch: { calls: FakeRequest[] }) => calls(fetch, "SetCertificate").map(form);

  it.each([
    ["指纹", mine()],
    ["CasId（站点证书没给指纹）", mine({ FingerprintSha256: undefined })],
  ])("新增站点证书遇到可重试错误：不原样重发，先重新列出站点证书，按%s认出上一次已添加成功即算成功", async (_, found) => {
    const { ctx, fetch } = context(esaSeqRoutes([[], [found]], [busy, added]));
    expect(await esa.deployer!.apply(ctx, CREDS, target(siteRecords()), input())).toEqual({ certId: "esa-mine" });
    expect(fetch.calls.map((c) => c.action)).toEqual(["ListCertificates", "SetCertificate", "ListCertificates"]);
  });

  it("新增遇到可重试错误、重新列出仍没有：再新增一次（仍不带 Id）", async () => {
    const { ctx, fetch } = context(esaSeqRoutes([[]], [busy, added]));
    expect(await esa.deployer!.apply(ctx, CREDS, target(siteRecords()), input())).toEqual({ certId: "esa-new" });
    expect(fetch.calls.map((c) => c.action)).toEqual(["ListCertificates", "SetCertificate", "ListCertificates", "SetCertificate"]);
    expect(setForms(fetch).every((f) => f.Id === undefined)).toBe(true);
  });

  it("另一张同 CN 的证书（指纹、CasId 都不同）不算同一张，重试时照常新增", async () => {
    const other = mine({ Id: "esa-ecc", FingerprintSha256: ECC.fingerprint, CasId: "8000" });
    const { ctx, fetch } = context(esaSeqRoutes([[other]], [busy, added]));
    expect(await esa.deployer!.apply(ctx, CREDS, target(siteRecords()), input())).toEqual({ certId: "esa-new" });
    expect(setForms(fetch)).toHaveLength(2);
    expect(setForms(fetch).every((f) => f.Id === undefined)).toBe(true);
  });

  it("一直遇到可重试错误：最多 3 轮，每轮先重新列出，最后抛出可重试的错误", async () => {
    const { ctx, fetch } = context(esaSeqRoutes([[]], [busy]));
    const err = await esa.deployer!.apply(ctx, CREDS, target(siteRecords()), input()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CloudApiError);
    expect(err).toMatchObject({ code: "ServiceUnavailable" });
    expect(calls(fetch, "SetCertificate")).toHaveLength(3);
    expect(calls(fetch, "ListCertificates")).toHaveLength(3);
  });

  it("新增遇到不可重试的错误：直接抛出，不重发", async () => {
    const { ctx, fetch } = context(esaSeqRoutes([[]], [rpcError(400, "InvalidParameter", "bad")]));
    await expect(esa.deployer!.apply(ctx, CREDS, target(siteRecords()), input())).rejects.toMatchObject({ code: "InvalidParameter" });
    expect(calls(fetch, "SetCertificate")).toHaveLength(1);
  });

  it("站点上本来就有同一张证书：原地更新带它的 Id；遇到可重试错误重新列出后仍带 Id 原地更新", async () => {
    const { ctx, fetch } = context(esaSeqRoutes([[mine({ Id: "same" })]], [busy, { body: { Id: "same", RequestId: "r" } }]));
    expect(await esa.deployer!.apply(ctx, CREDS, target(siteRecords()), input())).toEqual({ certId: "same" });
    expect(fetch.calls.map((c) => c.action)).toEqual(["ListCertificates", "SetCertificate", "ListCertificates", "SetCertificate"]);
    expect(setForms(fetch).map((f) => f.Id)).toEqual(["same", "same"]);
  });

  it("SaaS 域名：UpdateCustomHostname 只改该域名的证书，记录绑定原样带回", async () => {
    const { ctx, fetch } = context(esaWriteRoutes([]));
    const out = await esa.deployer!.apply(ctx, CREDS, target([rec("esa", "shop.customer.com", { https: false, cert: undefined, extra: saas })], "deploy"), input());
    expect(out).toEqual({ certId: "9001" });
    expect(fetch.calls.map((c) => c.action)).toEqual(["UpdateCustomHostname"]);
    expectSignedPost(fetch.calls[0]!);
    expect(form(fetch.calls[0]!)).toEqual({ HostnameId: "77", RecordId: "88", SslFlag: "on", CertType: "cas", CasId: "9001", CasRegion: "cn-hangzhou" });
  });

  it("查询：SaaS 域名带上 hostnameId、recordId", async () => {
    const { ctx } = context((req) => {
      if (req.action === "ListSites") return { body: { TotalCount: 1, Sites: [{ SiteId: 1001, SiteName: "example.com", Status: "active" }] } };
      if (req.action === "ListCustomHostnames") {
        return { body: { TotalCount: 1, Hostnames: [{ HostnameId: 77, RecordId: 88, Hostname: "shop.customer.com", Status: "active", SslFlag: "off" }] } };
      }
      if (["ListRecords", "ListCertificates", "ListHttpsBasicConfigurations"].includes(req.action!)) return { body: { TotalCount: 0 } };
      return undefined;
    });
    const [r] = await esa.list(ctx, CREDS, () => {});
    expect(r!.extra).toEqual(saas);
  });
});

/** 一个站点、一条记录 api.example.com，被 RSA 与 ECC 两张泛域名证书同时覆盖 */
function esaDualRoutes(rsaNotAfter: string, eccNotAfter: string) {
  const cas = casRoutes([[]]);
  return (req: FakeRequest): FakeReply => {
    if (req.url.host === CAS_HOST) return cas(req);
    if (req.url.host !== ESA_HOST) return undefined;
    switch (req.action) {
      case "ListSites":
        return { body: { TotalCount: 1, Sites: [{ SiteId: 1001, SiteName: "example.com", Status: "active" }] } };
      case "ListRecords":
        return { body: { TotalCount: 1, Records: [{ RecordName: "api.example.com", Proxied: true }] } };
      case "ListCertificates":
        return {
          body: {
            TotalCount: 2,
            Result: [
              { Id: "rsa", Name: "wild-rsa", Type: "upload", Status: "OK", CommonName: "*.example.com", PubAlg: "RSA", NotBefore: "2026-01-01 00:00:00", NotAfter: rsaNotAfter, CreateTime: "2026-01-01 00:00:00" },
              { Id: "ecc", Name: "wild-ecc", Type: "upload", Status: "OK", CommonName: "*.example.com", PubAlg: "ECDSA", NotBefore: "2026-01-01 00:00:00", NotAfter: eccNotAfter, CreateTime: "2026-01-01 00:00:00" },
            ],
          },
        };
      case "ListHttpsBasicConfigurations":
        return { body: { TotalCount: 0, Configs: [] } };
      case "ListCustomHostnames":
        return { body: { TotalCount: 0, Hostnames: [] } };
      case "SetCertificate":
        return { body: { Id: "esa-new", RequestId: "r" } };
      default:
        return undefined;
    }
  };
}

async function deploy(route: (req: FakeRequest) => FakeReply, opts: Partial<DeployOptions> = {}) {
  const { ctx, fetch } = context(route);
  const plan = await planDeploy(ctx, CERT, { providers: ["aliyun"], force: false, dryRun: false, ...opts });
  return { report: await executeDeploy(ctx, CERT, plan), fetch };
}

describe("aliyun 双证书（ESA RSA + ECC）", () => {
  it("查询：两张生效证书都列在 certs 里并标算法，cert 为先到期的那张", async () => {
    const { ctx } = context(esaDualRoutes("2026-10-25 00:00:00", "2027-05-01 00:00:00"));
    const [r] = await service("esa").list(ctx, CREDS, () => {});
    expect(r!.cert).toMatchObject({ id: "rsa", algorithm: "RSA" });
    expect(r!.certs).toEqual([expect.objectContaining({ id: "rsa", algorithm: "RSA" }), expect.objectContaining({ id: "ecc", algorithm: "ECC" })]);
  });

  it("新证书是 RSA：按 RSA 那张判断到期，只往站点添加新证书，ECC 证书保留并在结果里提示", async () => {
    const { report, fetch } = await deploy(esaDualRoutes("2026-10-25 00:00:00", "2027-05-01 00:00:00"), { services: ["esa"] });
    expect(report.results).toEqual([
      expect.objectContaining({ service: "esa", domain: "api.example.com", action: "updated", before: expect.objectContaining({ id: "rsa", daysLeft: 10 }), after: { id: "esa-new", notAfter: CERT.notAfter } }),
    ]);
    expect(report.results[0]!.message).toContain("wild-ecc");
    expect(report.uploads).toEqual([{ provider: "aliyun", certId: "9001", reused: false }]);
    expect(form(calls(fetch, "SetCertificate")[0]!)).toEqual({ SiteId: "1001", Type: "cas", CasId: "9001", Region: "cn-hangzhou" });
    expect(fetch.calls.some((c) => c.action === "DeleteCertificate")).toBe(false);
    expectNoPemInUrl(fetch);
  });

  it("ECC 那张快到期但 RSA 那张还早：新 RSA 证书按 RSA 那张判断为未到期", async () => {
    const { report, fetch } = await deploy(esaDualRoutes("2026-12-20 00:00:00", "2026-10-25 00:00:00"), { services: ["esa"] });
    expect(report.results).toEqual([expect.objectContaining({ domain: "api.example.com", action: "skipped", reason: "not_due", needsConfirm: true, before: expect.objectContaining({ id: "rsa" }) })]);
    expect(calls(fetch, "SetCertificate")).toHaveLength(0);
  });
});

describe("aliyun 部署全流程", () => {
  it("CDN 与直播共用一次上传；推流域名跳过 unsupported，未到期的跳过 not_due", async () => {
    const cas = casRoutes([[]]);
    const route = (req: FakeRequest): FakeReply => {
      if (req.url.host === CAS_HOST) return cas(req);
      if (req.action === "DescribeUserDomains") {
        return {
          body: {
            TotalCount: 2,
            Domains: {
              PageData: [
                { DomainName: "a.example.com", DomainStatus: "online", SslProtocol: "on" },
                { DomainName: "b.example.com", DomainStatus: "online", SslProtocol: "on" },
              ],
            },
          },
        };
      }
      if (req.action === "DescribeCdnHttpsDomainList") {
        return {
          body: {
            TotalCount: 2,
            CertInfos: {
              CertInfo: [
                { DomainName: "a.example.com", CertName: "old-a", CertType: "cas", CertExpireTime: "2026-10-25T00:00:00Z" },
                { DomainName: "b.example.com", CertName: "old-b", CertType: "cas", CertExpireTime: "2026-12-25T00:00:00Z" },
              ],
            },
          },
        };
      }
      if (req.action === "DescribeLiveUserDomains") {
        return {
          body: {
            TotalCount: 2,
            Domains: {
              PageData: [
                { DomainName: "push.example.com", LiveDomainStatus: "online", LiveDomainType: "liveEdge" },
                { DomainName: "play.example.com", LiveDomainStatus: "online", LiveDomainType: "liveVideo" },
              ],
            },
          },
        };
      }
      if (req.action === "DescribeLiveHttpsDomainList") {
        return { body: { TotalCount: 1, CertInfos: { CertInfo: [{ DomainName: "play.example.com", CertName: "old-play", CertExpireTime: "2026-10-20T00:00:00Z" }] } } };
      }
      if (req.action === "SetCdnDomainSSLCertificate" || req.action === "SetLiveDomainCertificate") return { body: { RequestId: "r" } };
      return undefined;
    };
    const { report, fetch } = await deploy(route, { services: ["cdn", "live"] });
    expect(report.results.map((r) => [r.service, r.domain, r.action, r.reason])).toEqual([
      ["cdn", "a.example.com", "updated", undefined],
      ["cdn", "b.example.com", "skipped", "not_due"],
      ["live", "play.example.com", "updated", undefined],
      ["live", "push.example.com", "skipped", "unsupported"],
    ]);
    expect(calls(fetch, "UploadUserCertificate")).toHaveLength(1);
    expect(form(calls(fetch, "SetCdnDomainSSLCertificate")[0]!)).toMatchObject({ DomainName: "a.example.com", CertId: "9001" });
    expect(form(calls(fetch, "SetLiveDomainCertificate")[0]!)).toMatchObject({ DomainName: "play.example.com", CertName: NAME });
    expectNoPemInUrl(fetch);
  });
});
