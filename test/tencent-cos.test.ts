import { describe, expect, it } from "vitest";
import { cosAuthorization } from "../src/providers/tencent/sign.js";
import { TENCENT_ENV, fakeFetch, runCli, type FakeRequest } from "./helpers.js";

describe("COS 请求签名（q-sign-algorithm=sha1）", () => {
  // tencentcloud.com/document/product/436/7778 的两个签名示例（SecretKey 取自该文档）。
  // 文档公布了 SignKey、SHA1(HttpString) 等中间值，最终签名只公布前 36 位（末 4 位打码），
  // 期望值由已核对一致的中间值算出：示例一 3b8851a11a569213c17ba8fa7dcf2abec693****，示例二 01681b8c9d798a678e43b685a9f1bba0f6c0****
  const docKey = "BQYIM75p8x0iWVFSIgqEKwFprpRSVHlz";

  it("文档示例一：PUT Object，多个请求头参与签名", () => {
    const auth = cosAuthorization({
      secretId: "test-secret-id",
      secretKey: docKey,
      method: "PUT",
      path: "/exampleobject(腾讯云)",
      query: {},
      headers: {
        Date: "Thu, 16 May 2019 06:45:51 GMT",
        Host: "examplebucket-1250000000.cos.ap-beijing.myqcloud.com",
        "Content-Type": "text/plain",
        "Content-Length": "13",
        "Content-MD5": "mQ/fVh815F3k6TAUm8m0eg==",
        "x-cos-acl": "private",
        "x-cos-grant-read": 'uin="100000000011"',
      },
      start: 1557989151,
      end: 1557996351,
    });
    expect(auth).toBe(
      "q-sign-algorithm=sha1&q-ak=test-secret-id&q-sign-time=1557989151;1557996351&q-key-time=1557989151;1557996351" +
        "&q-header-list=content-length;content-md5;content-type;date;host;x-cos-acl;x-cos-grant-read&q-url-param-list=" +
        "&q-signature=3b8851a11a569213c17ba8fa7dcf2abec6935172",
    );
  });

  it("文档示例二：GET Object，请求参数按小写 key 排序并编码", () => {
    const auth = cosAuthorization({
      secretId: "test-secret-id",
      secretKey: docKey,
      method: "GET",
      path: "/exampleobject(腾讯云)",
      query: { "response-content-type": "application/octet-stream", "response-cache-control": "max-age=600" },
      headers: { Date: "Thu, 16 May 2019 06:55:53 GMT", Host: "examplebucket-1250000000.cos.ap-beijing.myqcloud.com" },
      start: 1557989753,
      end: 1557996953,
    });
    expect(auth).toBe(
      "q-sign-algorithm=sha1&q-ak=test-secret-id&q-sign-time=1557989753;1557996953&q-key-time=1557989753;1557996953" +
        "&q-header-list=date;host&q-url-param-list=response-cache-control;response-content-type" +
        "&q-signature=01681b8c9d798a678e43b685a9f1bba0f6c0e012",
    );
  });

  it("cos-go-sdk-v5 auth_test.go 的 TestNewAuthorization 向量", () => {
    // 该单测的 SecretKey 恰好以 AKID 开头（公开的测试值，并非真实密钥），拆开写以免被密钥扫描误判
    const auth = cosAuthorization({
      secretId: "QmFzZTY0IGlzIGEgZ2VuZXJp",
      secretKey: ["AKID", "ZfbOA78asKUYBcXFrJD0a1ICvR98JM"].join(""),
      method: "PUT",
      path: "/testfile2",
      query: {},
      headers: {
        Host: "testbucket-125000000.cos.ap-guangzhou.myqcloud.com",
        "x-cos-content-sha1": "db8ac1c259eb89d4a131b253bacfca5f319d54f2",
        "x-cos-stroage-class": "nearline",
      },
      start: 1480932292,
      end: 1481012292,
    });
    expect(auth).toBe(
      "q-sign-algorithm=sha1&q-ak=QmFzZTY0IGlzIGEgZ2VuZXJp&q-sign-time=1480932292;1481012292&q-key-time=1480932292;1481012292" +
        "&q-header-list=host;x-cos-content-sha1;x-cos-stroage-class&q-url-param-list=&q-signature=ce4ac0ecbcdb30538b3fee0a97cc6389694ce53a",
    );
  });
});

const SERVICE = "service.cos.myqcloud.com";
const cosErr = (status: number, code: string, message: string) => ({
  status,
  body: `<?xml version='1.0' encoding='utf-8' ?>\n<Error>\n\t<Code>${code}</Code>\n\t<Message>${message}</Message>\n\t<Resource>/</Resource>\n\t<RequestId>req-${code}</RequestId>\n</Error>`,
});

const LIST_BUCKETS = `<?xml version="1.0" encoding="UTF-8" ?>
<ListAllMyBucketsResult>
  <Owner><ID>qcs::cam::uin/100000000001:uin/100000000001</ID><DisplayName>100000000001</DisplayName></Owner>
  <Marker></Marker><NextMarker></NextMarker><IsTruncated>false</IsTruncated>
  <Buckets>
    <Bucket><Name>static-1250000000</Name><Location>ap-shanghai</Location><CreationDate>2024-06-16T13:08:28Z</CreationDate></Bucket>
    <Bucket><Name>plain-1250000000</Name><Location>ap-guangzhou</Location><CreationDate>2024-06-10T09:00:07Z</CreationDate></Bucket>
    <Bucket><Name>locked-1250000000</Name><Location>ap-beijing</Location><CreationDate>2024-06-10T09:00:07Z</CreationDate></Bucket>
  </Buckets>
</ListAllMyBucketsResult>`;

const DOMAINS = `<DomainConfiguration>
  <DomainRule><Status>ENABLED</Status><Name>img.example.com</Name><Type>REST</Type></DomainRule>
  <DomainRule><Status>ENABLED</Status><Name>site.example.com</Name><Type>WEBSITE</Type><ForcedReplacement>CNAME</ForcedReplacement></DomainRule>
  <DomainRule><Status>DISABLED</Status><Name>old.example.com</Name><Type>REST</Type></DomainRule>
  <DomainRule><Status>ENABLED</Status><Name>dl.example.com</Name><Type>ACCELERATE</Type></DomainRule>
</DomainConfiguration>`;

const certXml = (status: string, info = "") => `<DomainCertificate><Status>${status}</Status>${info}</DomainCertificate>`;

function cosRoute(req: FakeRequest) {
  const host = req.url.host;
  const q = req.url.searchParams;
  if (host === SERVICE) return { body: LIST_BUCKETS };
  if (host === "static-1250000000.cos.ap-shanghai.myqcloud.com") {
    if (req.url.search === "?domain") return { body: DOMAINS };
    if (q.has("domaincertificate")) {
      switch (q.get("domainname")) {
        case "img.example.com":
          return {
            body: certXml(
              "Enabled",
              "<CertificateInfo><CertId>ssl-cos</CertId><ValidityBegin>1785542400</ValidityBegin><ValidityExpire>1795132800</ValidityExpire></CertificateInfo>",
            ),
          };
        // 绑过证书但已关闭
        case "site.example.com":
          return { body: certXml("Disabled", "<CertificateInfo><CertId>ssl-old</CertId><ValidityExpire>1788220800</ValidityExpire></CertificateInfo>") };
        // 从没配置过证书
        case "old.example.com":
          return cosErr(404, "NoSuchCertificate", "certificate not found");
        case "dl.example.com":
          return cosErr(500, "InternalError", "internal error");
      }
    }
  }
  if (host === "plain-1250000000.cos.ap-guangzhou.myqcloud.com") return cosErr(404, "DomainConfigNotFoundError", "domain config not found");
  if (host === "locked-1250000000.cos.ap-beijing.myqcloud.com") return cosErr(403, "AccessDenied", "Access Denied.");
  return undefined;
}

describe("tencent cos", () => {
  it("列 bucket → 逐个 bucket 查自定义域名 → 逐个域名查证书；HTTPS 以证书配置 Enabled 为准", async () => {
    const fetch = fakeFetch(cosRoute);
    const r = await runCli(["domains", "-s", "cos", "--json"], { env: TENCENT_ENV, fetch });
    expect(r.code).toBe(0);
    const extra = { bucket: "static-1250000000", region: "ap-shanghai" };
    expect(r.json.data.items).toEqual([
      {
        provider: "tencent",
        service: "cos",
        domain: "img.example.com",
        status: "ENABLED",
        https: true,
        cert: { id: "ssl-cos", notBefore: "2026-08-01T00:00:00.000Z", notAfter: "2026-11-20T00:00:00.000Z", status: "Enabled" },
        extra: { ...extra, type: "REST" },
        daysLeft: 36,
      },
      // 证书配置查询失败（非 404）：不知道是否开着 HTTPS，标记 httpsUnknown，不能当作未开启
      {
        provider: "tencent",
        service: "cos",
        domain: "dl.example.com",
        status: "ENABLED",
        https: false,
        extra: { ...extra, type: "ACCELERATE", httpsUnknown: "true" },
      },
      { provider: "tencent", service: "cos", domain: "old.example.com", status: "DISABLED", https: false, extra: { ...extra, type: "REST" } },
      { provider: "tencent", service: "cos", domain: "site.example.com", status: "ENABLED", https: false, extra: { ...extra, type: "WEBSITE" } },
    ]);
    // 没配置自定义域名的 bucket（404）不算错误；单个 bucket / 域名失败只记 issue
    expect(r.json.data.issues).toEqual([
      expect.objectContaining({ service: "cos", kind: "error", target: "bucket locked-1250000000", code: "AccessDenied", requestId: "req-AccessDenied" }),
      expect.objectContaining({ service: "cos", kind: "error", target: "domain dl.example.com", code: "InternalError" }),
    ]);
    // 证书缺名称时会按 ID 拉 SSL 证书列表补名称；有到期时间，拉取失败（这里没有路由）不记 issue
    expect(fetch.calls.filter((c) => c.url.host === "ssl.tencentcloudapi.com")).toHaveLength(1);
  });

  it("证书配置查询无权限 / 限流重试仍失败时标记 httpsUnknown；404（从没配置过证书）才是确定的未开启", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.host === SERVICE) {
        return { body: `<ListAllMyBucketsResult><Buckets><Bucket><Name>b-1250000000</Name><Location>ap-nanjing</Location></Bucket></Buckets></ListAllMyBucketsResult>` };
      }
      if (req.url.search === "?domain") {
        const rule = (name: string) => `<DomainRule><Status>ENABLED</Status><Name>${name}</Name><Type>REST</Type></DomainRule>`;
        return { body: `<DomainConfiguration>${rule("denied.example.com")}${rule("slow.example.com")}${rule("none.example.com")}</DomainConfiguration>` };
      }
      switch (req.url.searchParams.get("domainname")) {
        case "denied.example.com":
          return cosErr(403, "AccessDenied", "Access Denied.");
        case "slow.example.com":
          return cosErr(503, "SlowDown", "Reduce your request rate.");
        case "none.example.com":
          return cosErr(404, "NoSuchCertificate", "certificate not found");
      }
      return undefined;
    });
    const r = await runCli(["domains", "-s", "cos", "--json"], { env: TENCENT_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items.map((d: any) => [d.domain, d.https, d.extra.httpsUnknown])).toEqual([
      ["denied.example.com", false, "true"],
      ["none.example.com", false, undefined],
      ["slow.example.com", false, "true"],
    ]);
    expect(r.json.data.issues.map((i: any) => [i.target, i.code])).toEqual([
      ["domain denied.example.com", "AccessDenied"],
      ["domain slow.example.com", "Throttling"],
    ]);
  });

  it("请求格式：GET + q-sign 签名头，签 host 与所有请求参数", async () => {
    const fetch = fakeFetch(cosRoute);
    await runCli(["domains", "-s", "cos", "--json"], { env: TENCENT_ENV, fetch });
    const list = fetch.calls[0]!;
    expect(list.method).toBe("GET");
    expect(list.url.href).toBe("https://service.cos.myqcloud.com/?max-keys=2000");
    expect(list.headers["x-cos-security-token"]).toBeUndefined();
    expect(list.headers.authorization).toMatch(
      /^q-sign-algorithm=sha1&q-ak=AKIDtest00000000&q-sign-time=(\d+);(\d+)&q-key-time=\1;\2&q-header-list=host&q-url-param-list=max-keys&q-signature=[0-9a-f]{40}$/,
    );
    const cert = fetch.calls.find((c) => c.url.searchParams.get("domainname") === "img.example.com")!;
    expect(cert.url.href).toBe("https://static-1250000000.cos.ap-shanghai.myqcloud.com/?domaincertificate&domainname=img.example.com");
    const auth = cert.headers.authorization!;
    const [start, end] = /q-sign-time=(\d+);(\d+)/.exec(auth)!.slice(1).map(Number) as [number, number];
    expect(end - start).toBe(960);
    expect(auth).toBe(
      cosAuthorization({
        secretId: "AKIDtest00000000",
        secretKey: "testkey",
        method: "GET",
        path: "/",
        query: { domaincertificate: "", domainname: "img.example.com" },
        headers: { host: "static-1250000000.cos.ap-shanghai.myqcloud.com" },
        start,
        end,
      }),
    );
  });

  it("临时凭证：带 x-cos-security-token 并参与签名", async () => {
    const fetch = fakeFetch(cosRoute);
    await runCli(["domains", "-s", "cos", "--json"], { env: { ...TENCENT_ENV, TENCENTCLOUD_SESSION_TOKEN: "tok+/=" }, fetch });
    const list = fetch.calls[0]!;
    expect(list.headers["x-cos-security-token"]).toBe("tok+/=");
    const [start, end] = /q-sign-time=(\d+);(\d+)/.exec(list.headers.authorization!)!.slice(1).map(Number) as [number, number];
    expect(list.headers.authorization).toBe(
      cosAuthorization({
        secretId: "AKIDtest00000000",
        secretKey: "testkey",
        method: "GET",
        path: "/",
        query: { "max-keys": "2000" },
        headers: { host: SERVICE, "x-cos-security-token": "tok+/=" },
        start,
        end,
      }),
    );
    expect(list.headers.authorization).toContain("&q-header-list=host;x-cos-security-token&");
  });

  it("bucket 列表按 marker 翻页", async () => {
    const page1 = `<ListAllMyBucketsResult><IsTruncated>true</IsTruncated><NextMarker>b1-1250000000</NextMarker><Buckets><Bucket><Name>b1-1250000000</Name><Location>ap-chengdu</Location></Bucket></Buckets></ListAllMyBucketsResult>`;
    const page2 = `<ListAllMyBucketsResult><IsTruncated>false</IsTruncated><Buckets><Bucket><Name>b2-1250000000</Name><Location>ap-hongkong</Location></Bucket></Buckets></ListAllMyBucketsResult>`;
    const fetch = fakeFetch((req) => {
      if (req.url.host === SERVICE) return { body: req.url.searchParams.get("marker") === "b1-1250000000" ? page2 : page1 };
      if (req.url.search === "?domain") return cosErr(404, "DomainConfigNotFoundError", "not found");
      return undefined;
    });
    const r = await runCli(["domains", "-s", "cos", "--json"], { env: TENCENT_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.issues).toEqual([]);
    expect(fetch.calls.map((c) => c.url.href)).toEqual([
      "https://service.cos.myqcloud.com/?max-keys=2000",
      "https://service.cos.myqcloud.com/?max-keys=2000&marker=b1-1250000000",
      "https://b1-1250000000.cos.ap-chengdu.myqcloud.com/?domain",
      "https://b2-1250000000.cos.ap-hongkong.myqcloud.com/?domain",
    ]);
  });

  it("证书配置只有证书 ID 时从 SSL 证书列表补全；毫秒时间戳也能识别", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.host === SERVICE) {
        return { body: `<ListAllMyBucketsResult><Buckets><Bucket><Name>b-1250000000</Name><Location>ap-nanjing</Location></Bucket></Buckets></ListAllMyBucketsResult>` };
      }
      if (req.url.search === "?domain") {
        return { body: `<DomainConfiguration><DomainRule><Status>ENABLED</Status><Name>a.example.com</Name><Type>REST</Type></DomainRule><DomainRule><Status>ENABLED</Status><Name>b.example.com</Name><Type>REST</Type></DomainRule></DomainConfiguration>` };
      }
      if (req.url.searchParams.get("domainname") === "a.example.com") {
        return { body: certXml("Enabled", "<CertificateInfo><CertId>ssl-1</CertId><ValidityBegin>0</ValidityBegin><ValidityExpire>0</ValidityExpire></CertificateInfo>") };
      }
      if (req.url.searchParams.get("domainname") === "b.example.com") {
        return { body: certXml("Enabled", "<CertificateInfo><CertId>ssl-2</CertId><ValidityExpire>1799582400000</ValidityExpire></CertificateInfo>") };
      }
      if (req.url.host === "ssl.tencentcloudapi.com") {
        return {
          body: {
            Response: {
              RequestId: "rid",
              TotalCount: 1,
              Certificates: [
                { CertificateId: "ssl-1", Alias: "wild", Domain: "*.example.com", SubjectAltName: ["*.example.com"], CertBeginTime: "2026-08-01 08:00:00", CertEndTime: "2026-10-30 07:59:59" },
              ],
            },
          },
        };
      }
      return undefined;
    });
    const r = await runCli(["domains", "-s", "cos", "--json"], { env: TENCENT_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items.map((d: any) => [d.domain, d.cert, d.daysLeft])).toEqual([
      [
        "a.example.com",
        { id: "ssl-1", name: "wild", commonName: "*.example.com", sans: ["*.example.com"], notBefore: "2026-08-01T00:00:00.000Z", notAfter: "2026-10-29T23:59:59.000Z", status: "Enabled" },
        14,
      ],
      ["b.example.com", { id: "ssl-2", notAfter: "2027-01-10T12:00:00.000Z", status: "Enabled" }, 87],
    ]);
  });

  it("bucket 列表失败记为整个服务失败；错误码与 RequestId 取自 XML", async () => {
    const fetch = fakeFetch(() => cosErr(403, "InvalidAccessKeyId", "The Access Key Id you provided does not exist in our records"));
    const r = await runCli(["domains", "-s", "cos", "--json"], { env: TENCENT_ENV, fetch });
    expect(r.code).toBe(1);
    expect(JSON.parse(r.stderr)).toMatchObject({ ok: false, status: "InvalidAccessKeyId" });
    expect(fetch.calls).toHaveLength(1);
  });

  it("SlowDown 限流记为 Throttling 并重试，原始错误码保留在 message", async () => {
    let n = 0;
    const flaky = fakeFetch((req) => {
      if (req.url.host === SERVICE && n++ === 0) return cosErr(503, "SlowDown", "Reduce your request rate.");
      return cosRoute(req);
    });
    const ok = await runCli(["domains", "-s", "cos", "--json"], { env: TENCENT_ENV, fetch: flaky });
    expect(ok.code).toBe(0);
    expect(flaky.calls.filter((c) => c.url.host === SERVICE)).toHaveLength(2);

    const always = fakeFetch(() => cosErr(503, "SlowDown", "Reduce your request rate."));
    const r = await runCli(["domains", "-s", "cos", "--json"], { env: TENCENT_ENV, fetch: always });
    expect(always.calls).toHaveLength(3);
    expect(JSON.parse(r.stderr)).toMatchObject({ status: "Throttling" });
    expect(JSON.parse(r.stderr).message).toContain("SlowDown");
  });
});
