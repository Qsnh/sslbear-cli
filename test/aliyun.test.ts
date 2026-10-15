import { describe, expect, it } from "vitest";
import { ALIYUN_ENV, fakeFetch, runCli, type FakeRequest } from "./helpers.js";

const rpcError = (status: number, Code: string, Message: string) => ({
  status,
  body: { RequestId: "req-1", Code, Message },
});

/** CDN：两个域名，其中一个开了 HTTPS */
function cdnRoutes(req: FakeRequest) {
  if (req.url.host !== "cdn.aliyuncs.com") return undefined;
  if (req.action === "DescribeUserDomains") {
    return {
      body: {
        TotalCount: 2,
        Domains: {
          PageData: [
            { DomainName: "api.example.com", DomainStatus: "online", SslProtocol: "on" },
            { DomainName: "plain.example.com", DomainStatus: "online", SslProtocol: "off" },
          ],
        },
      },
    };
  }
  if (req.action === "DescribeCdnHttpsDomainList") {
    return {
      body: {
        TotalCount: 1,
        CertInfos: {
          CertInfo: [
            {
              DomainName: "api.example.com",
              CertName: "api-cert",
              CertCommonName: "*.example.com",
              CertType: "cas",
              CertStatus: "ok",
              CertStartTime: "2026-08-01 08:00:00",
              CertExpireTime: "2026-11-01 08:00:00",
            },
          ],
        },
      },
    };
  }
  return undefined;
}

describe("aliyun domains", () => {
  it("CDN：域名列表与 HTTPS 证书列表按域名合并，并带上签名参数", async () => {
    const fetch = fakeFetch(cdnRoutes);
    const r = await runCli(["domains", "-p", "aliyun", "-s", "cdn", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.issues).toEqual([]);
    expect(r.json.data.items).toEqual([
      {
        provider: "aliyun",
        service: "cdn",
        domain: "api.example.com",
        status: "online",
        https: true,
        cert: {
          name: "api-cert",
          commonName: "*.example.com",
          notBefore: "2026-08-01T00:00:00.000Z",
          notAfter: "2026-11-01T00:00:00.000Z",
          status: "ok",
        },
        extra: { certType: "cas" },
        daysLeft: 17,
      },
      { provider: "aliyun", service: "cdn", domain: "plain.example.com", status: "online", https: false },
    ]);
    const q = fetch.calls[0]!.url.searchParams;
    expect(q.get("Version")).toBe("2018-05-10");
    expect(q.get("AccessKeyId")).toBe(ALIYUN_ENV.ALIBABA_CLOUD_ACCESS_KEY_ID);
    expect(q.get("SignatureMethod")).toBe("HMAC-SHA1");
    expect(q.get("Signature")).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });

  it("STS 临时凭证带上 SecurityToken", async () => {
    const fetch = fakeFetch(cdnRoutes);
    await runCli(["domains", "-s", "cdn", "--json"], {
      env: { ...ALIYUN_ENV, ALIBABA_CLOUD_SECURITY_TOKEN: "sts-token" },
      fetch,
    });
    expect(fetch.calls.every((c) => c.url.searchParams.get("SecurityToken") === "sts-token")).toBe(true);
  });

  it("翻页直到取完", async () => {
    const all = Array.from({ length: 501 }, (_, i) => ({ DomainName: `d${i}.example.com`, DomainStatus: "online", SslProtocol: "off" }));
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeUserDomains") {
        const page = Number(req.url.searchParams.get("PageNumber"));
        const size = Number(req.url.searchParams.get("PageSize"));
        return { body: { TotalCount: all.length, Domains: { PageData: all.slice((page - 1) * size, page * size) } } };
      }
      if (req.action === "DescribeCdnHttpsDomainList") return rpcError(400, "NoHttpsDomain", "no https domain");
      return undefined;
    });
    const r = await runCli(["domains", "-s", "cdn", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toHaveLength(501);
    expect(r.json.data.issues).toEqual([]);
    expect(fetch.calls.filter((c) => c.action === "DescribeUserDomains")).toHaveLength(2);
  });

  it("DCDN 未开通记为 inactive，不影响其他服务与退出码", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.host === "dcdn.aliyuncs.com") return rpcError(403, "DcdnServiceNotFound", "The DCDN service is not activated.");
      return cdnRoutes(req);
    });
    const r = await runCli(["domains", "-s", "cdn,dcdn", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toHaveLength(2);
    expect(r.json.data.issues).toEqual([
      {
        provider: "aliyun",
        service: "dcdn",
        kind: "inactive",
        code: "DcdnServiceNotFound",
        message: "The DCDN service is not activated.",
        requestId: "req-1",
      },
    ]);
  });

  it("限流自动重试", async () => {
    let n = 0;
    const fetch = fakeFetch((req) => {
      if (req.action === "DescribeUserDomains" && n++ === 0) return rpcError(400, "Throttling.User", "Request was denied due to user flow control.");
      return cdnRoutes(req);
    });
    const r = await runCli(["domains", "-s", "cdn", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toHaveLength(2);
  });

  it("全部查询失败时 exit 1，stderr 输出错误 JSON", async () => {
    const fetch = fakeFetch(() => rpcError(400, "InvalidAccessKeyId.NotFound", "Specified access key is not found."));
    const r = await runCli(["domains", "-s", "cdn,live", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(1);
    expect(r.stdout).toBe("");
    const err = JSON.parse(r.stderr);
    expect(err).toMatchObject({ ok: false, status: "InvalidAccessKeyId.NotFound" });
  });

  it("直播：状态字段为 LiveDomainStatus，证书走批量 HTTPS 列表", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.host !== "live.aliyuncs.com") return undefined;
      if (req.action === "DescribeLiveUserDomains") {
        expect(req.url.searchParams.get("PageSize")).toBe("50");
        return { body: { TotalCount: 1, Domains: { PageData: [{ DomainName: "play.example.com", LiveDomainStatus: "online", LiveDomainType: "liveVideo" }] } } };
      }
      if (req.action === "DescribeLiveHttpsDomainList") {
        return { body: { TotalCount: 1, CertInfos: { CertInfo: [{ DomainName: "play.example.com", CertName: "live", CertExpireTime: "2026-10-10 00:00:00" }] } } };
      }
      return undefined;
    });
    const r = await runCli(["domains", "-s", "live", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.json.data.items[0]).toMatchObject({ domain: "play.example.com", status: "online", https: true, daysLeft: -6 });
  });

  it("点播：只对开启 HTTPS 的域名查证书，单个域名失败只记 issue", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.host !== "vod.cn-shanghai.aliyuncs.com") return undefined;
      if (req.action === "DescribeVodUserDomains") {
        return {
          body: {
            TotalCount: 3,
            Domains: {
              PageData: [
                { DomainName: "v1.example.com", DomainStatus: "online", SslProtocol: "on" },
                { DomainName: "v2.example.com", DomainStatus: "online", SslProtocol: "on" },
                { DomainName: "v3.example.com", DomainStatus: "offline", SslProtocol: "off" },
              ],
            },
          },
        };
      }
      if (req.action === "DescribeVodDomainCertificateInfo") {
        if (req.url.searchParams.get("DomainName") === "v2.example.com") return rpcError(500, "InternalError", "boom");
        return {
          body: {
            CertInfos: {
              CertInfo: [{ CertId: "123-cn-hangzhou", CertName: "vod", CertDomainName: "v1.example.com", CertExpireTime: "2027-01-01T00:00:00Z", Status: "success" }],
            },
          },
        };
      }
      return undefined;
    });
    const r = await runCli(["domains", "-s", "vod", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(fetch.calls.filter((c) => c.action === "DescribeVodDomainCertificateInfo")).toHaveLength(2);
    const byDomain = Object.fromEntries(r.json.data.items.map((d: any) => [d.domain, d]));
    expect(byDomain["v1.example.com"].cert).toMatchObject({ id: "123-cn-hangzhou", notAfter: "2027-01-01T00:00:00.000Z" });
    expect(byDomain["v2.example.com"]).toMatchObject({ https: true });
    expect(byDomain["v2.example.com"].cert).toBeUndefined();
    expect(byDomain["v3.example.com"]).toMatchObject({ https: false });
    expect(r.json.data.issues).toEqual([
      expect.objectContaining({ service: "vod", kind: "error", code: "InternalError", target: "v2.example.com" }),
    ]);
  });
});

const LIST_BUCKETS = `<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult>
  <Owner><ID>1</ID><DisplayName>1</DisplayName></Owner>
  <Buckets>
    <Bucket>
      <CreationDate>2024-01-01T00:00:00.000Z</CreationDate>
      <ExtranetEndpoint>oss-cn-shanghai.aliyuncs.com</ExtranetEndpoint>
      <Location>oss-cn-shanghai</Location>
      <Name>static-prod</Name>
      <Region>cn-shanghai</Region>
    </Bucket>
    <Bucket>
      <ExtranetEndpoint>oss-cn-beijing.aliyuncs.com</ExtranetEndpoint>
      <Location>oss-cn-beijing</Location>
      <Name>locked</Name>
      <Region>cn-beijing</Region>
    </Bucket>
  </Buckets>
</ListAllMyBucketsResult>`;

const LIST_CNAME = `<?xml version="1.0" encoding="UTF-8"?>
<ListCnameResult>
  <Bucket>static-prod</Bucket>
  <Owner>1</Owner>
  <Cname>
    <Domain>img.example.com</Domain>
    <LastModified>2021-09-15T02:35:07.000Z</LastModified>
    <Status>Enabled</Status>
    <Certificate>
      <Type>CAS</Type>
      <CertId>493****-cn-hangzhou</CertId>
      <Status>Enabled</Status>
      <CreationDate>Wed, 15 Sep 2021 02:35:06 GMT</CreationDate>
      <Fingerprint>DE:01</Fingerprint>
      <ValidStartDate>Wed, 12 Aug 2026 10:14:51 GMT</ValidStartDate>
      <ValidEndDate>Mon, 2 Nov 2026 10:14:51 GMT</ValidEndDate>
    </Certificate>
  </Cname>
  <Cname>
    <Domain>raw.example.com</Domain>
    <Status>Enabled</Status>
  </Cname>
</ListCnameResult>`;

describe("aliyun oss", () => {
  it("列 bucket 后逐个查 CNAME，使用 V4 签名；单个 bucket 无权限只记 issue", async () => {
    const fetch = fakeFetch((req) => {
      if (req.url.host === "oss-cn-hangzhou.aliyuncs.com") return { body: LIST_BUCKETS };
      if (req.url.host === "static-prod.oss-cn-shanghai.aliyuncs.com" && req.url.search === "?cname") return { body: LIST_CNAME };
      if (req.url.host === "locked.oss-cn-beijing.aliyuncs.com") {
        return { status: 403, body: "<Error><Code>AccessDenied</Code><Message>denied by bucket policy</Message><RequestId>oss-req</RequestId></Error>" };
      }
      return undefined;
    });
    const r = await runCli(["domains", "-s", "oss", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toEqual([
      {
        provider: "aliyun",
        service: "oss",
        domain: "img.example.com",
        status: "Enabled",
        https: true,
        cert: {
          id: "493****-cn-hangzhou",
          notBefore: "2026-08-12T10:14:51.000Z",
          notAfter: "2026-11-02T10:14:51.000Z",
          status: "Enabled",
        },
        extra: { bucket: "static-prod", region: "cn-shanghai", certType: "CAS" },
        daysLeft: 18,
      },
      {
        provider: "aliyun",
        service: "oss",
        domain: "raw.example.com",
        status: "Enabled",
        https: false,
        extra: { bucket: "static-prod", region: "cn-shanghai" },
      },
    ]);
    expect(r.json.data.issues).toEqual([
      {
        provider: "aliyun",
        service: "oss",
        target: "bucket locked",
        kind: "error",
        code: "AccessDenied",
        message: "denied by bucket policy",
        requestId: "oss-req",
      },
    ]);
    const cnameCall = fetch.calls.find((c) => c.url.host.startsWith("static-prod."))!;
    expect(cnameCall.headers.authorization).toMatch(
      /^OSS4-HMAC-SHA256 Credential=LTAItestid0000\/\d{8}\/cn-shanghai\/oss\/aliyun_v4_request,Signature=[0-9a-f]{64}$/,
    );
    expect(cnameCall.headers["x-oss-content-sha256"]).toBe("UNSIGNED-PAYLOAD");
  });

  it("ListBuckets 截断时按 NextMarker 翻页", async () => {
    const page1 = `<ListAllMyBucketsResult><IsTruncated>true</IsTruncated><NextMarker>b1</NextMarker><Buckets><Bucket><Name>b1</Name><Region>cn-hangzhou</Region><ExtranetEndpoint>oss-cn-hangzhou.aliyuncs.com</ExtranetEndpoint></Bucket></Buckets></ListAllMyBucketsResult>`;
    const page2 = `<ListAllMyBucketsResult><Buckets><Bucket><Name>b2</Name><Region>cn-hangzhou</Region><ExtranetEndpoint>oss-cn-hangzhou.aliyuncs.com</ExtranetEndpoint></Bucket></Buckets></ListAllMyBucketsResult>`;
    const fetch = fakeFetch((req) => {
      if (req.url.host === "oss-cn-hangzhou.aliyuncs.com") return { body: req.url.searchParams.get("marker") === "b1" ? page2 : page1 };
      return { body: "<ListCnameResult></ListCnameResult>" };
    });
    const r = await runCli(["domains", "-s", "oss", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(fetch.calls.map((c) => c.url.host)).toEqual([
      "oss-cn-hangzhou.aliyuncs.com",
      "oss-cn-hangzhou.aliyuncs.com",
      "b1.oss-cn-hangzhou.aliyuncs.com",
      "b2.oss-cn-hangzhou.aliyuncs.com",
    ]);
  });
});

describe("aliyun certs", () => {
  it("有效证书与已过期证书两次查询合并去重", async () => {
    const fetch = fakeFetch((req) => {
      if (req.action !== "ListUserCertificateOrder") return undefined;
      expect(req.url.searchParams.get("OrderType")).toBe("CERT");
      if (req.url.searchParams.get("Status") === "EXPIRED") {
        return {
          body: {
            TotalCount: 1,
            CertificateOrderList: [{ CertificateId: 2, Name: "old", CommonName: "old.example.com", EndDate: "2026-09-01", Expired: true, Upload: true }],
          },
        };
      }
      return {
        body: {
          TotalCount: 1,
          CertificateOrderList: [
            {
              CertificateId: 1,
              Name: "wild",
              CommonName: "*.example.com",
              Sans: "*.example.com,example.com",
              Issuer: "DigiCert",
              StartDate: "2026-01-01",
              EndDate: "2027-01-01",
              Expired: false,
              Upload: false,
            },
          ],
        },
      };
    });
    const r = await runCli(["certs", "--json"], { env: ALIYUN_ENV, fetch });
    expect(r.code).toBe(0);
    expect(r.json.data.items).toEqual([
      {
        provider: "aliyun",
        id: "2",
        name: "old",
        commonName: "old.example.com",
        notAfter: "2026-08-31T16:00:00.000Z",
        status: "EXPIRED",
        source: "upload",
        daysLeft: -45,
      },
      {
        provider: "aliyun",
        id: "1",
        name: "wild",
        commonName: "*.example.com",
        sans: ["*.example.com", "example.com"],
        issuer: "DigiCert",
        notBefore: "2025-12-31T16:00:00.000Z",
        notAfter: "2026-12-31T16:00:00.000Z",
        status: "ISSUED",
        source: "issued",
        daysLeft: 77,
      },
    ]);
  });
});
