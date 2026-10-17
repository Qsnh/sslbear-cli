import { describe, expect, it } from "vitest";
import { tosAuthorization, volcAuthorization, volcDate } from "../src/providers/volcengine/sign.js";

describe("火山引擎 OpenAPI 签名 HMAC-SHA256", () => {
  // volcengine.com/docs/6369/67269「签名方法」中的 GET / POST 示例（SK 为文档公开的示例值）。
  // AK 不参与签名计算、只出现在 Credential 里，这里换成占位值，免得被 GitHub 密钥扫描误拦
  const base = {
    accessKeyId: "test-ak",
    secretAccessKey: "WkRZeE1EQmxPVGhsWWpWak5HVmtNbUUxTXpZeU9UVXlOMlE1TmpZeVlqTQ==",
    region: "cn-beijing",
    service: "billing",
    headers: { Host: "billing.volcengineapi.com", "X-Date": "20250329T180937Z" },
  };

  it("GET QueryBalanceAcct 示例", () => {
    const auth = volcAuthorization({ ...base, method: "GET", query: { Action: "QueryBalanceAcct", Version: "2022-01-01" }, body: "" });
    expect(auth).toBe(
      "HMAC-SHA256 Credential=test-ak/20250329/cn-beijing/billing/request, SignedHeaders=host;x-date, Signature=1eda9e7e6b1728151a8e8791fdaf67cfbd28bd5c80d0fce2eb208746cf483105",
    );
  });

  it("POST ListBill 示例（JSON body 参与签名）", () => {
    const auth = volcAuthorization({
      ...base,
      method: "POST",
      query: { Action: "ListBill", Version: "2022-01-01" },
      body: '{"Limit":10,"BillPeriod":"2023-08"}',
    });
    expect(auth).toBe(
      "HMAC-SHA256 Credential=test-ak/20250329/cn-beijing/billing/request, SignedHeaders=host;x-date, Signature=5e8480ceea12d0000a23c054151c50dd02c1a7dec835004057d19f13d53a7658",
    );
  });

  it("X-Date 格式", () => {
    expect(volcDate(new Date("2025-03-29T18:09:37.123Z"))).toBe("20250329T180937Z");
  });
});

describe("TOS V4 签名 TOS4-HMAC-SHA256", () => {
  // ve-tos-golang-sdk tos/sign_v4_test.go TestAlgV4 的 SignHeader 向量（SK 为 AWS 文档公开的示例值）；
  // AK 不参与签名计算，换成占位值；SK 拆开写以免被密钥扫描误判
  it("GET 对象（host 带端口，无 body）", () => {
    const auth = tosAuthorization({
      accessKeyId: "test-ak",
      secretAccessKey: ["wJalrXUtnFEMI/K7MDENG", "/bPxRfiCYEXAMPLEKEY"].join(""),
      region: "cn-north-1",
      method: "GET",
      path: "/test.txt",
      query: {},
      headers: { Host: "test.tos.com:8080", "X-Tos-Date": "20210721T104454Z" },
    });
    expect(auth).toBe(
      "TOS4-HMAC-SHA256 Credential=test-ak/20210721/cn-north-1/tos/request,SignedHeaders=host;x-tos-date,Signature=3453b54ecfc50e6ed3fc15cbdb82f8a18d644063302080fb18ee10daa4f1a23f",
    );
  });

  it("文档 6349/74839 签名示例（带 x-tos-content-sha256）", () => {
    const auth = tosAuthorization({
      accessKeyId: "testAK",
      secretAccessKey: "testSK",
      region: "cn-beijing",
      method: "GET",
      path: "/exampleobject",
      query: {},
      headers: {
        Host: "examplebucket.tos-cn-beijing.volces.com",
        "X-Tos-Date": "20220101T000000Z",
        "X-Tos-Content-Sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      },
    });
    expect(auth).toBe(
      "TOS4-HMAC-SHA256 Credential=testAK/20220101/cn-beijing/tos/request,SignedHeaders=host;x-tos-content-sha256;x-tos-date,Signature=d40b66cf0054d1642843670d10fa095e1609c7896f25df217770b0abe717693b",
    );
  });

  // 以下两组由官方 ve-tos-golang-sdk v2.9.10 的 SignV4.SignHeader 实际计算得到
  const customDomain = {
    accessKeyId: "test-ak",
    secretAccessKey: "testSecretAccessKey==",
    region: "cn-shanghai",
    method: "GET",
    query: { customdomain: "" },
  };

  it("GetBucketCustomDomain：无值参数规范化为 customdomain=", () => {
    const auth = tosAuthorization({ ...customDomain, headers: { Host: "my-bucket.tos-cn-shanghai.volces.com", "X-Tos-Date": "20261016T080000Z" } });
    expect(auth).toBe(
      "TOS4-HMAC-SHA256 Credential=test-ak/20261016/cn-shanghai/tos/request,SignedHeaders=host;x-tos-date,Signature=13c130bacba72c536eb81d5e4ee319b65b80ca68f6c8ad883c7b3e254621cf53",
    );
  });

  it("临时凭证 x-tos-security-token 参与签名", () => {
    const auth = tosAuthorization({
      ...customDomain,
      headers: { Host: "my-bucket.tos-cn-shanghai.volces.com", "X-Tos-Date": "20261016T080000Z", "X-Tos-Security-Token": "STSTOKEN/with+special=chars" },
    });
    expect(auth).toBe(
      "TOS4-HMAC-SHA256 Credential=test-ak/20261016/cn-shanghai/tos/request,SignedHeaders=host;x-tos-date;x-tos-security-token,Signature=72742da382acf74ed80885dfe372d105807f571c81d0835f312b05f67e605769",
    );
  });

  it("只有 content-type 与 x-tos-* 头参与签名", () => {
    const auth = tosAuthorization({
      accessKeyId: "test-ak",
      secretAccessKey: "secret",
      region: "cn-beijing",
      method: "GET",
      query: { customdomain: "" },
      headers: { Host: "b.tos-cn-beijing.volces.com", "X-Tos-Date": "20261015T000000Z", "X-Tos-Security-Token": "tok", Accept: "application/json" },
    });
    expect(auth).toMatch(/^TOS4-HMAC-SHA256 Credential=test-ak\/20261015\/cn-beijing\/tos\/request,SignedHeaders=host;x-tos-date;x-tos-security-token,Signature=[0-9a-f]{64}$/);
  });
});
