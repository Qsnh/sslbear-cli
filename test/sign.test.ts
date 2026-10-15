import { describe, expect, it } from "vitest";
import { ossDate, ossV4Authorization, rpcSignature } from "../src/providers/aliyun/sign.js";
import { tc3Authorization } from "../src/providers/tencent/sign.js";

describe("阿里云 RPC 签名 V1", () => {
  it("与官方文档 DescribeRegions 示例一致", () => {
    const params = {
      AccessKeyId: "testid",
      Action: "DescribeRegions",
      Format: "XML",
      SignatureMethod: "HMAC-SHA1",
      SignatureNonce: "3ee8c1b8-83d3-44af-a94f-4e0ad82fd6cf",
      SignatureVersion: "1.0",
      Timestamp: "2016-02-23T12:46:24Z",
      Version: "2014-05-26",
    };
    expect(rpcSignature(params, "testsecret")).toBe("OLeaidS1JvxuMvnyHOwuJ+uX5qY=");
  });
});

describe("腾讯云 TC3-HMAC-SHA256", () => {
  // tencentcloud.com/document/product/267/37447 中未打码的完整示例。
  // SecretId 不参与签名计算、只出现在 Credential 里，这里换成占位值（文档原值会被 GitHub 密钥扫描误拦）
  it("与官方文档 DescribeInstances 示例一致", () => {
    const auth = tc3Authorization({
      secretId: "test-secret-id",
      secretKey: "Gu5t9xGARNpq86cd98joQYCN3EXAMPLE",
      service: "cvm",
      host: "cvm.tencentcloudapi.com",
      timestamp: 1551113065,
      payload: '{"Limit": 1, "Filters": [{"Values": ["\\u672a\\u547d\\u540d"], "Name": "instance-name"}]}',
    });
    expect(auth).toBe(
      "TC3-HMAC-SHA256 Credential=test-secret-id/2019-02-25/cvm/tc3_request, SignedHeaders=content-type;host, Signature=72e494ea809ad7a8c8f7a4507b9bddcbaa8e581f516e8da2f66e2c5a96525168",
    );
  });
});

describe("阿里云 RPC 签名 V1（新版文档示例）", () => {
  it("DescribeDedicatedHosts 示例", () => {
    const params = {
      AccessKeyId: "testid",
      Action: "DescribeDedicatedHosts",
      Format: "JSON",
      RegionId: "cn-beijing",
      SignatureMethod: "HMAC-SHA1",
      SignatureNonce: "edb2b34af0af9a6d14deaf7c1a5315eb",
      SignatureVersion: "1.0",
      Timestamp: "2023-03-13T08:34:30Z",
      Version: "2014-05-26",
    };
    expect(rpcSignature(params, "testsecret")).toBe("9NaGiOspFP5UPcwX8Iwt2YJXXuk=");
  });
});

describe("OSS 签名 V4", () => {
  // 期望值来自独立实现（该实现通过了 OSS Go SDK v2 的官方 V4 用例），用于交叉校验
  const base = {
    accessKeyId: "ak",
    accessKeySecret: "sk",
    region: "cn-hangzhou",
    method: "GET",
    headers: { "x-oss-date": "20250417T153912Z", "x-oss-content-sha256": "UNSIGNED-PAYLOAD" },
  };
  it("ListCname：bucket 级、无值子资源", () => {
    expect(ossV4Authorization({ ...base, bucket: "examplebucket", query: { cname: "" } })).toBe(
      "OSS4-HMAC-SHA256 Credential=ak/20250417/cn-hangzhou/oss/aliyun_v4_request,Signature=a2b64f9a03decf846bc9ded001322676e89a71babb7c48eaf492aed09ee06f0d",
    );
  });
  it("ListBuckets：服务级", () => {
    expect(ossV4Authorization({ ...base, query: {} })).toBe(
      "OSS4-HMAC-SHA256 Credential=ak/20250417/cn-hangzhou/oss/aliyun_v4_request,Signature=9246d65bc2d1dcb41a5069b738acdd7f8564e336e4d55dd7b64a617b2931596f",
    );
  });
  it("x-oss-date 格式", () => {
    expect(ossDate(new Date("2025-04-17T15:39:12.345Z"))).toBe("20250417T153912Z");
  });
});
