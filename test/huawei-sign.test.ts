import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  apigAuthorization,
  apigCanonicalRequest,
  canonicalQuery,
  obsAuthorization,
  obsStringToSign,
  sdkDate,
} from "../src/providers/huawei/sign.js";

describe("华为云 API 网关签名 SDK-HMAC-SHA256", () => {
  // huaweicloud-sdk-go-v3 core/auth/signer/signer_test.go 的 TestSigner_Sign 用例（AK/SK 为 AccessKey/SecretKey）
  const base = { accessKeyId: "AccessKey", secretAccessKey: "SecretKey", path: "/path", headers: { "X-Sdk-Date": "20060102T150405Z" } };

  it("GET 带查询参数（SDK 单测 test1）", () => {
    expect(apigAuthorization({ ...base, method: "GET", query: { limit: "1" } })).toBe(
      "SDK-HMAC-SHA256 Access=AccessKey, SignedHeaders=x-sdk-date, Signature=5a2ce64c865e0e6046321c6f3d5a77ba8413eeaf355c3166c03d58d02ac79624",
    );
  });

  // SDK 用 json.Encoder 序列化请求体，末尾带换行
  it("POST JSON 请求体（SDK 单测 test2，Content-Type 不参与签名）", () => {
    expect(apigAuthorization({ ...base, method: "POST", query: { key: "value" }, body: '{"Name":"test","Id":1}\n' })).toBe(
      "SDK-HMAC-SHA256 Access=AccessKey, SignedHeaders=x-sdk-date, Signature=cecc2af119b18ab70b4d094c0750f3b42c02f254903179a0fc2cc72fc9db4f59",
    );
  });

  it("规范查询字符串的编码与排序（SDK 单测 TestSigner_canonicalQueryString，去掉多值参数）", () => {
    expect(canonicalQuery({ limit: "1", enable: "true", test: "一 (&=?!#%.*)", path: "/tmp/123" })).toBe(
      "enable=true&limit=1&path=%2Ftmp%2F123&test=%E4%B8%80%20%28%26%3D%3F%21%23%25.%2A%29",
    );
  });

  // support.huaweicloud.com/devg-apisign/api-sign-algorithm-002.html：文档里的 SK 打了码，只能校验规范请求的哈希
  it("规范请求与官方文档「API签名认证机制示例」一致（URI 末尾补 /）", () => {
    const { canonicalRequest, signedHeaders } = apigCanonicalRequest({
      accessKeyId: "ak",
      secretAccessKey: "sk",
      method: "GET",
      path: "/v1/77b6a44cba5143ab91d13ab9a8ff44fd/vpcs",
      query: { marker: "13551d6b-755d-4757-b956-536f674975c0", limit: "2" },
      headers: { "Content-Type": "application/json", Host: "service.region.example.com", "X-Sdk-Date": "20191115T033655Z" },
    });
    expect(signedHeaders).toBe("content-type;host;x-sdk-date");
    expect(createHash("sha256").update(canonicalRequest).digest("hex")).toBe(
      "b25362e603ee30f4f25e7858e8a7160fd36e803bb2dfe206278659d71a9bcd7a",
    );
  });

  it("X-Sdk-Date 格式", () => {
    expect(sdkDate(new Date("2019-11-15T03:36:55.123Z"))).toBe("20191115T033655Z");
  });
});

describe("OBS 签名", () => {
  // 期望值由官方 huaweicloud-sdk-go-obs v3.26.6 计算（OBS 协议签名，AK/SK 为 test-ak/test-sk，固定 Date 头）
  const date = "Mon, 25 Jun 2018 05:37:12 GMT";
  const sign = (headers: Record<string, string>, resource: string) =>
    obsAuthorization("test-ak", "test-sk", obsStringToSign("GET", headers, resource));

  it("ListBuckets：服务级资源 /，x-obs-bucket-type 参与签名", () => {
    expect(sign({ Date: date, "x-obs-bucket-type": "OBJECT" }, "/")).toBe("OBS test-ak:yl2zuWuUU7EJhosKyvUCe/Upf9Y=");
    expect(sign({ Date: date, "x-obs-bucket-type": "OBJECT", "x-obs-security-token": "test-security-token" }, "/")).toBe(
      "OBS test-ak:yDvU3P9ZEciiB3wDXZuyik0jy6Y=",
    );
  });

  it("GetBucketCustomdomain：桶级资源 /bucket/?customdomain", () => {
    expect(sign({ Date: date }, "/examplebucket/?customdomain")).toBe("OBS test-ak:JOGyUluMkDgtUSPEOnXH0WgYdWU=");
    expect(sign({ Date: date, "x-obs-security-token": "test-security-token" }, "/examplebucket/?customdomain")).toBe(
      "OBS test-ak:skXlSahe254DSj5SQXYMTYoy89Q=",
    );
  });

  // support.huaweicloud.com/api-obs/obs_04_0010.html「StringToSign构造示例」表5：带 x-obs-date 时 Date 行为空
  it("StringToSign 与官方文档示例一致", () => {
    expect(
      obsStringToSign(
        "PUT",
        { "x-obs-date": "Tue, 15 Oct 2015 07:20:09 GMT", "x-obs-security-token": "YwkaRTbdY8g7q....", "content-type": "text/plain" },
        "/bucket/object.txt",
      ),
    ).toBe("PUT\n\ntext/plain\n\nx-obs-date:Tue, 15 Oct 2015 07:20:09 GMT\nx-obs-security-token:YwkaRTbdY8g7q....\n/bucket/object.txt");
    expect(obsStringToSign("GET", { Date: "Sat, 12 Oct 2015 08:12:38 GMT" }, "/bucket/object.txt?acl")).toBe(
      "GET\n\n\nSat, 12 Oct 2015 08:12:38 GMT\n/bucket/object.txt?acl",
    );
  });
});
