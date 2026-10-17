import { describe, expect, it } from "vitest";
import { bceAuthorization, bceTimestamp, canonicalPath, canonicalQuery, uriEncode } from "../src/providers/baidu/sign.js";

describe("百度智能云 bce-auth-v1 签名", () => {
  // cloud.baidu.com/doc/Reference/s/njwvz1yfu「认证字符串示例」：BOS UploadPart，AK/SK 为文档里的 a/b 占位串。
  // 文档的 signedHeaders 留空（用推荐范围），这里显式列出同一组头，签名摘要不变
  it("与官方文档 UploadPart 示例一致", () => {
    const auth = bceAuthorization({
      accessKeyId: "a".repeat(32),
      secretAccessKey: "b".repeat(32),
      method: "PUT",
      path: "/v1/test/myfolder/readme.txt",
      query: { partNumber: "9", uploadId: "a44cc9bab11cbd156984767aad637851" },
      headers: {
        Host: "bj.bcebos.com",
        Date: "Mon, 27 Apr 2015 16:23:49 +0800",
        "Content-Type": "text/plain",
        "Content-Length": "8",
        "Content-Md5": "NFzcPqhviddjRNnSOGo4rw==",
        "x-bce-date": "2015-04-27T08:23:49Z",
      },
      timestamp: "2015-04-27T08:23:49Z",
    });
    expect(auth).toBe(
      `bce-auth-v1/${"a".repeat(32)}/2015-04-27T08:23:49Z/1800/content-length;content-md5;content-type;host;x-bce-date/d74a04362e6a848f5b39b15421cb449427f419c95a480fd6b8cf9fc783e2999e`,
    );
  });

  // baidubce/bce-sdk-js test/sdk/auth.spec.js generateAuthorization 的两组用例
  it("与 bce-sdk-js 用例一致：非推荐头不签名、空值参数保留 key=", () => {
    const auth = bceAuthorization({
      accessKeyId: "my_ak",
      secretAccessKey: "my_sk",
      method: "PUT",
      path: "/v1/bucket/object1",
      query: { A: "", b: "", C: "d" },
      headers: { Host: "bce.baidu.com", abc: "123", "x-bce-meta-key1": "ABC" },
      timestamp: bceTimestamp(new Date(1402639056 * 1000)),
    });
    expect(auth).toBe(
      "bce-auth-v1/my_ak/2014-06-13T05:57:36Z/1800/host;x-bce-meta-key1/80c9672aca2ea9af4bb40b9a8ff458d72df94e97d550840727f3a929af271d25",
    );
  });

  it("与 bce-sdk-js 用例一致：content-length 为 0 也参与签名", () => {
    const auth = bceAuthorization({
      accessKeyId: "my_ak",
      secretAccessKey: "my_sk",
      method: "DELETE",
      path: "/v1/test-bucket1361199862",
      query: {},
      headers: { "Content-Type": "application/json; charset=utf-8", "Content-Length": "0", "User-Agent": "This is the user-agent" },
      timestamp: "2014-06-13T05:57:36Z",
      expirationSeconds: 1800,
    });
    expect(auth).toBe(
      "bce-auth-v1/my_ak/2014-06-13T05:57:36Z/1800/content-length;content-type/c9386b15d585960ae5e6972f73ed92a9a682dc81025480ba5b41206d3e489822",
    );
  });

  it("编码规则与官方文档示例一致", () => {
    expect(uriEncode("!'()*this is an example for 测试")).toBe("%21%27%28%29%2Athis%20is%20an%20example%20for%20%E6%B5%8B%E8%AF%95");
    expect(canonicalPath("/example/测试")).toBe("/example/%E6%B5%8B%E8%AF%95");
    expect(canonicalPath("/v2/domain/*.example.com/config")).toBe("/v2/domain/%2A.example.com/config");
    // 按编码后的整串排序：text10=test 排在 text1=... 前面
    expect(canonicalQuery({ text: "", text1: "测试", text10: "test" })).toBe("text10=test&text1=%E6%B5%8B%E8%AF%95&text=");
    expect(canonicalQuery({ authorization: "x", https: "" })).toBe("https=");
    expect(bceTimestamp(new Date("2015-04-27T08:23:49.123Z"))).toBe("2015-04-27T08:23:49Z");
  });
});
