import { describe, expect, it } from "vitest";
import { qboxAuthorization, qiniuAuthorization, qiniuDate } from "../src/providers/qiniu/sign.js";

// 向量来自 qiniu/python-sdk tests/cases/test_auth.py（QiniuMacAuth("ak", "sk")）
// 与 qiniu/nodejs-sdk test/util.test.js 的 generateAccessTokenV2 用例
describe("七牛 Qiniu 鉴权", () => {
  const base = { accessKey: "ak", secretKey: "sk", method: "GET", host: "upload.qiniup.com" };
  const xHeaders = { "X-Qiniu-Bbb": "BBB", "X-Qiniu-Aaa": "DDD", "X-Qiniu-": "a", "X-Qiniu": "b" };
  const form = "application/x-www-form-urlencoded";

  it("空路径、表单类型、无 X-Qiniu 头（python-sdk）", () => {
    expect(
      qiniuAuthorization({ ...base, host: "", pathWithQuery: "", contentType: form, headers: { "X-Qiniu-": "a", "X-Qiniu": "b" }, body: '{"name": "test"}' }),
    ).toBe("Qiniu ak:0i1vKClRDWFyNkcTFzwcE7PzX74=");
  });

  it("POST JSON 请求体参与签名，X-Qiniu（无后缀）不参与（python-sdk）", () => {
    expect(
      qiniuAuthorization({ ...base, method: "POST", host: "", pathWithQuery: "", contentType: "application/json", headers: { "X-Qiniu": "b" }, body: '{"name": "test"}' }),
    ).toBe("Qiniu ak:0ujEjW_vLRZxebsveBgqa3JyQ-w=");
  });

  it("X-Qiniu-* 头规范化后按名排序（python-sdk）", () => {
    expect(qiniuAuthorization({ ...base, pathWithQuery: "", contentType: "application/json", headers: xHeaders, body: '{"name": "test"}' })).toBe(
      "Qiniu ak:DhNA1UCaBqSHCsQjMOLRfVn63GQ=",
    );
  });

  it("带路径与 query（python-sdk / nodejs-sdk 一致）", () => {
    const body = "name=test&language=go";
    expect(qiniuAuthorization({ ...base, pathWithQuery: "/mkfile/sdf.jpg", contentType: form, headers: xHeaders, body })).toBe(
      "Qiniu ak:fkRck5_LeyfwdkyyLk-hyNwGKac=",
    );
    expect(qiniuAuthorization({ ...base, pathWithQuery: "/mkfile/sdf.jpg?s=er3&df", contentType: form, headers: xHeaders, body })).toBe(
      "Qiniu ak:PUFPWsEUIpk_dzUvvxTTmwhp3p4=",
    );
  });

  it("方法与头名大小写不敏感；octet-stream 请求体不参与（nodejs-sdk）", () => {
    const body = '{"name": "test"}';
    expect(
      qiniuAuthorization({ ...base, method: "gET", pathWithQuery: "/", contentType: "application/json", headers: { "X-Qiniu-Bbb": "BBB", "x-qIniu-aAa": "DDD" }, body }),
    ).toBe("Qiniu ak:eOaX4RziJPW9ywnJ02jshmEMfhI=");
    expect(qiniuAuthorization({ ...base, pathWithQuery: "/", contentType: "application/octet-stream", headers: xHeaders, body })).toBe(
      "Qiniu ak:GQQrYvDCdN_RaVjyJC7hIkv5TYk=",
    );
  });

  it("X-Qiniu-Date 格式", () => {
    expect(qiniuDate(new Date("2026-02-13T12:00:00.123Z"))).toBe("20260213T120000Z");
  });
});

// 向量来自 qiniu/python-sdk tests/cases/test_auth.py（Auth("abcdefghklmnopq", "1234567890").token_of_request）
describe("七牛 QBox 鉴权", () => {
  const base = { accessKey: "abcdefghklmnopq", secretKey: "1234567890", pathWithQuery: "?go=1" };
  it("只签路径 + query", () => {
    expect(qboxAuthorization(base)).toBe("QBox abcdefghklmnopq:cFyRVoWrE3IugPIMP5YJFTO-O-Y=");
  });
  it("表单请求体参与签名", () => {
    expect(qboxAuthorization({ ...base, formBody: "test" })).toBe("QBox abcdefghklmnopq:svWRNcacOE-YMsc70nuIYdaa1e4=");
  });
});
