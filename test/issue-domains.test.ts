import { describe, expect, it } from "vitest";
import { certDirName, challengeName, MAX_DOMAINS, normalizeIssueDomain, parseDomains } from "../src/issue/domains.js";
import { UsageError } from "../src/query.js";

describe("normalizeIssueDomain", () => {
  it("小写、去首尾空白与结尾点，IDN 转 punycode", () => {
    expect(normalizeIssueDomain(" WWW.Example.COM. ")).toBe("www.example.com");
    expect(normalizeIssueDomain("例子.测试")).toBe("xn--fsqu00a.xn--0zwm56d");
    expect(normalizeIssueDomain("*.münchen.de")).toBe("*.xn--mnchen-3ya.de");
    // 全角字母与中文句号按 IDNA 映射
    expect(normalizeIssueDomain("ＥＸＡＭＰＬＥ。com")).toBe("example.com");
  });

  it("泛域名只允许最左侧一个 *.", () => {
    expect(normalizeIssueDomain("*.example.com")).toBe("*.example.com");
    for (const bad of ["*.*.example.com", "www.*.example.com", "*example.com", "w*.example.com", "*"]) {
      expect(() => normalizeIssueDomain(bad), bad).toThrow(UsageError);
    }
  });

  it("拒绝 IP（含 domainToASCII 会解析成 IPv4 的写法）", () => {
    for (const ip of ["1.2.3.4", "::1", "[::1]", "0x7f.1", "*.1.2.3.4"]) {
      expect(() => normalizeIssueDomain(ip), ip).toThrow(/IP|不合法/);
    }
  });

  it("label 字符、长度与级数", () => {
    const cases = [
      "localhost", // 只有一级
      "*.com",
      "a_b.example.com", // Let's Encrypt 不接受下划线
      "-a.example.com",
      "a-.example.com",
      "a..example.com",
      "a b.example.com",
      `${"a".repeat(64)}.example.com`,
      "example.123",
      "",
    ];
    for (const bad of cases) expect(() => normalizeIssueDomain(bad), bad).toThrow(UsageError);
    expect(normalizeIssueDomain(`${"a".repeat(63)}.example.com`)).toHaveLength(75);
    expect(normalizeIssueDomain("a--b.example.com")).toBe("a--b.example.com");
  });

  it("总长度不超过 253", () => {
    const label = "a".repeat(63);
    const ok = [label, label, label, "b".repeat(57), "com"].join("."); // 253
    expect(ok).toHaveLength(253);
    expect(normalizeIssueDomain(ok)).toBe(ok);
    expect(() => normalizeIssueDomain(`x.${ok}`)).toThrow(/253/);
    // *. 也算进长度
    expect(() => normalizeIssueDomain(`*.${ok}`)).toThrow(/253/);
  });

  it("错误信息带原始输入", () => {
    expect(() => normalizeIssueDomain("bad_name.example.com")).toThrow('域名 "bad_name.example.com" 不合法');
  });
});

describe("parseDomains", () => {
  it("去重；主域名排第一，其余保持首次出现的顺序", () => {
    expect(parseDomains(["b.example.com", "*.example.com", "B.example.com.", "example.com"])).toEqual(["example.com", "b.example.com", "*.example.com"]);
  });

  it("主域名与 -d 的顺序无关：层级少的优先，同级时非泛域名优先、再按字母序", () => {
    expect(parseDomains(["*.example.com", "example.com"])[0]).toBe("example.com");
    expect(parseDomains(["example.com", "*.example.com"])[0]).toBe("example.com");
    expect(parseDomains(["www.example.com", "*.example.com"])[0]).toBe("*.example.com");
    expect(parseDomains(["*.a.example.com", "b.example.com", "a.example.com"])[0]).toBe("a.example.com");
    expect(parseDomains(["*.example.com"])[0]).toBe("*.example.com");
    expect(parseDomains(["b.example.net", "a.example.org"])[0]).toBe("a.example.org");
  });

  it("空列表、超过 100 个（按去重后计）时报参数错误", () => {
    expect(() => parseDomains([])).toThrow("--domain 不能为空");
    const many = Array.from({ length: MAX_DOMAINS }, (_, i) => `d${i}.example.com`);
    expect(parseDomains([...many, ...many])).toHaveLength(MAX_DOMAINS);
    expect(() => parseDomains([...many, "extra.example.com"])).toThrow(/最多 100 个/);
  });
});

describe("保存目录名与验证记录名", () => {
  it("主域名 + 算法，测试环境加 _staging；* 换成 _", () => {
    expect(certDirName("example.com", "rsa", false)).toBe("example.com_rsa");
    expect(certDirName("*.example.com", "ecc", false)).toBe("_.example.com_ecc");
    expect(certDirName("*.example.com", "rsa", true)).toBe("_.example.com_rsa_staging");
  });

  it("泛域名与根域名共用 _acme-challenge.<根域名>", () => {
    expect(challengeName("example.com")).toBe("_acme-challenge.example.com");
    expect(challengeName("*.example.com")).toBe("_acme-challenge.example.com");
    expect(challengeName("*.www.example.com")).toBe("_acme-challenge.www.example.com");
  });
});
