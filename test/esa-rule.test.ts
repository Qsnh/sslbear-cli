import { describe, expect, it } from "vitest";
import { matchHost } from "../src/providers/aliyun/esa-rule.js";

const HOST = "www.Example.com";

describe("ESA 规则表达式按主机名求值", () => {
  it.each<[string, boolean]>([
    ["true", true],
    ["false", false],
    ['(http.host eq "www.example.com")', true],
    // 与 ESA 一致区分大小写，主机名按小写参与比较
    ['(http.host eq "WWW.EXAMPLE.COM")', false],
    ['(http.host contains "Example")', false],
    ['(http.host == "blog.example.com")', false],
    ['(http.host ne "blog.example.com")', true],
    ['(http.host in {"blog.example.com" "www.example.com"})', true],
    ['(http.host in {"blog.example.com", "a.example.com"})', false],
    ['(not http.host in {"blog.example.com"})', true],
    ['(http.host contains "example")', true],
    ['(not http.host contains "example")', false],
    ['(starts_with(http.host, "www."))', true],
    ['(not starts_with(http.host, "blog"))', true],
    ['(ends_with(http.host, ".cn"))', false],
    ['(lower(http.host) eq "www.example.com")', true],
    ['(http.host matches "(www|blog)\\.example\\.com")', true],
    ['(http.host matches "^blog\\.")', false],
    ['(http.host matches "^WWW\\.")', false],
    ['(http.host matches "^www\\.example\\.com$")', true],
    ["(len(http.host) eq 15)", true],
    ["(len(http.host) ge 15)", true],
    ["(len(http.host) lt 15)", false],
    ["(exists(http.host))", true],
    ['(http.host in {"www.example.com" $vip})', true],
    ['(http.host eq "a\\\\b")', false],
    ['http.host == "www.example.com" && !(http.host == "a")', true],
    ['http.host == "a" || http.host == "www.example.com"', true],
    // not 只作用于紧跟的比较
    ['not http.host eq "www.example.com" and http.host eq "a"', false],
    // API 文档示例里带转义引号的写法
    ['(http.host eq \\"www.example.com\\")', true],
    ['(http.host eq "a \\" b")', false],
    ['(http.host eq "a.com") or (http.host eq "www.example.com")', true],
    ['(http.host eq "www.example.com" and ((http.host in {"x"}) or (ends_with(http.host, "com"))))', true],
    ['not (http.host eq "www.example.com")', false],
    // and 优先于 or
    ['http.host eq "www.example.com" or http.host eq "b" and http.host eq "c"', true],
    ['(http.host eq "b" or http.host eq "www.example.com") and http.host eq "c"', false],
    // 一边无法判断时，结果不受它影响才给出确定值
    ['(http.host eq "a.com" and ip.geoip.country eq "CN")', false],
    ['(ip.geoip.country eq "CN" and http.host eq "a.com")', false],
    ['(http.host eq "www.example.com" or ip.geoip.country eq "CN")', true],
  ])("%s", (expr, want) => {
    expect(matchHost(expr, HOST)).toBe(want);
  });

  it.each([
    '(http.request.uri.path eq "/a")',
    "(http.host in $vip)",
    '(http.host eq "www.example.com" and ip.geoip.country eq "CN")',
    '(ip.geoip.country eq "CN" or http.host eq "a.com")',
    '(http.request.headers["x-a"] eq "1")',
    "(percent(ip.src, 80))",
    '(http.host matches "(")',
    '(http.host matches "\\Awww\\.example\\.com\\z")',
    '(http.host matches "^[[:alpha:]]+\\.example\\.com$")',
    '(http.host in {"a" $vip})',
    '（http.host eq "www.example.com"）',
    '(http.host eq "www.example.com"',
    '(http.host wildcard "*.example.com")',
    "",
  ])("无法判断：%s", (expr) => {
    expect(matchHost(expr, HOST)).toBeUndefined();
  });
});
