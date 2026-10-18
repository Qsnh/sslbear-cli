import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { certCovers, loadLocalCert, normalizeDomain } from "../src/deploy/cert.js";
import { UsageError } from "../src/query.js";

const FIX = fileURLToPath(new URL("./fixtures/deploy/", import.meta.url));
const read = (name: string) => readFileSync(join(FIX, name), "utf8");
const NOW = new Date("2026-10-15T00:00:00Z");

describe("loadLocalCert", () => {
  it("解析 RSA fullchain：域名、到期时间、算法、指纹", () => {
    const c = loadLocalCert(read("rsa-fullchain.pem"), read("rsa-key.pem"), NOW);
    expect(c.commonName).toBe("example.com");
    expect(c.sans).toEqual(["example.com", "*.example.com"]);
    expect(c.notBefore).toBe("2026-01-01T00:00:00.000Z");
    expect(c.notAfter).toBe("2027-01-01T00:00:00.000Z");
    expect(c.algorithm).toBe("RSA");
    expect(c.serialNumber).toBe("1A2B3C");
    expect(c.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(c.issuer).toBe("sslbear test CA");
    expect(c.certPem.match(/BEGIN CERTIFICATE/g)).toHaveLength(2);
    expect(c.certPem.endsWith("-----END CERTIFICATE-----\n")).toBe(true);
  });

  it("解析 ECC fullchain", () => {
    const c = loadLocalCert(read("ecc-fullchain.pem"), read("ecc-key.pem"), NOW);
    expect(c.algorithm).toBe("ECC");
    expect(c.serialNumber).toBe("4D5E6F");
  });

  it("中间证书在前、CRLF 换行、带 BOM 时仍以与私钥匹配的叶子为准，输出叶子在前", () => {
    const c = loadLocalCert(`﻿${read("chain-reversed.pem")}`, read("rsa-key.pem"), NOW);
    expect(c.serialNumber).toBe("1A2B3C");
    const leafFirst = loadLocalCert(read("rsa-fullchain.pem"), read("rsa-key.pem"), NOW);
    expect(c.certPem).toBe(leafFirst.certPem);
    expect(c.certPem).not.toContain("\r");
  });

  it("没有 SAN 时用 CN 作为覆盖域名", () => {
    const c = loadLocalCert(read("cn-only-fullchain.pem"), read("cn-only-key.pem"), NOW);
    expect(c.sans).toEqual(["only.example.net"]);
  });

  it("没有 subject、只有 SAN 的证书（如 Let's Encrypt 短期证书）：没有 commonName，覆盖域名取 SAN", () => {
    const c = loadLocalCert(read("san-only-fullchain.pem"), read("san-only-key.pem"), NOW);
    expect(c.commonName).toBeUndefined();
    expect(c.sans).toEqual(["example.com", "*.example.com"]);
    expect(c.issuer).toBe("sslbear test CA 2");
  });

  it("自签证书不要求证书链", () => {
    const c = loadLocalCert(read("selfsigned.pem"), read("selfsigned-key.pem"), NOW);
    expect(c.sans).toEqual(["self.example.org"]);
  });

  it("只有叶子证书、缺中间证书链时拒绝", () => {
    expect(() => loadLocalCert(read("leaf-only.pem"), read("rsa-key.pem"), NOW)).toThrow(UsageError);
    expect(() => loadLocalCert(read("leaf-only.pem"), read("rsa-key.pem"), NOW)).toThrow(/中间证书.*fullchain/);
  });

  it("私钥与证书不匹配时拒绝", () => {
    expect(() => loadLocalCert(read("rsa-fullchain.pem"), read("other-key.pem"), NOW)).toThrow(/私钥与证书不匹配/);
  });

  it("不在有效期内时拒绝", () => {
    expect(() => loadLocalCert(read("rsa-fullchain.pem"), read("rsa-key.pem"), new Date("2027-01-02T00:00:00Z"))).toThrow(/不在有效期内/);
    expect(() => loadLocalCert(read("rsa-fullchain.pem"), read("rsa-key.pem"), new Date("2025-12-31T00:00:00Z"))).toThrow(/不在有效期内/);
  });

  it("加密私钥、非 PEM 内容拒绝，错误信息不带私钥内容", () => {
    const key = read("encrypted-key.pem");
    expect(() => loadLocalCert(read("rsa-fullchain.pem"), key, NOW)).toThrow(/加密/);
    expect(() => loadLocalCert("not a pem", read("rsa-key.pem"), NOW)).toThrow(UsageError);
    expect(() => loadLocalCert(read("rsa-fullchain.pem"), "garbage", NOW)).toThrow(UsageError);
    try {
      loadLocalCert(read("rsa-fullchain.pem"), read("rsa-key.pem").replace("MII", "MIIX"), NOW);
    } catch (e) {
      expect((e as Error).message).not.toContain("MII");
    }
  });
});

describe("certCovers / normalizeDomain", () => {
  const sans = ["example.com", "*.example.com"];

  it("规范化：小写、去结尾点、七牛的 .example.com 写法转为 *.example.com", () => {
    expect(normalizeDomain(" A.Example.COM. ")).toBe("a.example.com");
    expect(normalizeDomain(".example.com")).toBe("*.example.com");
  });

  it("精确匹配与一级泛域名匹配", () => {
    expect(certCovers(sans, "example.com")).toBe(true);
    expect(certCovers(sans, "A.Example.com.")).toBe(true);
    expect(certCovers(sans, "*.example.com")).toBe(true);
    expect(certCovers(sans, ".example.com")).toBe(true);
  });

  it("泛域名不覆盖多级子域、根域与其他域名", () => {
    expect(certCovers(["*.example.com"], "example.com")).toBe(false);
    expect(certCovers(sans, "a.b.example.com")).toBe(false);
    expect(certCovers(sans, "example.org")).toBe(false);
    expect(certCovers(sans, "badexample.com")).toBe(false);
  });

  it("云上的泛域名只能由同样的泛域名证书覆盖", () => {
    expect(certCovers(["a.example.com"], "*.example.com")).toBe(false);
    expect(certCovers(["*.a.example.com"], "*.example.com")).toBe(false);
  });
});
