import { spawnSync } from "node:child_process";
import { createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { children, integer, oid, readTlv, tlv } from "../src/issue/asn1.js";
import { ariCertId, buildCsr, generateCertKey } from "../src/issue/csr.js";

const FIX = fileURLToPath(new URL("./fixtures/issue/", import.meta.url));
const read = (name: string) => readFileSync(join(FIX, name), "utf8");

const HAS_OPENSSL = !spawnSync("openssl", ["version"]).error;

/** 用 openssl 解析并验签 CSR；stdout 为 -text 输出，验签结果在 stderr（OpenSSL 3 与 LibreSSL 措辞不同，都含 "verify OK"） */
function opensslReq(der: Buffer): { status: number | null; text: string; verify: string } {
  const r = spawnSync("openssl", ["req", "-inform", "DER", "-noout", "-verify", "-text"], { input: der });
  return { status: r.status, text: r.stdout.toString(), verify: r.stderr.toString() };
}

describe("asn1", () => {
  it("长度超过 127 字节用长格式", () => {
    expect(tlv(0x04, Buffer.alloc(5)).subarray(0, 2)).toEqual(Buffer.from([0x04, 0x05]));
    expect(tlv(0x04, Buffer.alloc(200)).subarray(0, 3)).toEqual(Buffer.from([0x04, 0x81, 200]));
    expect(tlv(0x04, Buffer.alloc(300)).subarray(0, 4)).toEqual(Buffer.from([0x04, 0x82, 0x01, 0x2c]));
    const big = readTlv(tlv(0x04, Buffer.alloc(300, 7)));
    expect(big.content.length).toBe(300);
  });

  it("OID 多字节分量、INTEGER 补前导 0", () => {
    expect(oid("1.2.840.113549.1.9.14").toString("hex")).toBe("06092a864886f70d01090e");
    expect(oid("2.5.29.17").toString("hex")).toBe("0603551d11");
    expect(integer(0).toString("hex")).toBe("020100");
    expect(integer(0x80).toString("hex")).toBe("02020080");
  });

  it("解析时拒绝截断与不定长格式", () => {
    expect(() => readTlv(Buffer.from([0x30, 0x05, 0x01]))).toThrow();
    expect(() => readTlv(Buffer.from([0x30, 0x80, 0x00, 0x00]))).toThrow();
    expect(children(readTlv(Buffer.from("3006020101020102", "hex"))).map((t) => t.content[0])).toEqual([1, 2]);
  });
});

describe("buildCsr", () => {
  /** 不依赖 openssl 的结构检查：拆出 certificationRequestInfo，用 CSR 里的公钥对签名验签 */
  function selfVerify(der: Buffer, dsaEncoding?: "der") {
    const [info, alg, sig] = children(readTlv(der));
    const spki = children(info!)[2]!;
    const pub = createPublicKey({ key: spki.raw, format: "der", type: "spki" });
    return { alg: alg!.raw.toString("hex"), ok: verify("sha256", info!.raw, dsaEncoding ? { key: pub, dsaEncoding } : pub, sig!.content.subarray(1)) };
  }

  it("RSA：sha256WithRSAEncryption（NULL 参数），自验签通过", () => {
    const key = generateCertKey("rsa");
    const r = selfVerify(buildCsr(key, ["example.com", "*.example.com"]));
    expect(r.alg).toBe("300d06092a864886f70d01010b0500");
    expect(r.ok).toBe(true);
  });

  it("ECC：ecdsa-with-SHA256（无参数、DER 签名），自验签通过", () => {
    const key = generateCertKey("ecc");
    const r = selfVerify(buildCsr(key, ["example.com"]), "der");
    expect(r.alg).toBe("300a06082a8648ce3d040302");
    expect(r.ok).toBe(true);
  });

  it.skipIf(!HAS_OPENSSL)("openssl 校验 RSA CSR：CN、SAN、签名算法、验签", () => {
    const r = opensslReq(buildCsr(generateCertKey("rsa"), ["example.com", "*.example.com", "www.example.com"]));
    expect(r.status).toBe(0);
    expect(r.verify).toMatch(/verify OK/i);
    expect(r.text).toMatch(/Subject: CN\s?=\s?example\.com/);
    expect(r.text).toContain("DNS:example.com, DNS:*.example.com, DNS:www.example.com");
    expect(r.text).toContain("sha256WithRSAEncryption");
    expect(r.text).toMatch(/Public Key Algorithm: rsaEncryption/);
  });

  it.skipIf(!HAS_OPENSSL)("openssl 校验 ECC CSR", () => {
    const r = opensslReq(buildCsr(generateCertKey("ecc"), ["a.example.net", "b.example.net"]));
    expect(r.status).toBe(0);
    expect(r.verify).toMatch(/verify OK/i);
    expect(r.text).toMatch(/Subject: CN\s?=\s?a\.example\.net/);
    expect(r.text).toContain("DNS:a.example.net, DNS:b.example.net");
    expect(r.text).toContain("ecdsa-with-SHA256");
    expect(r.text).toContain("id-ecPublicKey");
  });

  it.skipIf(!HAS_OPENSSL)("第一个域名超过 64 个字符时 subject 为空，域名只在 SAN 里；正好 64 个字符仍设 CN", () => {
    const long = `${"a".repeat(60)}.example.com`; // 72 个字符
    const r = opensslReq(buildCsr(generateCertKey("ecc"), [long, "example.com"]));
    expect(r.status).toBe(0);
    expect(r.verify).toMatch(/verify OK/i);
    expect(r.text).not.toContain("CN");
    expect(r.text).toContain(`DNS:${long}, DNS:example.com`);

    const exact = `${"b".repeat(52)}.example.com`; // 64 个字符
    expect(exact).toHaveLength(64);
    expect(opensslReq(buildCsr(generateCertKey("ecc"), [exact])).text).toContain(exact);
    expect(opensslReq(buildCsr(generateCertKey("ecc"), [exact])).text).toMatch(/Subject: CN/);
  });

  it("没有域名、域名不是 ASCII、密钥类型不支持时报错", () => {
    const key = generateCertKey("ecc");
    expect(() => buildCsr(key, [])).toThrow(/至少/);
    expect(() => buildCsr(key, ["例子.com"])).toThrow(/punycode/);
    expect(() => buildCsr(generateKeyPairSync("ed25519").privateKey, ["example.com"])).toThrow(/不支持/);
  });
});

/**
 * fixture 生成方式（OpenSSL 3，私钥只在临时目录、不入库）：
 *
 *   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -subj "/CN=sslbear ARI test CA" -days 3650 \
 *     -addext "subjectKeyIdentifier=69:88:5B:6B:87:46:40:41:E1:B3:7B:84:7B:A0:AE:2C:DE:01:C8:D4" -addext "basicConstraints=critical,CA:TRUE" -out ca.pem
 *   openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout leaf.key -subj "/CN=ari.example.com" -out leaf.csr
 *   printf 'authorityKeyIdentifier=keyid:always\nsubjectAltName=DNS:ari.example.com\n' > leaf.ext
 *   openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -set_serial 0x87654321 -days 3650 -extfile leaf.ext -out leaf.pem
 *   cat leaf.pem ca.pem > ari-fullchain.pem
 *   printf 'subjectKeyIdentifier=none\nauthorityKeyIdentifier=none\nsubjectAltName=DNS:no-aki.example.com\n' > noaki.ext
 *   openssl x509 -req -in leaf.csr -key leaf.key -set_serial 0x1234 -days 3650 -extfile noaki.ext -out no-aki.pem
 *
 * rfc9773-example.pem 为 RFC 9773 附录 A 的示例证书原文。
 */
describe("ariCertId", () => {
  // RFC 9773 第 4.1 节：keyIdentifier 69:88:5B:...:C8:D4 → aYhba4dGQEHhs3uEe6CuLN4ByNQ；序列号 DER 内容 00:87:65:43:21 → AIdlQyE
  const RFC_ID = "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE";

  it("RFC 9773 附录 A 的示例证书", () => {
    expect(ariCertId(read("rfc9773-example.pem"))).toBe(RFC_ID);
  });

  it("openssl 签发的同参数证书（fullchain 取第一张叶子，序列号保留前导 0x00）", () => {
    const chain = read("ari-fullchain.pem");
    expect(ariCertId(chain)).toBe(RFC_ID);
    const leaf = chain.slice(0, chain.indexOf("-----END CERTIFICATE-----") + 25);
    expect(ariCertId(leaf)).toBe(RFC_ID);
  });

  it("没有 AKI 的证书、不是证书的输入返回 undefined", () => {
    expect(ariCertId(read("no-aki.pem"))).toBeUndefined();
    expect(ariCertId("")).toBeUndefined();
    expect(ariCertId("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")).toBeUndefined();
  });
});
