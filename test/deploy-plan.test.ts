import { describe, expect, it } from "vitest";
import type { LocalCert } from "../src/deploy/cert.js";
import { NEEDS_CONFIRM, RENEW_WITHIN_DAYS, decide, pickOldCert } from "../src/deploy/plan.js";
import type { DomainRecord } from "../src/types.js";

const NOW = new Date("2026-10-15T00:00:00Z");
const CERT = { notAfter: "2027-01-01T00:00:00.000Z", algorithm: "RSA", sans: ["example.com"] } as LocalCert;

const rec = (r: Partial<DomainRecord>): DomainRecord => ({ provider: "aliyun", service: "cdn", domain: "example.com", https: true, ...r });
const on = (notAfter?: string) => rec({ cert: notAfter ? { name: "old", notAfter } : { name: "old" } });
const opts = { named: false, force: false, now: NOW };

describe("decide", () => {
  it("阈值固定 30 天", () => {
    expect(RENEW_WITHIN_DAYS).toBe(30);
    expect([...NEEDS_CONFIRM].sort()).toEqual(["newer_current", "not_due", "unknown_expiry"]);
  });

  it("平台托管域名跳过（--force 也不处理）", () => {
    const d = decide(rec({ extra: { managed: "platform" } }), CERT, { ...opts, force: true });
    expect(d).toMatchObject({ kind: "skip", reason: "platform_managed" });
  });

  it("服务不支持时跳过并带上原因", () => {
    const d = decide(on("2026-10-20T00:00:00Z"), CERT, { ...opts, force: true, unsupported: "推流域名不能绑定证书" });
    expect(d).toMatchObject({ kind: "skip", reason: "unsupported", message: "推流域名不能绑定证书" });
  });

  it("没开 HTTPS 且未点名：跳过并提示用 --domain 点名", () => {
    const d = decide(rec({ https: false }), CERT, { ...opts, force: true });
    expect(d).toMatchObject({ kind: "skip", reason: "https_off" });
    expect(d.message).toContain("--domain");
    expect(d.needsConfirm).toBeUndefined();
  });

  it("没开 HTTPS 且点名：直接部署，不看仍绑着的旧证书", () => {
    const d = decide(rec({ https: false, cert: { notAfter: "2027-06-01T00:00:00Z" } }), CERT, { ...opts, named: true });
    expect(d).toMatchObject({ kind: "deploy" });
  });

  it("旧证书与新证书到期时间相差 48 小时内视为同一张（--force 也跳过）", () => {
    for (const t of ["2027-01-01T00:00:00Z", "2026-12-31T16:00:00Z", "2027-01-02T23:00:00Z"]) {
      expect(decide(on(t), CERT, { ...opts, force: true })).toMatchObject({ kind: "skip", reason: "already_current" });
    }
  });

  it("查不到旧证书到期时间：需确认，--force 后更新", () => {
    const d = decide(on(undefined), CERT, opts);
    expect(d).toMatchObject({ kind: "skip", reason: "unknown_expiry", needsConfirm: true });
    expect(d.message).toContain("--force");
    expect(decide(rec({}), CERT, opts)).toMatchObject({ reason: "unknown_expiry" });
    expect(decide(on(undefined), CERT, { ...opts, force: true })).toMatchObject({ kind: "update" });
  });

  it("旧证书比新证书还晚：需确认，--force 后更新", () => {
    const d = decide(on("2027-03-01T00:00:00Z"), CERT, opts);
    expect(d).toMatchObject({ kind: "skip", reason: "newer_current", needsConfirm: true });
    expect(d.message).toContain("2027-03-01");
    expect(decide(on("2027-03-01T00:00:00Z"), CERT, { ...opts, force: true })).toMatchObject({ kind: "update" });
  });

  it("旧证书剩余超过 30 天：需确认，文案写明剩余天数与 --force", () => {
    const d = decide(on("2026-11-15T00:00:00Z"), CERT, opts);
    expect(d).toMatchObject({ kind: "skip", reason: "not_due", needsConfirm: true, oldDaysLeft: 31 });
    expect(d.message).toBe(
      "当前证书还剩 31 天，未到更新时间；确需提前更换请向用户确认后加 --force 重新执行（可配合 -d 只针对这些域名）",
    );
    expect(decide(on("2026-11-15T00:00:00Z"), CERT, { ...opts, force: true })).toMatchObject({ kind: "update", oldDaysLeft: 31 });
  });

  it("旧证书剩余 30 天以内或已过期：更新", () => {
    expect(decide(on("2026-11-14T00:00:00Z"), CERT, opts)).toMatchObject({ kind: "update", oldDaysLeft: 30, oldCert: { name: "old" } });
    expect(decide(on("2026-10-01T00:00:00Z"), CERT, opts)).toMatchObject({ kind: "update", oldDaysLeft: -14 });
  });
});

describe("pickOldCert", () => {
  const rsa = { id: "r", algorithm: "RSA" as const, notAfter: "2026-11-01T00:00:00Z" };
  const ecc = { id: "e", algorithm: "ECC" as const, notAfter: "2026-10-20T00:00:00Z" };
  const sm2 = { id: "s", algorithm: "SM2" as const, notAfter: "2026-10-16T00:00:00Z" };

  it("双证书取与新证书同算法的那张", () => {
    const r = rec({ cert: ecc, certs: [rsa, ecc] });
    expect(pickOldCert(r, "RSA")).toBe(rsa);
    expect(pickOldCert(r, "ECC")).toBe(ecc);
  });

  it("没有同算法的证书时取另一张国际证书，国密证书不参与", () => {
    expect(pickOldCert(rec({ cert: sm2, certs: [sm2, ecc] }), "RSA")).toBe(ecc);
    expect(pickOldCert(rec({ cert: sm2, certs: [sm2] }), "RSA")).toBeUndefined();
  });

  it("没有 certs 时用 cert", () => {
    expect(pickOldCert(rec({ cert: rsa }), "ECC")).toBe(rsa);
    expect(pickOldCert(rec({}), "ECC")).toBeUndefined();
  });

  it("决策按同算法那张的到期时间", () => {
    const r = rec({ cert: ecc, certs: [rsa, ecc] });
    expect(decide(r, CERT, opts)).toMatchObject({ kind: "update", oldCert: rsa });
    expect(decide(r, { ...CERT, algorithm: "ECC" }, opts)).toMatchObject({ kind: "update", oldCert: ecc, oldDaysLeft: 5 });
  });
});
