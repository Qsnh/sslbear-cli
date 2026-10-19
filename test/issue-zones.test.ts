import { describe, expect, it, vi } from "vitest";
import { DNS_DEFS } from "../src/dns/index.js";
import type { DnsZone } from "../src/dns/types.js";
import { CloudApiError, type QueryContext } from "../src/lib/http.js";
import { findZones, resolveDnsTargets, ZoneError, type DnsTarget } from "../src/issue/zones.js";
import { UsageError } from "../src/query.js";
import type { DnsVendor } from "../src/types.js";
import { ALIYUN_ENV, TENCENT_ENV } from "./helpers.js";
import { CLOUDFLARE_ENV, fakeDnsDefs, fakeLookup, fakeWorld } from "./issue-fakes.js";

const ctx = { fetch: globalThis.fetch, timeoutMs: 1000, now: new Date("2026-10-15T00:00:00Z"), env: {} } as QueryContext;
const zone = (name: string, extra: Partial<DnsZone> = {}): DnsZone => ({ name, id: `id-${name}`, ...extra });

function targetsFor(zones: Partial<Record<DnsVendor, DnsZone[]>>, ns: Record<string, string[]> = {}) {
  const world = fakeWorld(ns);
  const defs = fakeDnsDefs(zones, world);
  const targets: DnsTarget[] = (Object.keys(zones) as DnsVendor[]).map((v) => ({ def: defs[v], creds: {} }));
  return { targets, lookup: fakeLookup(world), defs };
}

const picked = (r: Awaited<ReturnType<typeof findZones>>) => r.matches.map((m) => [m.domain, m.target.def.vendor, m.zone.name, m.record]);

async function zoneError(p: Promise<unknown>): Promise<ZoneError> {
  const e = await p.then(
    () => undefined,
    (err: unknown) => err,
  );
  expect(e).toBeInstanceOf(ZoneError);
  return e as ZoneError;
}

describe("findZones", () => {
  it("取最长后缀匹配的 zone；根域名与泛域名共用一个记录名", async () => {
    const { targets, lookup } = targetsFor({ aliyun: [zone("example.com"), zone("other.org")] });
    const r = await findZones(ctx, lookup, targets, ["example.com", "*.example.com", "a.b.example.com"]);
    expect(picked(r)).toEqual([
      ["example.com", "aliyun", "example.com", "_acme-challenge.example.com"],
      ["*.example.com", "aliyun", "example.com", "_acme-challenge.example.com"],
      ["a.b.example.com", "aliyun", "example.com", "_acme-challenge.a.b.example.com"],
    ]);
    expect(r.issues).toEqual([]);
    // 只有一家托管时不查 NS
    expect(lookup.resolveNs).not.toHaveBeenCalled();
  });

  it("后缀必须按 label 匹配：notexample.com 不属于 example.com", async () => {
    const { targets, lookup } = targetsFor({ aliyun: [zone("example.com")] });
    const e = await zoneError(findZones(ctx, lookup, targets, ["notexample.com"]));
    expect(e.status).toBe("ZoneNotFound");
  });

  it("子域单独托管在别家时以子域 zone 为准；服务商返回的大写、结尾点会被规范化", async () => {
    const { targets, lookup } = targetsFor({ aliyun: [zone("example.com")], cloudflare: [zone("Sub.Example.com.")] });
    const r = await findZones(ctx, lookup, targets, ["www.sub.example.com", "*.sub.example.com", "www.example.com"]);
    expect(picked(r)).toEqual([
      ["www.sub.example.com", "cloudflare", "sub.example.com", "_acme-challenge.www.sub.example.com"],
      ["*.sub.example.com", "cloudflare", "sub.example.com", "_acme-challenge.sub.example.com"],
      ["www.example.com", "aliyun", "example.com", "_acme-challenge.www.example.com"],
    ]);
  });

  it("多家托管同一个 zone：按实际 NS 匹配服务商的 NS 规则判定", async () => {
    const { targets, lookup } = targetsFor(
      { aliyun: [zone("example.com")], cloudflare: [zone("example.com")] },
      { "example.com": ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"] },
    );
    const r = await findZones(ctx, lookup, targets, ["example.com", "*.example.com"]);
    expect(picked(r).map((m) => m[1])).toEqual(["cloudflare", "cloudflare"]);
    // 同一个 zone 的 NS 只查一次
    expect(lookup.resolveNs).toHaveBeenCalledTimes(1);
  });

  it("多家托管时优先比对接口返回的 zone NS（同一家里的同名 zone 也能区分）", async () => {
    const { targets, lookup } = targetsFor(
      {
        aws: [zone("example.com", { id: "Z1", nameServers: ["ns-1.awsdns-01.org"] }), zone("example.com", { id: "Z2", nameServers: ["ns-2.awsdns-02.net"] })],
        tencent: [zone("example.com")],
      },
      { "example.com": ["ns-2.awsdns-02.net", "ns-9.awsdns-09.com"] },
    );
    const r = await findZones(ctx, lookup, targets, ["www.example.com"]);
    expect(r.matches[0]).toMatchObject({ target: { def: { vendor: "aws" } }, zone: { id: "Z2" } });
  });

  it("NS 判定不出（都不匹配 / 都匹配 / 查不到 NS）时 ZoneAmbiguous，带 domain、providers", async () => {
    const cases: Record<string, string[]>[] = [
      { "example.com": ["ns1.example-dns.net"] },
      { "example.com": ["dns1.hichina.com", "a.ns.cloudflare.com"] },
      {},
    ];
    for (const ns of cases) {
      const { targets, lookup } = targetsFor({ aliyun: [zone("example.com")], cloudflare: [zone("example.com")] }, ns);
      const e = await zoneError(findZones(ctx, lookup, targets, ["www.example.com"]));
      expect(e.status).toBe("ZoneAmbiguous");
      expect(e.extra).toEqual({ domain: "www.example.com", providers: ["aliyun", "cloudflare"] });
      expect(e.message).toContain("--dns");
    }
  });

  it("找不到：ZoneNotFound 列出全部找不到的域名与查过的服务商，issues 带上列 zone 失败的服务商", async () => {
    const world = fakeWorld();
    const defs = fakeDnsDefs({ aliyun: [zone("example.com")] }, world, {
      cloudflare: { listZones: vi.fn(async () => Promise.reject(new CloudApiError("cloudflare", "Unauthorized", "Invalid API Token", "cf-ray-1", 403))) },
      tencent: { listZones: vi.fn(async () => Promise.reject(new Error("boom"))) },
    });
    const targets = (["aliyun", "cloudflare", "tencent"] as const).map((v) => ({ def: defs[v], creds: {} }));
    const e = await zoneError(findZones(ctx, fakeLookup(world), targets, ["www.example.com", "a.example.org", "*.example.net"]));
    expect(e.status).toBe("ZoneNotFound");
    expect(e.extra).toEqual({ domains: ["a.example.org", "*.example.net"] });
    expect(e.message).toContain("aliyun、cloudflare、tencent");
    expect(e.message).toContain("Unauthorized");
    expect(e.issues).toEqual([
      { provider: "cloudflare", kind: "error", code: "Unauthorized", message: "Invalid API Token", requestId: "cf-ray-1" },
      { provider: "tencent", kind: "error", code: "Unknown", message: "boom" },
    ]);
  });

  it("部分服务商列 zone 失败但域名找到了：照常返回，失败记进 issues", async () => {
    const world = fakeWorld();
    const defs = fakeDnsDefs({ aliyun: [zone("example.com")] }, world, {
      cloudflare: { listZones: vi.fn(async () => Promise.reject(new CloudApiError("cloudflare", "Forbidden", "denied"))) },
    });
    const targets = (["aliyun", "cloudflare"] as const).map((v) => ({ def: defs[v], creds: {} }));
    const r = await findZones(ctx, fakeLookup(world), targets, ["example.com"]);
    expect(picked(r)).toEqual([["example.com", "aliyun", "example.com", "_acme-challenge.example.com"]]);
    expect(r.issues).toEqual([{ provider: "cloudflare", kind: "error", code: "Forbidden", message: "denied" }]);
  });

  it("各服务商并行列 zone", async () => {
    let active = 0;
    let max = 0;
    const slow = (zones: DnsZone[]) =>
      vi.fn(async () => {
        active++;
        max = Math.max(max, active);
        await new Promise((r) => setTimeout(r, 5));
        active--;
        return zones;
      });
    const world = fakeWorld();
    const defs = fakeDnsDefs({}, world, { aliyun: { listZones: slow([zone("a.com")]) }, tencent: { listZones: slow([zone("b.com")]) } });
    const targets = (["aliyun", "tencent"] as const).map((v) => ({ def: defs[v], creds: {} }));
    await findZones(ctx, fakeLookup(world), targets, ["a.com", "b.com"]);
    expect(max).toBe(2);
  });
});

describe("resolveDnsTargets", () => {
  it("默认用所有已配置凭证的服务商，配置不完整的跳过并记 IncompleteCredentials", () => {
    const env = { ...ALIYUN_ENV, ...CLOUDFLARE_ENV, AZURE_TENANT_ID: "t", AWS_ACCESS_KEY_ID: "AKIA..." };
    const r = resolveDnsTargets(env, DNS_DEFS);
    expect(r.targets.map((t) => t.def.vendor)).toEqual(["aliyun", "cloudflare"]);
    expect(r.issues).toEqual([
      { provider: "aws", kind: "error", code: "IncompleteCredentials", message: expect.stringContaining("AWS_SECRET_ACCESS_KEY") },
      { provider: "azure", kind: "error", code: "IncompleteCredentials", message: expect.stringContaining("AZURE_CLIENT_SECRET") },
    ]);
  });

  it("--dns 显式指定的没配置 / 配置不完整：参数错误", () => {
    expect(() => resolveDnsTargets({ ...ALIYUN_ENV }, DNS_DEFS, ["cloudflare"])).toThrow(/cloudflare（Cloudflare）未配置凭证.*CLOUDFLARE_API_TOKEN/);
    expect(() => resolveDnsTargets({ GODADDY_API_KEY: "k" }, DNS_DEFS, ["godaddy"])).toThrow(/godaddy（GoDaddy）凭证不完整.*GODADDY_API_SECRET/);
    expect(resolveDnsTargets({ ...ALIYUN_ENV, ...TENCENT_ENV }, DNS_DEFS, ["tencent"]).targets.map((t) => t.def.vendor)).toEqual(["tencent"]);
  });

  it("一家都没配置：参数错误，列出 11 家各自需要的变量", () => {
    let err: unknown;
    try {
      resolveDnsTargets({ AZURE_CLIENT_ID: "x" }, DNS_DEFS);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(UsageError);
    const msg = (err as Error).message;
    expect(msg).toContain("azure 凭证不完整");
    for (const name of ["ALIBABA_CLOUD_ACCESS_KEY_ID", "TENCENTCLOUD_SECRET_ID", "CLOUDFLARE_API_TOKEN", "AWS_SECRET_ACCESS_KEY", "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_SUBSCRIPTION_ID", "DIGITALOCEAN_TOKEN", "GODADDY_API_SECRET", "BAIDUCLOUD_ACCESS_KEY", "HUAWEICLOUD_SDK_AK", "VOLCENGINE_ACCESS_KEY"]) {
      expect(msg).toContain(name);
    }
  });
});
