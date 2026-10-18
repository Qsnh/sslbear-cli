import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { loadLocalCert } from "../src/deploy/cert.js";
import { executeDeploy, planDeploy, type DeployOptions } from "../src/deploy/run.js";
import { ENV_FAMILIES } from "../src/lib/env.js";
import { CloudApiError, isRetryable, isRetryableCode, type QueryContext } from "../src/lib/http.js";
import type { ProviderDefs } from "../src/query.js";
import type { Deployer, DomainService, ProviderDef } from "../src/providers/registry.js";
import type { DomainRecord, Provider } from "../src/types.js";

const FIX = fileURLToPath(new URL("./fixtures/deploy/", import.meta.url));
const NOW = new Date("2026-10-15T00:00:00Z");
const CERT = loadLocalCert(readFileSync(join(FIX, "rsa-fullchain.pem"), "utf8"), readFileSync(join(FIX, "rsa-key.pem"), "utf8"), NOW);
const ctx: QueryContext = { env: {}, fetch: (() => {}) as never, now: NOW, timeoutMs: 1000, sleep: async () => {} };

const DUE = "2026-10-25T00:00:00Z"; // 剩 10 天
const LATER = "2026-12-01T00:00:00Z"; // 剩 47 天

function rec(service: string, domain: string, r: Partial<DomainRecord> = {}): DomainRecord {
  return { provider: "aliyun", service, domain, https: true, cert: { name: "old", notAfter: DUE }, ...r };
}

function svc(key: string, records: DomainRecord[], deployer?: Deployer<unknown>): DomainService<unknown> {
  return { key, label: key.toUpperCase(), list: async () => records, ...(deployer && { deployer }) };
}

function def(provider: Provider, services: DomainService<unknown>[], upload?: ProviderDef<unknown>["uploadCertificate"]): ProviderDef<unknown> {
  return {
    provider,
    envFamilies: ENV_FAMILIES[provider],
    readCredentials: () => ({ state: "ok", credentials: { p: provider } }),
    services,
    listCertificates: async () => [],
    isInactive: () => false,
    ...(upload && { uploadCertificate: upload }),
  };
}

const missing = (provider: Provider) => ({ ...def(provider, []), readCredentials: () => ({ state: "missing" as const }) });

function defs(aliyun: ProviderDef<unknown>, tencent?: ProviderDef<unknown>): ProviderDefs {
  return {
    aliyun,
    tencent: tencent ?? missing("tencent"),
    volcengine: missing("volcengine"),
    huawei: missing("huawei"),
    baidu: missing("baidu"),
    qiniu: missing("qiniu"),
  };
}

const OPTS: DeployOptions = { force: false, dryRun: false };

async function run(d: ProviderDefs, opts: Partial<DeployOptions> = {}) {
  const o = { ...OPTS, ...opts };
  const plan = await planDeploy(ctx, CERT, o, d);
  return o.dryRun ? plan.report : executeDeploy(ctx, CERT, plan);
}

const okDeployer = () => {
  const apply = vi.fn(async (_c: QueryContext, _cr: unknown, _t: unknown, input: { certId(): Promise<string> }) => ({ certId: await input.certId() }));
  return { apply } satisfies Deployer<unknown>;
};

describe("planDeploy / executeDeploy", () => {
  it("只处理证书覆盖的域名，按决策表部署 / 更新 / 跳过", async () => {
    const dep = okDeployer();
    const upload = vi.fn(async () => ({ id: "cas-1", reused: false }));
    const d = defs(
      def("aliyun", [
        svc(
          "cdn",
          [
            rec("cdn", "a.example.com"),
            rec("cdn", "b.example.com", { cert: { notAfter: LATER } }),
            rec("cdn", "c.example.com", { https: false, cert: undefined }),
            rec("cdn", "other.org"),
          ],
          dep,
        ),
      ], upload),
    );
    const r = await run(d);
    expect(r.results).toEqual([
      expect.objectContaining({ service: "cdn", domain: "a.example.com", action: "updated", before: { name: "old", notAfter: DUE, daysLeft: 10 }, after: { id: "cas-1", notAfter: CERT.notAfter } }),
      expect.objectContaining({ domain: "b.example.com", action: "skipped", reason: "not_due", needsConfirm: true }),
      expect.objectContaining({ domain: "c.example.com", action: "skipped", reason: "https_off" }),
    ]);
    expect(dep.apply).toHaveBeenCalledTimes(1);
    expect(dep.apply.mock.calls[0]![2]).toMatchObject({ mode: "update", records: [{ domain: "a.example.com" }] });
    expect(r.uploads).toEqual([{ provider: "aliyun", certId: "cas-1", reused: false }]);
    expect(r.cert).toMatchObject({ commonName: "example.com", sans: ["example.com", "*.example.com"], algorithm: "RSA" });
  });

  it("--force 后需确认的域名也更新；点名的 off 域名部署", async () => {
    const dep = okDeployer();
    const d = defs(
      def("aliyun", [svc("cdn", [rec("cdn", "b.example.com", { cert: { notAfter: LATER } }), rec("cdn", "c.example.com", { https: false })], dep)], async () => ({ id: "x", reused: true })),
    );
    const r = await run(d, { force: true, domains: ["b.example.com", "C.example.com"] });
    expect(r.results.map((x) => [x.domain, x.action])).toEqual([
      ["b.example.com", "updated"],
      ["c.example.com", "deployed"],
    ]);
    expect(r.uploads).toEqual([{ provider: "aliyun", certId: "x", reused: true }]);
  });

  it("-d 精确匹配：不覆盖的记 NotCovered，找不到的记 DomainNotFound 并提示查询失败的服务", async () => {
    const broken = svc("oss", []);
    broken.list = async () => {
      throw new CloudApiError("aliyun", "Forbidden", "no permission", "rid-1");
    };
    const d = defs(def("aliyun", [svc("cdn", [rec("cdn", "a.example.com"), rec("cdn", "x.other.org")], okDeployer()), broken]));
    const r = await run(d, { domains: ["x.other.org", "ghost.example.com"] });
    expect(r.results).toEqual([
      expect.objectContaining({ provider: "aliyun", service: "cdn", domain: "x.other.org", action: "failed", code: "NotCovered", retryable: false }),
      expect.objectContaining({ domain: "ghost.example.com", action: "failed", code: "DomainNotFound" }),
    ]);
    expect(r.results[1]!.provider).toBeUndefined();
    expect(r.results[1]!.message).toContain("aliyun/oss");
    expect(r.results[1]!.retryable).toBe(false);
    expect(r.issues).toEqual([expect.objectContaining({ service: "oss", code: "Forbidden" })]);
  });

  it("DomainNotFound：提示列出所有失败的查询（含子项），有可重试的错误时 retryable 为 true", async () => {
    const esa: DomainService<unknown> = {
      key: "esa",
      label: "ESA",
      list: async (_c, _cr, warn) => {
        warn(new CloudApiError("aliyun", "Throttling.User", "slow down"), "site-1");
        warn(new CloudApiError("aliyun", "InactiveService", "not opened"), "site-2");
        return [];
      },
    };
    const d = { ...defs(def("aliyun", [svc("cdn", [rec("cdn", "a.example.com")], okDeployer()), esa])) };
    d.aliyun = { ...d.aliyun, isInactive: (code: string) => code === "InactiveService" };
    const r = await run(d, { domains: ["ghost.example.com"] });
    expect(r.results).toEqual([expect.objectContaining({ domain: "ghost.example.com", action: "failed", code: "DomainNotFound", retryable: true })]);
    expect(r.results[0]!.message).toContain("aliyun/esa site-1");
    expect(r.results[0]!.message).not.toContain("site-2");

    const clean = await run(defs(def("aliyun", [svc("cdn", [rec("cdn", "a.example.com")], okDeployer())])), { domains: ["ghost.example.com"] });
    expect(clean.results[0]).toMatchObject({ code: "DomainNotFound", retryable: false });
    expect(clean.results[0]!.message).toBe("所选云厂商 / 服务上没有找到该域名");
  });

  it("isRetryableCode 与 isRetryable 规则一致", () => {
    for (const code of ["Throttling.User", "RequestLimitExceeded", "ServiceUnavailable", "Timeout", "NetworkError"]) expect(isRetryableCode(code), code).toBe(true);
    for (const code of ["Forbidden", "TimeoutX", "InvalidParameter"]) expect(isRetryableCode(code), code).toBe(false);
    expect(isRetryable(new CloudApiError("aliyun", "Whatever", "x", undefined, 429))).toBe(true);
    expect(isRetryable(new CloudApiError("aliyun", "Throttling", "x"))).toBe(true);
    expect(isRetryable(new Error("Throttling"))).toBe(false);
  });

  it("HTTPS 状态未知的记录一律记为可重试的失败，不调用 apply（点名、--force 也一样）", async () => {
    const dep = okDeployer();
    const unknown = { httpsUnknown: "true" };
    const records = [
      rec("cdn", "a.example.com", { extra: unknown }),
      rec("cdn", "b.example.com", { https: false, cert: undefined, extra: unknown }),
      rec("cdn", "c.example.com"),
    ];
    const d = defs(def("aliyun", [svc("cdn", records, dep)], async () => ({ id: "x", reused: false })));
    const expected = (domain: string) =>
      expect.objectContaining({ domain, action: "failed", code: "HttpsStateUnknown", retryable: true, message: "查询该域名的 HTTPS 配置失败（见 issues），无法判断现状，未做修改；可稍后重试" });

    const all = await run(d);
    expect(all.results).toEqual([expected("a.example.com"), expected("b.example.com"), expect.objectContaining({ domain: "c.example.com", action: "updated" })]);
    expect(dep.apply.mock.calls.map((c) => (c[2] as { records: DomainRecord[] }).records.map((x) => x.domain))).toEqual([["c.example.com"]]);

    const named = await run(d, { domains: ["a.example.com", "b.example.com"], force: true, dryRun: true });
    expect(named.results).toEqual([expected("a.example.com"), expected("b.example.com")]);

    // 用了 -d 时，未点名的记录不在范围内，不单独报
    const other = await run(d, { domains: ["c.example.com"], dryRun: true });
    expect(other.results).toEqual([expect.objectContaining({ domain: "c.example.com", action: "would_update" })]);
  });

  it("HTTPS 状态未知但无论如何都不能部署的记录（平台托管、服务或记录不支持）照常跳过，不记失败", async () => {
    const unknown = { httpsUnknown: "true" };
    const d = defs(
      def("aliyun", [
        svc("cdn", [rec("cdn", "a.example.com", { extra: unknown })]),
        svc("live", [rec("live", "push.example.com", { https: false, extra: unknown })], { ...okDeployer(), unsupported: () => "推流域名不能绑定证书" }),
        svc("vod", [rec("vod", "v.example.com", { extra: { ...unknown, managed: "platform" } })], okDeployer()),
      ]),
    );
    const r = await run(d);
    expect(r.results).toEqual([
      expect.objectContaining({ service: "cdn", action: "skipped", reason: "unsupported" }),
      expect.objectContaining({ service: "live", action: "skipped", reason: "unsupported", message: "推流域名不能绑定证书" }),
      expect.objectContaining({ service: "vod", action: "skipped", reason: "platform_managed" }),
    ]);
  });

  it("没有 deployer 的服务、deployer 声明不支持的记录：跳过 unsupported", async () => {
    const d = defs(
      def("aliyun", [
        svc("cdn", [rec("cdn", "a.example.com")]),
        svc("live", [rec("live", "push.example.com")], { ...okDeployer(), unsupported: () => "推流域名不能绑定证书" }),
      ]),
    );
    const r = await run(d);
    expect(r.results).toEqual([
      expect.objectContaining({ service: "cdn", action: "skipped", reason: "unsupported", message: expect.stringContaining("暂不支持") }),
      expect.objectContaining({ service: "live", action: "skipped", reason: "unsupported", message: "推流域名不能绑定证书" }),
    ]);
  });

  it("共享作用域：组内都可更新时一次 apply 覆盖全组", async () => {
    const dep = { ...okDeployer(), sharedScope: (r: DomainRecord) => r.extra?.site };
    const site = { site: "s1" };
    const d = defs(
      def("aliyun", [svc("esa", [rec("esa", "a.example.com", { extra: site }), rec("esa", "b.example.com", { extra: site }), rec("esa", "c.example.com", { extra: { site: "s2" } })], dep)], async () => ({ id: "x", reused: false })),
    );
    const r = await run(d);
    expect(dep.apply).toHaveBeenCalledTimes(2);
    expect(dep.apply.mock.calls.map((c) => (c[2] as { records: DomainRecord[] }).records.map((x) => x.domain))).toEqual([["a.example.com", "b.example.com"], ["c.example.com"]]);
    expect(r.results.every((x) => x.action === "updated")).toBe(true);
  });

  it("共享作用域：组内有未到期或未点名的记录时全组跳过 shared_cert_blocked", async () => {
    const dep = { ...okDeployer(), sharedScope: (r: DomainRecord) => r.extra?.site };
    const site = { site: "s1" };
    const records = [rec("esa", "a.example.com", { extra: site }), rec("esa", "b.example.com", { extra: site, cert: { notAfter: LATER } })];
    const d = defs(def("aliyun", [svc("esa", records, dep)], async () => ({ id: "x", reused: false })));

    const notDue = await run(d);
    expect(dep.apply).not.toHaveBeenCalled();
    expect(notDue.results).toEqual([
      expect.objectContaining({ domain: "a.example.com", action: "skipped", reason: "shared_cert_blocked", needsConfirm: true, message: expect.stringContaining("b.example.com") }),
      expect.objectContaining({ domain: "b.example.com", action: "skipped", reason: "not_due" }),
    ]);

    const unnamed = await run(d, { domains: ["a.example.com"], force: true });
    expect(dep.apply).not.toHaveBeenCalled();
    expect(unnamed.results).toEqual([expect.objectContaining({ domain: "a.example.com", reason: "shared_cert_blocked", message: expect.stringContaining("b.example.com") })]);
    expect(unnamed.results[0]!.needsConfirm).toBeUndefined();

    const forced = await run(d, { force: true });
    expect(dep.apply).toHaveBeenCalledTimes(1);
    expect(forced.results.map((x) => x.action)).toEqual(["updated", "updated"]);
  });

  it("共享作用域：没开 HTTPS 的记录也参与分组，且必然挡住整组", async () => {
    const scopes: string[] = [];
    const dep = {
      ...okDeployer(),
      sharedScope: (r: DomainRecord) => (scopes.push(r.domain), r.extra?.site),
    };
    const site = { site: "s1" };
    const records = [rec("esa", "a.example.com", { extra: site }), rec("esa", "c.example.com", { extra: site, https: false, cert: undefined })];
    const d = defs(def("aliyun", [svc("esa", records, dep)], async () => ({ id: "x", reused: false })));

    const r = await run(d, { force: true });
    expect(scopes).toContain("c.example.com");
    expect(dep.apply).not.toHaveBeenCalled();
    expect(r.results).toEqual([
      expect.objectContaining({ domain: "a.example.com", action: "skipped", reason: "shared_cert_blocked", before: expect.objectContaining({ notAfter: DUE }) }),
      expect.objectContaining({ domain: "c.example.com", action: "skipped", reason: "https_off" }),
    ]);
    expect(r.results[0]!.needsConfirm).toBeUndefined();
    expect(r.results[0]!.message).toContain("c.example.com（未开启 HTTPS，站点加证书后会开始用新证书提供 HTTPS）");

    // 点名后 c 会被部署，但它与 a 共用站点证书，同样挡住整组
    const named = await run(d, { domains: ["a.example.com", "c.example.com"], force: true });
    expect(dep.apply).not.toHaveBeenCalled();
    expect(named.results.map((x) => [x.domain, x.action, x.reason])).toEqual([
      ["a.example.com", "skipped", "shared_cert_blocked"],
      ["c.example.com", "skipped", "shared_cert_blocked"],
    ]);
    expect(named.results.every((x) => x.needsConfirm === undefined)).toBe(true);
  });

  it("共享作用域：阻挡项里有不能靠 --force 放行的，组内需确认的记录也报 shared_cert_blocked 且不带 needsConfirm", async () => {
    const dep = { ...okDeployer(), sharedScope: (r: DomainRecord) => r.extra?.site };
    const site = { site: "s1" };
    const records = [
      rec("esa", "a.example.com", { extra: site }),
      rec("esa", "b.example.com", { extra: site }),
      rec("esa", "d.example.com", { extra: site, cert: { notAfter: LATER } }),
      rec("esa", "e.example.com", { extra: site, cert: { notAfter: CERT.notAfter } }),
    ];
    const d = defs(def("aliyun", [svc("esa", records, dep)], async () => ({ id: "x", reused: false })));

    const r = await run(d, { domains: ["a.example.com", "d.example.com", "e.example.com"] });
    expect(dep.apply).not.toHaveBeenCalled();
    expect(r.results.map((x) => [x.domain, x.reason, x.needsConfirm])).toEqual([
      ["a.example.com", "shared_cert_blocked", undefined],
      ["d.example.com", "shared_cert_blocked", undefined],
      ["e.example.com", "already_current", undefined],
    ]);
    const msg = r.results[0]!.message!;
    expect(msg).toContain("b.example.com（未用 -d 点名）");
    expect(msg).toContain("d.example.com（当前证书还剩 47 天）");
    expect(msg).not.toContain("a.example.com（");
    expect(msg).not.toContain("e.example.com");
    expect(msg).toContain("-d");
    expect(msg).toContain("--force");
    expect(r.results[1]!.message).toBe(msg);

    // 不用 -d：只有 d 需确认，--force 能放行整组；提示用 -d 时也要点名已是该证书的 e，否则 e 会变成范围外的阻挡项
    const all = await run(d);
    expect(all.results.map((x) => [x.domain, x.reason, x.needsConfirm])).toEqual([
      ["a.example.com", "shared_cert_blocked", true],
      ["b.example.com", "shared_cert_blocked", true],
      ["d.example.com", "not_due", true],
      ["e.example.com", "already_current", undefined],
    ]);
    expect(all.results[0]!.message).toContain("d.example.com（当前证书还剩 47 天）");
    expect(all.results[0]!.message).toContain("用 -d 时须同时点名同组已是该证书的 e.example.com");
    expect(all.results[0]!.message).toMatch(/--force 重新执行/);
  });

  it("共享作用域：组内有 HTTPS 状态未知的记录时，它记失败，其余记录被挡住且不带 needsConfirm", async () => {
    const dep = { ...okDeployer(), sharedScope: (r: DomainRecord) => r.extra?.site };
    const records = [
      rec("esa", "a.example.com", { extra: { site: "s1" } }),
      rec("esa", "u.example.com", { extra: { site: "s1", httpsUnknown: "true" } }),
    ];
    const d = defs(def("aliyun", [svc("esa", records, dep)], async () => ({ id: "x", reused: false })));
    const r = await run(d, { force: true });
    expect(dep.apply).not.toHaveBeenCalled();
    expect(r.results).toEqual([
      expect.objectContaining({ domain: "a.example.com", action: "skipped", reason: "shared_cert_blocked" }),
      expect.objectContaining({ domain: "u.example.com", action: "failed", code: "HttpsStateUnknown", retryable: true }),
    ]);
    expect(r.results[0]!.needsConfirm).toBeUndefined();
    expect(r.results[0]!.message).toContain("u.example.com（");

    // 未点名的状态未知记录同样挡住整组
    const scoped = await run(d, { domains: ["a.example.com"], force: true });
    expect(dep.apply).not.toHaveBeenCalled();
    expect(scoped.results).toEqual([expect.objectContaining({ domain: "a.example.com", reason: "shared_cert_blocked" })]);
  });

  it("多个服务共用一次上传；dry-run 不上传也不调用 apply", async () => {
    const upload = vi.fn(async () => ({ id: "cas-1", reused: false }));
    const a = okDeployer();
    const b = okDeployer();
    const d = defs(def("aliyun", [svc("cdn", [rec("cdn", "a.example.com"), rec("cdn", "b.example.com")], a), svc("dcdn", [rec("dcdn", "a.example.com")], b)], upload));

    const dry = await run(d, { dryRun: true });
    expect(dry.dryRun).toBe(true);
    expect(dry.results.map((x) => x.action)).toEqual(["would_update", "would_update", "would_update"]);
    expect(upload).not.toHaveBeenCalled();
    expect(a.apply).not.toHaveBeenCalled();

    const real = await run(d);
    expect(upload).toHaveBeenCalledTimes(1);
    expect(real.uploads).toHaveLength(1);
    expect(real.results.map((x) => x.action)).toEqual(["updated", "updated", "updated"]);
  });

  it("apply 失败：记 failed，带错误码、RequestId、是否可重试，并隐藏私钥", async () => {
    const keyLine = CERT.keyPem.split("\n")[1]!;
    const dep = {
      apply: vi.fn(async (_c: QueryContext, _cr: unknown, t: { records: DomainRecord[] }) => {
        if (t.records[0]!.domain === "a.example.com") throw new CloudApiError("aliyun", "Throttling.User", "slow down", "rid-2");
        throw new CloudApiError("aliyun", "InvalidParameter", `bad key: ${CERT.keyPem} / ${encodeURIComponent(keyLine)}`, "rid-3", 400);
      }),
    };
    const d = defs(def("aliyun", [svc("cdn", [rec("cdn", "a.example.com"), rec("cdn", "b.example.com")], dep)]));
    const r = await run(d);
    expect(r.results[0]).toMatchObject({ action: "failed", code: "Throttling.User", requestId: "rid-2", retryable: true });
    expect(r.results[1]).toMatchObject({ action: "failed", code: "InvalidParameter", retryable: false });
    expect(JSON.stringify(r)).not.toContain(keyLine);
    expect(r.results[1]!.message).toContain("[私钥已隐藏]");
  });

  it("云厂商没有 uploadCertificate 时 certId() 失败只影响用到它的服务", async () => {
    const pem = { apply: vi.fn(async () => ({})) };
    const d = defs(def("aliyun", [svc("cdn", [rec("cdn", "a.example.com")], okDeployer()), svc("vod", [rec("vod", "a.example.com")], pem)]));
    const r = await run(d);
    expect(r.results).toEqual([
      expect.objectContaining({ service: "cdn", action: "failed", code: "UploadUnsupported" }),
      expect.objectContaining({ service: "vod", action: "updated" }),
    ]);
  });

  it("上传失败时该云所有依赖它的服务都记 failed，且只尝试上传一次", async () => {
    const upload = vi.fn(async () => {
      throw new CloudApiError("aliyun", "NoPermission", "denied", "rid-9", 403);
    });
    const d = defs(def("aliyun", [svc("cdn", [rec("cdn", "a.example.com")], okDeployer()), svc("dcdn", [rec("dcdn", "a.example.com")], okDeployer())], upload));
    const r = await run(d);
    expect(upload).toHaveBeenCalledTimes(1);
    expect(r.results.map((x) => [x.action, x.code])).toEqual([
      ["failed", "NoPermission"],
      ["failed", "NoPermission"],
    ]);
    expect(r.uploads).toEqual([]);
  });
});
