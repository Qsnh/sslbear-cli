import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { loadLocalCert } from "../src/deploy/cert.js";
import { executeDeploy, planDeploy, type DeployOptions } from "../src/deploy/run.js";
import { ENV_FAMILIES } from "../src/lib/env.js";
import { CloudApiError, type QueryContext } from "../src/lib/http.js";
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
    expect(r.issues).toEqual([expect.objectContaining({ service: "oss", code: "Forbidden" })]);
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
