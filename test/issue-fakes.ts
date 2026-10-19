import { vi } from "vitest";
import { DNS_DEFS, type DnsDefs } from "../src/dns/index.js";
import type { DnsProviderDef, DnsZone, TxtRecord } from "../src/dns/types.js";
import type { DnsLookup } from "../src/issue/propagation.js";
import type { AcmeFactory } from "../src/issue/run.js";
import type { AcmeAuthorization, AcmeClient, AcmeDirectory, AcmeOrder } from "../src/issue/types.js";
import { DNS_VENDORS, type DnsVendor } from "../src/types.js";

/**
 * 假的 DNS 世界：各服务商的 zone、权威 DNS 上可见的 TXT、zone 的 NS。
 * log 与假 CA 共用，用来检查调用顺序（先加记录、再通知验证、验证完再删）
 */
export interface FakeWorld {
  txt: Map<string, string[]>;
  ns: Record<string, string[]>;
  log: string[];
  /** addTxt 同时在跑的最大个数：串行时为 1 */
  maxConcurrentAdds: number;
}

export function fakeWorld(ns: Record<string, string[]> = {}): FakeWorld {
  return { txt: new Map(), ns, log: [], maxConcurrentAdds: 0 };
}

type DefOverride = Partial<Pick<DnsProviderDef<unknown>, "listZones" | "addTxt" | "removeTxt" | "readCredentials">>;

/**
 * 11 家都用真实定义（凭证读取、label、NS 规则不变），只替换 listZones / addTxt / removeTxt：
 * 加的记录立刻出现在 world.txt 里（权威 DNS 马上可见），删除只删本次加的那个值
 */
export function fakeDnsDefs(zones: Partial<Record<DnsVendor, DnsZone[]>>, world: FakeWorld, overrides: Partial<Record<DnsVendor, DefOverride>> = {}) {
  let active = 0;
  let seq = 0;
  const defs = {} as DnsDefs;
  for (const v of DNS_VENDORS) {
    const def: DnsProviderDef<unknown> = {
      ...DNS_DEFS[v],
      listZones: vi.fn(async () => zones[v] ?? []),
      addTxt: vi.fn(async (_ctx, _creds, r: TxtRecord) => {
        active++;
        world.maxConcurrentAdds = Math.max(world.maxConcurrentAdds, active);
        await new Promise((res) => setTimeout(res, 1));
        active--;
        world.txt.set(r.fqdn, [...(world.txt.get(r.fqdn) ?? []), r.value]);
        world.log.push(`add ${v} ${r.fqdn} ${r.value}`);
        return `h${++seq}`;
      }),
      removeTxt: vi.fn(async (_ctx, _creds, r: TxtRecord, handle: string) => {
        world.txt.set(r.fqdn, (world.txt.get(r.fqdn) ?? []).filter((x) => x !== r.value));
        world.log.push(`remove ${v} ${r.fqdn} ${r.value} ${handle}`);
      }),
      ...overrides[v],
    };
    defs[v] = def;
  }
  return defs;
}

const errno = (code: string) => Object.assign(new Error(code), { code });

/** 按 world 应答：NS 查 world.ns，NS 主机的 IP 为 ip:<主机名>，TXT 查 world.txt */
export function fakeLookup(world: FakeWorld, over: Partial<DnsLookup> = {}): DnsLookup & { queried: string[] } {
  const queried: string[] = [];
  return {
    queried,
    resolveNs: vi.fn(async (zone: string) => {
      const ns = world.ns[zone];
      if (!ns) throw errno("ENODATA");
      return ns;
    }),
    resolveIp: vi.fn(async (host: string) => [`ip:${host}`]),
    queryTxt: vi.fn(async (ip: string, fqdn: string) => {
      queried.push(`${ip} ${fqdn}`);
      return world.txt.get(fqdn) ?? [];
    }),
    ...over,
  };
}

export interface FakeAcmeOptions {
  /** CA 下载返回的证书链 */
  certPem: string;
  /** 授权已是 valid 的标识（如 "*.example.com"） */
  valid?: string[];
  directory?: Partial<AcmeDirectory>;
  /** 替换默认行为，如让 newOrder / waitAuthorization 抛错 */
  newOrder?: AcmeClient["newOrder"];
  waitAuthorization?: AcmeClient["waitAuthorization"];
  finalize?: AcmeClient["finalize"];
}

/** 假 CA：每个标识一个授权，token 为 tok-<标识>，TXT 值为 v-<token> */
export function fakeAcme(world: FakeWorld, opts: FakeAcmeOptions) {
  const directory: AcmeDirectory = {
    url: "https://ca.test/dir",
    newNonce: "https://ca.test/nonce",
    newAccount: "https://ca.test/acct",
    newOrder: "https://ca.test/order",
    renewalInfo: "https://ca.test/ari",
    profiles: { classic: "classic", tlsserver: "tlsserver" },
    ...opts.directory,
  };
  const authzUrl = (id: string) => `https://ca.test/authz/${id}`;
  const idOf = (url: string) => url.slice(url.lastIndexOf("/") + 1);
  const log = world.log;
  const client = {
    directory,
    ensureAccount: vi.fn(async () => void log.push("account")),
    newOrder: vi.fn(
      opts.newOrder ??
        (async (domains: readonly string[]): Promise<AcmeOrder> => {
          log.push(`order ${domains.join(",")}`);
          return { url: "https://ca.test/order/1", status: "pending", authorizations: domains.map(authzUrl), finalize: "https://ca.test/finalize/1" };
        }),
    ),
    getAuthorization: vi.fn(async (url: string): Promise<AcmeAuthorization> => {
      const id = idOf(url);
      const wildcard = id.startsWith("*.");
      const valid = opts.valid?.includes(id);
      return {
        url,
        status: valid ? "valid" : "pending",
        domain: id.replace(/^\*\./, ""),
        wildcard,
        ...(!valid && { challenge: { url: `https://ca.test/chall/${id}`, token: `tok-${id}`, status: "pending" } }),
      };
    }),
    dnsTxtValue: vi.fn((token: string) => `v-${token}`),
    answerChallenge: vi.fn(async (url: string) => void log.push(`answer ${idOf(url)}`)),
    waitAuthorization: vi.fn(
      opts.waitAuthorization ??
        (async (url: string) => {
          log.push(`wait ${idOf(url)}`);
        }),
    ),
    finalize: vi.fn(
      opts.finalize ??
        (async (order: AcmeOrder) => {
          log.push("finalize");
          return { ...order, status: "valid" as const, certificate: "https://ca.test/cert/1" };
        }),
    ),
    downloadCertificate: vi.fn(async () => {
      log.push("download");
      return opts.certPem;
    }),
  } satisfies AcmeClient;
  const factory = vi.fn<AcmeFactory>(async () => client);
  return { client, factory };
}

export const CLOUDFLARE_ENV = { CLOUDFLARE_API_TOKEN: "cf-token-0123456789" };
