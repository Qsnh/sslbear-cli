import { promises as dns } from "node:dns";
import { normalizeName } from "../dns/types.js";

/** 查权威 DNS 用到的三种查询；测试注入假的实现，不发真实的 DNS 请求 */
export interface DnsLookup {
  /** 用系统解析器查 zone 的 NS 记录（主机名，小写、无结尾点）；没有记录或查不到时抛错（code 为 ENODATA / ENOTFOUND 等） */
  resolveNs(zone: string): Promise<string[]>;
  /** NS 主机名的 IPv4 地址 */
  resolveIp(host: string): Promise<string[]>;
  /** 直接向 serverIp 查 fqdn 的 TXT 记录，多段已拼接；查不到记录返回 []，连不上（超时、拒绝等）抛错 */
  queryTxt(serverIp: string, fqdn: string, timeoutMs: number): Promise<string[]>;
}

/** 权威服务器的「没有这条记录」：NOERROR 无数据或 NXDOMAIN，都说明服务器能连上、只是还没同步到 */
const NO_RECORD = new Set(["ENODATA", "ENOTFOUND"]);

export const systemDnsLookup: DnsLookup = {
  resolveNs: async (zone) => (await dns.resolveNs(zone)).map(normalizeName),
  resolveIp: (host) => dns.resolve4(host),
  async queryTxt(serverIp, fqdn, timeoutMs) {
    // 不走系统解析器：递归解析器有缓存，看到的可能是添加之前的结果
    const resolver = new dns.Resolver({ timeout: timeoutMs, tries: 2 });
    resolver.setServers([serverIp]);
    try {
      // 超过 255 字节的 TXT 值会被拆成多段，验证值本身只有 43 个字符，拼接只是为了比较时不出错
      return (await resolver.resolveTxt(fqdn)).map((chunks) => chunks.join(""));
    } catch (e) {
      if (NO_RECORD.has((e as NodeJS.ErrnoException).code ?? "")) return [];
      throw e;
    }
  },
};

/** NS 主机是否属于该服务商：优先比对接口返回的该 zone 的 NS，接口不返回时用服务商的 NS 主机名规则 */
export function nsBelongsTo(host: string, zone: { nameServers?: string[] }, pattern: RegExp): boolean {
  return zone.nameServers?.length ? zone.nameServers.includes(host) : pattern.test(host);
}

/** 一个 zone 里要确认生效的记录 */
export interface PropagationZone {
  /** 服务商里的 zone 名 */
  zone: string;
  /** 服务商的中文名，超时提示里用 */
  label: string;
  nameServers?: string[];
  nameServerPattern: RegExp;
  /** 每个记录名下本次添加的全部值（根域名与泛域名共用一个名字时有两个值） */
  records: { fqdn: string; values: string[] }[];
}

export interface WaitOptions {
  /** --dns-timeout：按累计等待时间计 */
  timeoutMs: number;
  /** 看到后再等多久，缺省 SETTLE_MS；验证因 DNS 失败重试时加长 */
  settleMs?: number;
  sleep: (ms: number) => Promise<void>;
  progress?: (message: string) => void;
}

export const POLL_INTERVAL_MS = 5_000;
/**
 * 全部权威服务器都看到后再等一会：Let's Encrypt 从多地验证，anycast 各节点同步有先后。
 * 实测 DNSPod 免费版加完记录 39 秒后仍有节点答「不存在」，本机也只能看到其中一个节点
 */
export const SETTLE_MS = 30_000;
/** 连不上任何权威服务器时（网络限制 UDP 53 等）的固定等待 */
export const FALLBACK_MS = 30_000;
const QUERY_TIMEOUT_MS = 3_000;
/**
 * 本机 DNS 被代理接管时的固定等待（不查询）：NS 解析到 fake-ip（198.18.0.0/15），53 端口（UDP、TCP）都被代理截走，
 * 应答来自代理的上游递归解析器。记录还没同步时查一次，「没有记录」就会被缓存几分钟（SOA 最小 TTL），之后一直查不到——
 * 实测火山引擎加完记录 20~30 秒才可见，第 20 秒查过一次后 5 分钟都查不到。所以干脆不查，固定等待后交给 CA 验证
 * （CA 查不到时编排层会重新下单重试一次）
 */
export const INTERCEPTED_WAIT_MS = 60_000;

/** Clash / Surge 等代理 fake-ip 模式用的保留地址段（RFC 2544 的 198.18.0.0/15） */
export function isFakeIp(ip: string): boolean {
  const m = /^198\.(\d+)\./.exec(ip);
  return !!m && (m[1] === "18" || m[1] === "19");
}

export class PropagationTimeout extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PropagationTimeout";
  }
}

interface Server {
  host: string;
  ip: string;
  /** 至少应答过一次：从没应答过的服务器多半是本机网络连不上，不拿它挡住流程 */
  reached: boolean;
  /** 已看到全部值的记录名：值不会消失，看到后就不再查 */
  seen: Set<string>;
}

interface ZoneState {
  z: PropagationZone;
  /** 实际查到 NS 的名字：zone 没有单独委派时是上级域名 */
  nsAt?: string;
  ns: string[];
  servers: Server[];
}

/**
 * 找 zone 的权威 NS：zone 本身没有 NS 记录（服务商那边加了子域 zone、注册商处却没委派）时逐级往上找，
 * 这样查的是 CA 实际会问的服务器，超时提示里也能说清楚是哪里没配好。网络错误不往上找，直接当作查不到
 */
async function locateNs(lookup: DnsLookup, zone: string): Promise<{ at: string; ns: string[] } | undefined> {
  const labels = zone.split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const at = labels.slice(i).join(".");
    try {
      const ns = (await lookup.resolveNs(at)).map(normalizeName).filter(Boolean);
      if (ns.length > 0) return { at, ns };
    } catch (e) {
      if (!NO_RECORD.has((e as NodeJS.ErrnoException).code ?? "")) return undefined;
    }
  }
  return undefined;
}

async function prepare(lookup: DnsLookup, z: PropagationZone): Promise<ZoneState> {
  const found = await locateNs(lookup, z.zone);
  if (!found) return { z, ns: [], servers: [] };
  const servers = await Promise.all(
    found.ns.map(async (host): Promise<Server | undefined> => {
      const ip = (await lookup.resolveIp(host).catch(() => []))[0];
      return ip ? { host, ip, reached: false, seen: new Set() } : undefined;
    }),
  );
  return { z, nsAt: found.at, ns: found.ns, servers: servers.filter((s): s is Server => !!s) };
}

/** 一轮查询：只查还没看到全部值的（服务器, 记录名） */
async function poll(lookup: DnsLookup, states: ZoneState[]): Promise<void> {
  const jobs = states.flatMap((st) =>
    st.servers.flatMap((s) =>
      st.z.records
        .filter((r) => !s.seen.has(r.fqdn))
        .map(async (r) => {
          try {
            const got = await lookup.queryTxt(s.ip, r.fqdn, QUERY_TIMEOUT_MS);
            s.reached = true;
            if (r.values.every((v) => got.includes(v))) s.seen.add(r.fqdn);
          } catch {
            // 连不上：这一轮不算，下一轮再查
          }
        }),
    ),
  );
  await Promise.all(jobs);
}

const reachedServers = (st: ZoneState) => st.servers.filter((s) => s.reached);
const zoneDone = (st: ZoneState) => reachedServers(st).every((s) => st.z.records.every((r) => s.seen.has(r.fqdn)));

/** 超时提示：哪些记录在哪些服务器上还没生效，以及 zone 实际的 NS 是否指向所用的服务商 */
function describePending(st: ZoneState): string {
  const { z } = st;
  const parts: string[] = [];
  for (const r of z.records) {
    const missing = reachedServers(st).filter((s) => !s.seen.has(r.fqdn));
    if (missing.length > 0) parts.push(`${r.fqdn} 在 ${missing.map((s) => s.host).join("、")} 上仍未生效`);
  }
  const ns = st.ns.join(", ");
  if (st.nsAt && st.nsAt !== z.zone) {
    parts.push(`${z.zone} 没有单独的 NS 记录（没有委派给 ${z.label}），实际由 ${st.nsAt} 的 NS（${ns}）解析`);
  } else {
    const foreign = st.ns.filter((h) => !nsBelongsTo(h, z, z.nameServerPattern));
    if (foreign.length === st.ns.length) parts.push(`${z.zone} 实际的 NS 为 ${ns}，域名的 NS 没有指向 ${z.label}`);
    else if (foreign.length > 0) parts.push(`${z.zone} 实际的 NS 为 ${ns}，其中 ${foreign.join("、")} 不属于 ${z.label}`);
    else parts.push(`${z.zone} 的 NS（${ns}）指向 ${z.label}，可能是服务商同步较慢`);
  }
  return parts.join("，");
}

/**
 * 等 TXT 记录在权威 DNS 上生效：每 5 秒直接向每个权威服务器查询，全部看到全部值后再等 10 秒。
 * - 连不上任何权威服务器（网络环境限制）时退化为固定等待 30 秒，返回 "unreachable"；
 * - 部分 zone 的服务器连不上时，其余 zone 照常确认，并保证总等待不少于 30 秒；
 * - 累计等待超过 timeoutMs 仍未全部生效 → PropagationTimeout。
 */
export async function waitForTxt(lookup: DnsLookup, zones: PropagationZone[], opts: WaitOptions): Promise<"visible" | "unreachable" | "intercepted"> {
  const say = opts.progress ?? (() => {});
  const states = await Promise.all(zones.map((z) => prepare(lookup, z)));
  let waited = 0;
  if (states.some((st) => st.servers.some((s) => isFakeIp(s.ip)))) {
    const wait = Math.min(INTERCEPTED_WAIT_MS, opts.timeoutMs) + (opts.settleMs ?? SETTLE_MS);
    say(`本机 DNS 被代理接管（权威 NS 解析到 fake-ip 地址），查不到权威 DNS，查代理又会缓存「不存在」，改为固定等待 ${wait / 1000} 秒后验证`);
    await opts.sleep(wait);
    return "intercepted";
  }
  for (;;) {
    // 查询本身的耗时也计入：连不上的服务器每轮要等满查询超时，只按 sleep 计时会远超 --dns-timeout
    const started = Date.now();
    await poll(lookup, states);
    waited += Date.now() - started;
    const reachable = states.filter((st) => reachedServers(st).length > 0);
    // 应答过的服务器会一直算作连得上，所以只有第一轮可能一个都没有
    if (reachable.length === 0) {
      say(`连不上任何权威 DNS 服务器（可能是网络限制），固定等待 ${FALLBACK_MS / 1000} 秒后继续`);
      await opts.sleep(FALLBACK_MS);
      return "unreachable";
    }
    if (reachable.length > 0 && reachable.every(zoneDone)) {
      const base = opts.settleMs ?? SETTLE_MS;
      const settle = reachable.length < states.length ? Math.max(base, FALLBACK_MS - waited) : base;
      say(`权威 DNS 已全部生效，再等 ${settle / 1000} 秒让各节点同步`);
      await opts.sleep(settle);
      return "visible";
    }
    if (waited >= opts.timeoutMs) {
      // 从没连上过的 zone 不在提示之列：它们不是没生效，而是查不了
      const pending = reachable.filter((st) => !zoneDone(st)).map(describePending);
      throw new PropagationTimeout(`等待 ${Math.round(waited / 1000)} 秒后仍未在权威 DNS 上看到全部 TXT 记录：${pending.join("；")}。可加大 --dns-timeout 后重试`);
    }
    await opts.sleep(POLL_INTERVAL_MS);
    waited += POLL_INTERVAL_MS;
  }
}
