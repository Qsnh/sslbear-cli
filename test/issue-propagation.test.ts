import { createSocket, type Socket } from "node:dgram";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  FALLBACK_MS,
  INTERCEPTED_DELAY_MS,
  isFakeIp,
  POLL_INTERVAL_MS,
  PropagationTimeout,
  SETTLE_MS,
  systemDnsLookup,
  waitForTxt,
  type DnsLookup,
  type PropagationZone,
} from "../src/issue/propagation.js";

const errno = (code: string) => Object.assign(new Error(code), { code });

const aliyunZone = (records: PropagationZone["records"], over: Partial<PropagationZone> = {}): PropagationZone => ({
  zone: "example.com",
  label: "阿里云云解析",
  nameServerPattern: /(^|\.)(hichina|alidns)\.com$/,
  records,
  ...over,
});

/**
 * 按轮次应答的假权威 DNS：visibleFrom[服务器][记录名] = 从第几轮（0 起）开始能看到全部值；
 * 不在表里的服务器连不上（抛 ETIMEOUT）
 */
function staged(ns: Record<string, string[]>, visibleFrom: Record<string, Record<string, number>>, values: Record<string, string[]>) {
  let round = 0;
  const queries: string[] = [];
  const lookup: DnsLookup = {
    resolveNs: vi.fn(async (zone: string) => {
      if (!ns[zone]) throw errno("ENODATA");
      return ns[zone]!;
    }),
    resolveIp: vi.fn(async (host: string) => [`ip:${host}`]),
    queryTxt: vi.fn(async (ip: string, fqdn: string) => {
      const host = ip.slice(3);
      queries.push(`${round} ${host} ${fqdn}`);
      const from = visibleFrom[host];
      if (!from) throw errno("ETIMEOUT");
      return (from[fqdn] ?? Infinity) <= round ? values[fqdn]! : [];
    }),
  };
  const sleeps: number[] = [];
  const sleep = vi.fn(async (ms: number) => {
    sleeps.push(ms);
    if (ms === POLL_INTERVAL_MS) round++;
  });
  return { lookup, sleep, sleeps, queries };
}

const FQDN = "_acme-challenge.example.com";
const NS = { "example.com": ["dns1.hichina.com", "dns2.hichina.com"] };

describe("waitForTxt", () => {
  it("本机 DNS 被代理接管（NS 解析到 fake-ip）：先等 20 秒再查，超时提示里说明", async () => {
    expect([isFakeIp("198.18.0.105"), isFakeIp("198.19.255.1"), isFakeIp("198.20.0.1"), isFakeIp("10.198.18.1")]).toEqual([true, true, false, false]);
    const fake = (visible: boolean): DnsLookup => ({
      resolveNs: async () => ["dns1.hichina.com"],
      resolveIp: async () => ["198.18.0.105"],
      queryTxt: async () => (visible ? ["a"] : []),
    });
    const sleeps: number[] = [];
    const sleep = async (ms: number) => void sleeps.push(ms);
    expect(await waitForTxt(fake(true), [aliyunZone([{ fqdn: FQDN, values: ["a"] }])], { timeoutMs: 300_000, sleep })).toBe("visible");
    expect(sleeps).toEqual([INTERCEPTED_DELAY_MS, SETTLE_MS]);
    const e = await waitForTxt(fake(false), [aliyunZone([{ fqdn: FQDN, values: ["a"] }])], { timeoutMs: 30_000, sleep }).catch((err: unknown) => err);
    expect(e).toBeInstanceOf(PropagationTimeout);
    expect((e as Error).message).toContain("本机 DNS 被代理接管");
  });

  it("每 5 秒查一轮，全部权威服务器都看到全部值后再等 10 秒；看到了的服务器不再重复查", async () => {
    const { lookup, sleep, sleeps, queries } = staged(NS, { "dns1.hichina.com": { [FQDN]: 1 }, "dns2.hichina.com": { [FQDN]: 3 } }, { [FQDN]: ["a", "b"] });
    const r = await waitForTxt(lookup, [aliyunZone([{ fqdn: FQDN, values: ["a", "b"] }])], { timeoutMs: 300_000, sleep });
    expect(r).toBe("visible");
    expect(sleeps).toEqual([POLL_INTERVAL_MS, POLL_INTERVAL_MS, POLL_INTERVAL_MS, SETTLE_MS]);
    expect(queries.filter((q) => q.includes("dns1"))).toEqual([`0 dns1.hichina.com ${FQDN}`, `1 dns1.hichina.com ${FQDN}`]);
    expect(queries.filter((q) => q.includes("dns2"))).toHaveLength(4);
  });

  it("同名两个值（根域名 + 泛域名）只看到一个不算生效", async () => {
    let round = 0;
    const lookup: DnsLookup = {
      resolveNs: async () => ["dns1.hichina.com"],
      resolveIp: async (h) => [`ip:${h}`],
      queryTxt: async () => (round === 0 ? ["a"] : ["b", "a", "unrelated"]),
    };
    const sleep = vi.fn(async (ms: number) => void (ms === POLL_INTERVAL_MS && round++));
    await waitForTxt(lookup, [aliyunZone([{ fqdn: FQDN, values: ["a", "b"] }])], { timeoutMs: 300_000, sleep });
    expect(sleep.mock.calls.map((c) => c[0])).toEqual([POLL_INTERVAL_MS, SETTLE_MS]);
  });

  it("多个 zone、多个记录名：每个 zone 用各自的权威服务器", async () => {
    const ns = { "example.com": ["dns1.hichina.com"], "example.org": ["ada.ns.cloudflare.com"] };
    const { lookup, sleep, queries } = staged(
      ns,
      { "dns1.hichina.com": { [FQDN]: 0, "_acme-challenge.www.example.com": 2 }, "ada.ns.cloudflare.com": { "_acme-challenge.example.org": 1 } },
      { [FQDN]: ["a"], "_acme-challenge.www.example.com": ["w"], "_acme-challenge.example.org": ["o"] },
    );
    const zones = [
      aliyunZone([
        { fqdn: FQDN, values: ["a"] },
        { fqdn: "_acme-challenge.www.example.com", values: ["w"] },
      ]),
      { zone: "example.org", label: "Cloudflare", nameServerPattern: /\.ns\.cloudflare\.com$/, records: [{ fqdn: "_acme-challenge.example.org", values: ["o"] }] },
    ];
    expect(await waitForTxt(lookup, zones, { timeoutMs: 300_000, sleep })).toBe("visible");
    expect(queries.some((q) => q.includes("dns1.hichina.com _acme-challenge.example.org"))).toBe(false);
    expect(queries.some((q) => q.includes("cloudflare.com _acme-challenge.example.com"))).toBe(false);
    expect(sleep).toHaveBeenLastCalledWith(SETTLE_MS);
  });

  it("超时：按累计等待时间判定，message 说明 NS 没有指向所用的服务商", async () => {
    const ns = { "example.com": ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"] };
    const { lookup, sleep, sleeps } = staged(ns, { "ada.ns.cloudflare.com": {}, "bob.ns.cloudflare.com": {} }, {});
    const p = waitForTxt(lookup, [aliyunZone([{ fqdn: FQDN, values: ["a"] }])], { timeoutMs: 20_000, sleep });
    await expect(p).rejects.toBeInstanceOf(PropagationTimeout);
    const msg = await p.catch((e: Error) => e.message);
    expect(sleeps.reduce((a, b) => a + b, 0)).toBe(20_000);
    expect(sleeps.every((s) => s === POLL_INTERVAL_MS)).toBe(true);
    expect(msg).toContain("等待 20 秒后");
    expect(msg).toContain(`${FQDN} 在 ada.ns.cloudflare.com、bob.ns.cloudflare.com 上仍未生效`);
    expect(msg).toContain("example.com 实际的 NS 为 ada.ns.cloudflare.com, bob.ns.cloudflare.com，域名的 NS 没有指向 阿里云云解析");
    expect(msg).toContain("--dns-timeout");
  });

  it("超时提示：NS 确实指向该服务商时说明可能是同步慢；接口给了 zone NS 时按它比对", async () => {
    const { lookup, sleep } = staged(NS, { "dns1.hichina.com": {}, "dns2.hichina.com": { [FQDN]: 0 } }, { [FQDN]: ["a"] });
    const msg = await waitForTxt(lookup, [aliyunZone([{ fqdn: FQDN, values: ["a"] }])], { timeoutMs: 10_000, sleep }).catch((e: Error) => e.message);
    expect(msg).toContain(`${FQDN} 在 dns1.hichina.com 上仍未生效`);
    expect(msg).toContain("指向 阿里云云解析，可能是服务商同步较慢");

    const s2 = staged(NS, { "dns1.hichina.com": {}, "dns2.hichina.com": {} }, {});
    const zone = aliyunZone([{ fqdn: FQDN, values: ["a"] }], { nameServers: ["dns1.hichina.com", "dns9.hichina.com"] });
    const msg2 = await waitForTxt(s2.lookup, [zone], { timeoutMs: 10_000, sleep: s2.sleep }).catch((e: Error) => e.message);
    expect(msg2).toContain("其中 dns2.hichina.com 不属于 阿里云云解析");
  });

  it("zone 没有单独委派时往上级找 NS，超时提示里点明", async () => {
    const ns = { "example.com": ["dns1.hichina.com"] };
    const { lookup, sleep } = staged(ns, { "dns1.hichina.com": {} }, {});
    const zone = { zone: "sub.example.com", label: "Cloudflare", nameServerPattern: /\.ns\.cloudflare\.com$/, records: [{ fqdn: "_acme-challenge.sub.example.com", values: ["a"] }] };
    const msg = await waitForTxt(lookup, [zone], { timeoutMs: 10_000, sleep }).catch((e: Error) => e.message);
    expect(lookup.resolveNs).toHaveBeenCalledWith("sub.example.com");
    expect(lookup.resolveNs).toHaveBeenCalledWith("example.com");
    expect(msg).toContain("sub.example.com 没有单独的 NS 记录（没有委派给 Cloudflare），实际由 example.com 的 NS（dns1.hichina.com）解析");
  });

  it("全部权威服务器都连不上：固定等 30 秒后继续", async () => {
    const { lookup, sleep, sleeps } = staged(NS, {}, {});
    const progress = vi.fn();
    expect(await waitForTxt(lookup, [aliyunZone([{ fqdn: FQDN, values: ["a"] }])], { timeoutMs: 300_000, sleep, progress })).toBe("unreachable");
    expect(sleeps).toEqual([FALLBACK_MS]);
    expect(progress).toHaveBeenCalledWith(expect.stringContaining("固定等待 30 秒"));
  });

  it("查不到 NS（系统解析器网络错误）也退化为固定等待，不往上级找", async () => {
    const lookup: DnsLookup = {
      resolveNs: vi.fn(async () => Promise.reject(errno("ECONNREFUSED"))),
      resolveIp: vi.fn(async () => []),
      queryTxt: vi.fn(async () => []),
    };
    const sleep = vi.fn(async () => {});
    expect(await waitForTxt(lookup, [aliyunZone([{ fqdn: "_acme-challenge.a.b.example.com", values: ["a"] }], { zone: "b.example.com" })], { timeoutMs: 300_000, sleep })).toBe("unreachable");
    expect(lookup.resolveNs).toHaveBeenCalledTimes(1);
    expect(lookup.queryTxt).not.toHaveBeenCalled();
    expect(sleep).toHaveBeenCalledWith(FALLBACK_MS);
  });

  it("从没应答过的服务器不挡住流程；有 zone 整个连不上时总等待不少于 30 秒", async () => {
    const ns = { "example.com": ["dns1.hichina.com", "dns2.hichina.com"], "example.org": ["ada.ns.cloudflare.com"] };
    // dns2 一直连不上；example.org 的服务器也连不上
    const { lookup, sleep, sleeps } = staged(ns, { "dns1.hichina.com": { [FQDN]: 1 } }, { [FQDN]: ["a"] });
    const zones = [
      aliyunZone([{ fqdn: FQDN, values: ["a"] }]),
      { zone: "example.org", label: "Cloudflare", nameServerPattern: /\.ns\.cloudflare\.com$/, records: [{ fqdn: "_acme-challenge.example.org", values: ["o"] }] },
    ];
    expect(await waitForTxt(lookup, zones, { timeoutMs: 300_000, sleep })).toBe("visible");
    expect(sleeps).toEqual([POLL_INTERVAL_MS, FALLBACK_MS - POLL_INTERVAL_MS]);
  });
});

/** 本机 UDP 上的极简权威 DNS：只回 TXT，按名字决定应答方式，用来验证默认实现对各种应答的处理 */
function encodeTxt(chunks: string[]): Buffer {
  return Buffer.concat(chunks.map((c) => Buffer.concat([Buffer.from([c.length]), Buffer.from(c)])));
}

function reply(query: Buffer, rcode: number, answers: Buffer[]): Buffer {
  let off = 12;
  while (query[off]! !== 0) off += query[off]! + 1;
  const question = query.subarray(12, off + 5);
  const header = Buffer.alloc(12);
  query.copy(header, 0, 0, 2);
  header.writeUInt16BE(0x8400 | rcode, 2); // QR + AA
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(answers.length, 6);
  const rrs = answers.map((rdata) => {
    const rr = Buffer.alloc(12);
    rr.writeUInt16BE(0xc00c, 0); // 指向问题里的名字
    rr.writeUInt16BE(16, 2); // TXT
    rr.writeUInt16BE(1, 4);
    rr.writeUInt32BE(60, 6);
    rr.writeUInt16BE(rdata.length, 10);
    return Buffer.concat([rr, rdata]);
  });
  return Buffer.concat([header, question, ...rrs]);
}

function qname(query: Buffer): string {
  const labels: string[] = [];
  for (let off = 12; query[off]! !== 0; off += query[off]! + 1) labels.push(query.subarray(off + 1, off + 1 + query[off]!).toString());
  return labels.join(".");
}

describe("systemDnsLookup.queryTxt（本机假权威 DNS）", () => {
  let server: Socket;
  let addr: string;
  beforeAll(async () => {
    server = createSocket("udp4");
    server.on("message", (msg, rinfo) => {
      const name = qname(msg);
      let out: Buffer | undefined;
      if (name === "multi.test") out = reply(msg, 0, [encodeTxt(["abc", "def"]), encodeTxt(["other"])]);
      else if (name === "nodata.test") out = reply(msg, 0, []);
      else if (name === "nxdomain.test") out = reply(msg, 3, []);
      else if (name === "refused.test") out = reply(msg, 5, []);
      // timeout.test 不应答
      if (out) server.send(out, rinfo.port, rinfo.address);
    });
    await new Promise<void>((r) => server.bind(0, "127.0.0.1", () => r()));
    addr = `127.0.0.1:${server.address().port}`;
  });
  afterAll(() => server.close());

  it("多段 TXT 拼接，多条记录各自返回", async () => {
    expect(await systemDnsLookup.queryTxt(addr, "multi.test", 1000)).toEqual(["abcdef", "other"]);
  });

  it("NOERROR 无数据、NXDOMAIN 都是「没有记录」，返回 []", async () => {
    expect(await systemDnsLookup.queryTxt(addr, "nodata.test", 1000)).toEqual([]);
    expect(await systemDnsLookup.queryTxt(addr, "nxdomain.test", 1000)).toEqual([]);
  });

  it("拒绝应答、超时都算连不上，抛错", async () => {
    await expect(systemDnsLookup.queryTxt(addr, "refused.test", 1000)).rejects.toMatchObject({ code: "EREFUSED" });
    await expect(systemDnsLookup.queryTxt(addr, "timeout.test", 100)).rejects.toMatchObject({ code: "ETIMEOUT" });
  });
});
