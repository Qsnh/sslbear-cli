import { describe, expect, it } from "vitest";
import { signV4, type SigV4Input } from "../src/dns/aws-sign.js";
import { awsDns, unescapeName, type AwsCredentials } from "../src/dns/aws.js";
import type { DnsZone, TxtRecord } from "../src/dns/types.js";
import { CloudApiError, isRetryable, type Fetch, type QueryContext } from "../src/lib/http.js";
import { xmlBlocks, xmlText } from "../src/lib/xml.js";
import { fakeFetch, type FakeReply, type FakeRequest } from "./helpers.js";

describe("AWS SigV4 签名", () => {
  // aws-sig-v4-test-suite（awslabs/aws-c-auth tests/aws-signing-test-suite/v4）的向量：凭证、时间、region、service 各用例相同。
  // 凭证是官方公开的示例值，不是真实密钥；SK 拆开写以免被密钥扫描误判
  const suite = {
    accessKeyId: "AKIDEXAMPLE",
    secretAccessKey: ["wJalrXUtnFEMI/K7MDENG", "+bPxRfiCYEXAMPLEKEY"].join(""),
    region: "us-east-1",
    service: "service",
    host: "example.amazonaws.com",
    date: new Date("2015-08-30T12:36:00Z"),
  };
  const STS_TOKEN =
    "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==";
  const form = { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": "13" };

  const cases: [string, Partial<SigV4Input>, string][] = [
    ["get-vanilla", { method: "GET", path: "/" }, "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"],
    ["get-vanilla-empty-query-key", { method: "GET", path: "/", query: { Param1: "value1" } }, "a67d582fa61cc504c4bae71f336f98b97f1ea3c7a6bfe1b6e45aec72011b9aeb"],
    ["get-vanilla-query-order-key-case", { method: "GET", path: "/", query: { Param2: "value2", Param1: "value1" } }, "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"],
    [
      "get-vanilla-query-order-encoded（按编码后的名字排序）",
      { method: "GET", path: "/", query: { "Param-3": "Value3", Param: "Value2", "ሴ": "Value1" } },
      "371d3713e185cc334048618a97f809c9ffe339c62934c032af5a0e595648fcac",
    ],
    [
      "get-vanilla-query-unreserved",
      { method: "GET", path: "/", query: { "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz": "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" } },
      "9c3e54bfcdf0b19771a7f523ee5669cdf59bc7cc0884027167c21bb143a40197",
    ],
    ["get-vanilla-utf8-query", { method: "GET", path: "/", query: { "ሴ": "bar" } }, "2cdec8eed098649ff3a119c94853b13c643bcf08f8b0a1d91e12c9027818dd04"],
    ["get-unreserved", { method: "GET", path: "/-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" }, "07ef7494c76fa4850883e2b006601f940f8a34d404d0cfa977f52a65bbf5f24f"],
    ["get-utf8", { method: "GET", path: "/ሴ" }, "8318018e0b0f223aa2bbf98705b62bb787dc9c0e678f255a891fd03141be5d85"],
    ["get-space-unnormalized", { method: "GET", path: "/example space/" }, "652487583200325589f1fba4c7e578f72c47cb61beeca81406b39ddec1366741"],
    ["get-header-value-trim", { method: "GET", path: "/", headers: { "My-Header1": " value1", "My-Header2": ' "a   b   c"' } }, "acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736"],
    ["get-header-key-duplicate", { method: "GET", path: "/", headers: { "My-Header1": ["value2", "value2", "value1"] } }, "c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea"],
    ["get-header-value-order", { method: "GET", path: "/", headers: { "My-Header1": ["value4", "value1", "value3", "value2"] } }, "08c7e5a9acfcfeb3ab6b2185e75ce8b1deb5e634ec47601a50643f830c755c01"],
    [
      "get-vanilla-with-session-token",
      { method: "GET", path: "/", sessionToken: "6e86291e8372ff2a2260956d9b8aae1d763fbf315fa00fa31553b73ebf194267" },
      "07ec1639c89043aa0e3e2de82b96708f198cceab042d4a97044c66dd9f74e7f8",
    ],
    ["post-vanilla", { method: "POST", path: "/" }, "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"],
    ["post-vanilla-query", { method: "POST", path: "/", query: { Param1: "value1" } }, "28038455d6de14eafc1f9222cf5aa6f1a96197d7deb8263271d420d138af7f11"],
    ["post-header-key-sort", { method: "POST", path: "/", headers: { "My-Header1": "value1" } }, "c5410059b04c1ee005303aed430f6e6645f61f4dc9e1461ec8f8916fdf18852c"],
    ["post-header-value-case", { method: "POST", path: "/", headers: { "My-Header1": "VALUE1" } }, "cdbc9802e29d2942e5e10b5bccfdd67c5f22c7c4e8ae67b53629efa58b974b7d"],
    ["post-sts-header-before", { method: "POST", path: "/", sessionToken: STS_TOKEN }, "85d96828115b5dc0cfc3bd16ad9e210dd772bbebba041836c64533a82be05ead"],
    [
      "post-x-www-form-urlencoded",
      { method: "POST", path: "/", headers: form, body: "Param1=value1", contentSha256Header: true },
      "d3875051da38690788ef43de4db0d8f280229d82040bfac253562e56c3f20e0b",
    ],
    [
      "post-x-www-form-urlencoded-parameters",
      { method: "POST", path: "/", headers: { ...form, "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" }, body: "Param1=value1", contentSha256Header: true },
      "328d1b9eaadca9f5818ef05e8392801e091653bafec24fcab71e7344e7f51422",
    ],
  ];

  it.each(cases)("%s", (_, input, signature) => {
    expect(signV4({ ...suite, method: "GET", path: "/", ...input }).signature).toBe(signature);
  });

  it("get-vanilla：规范请求、待签字符串、Authorization 头与测试套件逐字一致", () => {
    const signed = signV4({ ...suite, method: "GET", path: "/" });
    expect(signed.canonicalRequest).toBe(
      "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    expect(signed.stringToSign).toBe(
      "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nbb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63",
    );
    // Host 由 fetch 自动带上，不在返回的头里
    expect(signed.headers).toEqual({
      "X-Amz-Date": "20150830T123600Z",
      Authorization:
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
    });
  });

  it("post-x-www-form-urlencoded：x-amz-content-sha256 参与签名并随请求发送", () => {
    const signed = signV4({ ...suite, method: "POST", path: "/", headers: form, body: "Param1=value1", contentSha256Header: true });
    expect(signed.canonicalRequest).toBe(
      [
        "POST",
        "/",
        "",
        "content-length:13",
        "content-type:application/x-www-form-urlencoded",
        "host:example.amazonaws.com",
        "x-amz-content-sha256:9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e",
        "x-amz-date:20150830T123600Z",
        "",
        "content-length;content-type;host;x-amz-content-sha256;x-amz-date",
        "9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e",
      ].join("\n"),
    );
    expect(signed.stringToSign.split("\n")[3]).toBe("b1edd1d03544c25390e32085d55b57acc9a3961bb59415ff86c45c3d89d16cfb");
    expect(signed.headers["X-Amz-Content-Sha256"]).toBe("9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e");
  });

  it("临时凭证：X-Amz-Security-Token 随请求发送", () => {
    const signed = signV4({ ...suite, method: "GET", path: "/", sessionToken: "tok" });
    expect(signed.headers["X-Amz-Security-Token"]).toBe("tok");
    expect(signed.headers.Authorization).toContain("SignedHeaders=host;x-amz-date;x-amz-security-token,");
  });
});

// ---------------- Route 53 适配器 ----------------

const XMLNS = "https://route53.amazonaws.com/doc/2013-04-01/";
const ZONE: DnsZone = { name: "example.com", id: "Z111111QQQQQQQ" };
const FQDN = "_acme-challenge.example.com";
const V1 = "XKrxpRBosdIKFzxW_CT3KLZNf6q0HG9i01zxXp5CPBs";
const V2 = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0";
const RECORD: TxtRecord = { zone: ZONE, fqdn: FQDN, value: V1 };
const CREDS: AwsCredentials = { accessKeyId: "AKIDEXAMPLE", secretAccessKey: "test-secret" };
const RRSET_PATH = `/2013-04-01/hostedzone/${ZONE.id}/rrset`;

const ctxOf = (fetch: Fetch): QueryContext => ({ env: {}, fetch, now: new Date("2026-10-18T00:00:00Z"), timeoutMs: 1000, sleep: async () => {} });

const xml = (s: string): FakeReply => ({ body: `<?xml version="1.0" encoding="UTF-8"?>\n${s}` });
const errorReply = (status: number, code: string, message: string): FakeReply => ({
  status,
  body: `<?xml version="1.0"?>\n<ErrorResponse xmlns="${XMLNS}"><Error><Type>Sender</Type><Code>${code}</Code><Message>${message}</Message></Error><RequestId>rid-${code}</RequestId></ErrorResponse>`,
});
const invalidBatch = (...messages: string[]): FakeReply => ({
  status: 400,
  body: `<?xml version="1.0"?>\n<InvalidChangeBatch xmlns="${XMLNS}"><Messages>${messages.map((m) => `<Message>${m}</Message>`).join("")}</Messages><RequestId>rid-batch</RequestId></InvalidChangeBatch>`,
});

interface SetXml {
  name: string;
  type: string;
  ttl?: number;
  /** ResourceRecord 的 Value，按 XML 原文写（含实体） */
  values?: string[];
  /** 插在 Type 后的其他元素，如 SetIdentifier / AliasTarget */
  extra?: string;
}
const rrsets = (...sets: SetXml[]): FakeReply =>
  xml(
    `<ListResourceRecordSetsResponse xmlns="${XMLNS}"><ResourceRecordSets>` +
      sets
        .map(
          (s) =>
            `<ResourceRecordSet><Name>${s.name}</Name><Type>${s.type}</Type>${s.extra ?? ""}` +
            (s.ttl !== undefined ? `<TTL>${s.ttl}</TTL>` : "") +
            (s.values ? `<ResourceRecords>${s.values.map((v) => `<ResourceRecord><Value>${v}</Value></ResourceRecord>`).join("")}</ResourceRecords>` : "") +
            `</ResourceRecordSet>`,
        )
        .join("") +
      `</ResourceRecordSets><IsTruncated>${sets.length > 0}</IsTruncated><MaxItems>1</MaxItems></ListResourceRecordSetsResponse>`,
  );
const CHANGE_OK = xml(
  `<ChangeResourceRecordSetsResponse xmlns="${XMLNS}"><ChangeInfo><Id>/change/C2682N5HXP0BZ4</Id><Status>PENDING</Status><SubmittedAt>2026-10-18T00:00:00.000Z</SubmittedAt></ChangeInfo></ChangeResourceRecordSetsResponse>`,
);

const isList = (r: FakeRequest) => r.method === "GET" && r.url.pathname === RRSET_PATH;
const isChange = (r: FakeRequest) => r.method === "POST" && r.url.pathname === `${RRSET_PATH}/`;

/** 解析提交的变更批次：每一项的动作、名字、类型、TTL、全部值（已反转义） */
function parseChanges(body: string) {
  return xmlBlocks(body, "Change").map((change) => {
    const set = xmlBlocks(change, "ResourceRecordSet")[0]!;
    return {
      action: xmlText(change, "Action"),
      name: xmlText(set, "Name"),
      type: xmlText(set, "Type"),
      ttl: Number(xmlText(set, "TTL")),
      values: xmlBlocks(set, "ResourceRecord").map((r) => xmlText(r, "Value")),
    };
  });
}
const NAME = `${FQDN}.`;

/** 按请求依次返回固定响应的路由：ListResourceRecordSets 按 lists 顺序返回（用完后重复最后一个），变更按 changes 顺序 */
function r53(lists: FakeReply[], changes: FakeReply[] = [CHANGE_OK]) {
  let li = 0;
  let ci = 0;
  return fakeFetch((r) => {
    if (r.url.host !== "route53.amazonaws.com") return undefined;
    if (isList(r)) return lists[Math.min(li++, lists.length - 1)];
    if (isChange(r)) return changes[Math.min(ci++, changes.length - 1)];
    return undefined;
  });
}

const hostedZone = (id: string, name: string, priv?: boolean) =>
  `<HostedZone><Id>/hostedzone/${id}</Id><Name>${name}</Name><CallerReference>ref-${id}</CallerReference>` +
  (priv === undefined ? "" : `<Config><Comment>c</Comment><PrivateZone>${priv}</PrivateZone></Config>`) +
  `<ResourceRecordSetCount>2</ResourceRecordSetCount></HostedZone>`;
const zonesPage = (zones: string[], next?: string): FakeReply =>
  xml(
    `<ListHostedZonesResponse xmlns="${XMLNS}"><HostedZones>${zones.join("")}</HostedZones>` +
      `<IsTruncated>${!!next}</IsTruncated>${next ? `<NextMarker>${next}</NextMarker>` : ""}<MaxItems>100</MaxItems></ListHostedZonesResponse>`,
  );

describe("AWS Route 53 listZones", () => {
  it("按 marker 翻页、去掉私有 zone、取 Id 里的 zone ID", async () => {
    const fetch = fakeFetch((r) => {
      if (r.url.pathname !== "/2013-04-01/hostedzone") return undefined;
      return r.url.searchParams.get("marker") === "Z4444444DDDDDD"
        ? zonesPage([hostedZone("Z4444444DDDDDD", "xn--fiqs8s.asia.", false)])
        : zonesPage(
            [hostedZone("Z111111QQQQQQQ", "example.com.", false), hostedZone("Z2222222BBBBBB", "internal.example.com.", true), hostedZone("Z3333333CCCCCC", "example.org.")],
            "Z4444444DDDDDD",
          );
    });
    const zones = await awsDns.listZones(ctxOf(fetch), CREDS);
    expect(zones).toEqual([
      { name: "example.com", id: "Z111111QQQQQQQ" },
      // 没有 Config 的 zone 按公网处理
      { name: "example.org", id: "Z3333333CCCCCC" },
      { name: "xn--fiqs8s.asia", id: "Z4444444DDDDDD" },
    ]);
    expect(fetch.calls.map((c) => c.url.search)).toEqual(["?maxitems=100", "?marker=Z4444444DDDDDD&maxitems=100"]);
    const auth = fetch.calls[0]!.headers.authorization;
    expect(auth).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/\d{8}\/us-east-1\/route53\/aws4_request, SignedHeaders=host;x-amz-date, Signature=[0-9a-f]{64}$/);
    expect(fetch.calls[0]!.headers["x-amz-date"]).toMatch(/^\d{8}T\d{6}Z$/);
    expect(fetch.calls[0]!.headers["x-amz-security-token"]).toBeUndefined();
  });

  it("临时凭证带 X-Amz-Security-Token 并参与签名", async () => {
    const fetch = fakeFetch(() => zonesPage([hostedZone("Z111111QQQQQQQ", "example.com.", false)]));
    await awsDns.listZones(ctxOf(fetch), { ...CREDS, sessionToken: "session/token+=" });
    expect(fetch.calls[0]!.headers["x-amz-security-token"]).toBe("session/token+=");
    expect(fetch.calls[0]!.headers.authorization).toContain("SignedHeaders=host;x-amz-date;x-amz-security-token,");
  });

  it("zone 名里的八进制转义还原后再规范化", async () => {
    const fetch = fakeFetch(() => zonesPage([hostedZone("Z5555555EEEEEE", "a\\052b.example.net.", false)]));
    expect(await awsDns.listZones(ctxOf(fetch), CREDS)).toEqual([{ name: "a*b.example.net", id: "Z5555555EEEEEE" }]);
  });

  it("同名的多个公网 zone 逐个 GetHostedZone 补上 NS；取不到的不带 NS", async () => {
    const ns = (n: number) =>
      xml(
        `<GetHostedZoneResponse xmlns="${XMLNS}">${hostedZone(`Z${n}`, "example.com.", false)}<DelegationSet><NameServers>` +
          `<NameServer>ns-${n}.awsdns-01.com</NameServer><NameServer>NS-${n}.awsdns-02.net.</NameServer></NameServers></DelegationSet></GetHostedZoneResponse>`,
      );
    const fetch = fakeFetch((r) => {
      if (r.url.pathname === "/2013-04-01/hostedzone") {
        return zonesPage([hostedZone("Z1", "example.com.", false), hostedZone("Z2", "example.com.", false), hostedZone("Z3", "example.com.", false), hostedZone("Z9", "other.com.", false)]);
      }
      if (r.url.pathname === "/2013-04-01/hostedzone/Z1") return ns(1);
      if (r.url.pathname === "/2013-04-01/hostedzone/Z2") return ns(2);
      if (r.url.pathname === "/2013-04-01/hostedzone/Z3") return errorReply(403, "AccessDenied", "not authorized to perform: route53:GetHostedZone");
      return undefined;
    });
    expect(await awsDns.listZones(ctxOf(fetch), CREDS)).toEqual([
      { name: "example.com", id: "Z1", nameServers: ["ns-1.awsdns-01.com", "ns-1.awsdns-02.net"] },
      { name: "example.com", id: "Z2", nameServers: ["ns-2.awsdns-01.com", "ns-2.awsdns-02.net"] },
      { name: "example.com", id: "Z3" },
      { name: "other.com", id: "Z9" },
    ]);
    // 不重名的 zone 不额外查询
    expect(fetch.calls.some((c) => c.url.pathname.endsWith("/Z9"))).toBe(false);
  });

  it("IsTruncated 为 true 却没有 NextMarker：报错而不是少返回 zone", async () => {
    const fetch = fakeFetch(() =>
      xml(`<ListHostedZonesResponse xmlns="${XMLNS}"><HostedZones>${hostedZone("Z1", "example.com.", false)}</HostedZones><IsTruncated>true</IsTruncated></ListHostedZonesResponse>`),
    );
    await expect(awsDns.listZones(ctxOf(fetch), CREDS)).rejects.toMatchObject({ code: "InvalidResponse" });
  });
});

describe("AWS Route 53 addTxt", () => {
  it("新建记录集：先按 name/type/maxitems=1 查询，再 CREATE 带引号的值（不用 UPSERT），TTL 60", async () => {
    const fetch = r53([rrsets({ name: "www.example.com.", type: "A", ttl: 300, values: ["192.0.2.1"] })]);
    const handle = await awsDns.addTxt(ctxOf(fetch), CREDS, RECORD);
    expect(handle).toBe(`${ZONE.id}/${FQDN}`);
    expect(fetch.calls).toHaveLength(2);
    const [list, change] = fetch.calls;
    expect(list!.url.search).toBe("?maxitems=1&name=_acme-challenge.example.com.&type=TXT");
    expect(change!.url.pathname).toBe(`${RRSET_PATH}/`);
    expect(change!.headers["content-type"]).toBe("application/xml");
    expect(change!.headers.authorization).toContain("SignedHeaders=content-type;host;x-amz-date,");
    expect(change!.body).toBe(
      `<?xml version="1.0" encoding="UTF-8"?>\n<ChangeResourceRecordSetsRequest xmlns="${XMLNS}"><ChangeBatch><Changes><Change><Action>CREATE</Action>` +
        `<ResourceRecordSet><Name>_acme-challenge.example.com.</Name><Type>TXT</Type><TTL>60</TTL><ResourceRecords><ResourceRecord><Value>"${V1}"</Value></ResourceRecord></ResourceRecords></ResourceRecordSet>` +
        `</Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>`,
    );
  });

  it("zone 里没有排在它之后的记录（返回空列表）也是新建", async () => {
    const fetch = r53([rrsets()]);
    await awsDns.addTxt(ctxOf(fetch), CREDS, RECORD);
    expect(parseChanges(fetch.calls[1]!.body)).toEqual([{ action: "CREATE", name: NAME, type: "TXT", ttl: 60, values: [`"${V1}"`] }]);
  });

  it("追加到已有记录集：同一批次 DELETE 读到的旧记录集 + CREATE 新记录集，其他值原样保留（含引号转义与 XML 实体），沿用原 TTL", async () => {
    const fetch = r53([rrsets({ name: `${FQDN}.`, type: "TXT", ttl: 300, values: [`"${V2}"`, `"say \\"hi\\" &amp; bye"`] })]);
    await awsDns.addTxt(ctxOf(fetch), CREDS, RECORD);
    const change = fetch.calls[1]!;
    expect(parseChanges(change.body)).toEqual([
      { action: "DELETE", name: NAME, type: "TXT", ttl: 300, values: [`"${V2}"`, `"say \\"hi\\" & bye"`] },
      { action: "CREATE", name: NAME, type: "TXT", ttl: 300, values: [`"${V2}"`, `"say \\"hi\\" & bye"`, `"${V1}"`] },
    ]);
    // 写回时重新转义 &（DELETE 与 CREATE 各一次）
    expect(change.body.split(`<Value>"say \\"hi\\" &amp; bye"</Value>`)).toHaveLength(3);
    expect(change.body).not.toContain("UPSERT");
  });

  it("读完之后被别人加了值（并发运行，DELETE 对不上报 InvalidChangeBatch）：重读后带上别人的值再写，不丢值", async () => {
    const V3 = "c".repeat(43);
    const fetch = r53(
      [rrsets({ name: NAME, type: "TXT", ttl: 60, values: [`"${V2}"`] }), rrsets({ name: NAME, type: "TXT", ttl: 60, values: [`"${V2}"`, `"${V3}"`] })],
      [invalidBatch("Tried to delete resource record set [name='_acme-challenge.example.com.', type='TXT'] but the values provided do not match the current values"), CHANGE_OK],
    );
    expect(await awsDns.addTxt(ctxOf(fetch), CREDS, RECORD)).toBe(`${ZONE.id}/${FQDN}`);
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET", "POST", "GET", "POST"]);
    expect(parseChanges(fetch.calls[3]!.body)).toEqual([
      { action: "DELETE", name: NAME, type: "TXT", ttl: 60, values: [`"${V2}"`, `"${V3}"`] },
      { action: "CREATE", name: NAME, type: "TXT", ttl: 60, values: [`"${V2}"`, `"${V3}"`, `"${V1}"`] },
    ]);
  });

  it("新建时记录集已被别人建出来（CREATE 报已存在）：重读后合并再写", async () => {
    const fetch = r53(
      [rrsets(), rrsets({ name: NAME, type: "TXT", ttl: 60, values: [`"${V2}"`] })],
      [invalidBatch("Tried to create resource record set [name='_acme-challenge.example.com.', type='TXT'] but it already exists"), CHANGE_OK],
    );
    await awsDns.addTxt(ctxOf(fetch), CREDS, RECORD);
    expect(parseChanges(fetch.calls[3]!.body)).toEqual([
      { action: "DELETE", name: NAME, type: "TXT", ttl: 60, values: [`"${V2}"`] },
      { action: "CREATE", name: NAME, type: "TXT", ttl: 60, values: [`"${V2}"`, `"${V1}"`] },
    ]);
  });

  it("上一次提交其实已生效（重复提交被拒）：重读到值已在，不再提交", async () => {
    const fetch = r53([rrsets(), rrsets({ name: NAME, type: "TXT", ttl: 60, values: [`"${V1}"`] })], [invalidBatch("Tried to create resource record set but it already exists")]);
    expect(await awsDns.addTxt(ctxOf(fetch), CREDS, RECORD)).toBe(`${ZONE.id}/${FQDN}`);
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET", "POST", "GET"]);
  });

  it("连续冲突只重读重试一次，然后报 InvalidChangeBatch", async () => {
    const fetch = r53([rrsets({ name: NAME, type: "TXT", ttl: 60, values: [`"${V2}"`] })], [invalidBatch("values provided do not match the current values")]);
    await expect(awsDns.addTxt(ctxOf(fetch), CREDS, RECORD)).rejects.toMatchObject({ code: "InvalidChangeBatch", requestId: "rid-batch" });
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET", "POST", "GET", "POST"]);
  });

  it("同名同值已存在：不提交变更，返回句柄", async () => {
    const fetch = r53([rrsets({ name: `${FQDN}.`, type: "TXT", ttl: 60, values: [`"${V2}"`, `"${V1}"`] })]);
    expect(await awsDns.addTxt(ctxOf(fetch), CREDS, RECORD)).toBe(`${ZONE.id}/${FQDN}`);
    expect(fetch.calls.filter(isChange)).toHaveLength(0);
  });

  it("返回的第一条是子名字（*._acme-challenge，八进制转义）：不是同一个记录集，新建", async () => {
    const fetch = r53([rrsets({ name: `\\052.${FQDN}.`, type: "TXT", ttl: 300, values: [`"${V2}"`] })]);
    await awsDns.addTxt(ctxOf(fetch), CREDS, RECORD);
    expect(parseChanges(fetch.calls[1]!.body)).toEqual([{ action: "CREATE", name: NAME, type: "TXT", ttl: 60, values: [`"${V1}"`] }]);
  });

  it("名字八进制转义还原后才比较（\\137 即 _）", async () => {
    const fetch = r53([rrsets({ name: "\\137acme-challenge.example.com.", type: "TXT", ttl: 120, values: [`"${V2}"`] })]);
    await awsDns.addTxt(ctxOf(fetch), CREDS, RECORD);
    expect(parseChanges(fetch.calls[1]!.body)).toEqual([
      { action: "DELETE", name: NAME, type: "TXT", ttl: 120, values: [`"${V2}"`] },
      { action: "CREATE", name: NAME, type: "TXT", ttl: 120, values: [`"${V2}"`, `"${V1}"`] },
    ]);
  });

  it("同名但类型不是 TXT：新建", async () => {
    const fetch = r53([rrsets({ name: `${FQDN}.`, type: "TYPE65534", ttl: 300, values: ["x"] })]);
    await awsDns.addTxt(ctxOf(fetch), CREDS, RECORD);
    expect(parseChanges(fetch.calls[1]!.body)).toEqual([{ action: "CREATE", name: NAME, type: "TXT", ttl: 60, values: [`"${V1}"`] }]);
  });

  it.each([
    ["加权路由（SetIdentifier）", "<SetIdentifier>a</SetIdentifier><Weight>10</Weight>"],
    ["别名记录", "<AliasTarget><HostedZoneId>Z1</HostedZoneId><DNSName>t.example.com.</DNSName><EvaluateTargetHealth>false</EvaluateTargetHealth></AliasTarget>"],
  ])("已有%s的 TXT 记录集：不改动，报 UnsupportedRecordSet", async (_, extra) => {
    const fetch = r53([rrsets({ name: `${FQDN}.`, type: "TXT", ttl: 60, values: [`"${V2}"`], extra })]);
    await expect(awsDns.addTxt(ctxOf(fetch), CREDS, RECORD)).rejects.toMatchObject({ provider: "aws", code: "UnsupportedRecordSet" });
    expect(fetch.calls.filter(isChange)).toHaveLength(0);
  });

  it("已有 CNAME：InvalidChangeBatch 的消息合并，并说明不支持 CNAME 委托", async () => {
    const msg = "RRSet of type TXT with DNS name _acme-challenge.example.com. is not permitted because a conflicting RRSet of type CNAME with the same DNS name already exists in zone example.com.";
    const fetch = r53([rrsets()], [invalidBatch(msg)]);
    const err = (await awsDns.addTxt(ctxOf(fetch), CREDS, RECORD).catch((e) => e)) as CloudApiError;
    expect(err).toBeInstanceOf(CloudApiError);
    expect(err).toMatchObject({ provider: "aws", code: "InvalidChangeBatch", requestId: "rid-batch", httpStatus: 400 });
    expect(err.message).toContain(msg);
    expect(err.message).toContain("CNAME");
    expect(isRetryable(err)).toBe(false);
  });
});

describe("AWS Route 53 removeTxt", () => {
  const HANDLE = `${ZONE.id}/${FQDN}`;

  it("同名下还有别的值：只去掉这一个，同一批次 DELETE 旧记录集 + CREATE 剩余值（原 TTL）", async () => {
    const fetch = r53([rrsets({ name: `${FQDN}.`, type: "TXT", ttl: 60, values: [`"${V2}"`, `"${V1}"`] })]);
    await awsDns.removeTxt(ctxOf(fetch), CREDS, RECORD, HANDLE);
    expect(parseChanges(fetch.calls[1]!.body)).toEqual([
      { action: "DELETE", name: NAME, type: "TXT", ttl: 60, values: [`"${V2}"`, `"${V1}"`] },
      { action: "CREATE", name: NAME, type: "TXT", ttl: 60, values: [`"${V2}"`] },
    ]);
  });

  it("删除途中别人又加了值（DELETE 对不上）：重读后保留别人的值再写", async () => {
    const V3 = "c".repeat(43);
    const fetch = r53(
      [rrsets({ name: NAME, type: "TXT", ttl: 60, values: [`"${V2}"`, `"${V1}"`] }), rrsets({ name: NAME, type: "TXT", ttl: 60, values: [`"${V2}"`, `"${V1}"`, `"${V3}"`] })],
      [invalidBatch("values provided do not match the current values"), CHANGE_OK],
    );
    await awsDns.removeTxt(ctxOf(fetch), CREDS, RECORD, HANDLE);
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET", "POST", "GET", "POST"]);
    expect(parseChanges(fetch.calls[3]!.body)).toEqual([
      { action: "DELETE", name: NAME, type: "TXT", ttl: 60, values: [`"${V2}"`, `"${V1}"`, `"${V3}"`] },
      { action: "CREATE", name: NAME, type: "TXT", ttl: 60, values: [`"${V2}"`, `"${V3}"`] },
    ]);
  });

  it("最后一个值：DELETE，TTL 与值与当前记录集完全一致", async () => {
    const fetch = r53([rrsets({ name: `${FQDN}.`, type: "TXT", ttl: 75, values: [`"${V1}"`] })]);
    await awsDns.removeTxt(ctxOf(fetch), CREDS, RECORD, HANDLE);
    expect(fetch.calls[1]!.body).toBe(
      `<?xml version="1.0" encoding="UTF-8"?>\n<ChangeResourceRecordSetsRequest xmlns="${XMLNS}"><ChangeBatch><Changes><Change><Action>DELETE</Action>` +
        `<ResourceRecordSet><Name>_acme-challenge.example.com.</Name><Type>TXT</Type><TTL>75</TTL><ResourceRecords><ResourceRecord><Value>"${V1}"</Value></ResourceRecord></ResourceRecords></ResourceRecordSet>` +
        `</Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>`,
    );
  });

  it("记录集已不存在 / 已没有这个值：视为成功，不提交变更", async () => {
    for (const list of [rrsets(), rrsets({ name: "www.example.com.", type: "A", ttl: 300, values: ["192.0.2.1"] }), rrsets({ name: `${FQDN}.`, type: "TXT", ttl: 60, values: [`"${V2}"`] })]) {
      const fetch = r53([list]);
      await awsDns.removeTxt(ctxOf(fetch), CREDS, RECORD, HANDLE);
      expect(fetch.calls.filter(isChange)).toHaveLength(0);
    }
  });

  it("DELETE 报 InvalidChangeBatch（记录集刚被改动 / 上次 DELETE 已生效）：重新读取，已不存在就算成功", async () => {
    const fetch = r53([rrsets({ name: `${FQDN}.`, type: "TXT", ttl: 60, values: [`"${V1}"`] }), rrsets()], [invalidBatch("Tried to delete resource record set [name='_acme-challenge.example.com.', type='TXT'] but it was not found")]);
    await awsDns.removeTxt(ctxOf(fetch), CREDS, RECORD, HANDLE);
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET", "POST", "GET"]);
  });

  it("DELETE 重读后值仍在、再次失败：抛出错误", async () => {
    const fetch = r53([rrsets({ name: `${FQDN}.`, type: "TXT", ttl: 60, values: [`"${V1}"`] })], [invalidBatch("values provided do not match the current values")]);
    await expect(awsDns.removeTxt(ctxOf(fetch), CREDS, RECORD, HANDLE)).rejects.toMatchObject({ code: "InvalidChangeBatch" });
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET", "POST", "GET", "POST"]);
  });

  it("zone 已被删除（NoSuchHostedZone）：视为成功", async () => {
    const fetch = r53([errorReply(404, "NoSuchHostedZone", `No hosted zone found with ID: ${ZONE.id}`)]);
    await expect(awsDns.removeTxt(ctxOf(fetch), CREDS, RECORD, HANDLE)).resolves.toBeUndefined();
  });
});

describe("AWS Route 53 错误映射与重试", () => {
  const zonesOk = zonesPage([hostedZone("Z111111QQQQQQQ", "example.com.", false)]);
  /** 依次返回 replies（用完后重复最后一个） */
  const seq = (...replies: FakeReply[]) => {
    let i = 0;
    return fakeFetch(() => replies[Math.min(i++, replies.length - 1)]);
  };

  it("AccessDenied：不重试，message 说明需要的权限", async () => {
    const fetch = seq(errorReply(403, "AccessDenied", "User: arn:aws:iam::123456789012:user/ci is not authorized to perform: route53:ListHostedZones"));
    const err = (await awsDns.listZones(ctxOf(fetch), CREDS).catch((e) => e)) as CloudApiError;
    expect(err).toBeInstanceOf(CloudApiError);
    expect(err).toMatchObject({ provider: "aws", code: "AccessDenied", requestId: "rid-AccessDenied", httpStatus: 403 });
    expect(err.message).toContain("not authorized to perform: route53:ListHostedZones");
    expect(err.message).toContain("route53:ChangeResourceRecordSets");
    expect(err.message).toContain("docs/permissions.md");
    expect(fetch.calls).toHaveLength(1);
  });

  it("Throttling（HTTP 400）自动重试", async () => {
    const fetch = seq(errorReply(400, "Throttling", "Rate exceeded"), zonesOk);
    expect(await awsDns.listZones(ctxOf(fetch), CREDS)).toHaveLength(1);
    expect(fetch.calls).toHaveLength(2);
  });

  it("PriorRequestNotComplete 映射为 Throttling.PriorRequestNotComplete 并重试", async () => {
    const prior = errorReply(400, "PriorRequestNotComplete", "The request was rejected because Route 53 was still processing a prior request.");
    const fetch = r53([rrsets()], [prior, CHANGE_OK]);
    await awsDns.addTxt(ctxOf(fetch), CREDS, RECORD);
    expect(fetch.calls.map((c) => c.method)).toEqual(["GET", "POST", "POST"]);

    const always = r53([rrsets()], [prior]);
    const err = await awsDns.addTxt(ctxOf(always), CREDS, RECORD).catch((e) => e);
    expect(err).toMatchObject({ code: "Throttling.PriorRequestNotComplete", httpStatus: 400 });
    expect(isRetryable(err)).toBe(true);
    expect(always.calls.filter(isChange)).toHaveLength(3);
  });

  it("5xx：InternalFailure 加 ServiceUnavailable. 前缀可重试，ServiceUnavailable 保持原样，非 XML 的网关错误按 HTTP 状态", async () => {
    const internal = seq({ status: 500, body: errorReply(500, "InternalFailure", "internal error")!.body });
    const err = await awsDns.listZones(ctxOf(internal), CREDS).catch((e) => e);
    expect(err).toMatchObject({ code: "ServiceUnavailable.InternalFailure", httpStatus: 500, requestId: "rid-InternalFailure" });
    expect(isRetryable(err)).toBe(true);
    expect(internal.calls).toHaveLength(3);

    const unavailable = seq(errorReply(503, "ServiceUnavailable", "try later"), zonesOk);
    expect(await awsDns.listZones(ctxOf(unavailable), CREDS)).toHaveLength(1);

    const gateway = seq({ status: 502, body: "<html><body>Bad Gateway</body></html>" });
    expect(await awsDns.listZones(ctxOf(gateway), CREDS).catch((e) => e)).toMatchObject({ code: "ServiceUnavailable.HTTP502", httpStatus: 502 });
  });

  it("InvalidClientTokenId：提示中国区密钥不支持", async () => {
    const fetch = seq(errorReply(403, "InvalidClientTokenId", "The security token included in the request is invalid."));
    const err = (await awsDns.listZones(ctxOf(fetch), CREDS).catch((e) => e)) as CloudApiError;
    expect(err.code).toBe("InvalidClientTokenId");
    expect(err.message).toContain("中国区");
  });

  it("HTTP 200 但不是预期的 XML：InvalidResponse，不当成没有 zone", async () => {
    const fetch = seq({ body: "<html>captive portal</html>" });
    await expect(awsDns.listZones(ctxOf(fetch), CREDS)).rejects.toMatchObject({ code: "InvalidResponse" });
  });
});

describe("AWS Route 53 其他", () => {
  it("名字的八进制转义还原", () => {
    expect(unescapeName("\\052.example.com.")).toBe("*.example.com.");
    expect(unescapeName("a\\100b\\134c.example.com")).toBe("a@b\\c.example.com");
    expect(unescapeName("_acme-challenge.example.com.")).toBe("_acme-challenge.example.com.");
  });

  it("权威 NS 主机名规则", () => {
    for (const ns of ["ns-2048.awsdns-64.com", "ns-2049.awsdns-65.net", "ns-2050.awsdns-66.org", "ns-2051.awsdns-67.co.uk"]) expect(awsDns.nameServerPattern.test(ns)).toBe(true);
    for (const ns of ["ns1.example.com", "awsdns-64.com", "ns-1.awsdns-64.com.cn", "ns-1.awsdns-64.co"]) expect(awsDns.nameServerPattern.test(ns)).toBe(false);
  });

  it("凭证：session token 可选；只设置一部分为 incomplete", () => {
    expect(awsDns.readCredentials({})).toEqual({ state: "missing" });
    expect(awsDns.readCredentials({ AWS_ACCESS_KEY_ID: "AKIDEXAMPLE" })).toEqual({ state: "incomplete", missing: ["AWS_SECRET_ACCESS_KEY"] });
    expect(awsDns.readCredentials({ AWS_ACCESS_KEY_ID: "AKIDEXAMPLE", AWS_SECRET_ACCESS_KEY: "s" })).toEqual({
      state: "ok",
      credentials: { accessKeyId: "AKIDEXAMPLE", secretAccessKey: "s" },
    });
    expect(awsDns.readCredentials({ AWS_ACCESS_KEY_ID: "AKIDEXAMPLE", AWS_SECRET_ACCESS_KEY: "s", AWS_SESSION_TOKEN: "t" })).toEqual({
      state: "ok",
      credentials: { accessKeyId: "AKIDEXAMPLE", secretAccessKey: "s", sessionToken: "t" },
    });
  });
});
