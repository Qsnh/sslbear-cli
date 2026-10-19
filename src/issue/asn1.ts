/**
 * 最小 DER（X.690）编码 / 解析：只覆盖构造 PKCS#10 CSR 和从证书里取 AKI、序列号要用到的类型。
 * 标签号都小于 31（单字节标签），不支持多字节标签与不定长格式（DER 本来就不允许不定长）。
 */

/** TLV：tag 为标签字节，content 为内容字节，raw 为含标签与长度的完整编码 */
export interface Tlv {
  tag: number;
  content: Buffer;
  raw: Buffer;
}

function encodeLength(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  // 长格式：首字节 0x80 | 后续字节数，之后为大端长度
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

export function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
}

export const sequence = (...items: Buffer[]): Buffer => tlv(0x30, Buffer.concat(items));
/** SET OF 在 DER 里要求元素按编码排序；这里的调用方都只放一个元素，不做排序 */
export const set = (...items: Buffer[]): Buffer => tlv(0x31, Buffer.concat(items));
export const nullValue = (): Buffer => Buffer.from([0x05, 0x00]);
export const octetString = (b: Buffer): Buffer => tlv(0x04, b);
/** 首字节为未用位数，签名、公钥都按整字节，固定为 0 */
export const bitString = (b: Buffer): Buffer => tlv(0x03, Buffer.concat([Buffer.from([0]), b]));
export const utf8String = (s: string): Buffer => tlv(0x0c, Buffer.from(s, "utf8"));
export const ia5String = (s: string): Buffer => tlv(0x16, Buffer.from(s, "ascii"));

/** 非负整数；DER 要求最短编码，最高位为 1 时补 0x00 以免被读成负数 */
export function integer(n: number): Buffer {
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  if (bytes.length === 0 || bytes[0]! & 0x80) bytes.unshift(0);
  return tlv(0x02, Buffer.from(bytes));
}

/** 点分 OID：前两段合成一个字节（40 * a + b），其余每段按 7 位一组、除末组外最高位置 1 */
export function oid(dotted: string): Buffer {
  const [a, b, ...rest] = dotted.split(".").map(Number);
  const bytes: number[] = [40 * a! + b!];
  for (const arc of rest) {
    const groups: number[] = [arc & 0x7f];
    for (let v = Math.floor(arc / 128); v > 0; v = Math.floor(v / 128)) groups.unshift((v & 0x7f) | 0x80);
    bytes.push(...groups);
  }
  return tlv(0x06, Buffer.from(bytes));
}

/** context-specific [n]：constructed 为 true 时是构造类型（0xA0 | n），否则为原始类型（0x80 | n，如 SAN 的 dNSName） */
export function contextTag(n: number, content: Buffer, constructed = true): Buffer {
  return tlv((constructed ? 0xa0 : 0x80) | n, content);
}

/** 读 offset 处的一个 TLV；越界或不是 DER 时抛错（调用方据此判定证书格式不对） */
export function readTlv(buf: Buffer, offset = 0): Tlv {
  const tag = buf[offset];
  let len = buf[offset + 1];
  if (tag === undefined || len === undefined || (tag & 0x1f) === 0x1f) throw new Error("ASN.1 格式错误");
  let start = offset + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    // 0x80 是不定长格式，DER 不允许；超过 4 字节的长度在证书里不会出现
    if (n === 0 || n > 4 || start + n > buf.length) throw new Error("ASN.1 格式错误");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[start + i]!;
    start += n;
  }
  const end = start + len;
  if (end > buf.length) throw new Error("ASN.1 格式错误");
  return { tag, content: buf.subarray(start, end), raw: buf.subarray(offset, end) };
}

/** 构造类型（SEQUENCE、SET、[n]）的直接子元素 */
export function children(parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  for (let offset = 0; offset < parent.content.length; ) {
    const t = readTlv(parent.content, offset);
    out.push(t);
    offset += t.raw.length;
  }
  return out;
}
