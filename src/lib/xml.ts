/**
 * OSS 接口的 XML 结构扁平且固定，用正则按标签取值即可，不必引入完整的 XML 解析器。
 * 仅适用于不含同名嵌套标签、不含 CDATA 的响应。
 */
export function xmlBlocks(xml: string, tag: string): string[] {
  const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`, "g");
  return Array.from(xml.matchAll(re), (m) => m[1] as string);
}

export function xmlText(xml: string, tag: string): string | undefined {
  const block = xmlBlocks(xml, tag)[0];
  return block === undefined ? undefined : decodeEntities(block.trim());
}

function decodeEntities(s: string): string {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, n: string) => String.fromCodePoint(Number(n)))
    .replace(/&amp;/g, "&");
}
