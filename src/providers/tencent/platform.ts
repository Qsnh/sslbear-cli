import { compact } from "../../lib/compact.js";
import type { DomainRecord } from "../../types.js";

/**
 * 腾讯云自有的域名后缀。各产品默认分配给用户的域名都在这些后缀下：点播 `{appid}.vod2.myqcloud.com`、
 * `{subappid}.vod-qcloud.com`，直播默认推流域名 `{bizid}.livepush.myqcloud.com`、`*.push.tlivecloud.com`，
 * CDN 里的 `*.video.myqcloud.com`、`*.file.myqcloud.com` 等。它们由腾讯云用自己的通配符证书提供 HTTPS，
 * 用户既不能绑定、也无需续期证书。
 *
 * 接口里没有区分「平台默认域名」的字段（CDN 只是 Cname 为空，直播只是 TargetDomain 等于域名本身，
 * 点播的 Type 都是 VOD），所以按后缀识别。这些后缀只有腾讯云自己能用，不会误判用户的自有域名。
 */
const PLATFORM_SUFFIXES = ["myqcloud.com", "vod-qcloud.com", "tlivecloud.com", "tencentcos.cn"];

export function isPlatformDomain(domain: string): boolean {
  const d = domain.toLowerCase().replace(/\.$/, "");
  return PLATFORM_SUFFIXES.some((s) => d === s || d.endsWith(`.${s}`));
}

/**
 * 平台默认域名统一处理：照常列出，extra.managed 标记为 "platform"；不带证书，因而没有 daysLeft、
 * 不计入到期统计；https 由调用方按平台实际情况给出。
 */
export function asPlatformDomain(r: DomainRecord, https: boolean): DomainRecord {
  return compact({ ...r, https, cert: undefined, extra: { ...r.extra, managed: "platform" } });
}
