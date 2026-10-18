import type { DnsVendor } from "../types.js";
import { aliyunDns } from "./aliyun.js";
import { awsDns } from "./aws.js";
import { azureDns } from "./azure.js";
import { baiduDns } from "./baidu.js";
import { cloudflareDns } from "./cloudflare.js";
import { digitaloceanDns } from "./digitalocean.js";
import { godaddyDns } from "./godaddy.js";
import { googleDns } from "./google.js";
import { huaweiDns } from "./huawei.js";
import { tencentDns } from "./tencent.js";
import type { DnsProviderDef } from "./types.js";
import { volcengineDns } from "./volcengine.js";

// 各服务商凭证类型不同，注册表里统一擦除；调用时凭证与 vendor 一一对应
export type DnsDefs = Record<DnsVendor, DnsProviderDef<any>>; // eslint-disable-line @typescript-eslint/no-explicit-any

export const DNS_DEFS: DnsDefs = {
  aliyun: aliyunDns,
  tencent: tencentDns,
  volcengine: volcengineDns,
  huawei: huaweiDns,
  baidu: baiduDns,
  cloudflare: cloudflareDns,
  aws: awsDns,
  google: googleDns,
  azure: azureDns,
  digitalocean: digitaloceanDns,
  godaddy: godaddyDns,
};
