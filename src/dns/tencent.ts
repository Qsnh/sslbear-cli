import { ENV_FAMILIES, readTencent, type TencentCredentials } from "../lib/env.js";
import { familyEnv } from "./env.js";
import { defineDns } from "./types.js";

// 占位：待实现
export const tencentDns = defineDns<TencentCredentials>({
  vendor: "tencent",
  label: "腾讯云 DNSPod",
  ...familyEnv(ENV_FAMILIES.tencent, readTencent),
  nameServerPattern: /(^|\.)dnspod\.(net|com)$/,
  listZones: async () => {
    throw new Error("未实现");
  },
  addTxt: async () => {
    throw new Error("未实现");
  },
  removeTxt: async () => {
    throw new Error("未实现");
  },
});
