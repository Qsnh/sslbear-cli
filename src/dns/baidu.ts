import { ENV_FAMILIES, readAccessKey, type AccessKeyCredentials } from "../lib/env.js";
import { familyEnv } from "./env.js";
import { defineDns } from "./types.js";

// 占位：待实现
export const baiduDns = defineDns<AccessKeyCredentials>({
  vendor: "baidu",
  label: "百度智能云 DNS",
  ...familyEnv(ENV_FAMILIES.baidu, readAccessKey(ENV_FAMILIES.baidu)),
  nameServerPattern: /$^/,
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
