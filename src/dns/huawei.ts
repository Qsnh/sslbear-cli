import { ENV_FAMILIES, readAccessKey, type AccessKeyCredentials } from "../lib/env.js";
import { familyEnv } from "./env.js";
import { defineDns } from "./types.js";

// 占位：待实现
export const huaweiDns = defineDns<AccessKeyCredentials>({
  vendor: "huawei",
  label: "华为云云解析",
  ...familyEnv(ENV_FAMILIES.huawei, readAccessKey(ENV_FAMILIES.huawei)),
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
