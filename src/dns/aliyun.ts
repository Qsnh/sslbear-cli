import { ENV_FAMILIES, readAliyun, type AliyunCredentials } from "../lib/env.js";
import { familyEnv } from "./env.js";
import { defineDns } from "./types.js";

// 占位：待实现
export const aliyunDns = defineDns<AliyunCredentials>({
  vendor: "aliyun",
  label: "阿里云云解析",
  ...familyEnv(ENV_FAMILIES.aliyun, readAliyun),
  nameServerPattern: /(^|\.)(hichina|alidns)\.com$/,
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
