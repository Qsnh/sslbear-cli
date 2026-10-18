import { ENV_FAMILIES, readAccessKey, type AccessKeyCredentials } from "../lib/env.js";
import { familyEnv } from "./env.js";
import { defineDns } from "./types.js";

// 占位：待实现
export const volcengineDns = defineDns<AccessKeyCredentials>({
  vendor: "volcengine",
  label: "火山引擎云解析",
  ...familyEnv(ENV_FAMILIES.volcengine, readAccessKey(ENV_FAMILIES.volcengine)),
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
