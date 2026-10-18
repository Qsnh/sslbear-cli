import { varsEnv } from "./env.js";
import { defineDns } from "./types.js";

export interface GoDaddyCredentials { apiKey: string; apiSecret: string }

// 占位：待实现
export const godaddyDns = defineDns<GoDaddyCredentials>({
  vendor: "godaddy",
  label: "GoDaddy",
  ...varsEnv<GoDaddyCredentials>([
    { name: "GODADDY_API_KEY", required: true, secret: false },
    { name: "GODADDY_API_SECRET", required: true, secret: true },
  ], (v) => ({ apiKey: v.GODADDY_API_KEY!, apiSecret: v.GODADDY_API_SECRET! })),
  nameServerPattern: /\.domaincontrol\.com$/,
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
