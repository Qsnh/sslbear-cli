import { varsEnv } from "./env.js";
import { defineDns } from "./types.js";

export interface CloudflareCredentials { apiToken: string }

// 占位：待实现
export const cloudflareDns = defineDns<CloudflareCredentials>({
  vendor: "cloudflare",
  label: "Cloudflare",
  ...varsEnv<CloudflareCredentials>([{ name: "CLOUDFLARE_API_TOKEN", required: true, secret: true }], (v) => ({ apiToken: v.CLOUDFLARE_API_TOKEN! })),
  nameServerPattern: /\.ns\.cloudflare\.com$/,
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
