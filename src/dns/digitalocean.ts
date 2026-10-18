import { varsEnv } from "./env.js";
import { defineDns } from "./types.js";

export interface DigitalOceanCredentials { token: string }

// 占位：待实现
export const digitaloceanDns = defineDns<DigitalOceanCredentials>({
  vendor: "digitalocean",
  label: "DigitalOcean",
  ...varsEnv<DigitalOceanCredentials>([{ name: "DIGITALOCEAN_TOKEN", aliases: ["DIGITALOCEAN_ACCESS_TOKEN"], required: true, secret: true }], (v) => ({ token: v.DIGITALOCEAN_TOKEN! })),
  nameServerPattern: /^ns[1-3]\.digitalocean\.com$/,
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
