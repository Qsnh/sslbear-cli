import { varsEnv } from "./env.js";
import { defineDns } from "./types.js";

export interface GoogleCredentials { keyFile: string; project?: string }

// 占位：待实现
export const googleDns = defineDns<GoogleCredentials>({
  vendor: "google",
  label: "Google Cloud DNS",
  ...varsEnv<GoogleCredentials>([
    { name: "GOOGLE_APPLICATION_CREDENTIALS", required: true, secret: false },
    { name: "GOOGLE_CLOUD_PROJECT", required: false, secret: false },
  ], (v) => ({ keyFile: v.GOOGLE_APPLICATION_CREDENTIALS!, ...(v.GOOGLE_CLOUD_PROJECT && { project: v.GOOGLE_CLOUD_PROJECT }) })),
  nameServerPattern: /^ns-cloud-[a-z]\d+\.googledomains\.com$/,
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
