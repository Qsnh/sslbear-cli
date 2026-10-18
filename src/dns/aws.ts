import { varsEnv } from "./env.js";
import { defineDns } from "./types.js";

export interface AwsCredentials { accessKeyId: string; secretAccessKey: string; sessionToken?: string }

// 占位：待实现
export const awsDns = defineDns<AwsCredentials>({
  vendor: "aws",
  label: "AWS Route 53",
  ...varsEnv<AwsCredentials>([
    { name: "AWS_ACCESS_KEY_ID", required: true, secret: false },
    { name: "AWS_SECRET_ACCESS_KEY", required: true, secret: true },
    { name: "AWS_SESSION_TOKEN", required: false, secret: true },
  ], (v) => ({
    accessKeyId: v.AWS_ACCESS_KEY_ID!,
    secretAccessKey: v.AWS_SECRET_ACCESS_KEY!,
    ...(v.AWS_SESSION_TOKEN && { sessionToken: v.AWS_SESSION_TOKEN }),
  })),
  nameServerPattern: /(^|\.)awsdns-\d+\.(com|net|org|co\.uk)$/,
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
