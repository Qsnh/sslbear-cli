import { varsEnv } from "./env.js";
import { defineDns } from "./types.js";

export interface AzureCredentials { tenantId: string; clientId: string; clientSecret: string; subscriptionId: string }

// 占位：待实现
export const azureDns = defineDns<AzureCredentials>({
  vendor: "azure",
  label: "Azure DNS",
  ...varsEnv<AzureCredentials>([
    { name: "AZURE_TENANT_ID", required: true, secret: false },
    { name: "AZURE_CLIENT_ID", required: true, secret: false },
    { name: "AZURE_CLIENT_SECRET", required: true, secret: true },
    { name: "AZURE_SUBSCRIPTION_ID", required: true, secret: false },
  ], (v) => ({
    tenantId: v.AZURE_TENANT_ID!,
    clientId: v.AZURE_CLIENT_ID!,
    clientSecret: v.AZURE_CLIENT_SECRET!,
    subscriptionId: v.AZURE_SUBSCRIPTION_ID!,
  })),
  nameServerPattern: /(^|\.)azure-dns\.(com|net|org|info)$/,
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
