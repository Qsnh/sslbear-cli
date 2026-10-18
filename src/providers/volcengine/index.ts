import { ENV_FAMILIES, readAccessKey, type AccessKeyCredentials } from "../../lib/env.js";
import { defineProvider } from "../registry.js";
import { cdn } from "./cdn.js";
import { listCertCenter, uploadToCertCenter } from "./certs.js";
import { dcdn } from "./dcdn.js";
import { imagex } from "./imagex.js";
import { live } from "./live.js";
import { tos } from "./tos.js";
import { vod } from "./vod.js";

// 各产品「未开通服务」的错误码：点播 OperationDenied（功能或服务未开通）、直播 RequestForbidden.BillingStatus（未开通或欠费）、
// veImageX 601001 / 600013（Code 可能为空串，客户端已换成 CodeN）；TOS 只知道 EC 0003-00000003，由 tos.ts 拼在 message 里
const INACTIVE_CODES = new Set([
  "OperationDenied",
  "RequestForbidden.BillingStatus",
  "601001",
  "600013",
  "ERR_SUBSCRIPTION_NOTFOUND",
  "ERR_INSTANCE_NOT_FOUND",
]);

export const volcengine = defineProvider<AccessKeyCredentials>({
  provider: "volcengine",
  envFamilies: ENV_FAMILIES.volcengine,
  readCredentials: readAccessKey(ENV_FAMILIES.volcengine),
  services: [cdn, dcdn, tos, vod, live, imagex],
  listCertificates: listCertCenter,
  // 上传到证书中心；视频直播只能用自己的证书管理，由 live 的 deployer 自行上传
  uploadCertificate: uploadToCertCenter,
  // CDN / DCDN 未开通的错误码文档未给出，按文案兜底
  isInactive: (code, message) =>
    INACTIVE_CODES.has(code) || /EC 0003-00000003|未开通|subscription not found|not (been )?(opened|activated)/i.test(message),
});
