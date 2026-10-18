import { ENV_FAMILIES, readAliyun, type AliyunCredentials } from "../../lib/env.js";
import { defineProvider } from "../registry.js";
import { listCasCertificates, uploadCasCertificate } from "./cas.js";
import { cdn, dcdn, live } from "./cdn.js";
import { esa } from "./esa.js";
import { oss } from "./oss.js";
import { vod } from "./vod.js";

// 各产品「未开通服务」的错误码；VOD / 直播未开通时也可能报通用的 OperationDenied，需结合文案判断
const INACTIVE_CODES = new Set([
  "CdnServiceNotFound",
  "DcdnServiceNotFound",
  "LiveServiceNotFound",
  "VodServiceNotFound",
  "EsaService.NotOpen",
]);

export const aliyun = defineProvider<AliyunCredentials>({
  provider: "aliyun",
  envFamilies: ENV_FAMILIES.aliyun,
  readCredentials: readAliyun,
  services: [cdn, dcdn, esa, oss, live, vod],
  listCertificates: listCasCertificates,
  uploadCertificate: uploadCasCertificate,
  isInactive: (code, message) =>
    INACTIVE_CODES.has(code) ||
    (code === "UserNotFound" && /not opened/i.test(message)) ||
    (code === "OperationDenied" && /not (open|enabled)/i.test(message)),
});
