import { ENV_KEYS, readAliyun, type AliyunCredentials } from "../../lib/env.js";
import { defineProvider } from "../registry.js";
import { listCasCertificates } from "./cas.js";
import { cdn, dcdn, live } from "./cdn.js";
import { oss } from "./oss.js";
import { vod } from "./vod.js";

const k = ENV_KEYS.aliyun;

// 各产品「未开通服务」的错误码；VOD / 直播未开通时也可能报通用的 OperationDenied，需结合文案判断
const INACTIVE_CODES = new Set(["CdnServiceNotFound", "DcdnServiceNotFound", "LiveServiceNotFound", "VodServiceNotFound"]);

export const aliyun = defineProvider<AliyunCredentials>({
  provider: "aliyun",
  envKeys: [
    { names: k.accessKeyId, required: true, secret: false },
    { names: k.accessKeySecret, required: true, secret: true },
    { names: k.securityToken, required: false, secret: true },
  ],
  readCredentials: readAliyun,
  services: [cdn, dcdn, oss, live, vod],
  listCertificates: listCasCertificates,
  isInactive: (code, message) =>
    INACTIVE_CODES.has(code) ||
    (code === "UserNotFound" && /not opened/i.test(message)) ||
    (code === "OperationDenied" && /not (open|enabled)/i.test(message)),
});
