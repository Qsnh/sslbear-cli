import { ENV_KEYS, readTencent, type TencentCredentials } from "../../lib/env.js";
import { defineProvider } from "../registry.js";
import { cdn } from "./cdn.js";
import { live } from "./live.js";
import { listSslCertificates } from "./ssl.js";
import { teo } from "./teo.js";
import { vod } from "./vod.js";

const k = ENV_KEYS.tencent;

// 各产品「未开通服务」的错误码；直播未开通时报哪个未有定论，两个都算
const INACTIVE_CODES = new Set([
  "ResourceNotFound.CdnUserNotExists",
  "ResourceNotFound.InvalidUser",
  "ResourceNotFound.UserNotExist",
  "FailedOperation.InvalidVodUser",
  "ResourceNotFound.ServiceNotExist",
]);

export const tencent = defineProvider<TencentCredentials>({
  provider: "tencent",
  envKeys: [
    { names: k.secretId, required: true, secret: false },
    { names: k.secretKey, required: true, secret: true },
    { names: k.sessionToken, required: false, secret: true },
  ],
  readCredentials: readTencent,
  services: [cdn, teo, live, vod],
  listCertificates: listSslCertificates,
  isInactive: (code) => INACTIVE_CODES.has(code),
});
