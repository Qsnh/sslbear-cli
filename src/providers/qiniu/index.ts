import { ENV_FAMILIES, readAccessKey, type AccessKeyCredentials } from "../../lib/env.js";
import { defineProvider } from "../registry.js";
import { cdn } from "./cdn.js";
import { listSslCertificates } from "./ssl.js";

export const qiniu = defineProvider<AccessKeyCredentials>({
  provider: "qiniu",
  envFamilies: ENV_FAMILIES.qiniu,
  readCredentials: readAccessKey(ENV_FAMILIES.qiniu),
  services: [cdn],
  listCertificates: listSslCertificates,
  // 七牛 CDN 无需单独开通（没有对应错误码），账号下没有域名时列表为空
  isInactive: () => false,
});
