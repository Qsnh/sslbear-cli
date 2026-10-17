import { ENV_FAMILIES, readAccessKey, type AccessKeyCredentials } from "../../lib/env.js";
import { defineProvider } from "../registry.js";
import { cdn } from "./cdn.js";
import { listBaiduCertificates } from "./cert.js";

/**
 * 「未开通服务」：OptInRequired 是百度智能云公共错误码（403，没有开通对应的服务）；
 * CDN 文档没有单列未开通的错误码，AccessDenied 只在文案明确提到未开通时才算
 */
const NOT_OPENED = /未开通|没有开通|not (been )?(opened|activated|subscribed)|subscription .*required/i;

export const baidu = defineProvider<AccessKeyCredentials>({
  provider: "baidu",
  envFamilies: ENV_FAMILIES.baidu,
  readCredentials: readAccessKey(ENV_FAMILIES.baidu),
  services: [cdn],
  listCertificates: listBaiduCertificates,
  isInactive: (code, message) => code === "OptInRequired" || (code === "AccessDenied" && NOT_OPENED.test(message)),
});
