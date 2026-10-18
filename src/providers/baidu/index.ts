import { ENV_FAMILIES, readAccessKey, type AccessKeyCredentials } from "../../lib/env.js";
import { defineProvider } from "../registry.js";
import { cdn } from "./cdn.js";
import { listBaiduCertificates, uploadBaiduCertificate } from "./cert.js";

/**
 * 「未开通服务」：OptInRequired 是百度智能云公共错误码（403，没有开通对应的服务，如 BOS 未开通）；
 * CDN 未开通时写接口返回 HTTP 500 + CDNNotActivated（实测；只读的域名列表接口照常返回空列表）；
 * AccessDenied 只在文案明确提到未开通时才算
 */
const NOT_OPENED = /未开通|没有开通|not (been )?(opened|activated|subscribed)|subscription .*required/i;

export const baidu = defineProvider<AccessKeyCredentials>({
  provider: "baidu",
  envFamilies: ENV_FAMILIES.baidu,
  readCredentials: readAccessKey(ENV_FAMILIES.baidu),
  services: [cdn],
  listCertificates: listBaiduCertificates,
  uploadCertificate: uploadBaiduCertificate,
  isInactive: (code, message) => code === "OptInRequired" || code === "CDNNotActivated" || (code === "AccessDenied" && NOT_OPENED.test(message)),
});
