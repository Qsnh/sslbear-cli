import { ENV_FAMILIES, readAccessKey, type AccessKeyCredentials } from "../../lib/env.js";
import { defineProvider } from "../registry.js";
import { cdn } from "./cdn.js";
import { live } from "./live.js";
import { obs } from "./obs.js";
import { listScmCertificates, uploadScmCertificate } from "./scm.js";

// 各产品「未开通服务」的错误码：CDN.0114 计费模式未配置（CDN 服务未开通）、OBS NotSignedUp 未注册 OBS、
// SCM.0001 服务未开放；直播未开通时报哪个文档没写，按「请求用户不存在」LIVE.100011009 处理
const INACTIVE_CODES = new Set(["CDN.0114", "NotSignedUp", "SCM.0001", "LIVE.100011009"]);

export const huawei = defineProvider<AccessKeyCredentials>({
  provider: "huawei",
  envFamilies: ENV_FAMILIES.huawei,
  readCredentials: readAccessKey(ENV_FAMILIES.huawei),
  services: [cdn, live, obs],
  listCertificates: listScmCertificates,
  uploadCertificate: uploadScmCertificate,
  isInactive: (code) => INACTIVE_CODES.has(code),
});
