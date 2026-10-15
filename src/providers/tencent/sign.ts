import { createHash, createHmac } from "node:crypto";

const sha256Hex = (s: string) => createHash("sha256").update(s).digest("hex");
const hmac = (key: string | Buffer, s: string) => createHmac("sha256", key).update(s).digest();

export interface Tc3Input {
  secretId: string;
  secretKey: string;
  service: string;
  host: string;
  payload: string;
  /** Unix 秒 */
  timestamp: number;
  contentType?: string;
}

/** 腾讯云 API 3.0 签名 v3（TC3-HMAC-SHA256），POST + JSON，签名头为 content-type;host */
export function tc3Authorization(input: Tc3Input): string {
  const contentType = input.contentType ?? "application/json; charset=utf-8";
  const signedHeaders = "content-type;host";
  const canonicalRequest = [
    "POST",
    "/",
    "",
    `content-type:${contentType}\nhost:${input.host}\n`,
    signedHeaders,
    sha256Hex(input.payload),
  ].join("\n");
  const date = new Date(input.timestamp * 1000).toISOString().slice(0, 10);
  const scope = `${date}/${input.service}/tc3_request`;
  const stringToSign = ["TC3-HMAC-SHA256", String(input.timestamp), scope, sha256Hex(canonicalRequest)].join("\n");
  const kDate = hmac(`TC3${input.secretKey}`, date);
  const kService = hmac(kDate, input.service);
  const kSigning = hmac(kService, "tc3_request");
  const signature = createHmac("sha256", kSigning).update(stringToSign).digest("hex");
  return `TC3-HMAC-SHA256 Credential=${input.secretId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}
