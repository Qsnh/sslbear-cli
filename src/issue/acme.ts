import type { KeyObject } from "node:crypto";
import type { QueryContext } from "../lib/http.js";
import type { AcmeClient } from "./types.js";

// 占位：待实现
export async function createAcmeClient(_ctx: QueryContext, _opts: { directoryUrl: string; accountKey: KeyObject }): Promise<AcmeClient> {
  throw new Error("未实现");
}
