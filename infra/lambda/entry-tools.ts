// Lambda entry for one Gateway tool. WRIT_TOOL pins which tool this function serves, so a target
// wired to the wrong function refuses instead of running some other tool.

import { randomUUID } from "node:crypto";
import type { Context } from "aws-lambda";
import { bareToolName } from "./identity";
import { runTool } from "./tools";

const env = process.env;
const writUrl = (env.WRIT_URL ?? "").replace(/\/+$/, "");
if (!writUrl.startsWith("https://")) throw new Error("WRIT_URL must be https");

export async function handler(event: unknown, context: Context) {
  const custom = (context.clientContext as { Custom?: Record<string, unknown>; custom?: Record<string, unknown> } | undefined) ?? {};
  const fields = custom.custom ?? custom.Custom ?? {};
  const tool = bareToolName(fields.bedrockAgentCoreToolName);
  if (tool !== env.WRIT_TOOL) return { ok: false, error: `this function serves ${env.WRIT_TOOL}, not ${tool || "an unnamed tool"}` };
  return runTool(tool, event, {
    writUrl,
    fetch: (url, init) => fetch(url, init),
    now: () => new Date(),
    uuid: randomUUID,
  });
}
