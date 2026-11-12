// Plain host: Bun on the Mac or on EC2. Secrets come from process.env (Bun loads .env).
// This is the only place that reads Airwallex settings from the environment.

import type { AdapterError, Mode, Result } from "../types";
import { AirwallexClient, type Exchange } from "../airwallex/client";
import { RestAdapter } from "../airwallex/rest-adapter";

export interface PlainHostOptions {
  env?: Record<string, string | undefined>;
  log?: (line: string) => void;
  onExchange?: (x: Exchange) => void;
  createdBy?: string;
}

export function readMode(raw: string | undefined): Mode | undefined {
  if (raw === undefined || raw === "") return "frozen";
  return raw === "ra" || raw === "frozen" ? raw : undefined;
}

export function buildPlainAdapter(o: PlainHostOptions = {}): Result<RestAdapter, AdapterError> {
  const env = o.env ?? process.env;
  const mode = readMode(env.WRIT_MODE);
  if (!mode) return { ok: false, error: { kind: "config", message: "WRIT_MODE must be ra or frozen" } };
  const client = new AirwallexClient({
    baseUrl: env.AIRWALLEX_BASE_URL ?? "",
    clientId: env.AIRWALLEX_CLIENT_ID ?? "",
    apiKey: env.AIRWALLEX_API_KEY ?? "",
    ...(o.log ? { log: o.log } : {}),
    ...(o.onExchange ? { onExchange: o.onExchange } : {}),
  });
  if (client.configProblem) return { ok: false, error: client.configProblem };
  return { ok: true, value: new RestAdapter({ client, mode, ...(o.createdBy ? { createdBy: o.createdBy } : {}) }) };
}
