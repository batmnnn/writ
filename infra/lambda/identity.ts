// Who is calling. The Gateway has already verified the JWT signature, issuer and client id before any
// interceptor runs, so here we only read claims. Team and agent come from this map, never from tool input.

export interface AgentIdentity {
  team: string;
  agent: string;
}

export interface CallerIdentity extends AgentIdentity {
  runId: string;
}

/** The argument the REQUEST interceptor writes into every tools/call. Model input under this name is dropped. */
export const IDENTITY_ARG = "_identity";

/** "clientId:team:agent;clientId:team:agent". */
export function parseAgentClients(raw: string | undefined): Map<string, AgentIdentity> {
  const out = new Map<string, AgentIdentity>();
  for (const entry of (raw ?? "").split(";")) {
    const parts = entry.trim().split(":");
    if (parts.length !== 3) continue;
    const [clientId, team, agent] = parts.map((p) => p.trim());
    if (clientId && team && agent) out.set(clientId, { team, agent });
  }
  return out;
}

export function jwtClaims(authorization: string | undefined): Record<string, unknown> | undefined {
  if (!authorization?.startsWith("Bearer ")) return undefined;
  const payload = authorization.slice(7).split(".")[1];
  if (!payload) return undefined;
  try {
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as unknown;
    return claims && typeof claims === "object" ? (claims as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

export function header(headers: Record<string, unknown> | undefined, name: string): string | undefined {
  if (!headers) return undefined;
  const want = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === want && typeof v === "string") return v;
  }
  return undefined;
}

const RUN_ID = /^[A-Za-z0-9._:-]{1,128}$/;

/**
 * Cognito client credentials tokens carry client_id. The run is, in order: X-Writ-Run-Id (the agent code
 * sends its AgentCore Runtime session id, so two invocations in one session are one run), the MCP session
 * id, then the token's jti. The model cannot set any of these; the agent's own code can. Unknown client
 * or no usable run id: undefined.
 */
export function resolveCaller(headers: Record<string, unknown> | undefined, clients: Map<string, AgentIdentity>): CallerIdentity | undefined {
  const claims = jwtClaims(header(headers, "authorization"));
  const clientId = claims?.client_id;
  if (typeof clientId !== "string") return undefined;
  const who = clients.get(clientId);
  if (!who) return undefined;
  const runId = header(headers, "x-writ-run-id") ?? header(headers, "mcp-session-id") ?? (typeof claims?.jti === "string" ? claims.jti : undefined);
  if (!runId || !RUN_ID.test(runId)) return undefined;
  return { team: who.team, agent: who.agent, runId };
}

export function isCallerIdentity(v: unknown): v is CallerIdentity {
  if (!v || typeof v !== "object") return false;
  const c = v as Record<string, unknown>;
  return [c.team, c.agent, c.runId].every((s) => typeof s === "string" && s !== "");
}

/** Gateway tool names are "<target>___<tool>". */
export const bareToolName = (name: unknown): string => {
  if (typeof name !== "string") return "";
  const i = name.lastIndexOf("___");
  return i >= 0 ? name.slice(i + 3) : name;
};
