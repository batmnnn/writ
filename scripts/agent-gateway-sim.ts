// Runs one MCP tools/call the way AgentCore Gateway does: REQUEST interceptor, Lambda target,
// RESPONSE interceptor. For tests and `agent-scene.ts --local` only. It does not verify the JWT;
// the real Gateway does that before any interceptor runs.

import { runTool, type ToolDeps } from "../infra/lambda/tools";

type Json = Record<string, unknown>;
type Interceptor = (event: unknown) => Promise<{ mcp: Json }>;

export const TARGETS = { read_page: "read", propose_writ: "propose", get_decision: "decision" } as const;

/** An unsigned token with a client_id claim. Shape only, the simulator does not check it. */
export function fakeToken(clientId: string, jti: string = crypto.randomUUID()): string {
  const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
  return `${b64({ alg: "none" })}.${b64({ client_id: clientId, token_use: "access", jti })}.sig`;
}

export interface SimCall {
  tool: keyof typeof TARGETS;
  args: Json;
  sentAt: string;
  returnedAt: string;
  text: string;
  isError: boolean;
  argsSeenByLambda?: Json;
}

export function createGatewaySim(opts: { interceptor: Interceptor; toolDeps: ToolDeps; token: string; sessionId: string }) {
  let id = 0;
  return async function callTool(tool: keyof typeof TARGETS, args: Json): Promise<SimCall> {
    id += 1;
    const sentAt = new Date().toISOString();
    const headers = { Authorization: `Bearer ${opts.token}`, "Mcp-Session-Id": opts.sessionId };
    const body = { jsonrpc: "2.0", id, method: "tools/call", params: { name: `${TARGETS[tool]}___${tool}`, arguments: args } };

    const pre = await opts.interceptor({ interceptorInputVersion: "1.0", mcp: { gatewayRequest: { path: "/mcp", httpMethod: "POST", headers, body } } });
    const short = pre.mcp.transformedGatewayResponse as { body?: Json } | undefined;
    let responseBody: Json;
    let forwarded = body as Json;
    let argsSeenByLambda: Json | undefined;
    if (short) {
      responseBody = short.body ?? {};
    } else {
      forwarded = ((pre.mcp.transformedGatewayRequest as { body?: Json } | undefined)?.body ?? body) as Json;
      argsSeenByLambda = ((forwarded.params as Json | undefined)?.arguments ?? {}) as Json;
      const result = await runTool(tool, argsSeenByLambda, opts.toolDeps);
      responseBody = { jsonrpc: "2.0", id, result: { isError: false, content: [{ type: "text", text: JSON.stringify(result) }] } };
    }
    const post = await opts.interceptor({
      interceptorInputVersion: "1.0",
      mcp: { gatewayRequest: { path: "/mcp", httpMethod: "POST", headers, body: forwarded }, gatewayResponse: { statusCode: 200, body: responseBody } },
    });
    const final = ((post.mcp.transformedGatewayResponse as { body?: Json } | undefined)?.body ?? responseBody) as Json;
    const result = (final.result ?? {}) as { isError?: boolean; content?: Array<{ text?: string }> };
    const text = (result.content ?? []).map((c) => c.text ?? "").join("\n");
    const call: SimCall = { tool, args, sentAt, returnedAt: new Date().toISOString(), text, isError: result.isError === true };
    if (argsSeenByLambda) call.argsSeenByLambda = argsSeenByLambda;
    return call;
  };
}
