// AgentCore Gateway interceptor, configured for both REQUEST and RESPONSE.
//
// REQUEST: on tools/call, read the caller from the Gateway-verified JWT and write it into the
// arguments as _identity, replacing anything the model sent under that name.
//
// RESPONSE: on read_page, if the URL is off the allowlist, sign a taint event with KMS, POST it to
// Writ and wait up to 1 s for Writ's signed ack. Only a good ack lets the page through. Anything else
// returns an error and the page text is dropped, so Writ learns "tainted" before the model sees a word.
//
// This Lambda is operator code, not attested. Removing it removes taint. The writ still caps the spend.

import type { KeyObject } from "node:crypto";
import { isAllowed } from "../../src/proxy";
import { type AgentIdentity, bareToolName, type CallerIdentity, IDENTITY_ARG, resolveCaller } from "./identity";
import { checkAck, sha256Hex, signedBytes, type TaintAck, type TaintEvent } from "./taint";

export interface InterceptorDeps {
  clients: Map<string, AgentIdentity>;
  allowlist: string[];
  writUrl: string;
  /** Undefined means no ledger key is configured: every off-list read fails closed. */
  ledgerKey: KeyObject | undefined;
  /** KMS Sign, ECDSA_SHA_256, MessageType RAW. Returns the DER signature. */
  sign: (message: Uint8Array) => Promise<Uint8Array>;
  nextSeq: (agent: string) => Promise<number>;
  fetch: (url: string, init: RequestInit) => Promise<Response>;
  now: () => string;
  ackTimeoutMs?: number;
  signTimeoutMs?: number;
  log?: (line: Record<string, unknown>) => void;
}

type Json = Record<string, unknown>;

interface McpInput {
  gatewayRequest?: { headers?: Json; body?: Json };
  gatewayResponse?: { statusCode?: number; headers?: Json; body?: Json };
}

export interface TaintRecord {
  event: TaintEvent;
  ack: TaintAck;
  /** Writ's Ed25519 signature over canonicalJson(ack), base64. Anyone with the ledger public key can check it. */
  ackSignature: string;
  ackReceivedAt: string;
  returnedAt: string;
}

const out = (mcp: Json) => ({ interceptorOutputVersion: "1.0", mcp });

const rpcError = (id: unknown, message: string) => ({
  statusCode: 200,
  body: { jsonrpc: "2.0", id: id ?? null, result: { isError: true, content: [{ type: "text", text: message }] } },
});

function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const t = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} took over ${ms} ms`)), ms);
  });
  return Promise.race([p, t]).finally(() => clearTimeout(timer));
}

/** Text content of a tools/call result, parsed as the read_page JSON when possible. */
function readPageResult(body: Json | undefined): { finalUrl?: string } {
  const result = body?.result as { content?: Array<{ type?: string; text?: string }> } | undefined;
  for (const item of result?.content ?? []) {
    if (item.type !== "text" || typeof item.text !== "string") continue;
    try {
      const parsed = JSON.parse(item.text) as { finalUrl?: unknown };
      if (typeof parsed.finalUrl === "string") return { finalUrl: parsed.finalUrl };
    } catch {
      // not JSON: nothing to read
    }
  }
  return {};
}

export function createInterceptor(deps: InterceptorDeps) {
  const ackTimeoutMs = deps.ackTimeoutMs ?? 1000;
  const signTimeoutMs = deps.signTimeoutMs ?? 2000;
  const log = deps.log ?? (() => {});

  async function recordTaint(caller: CallerIdentity, url: string): Promise<TaintRecord> {
    if (!deps.ledgerKey) throw new Error("no Writ ledger public key configured");
    const seq = await deps.nextSeq(caller.agent);
    const event: TaintEvent = { agent: caller.agent, runId: caller.runId, urlSha256: sha256Hex(url), at: deps.now(), seq };
    const der = await withTimeout(deps.sign(signedBytes(event)), signTimeoutMs, "KMS Sign");
    const signature = Buffer.from(der).toString("base64");
    const started = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), ackTimeoutMs);
    let reply: unknown;
    try {
      const res = await deps.fetch(`${deps.writUrl}/taint`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ event, signature }),
        signal: controller.signal,
      });
      if (!res.ok) throw new Error(`Writ answered ${res.status}`);
      reply = await res.json();
    } catch (err) {
      if (controller.signal.aborted) throw new Error(`no ack from Writ in ${ackTimeoutMs} ms`);
      throw err;
    } finally {
      clearTimeout(timer);
    }
    if (Date.now() - started > ackTimeoutMs) throw new Error(`no ack from Writ in ${ackTimeoutMs} ms`);
    const ackReceivedAt = deps.now();
    const check = checkAck(event, reply, deps.ledgerKey);
    if (!check.ok) throw new Error(check.why);
    return { event, ack: check.ack, ackSignature: check.signature, ackReceivedAt, returnedAt: deps.now() };
  }

  async function onRequest(mcp: McpInput) {
    const req = mcp.gatewayRequest ?? {};
    const body = req.body ?? {};
    const keep = req.headers ? { headers: req.headers } : {};
    if (body.method !== "tools/call") return out({ transformedGatewayRequest: { ...keep, body } });
    const caller = resolveCaller(req.headers, deps.clients);
    if (!caller) return out({ transformedGatewayResponse: rpcError(body.id, "Refused: this caller has no Writ agent identity.") });
    const params = (body.params ?? {}) as Json;
    const args = { ...((params.arguments ?? {}) as Json) };
    delete args[IDENTITY_ARG];
    args[IDENTITY_ARG] = { team: caller.team, agent: caller.agent, runId: caller.runId };
    return out({ transformedGatewayRequest: { ...keep, body: { ...body, params: { ...params, arguments: args } } } });
  }

  async function onResponse(mcp: McpInput) {
    const reqBody = mcp.gatewayRequest?.body ?? {};
    const res = mcp.gatewayResponse ?? {};
    const passThrough = out({ transformedGatewayResponse: { statusCode: res.statusCode ?? 200, body: res.body ?? {} } });
    if (reqBody.method !== "tools/call") return passThrough;
    const params = (reqBody.params ?? {}) as Json;
    if (bareToolName(params.name) !== "read_page") return passThrough;

    const id = reqBody.id;
    try {
      const args = (params.arguments ?? {}) as Json;
      const requested = typeof args.url === "string" ? args.url : "";
      const { finalUrl } = readPageResult(res.body);
      const offList = [requested, finalUrl ?? requested].find((u) => !isAllowed(u, deps.allowlist));
      if (offList === undefined) return passThrough;

      const caller = resolveCaller(mcp.gatewayRequest?.headers, deps.clients);
      if (!caller) throw new Error("no Writ agent identity for this caller");
      const record = await recordTaint(caller, offList);
      log({ kind: "WRIT_TAINT", ...record });

      const body = (res.body ?? {}) as Json;
      const result = (body.result ?? {}) as Json;
      const content = Array.isArray(result.content) ? result.content : [];
      const notice = {
        type: "text",
        text:
          `Writ recorded taint for this run before this page reached you (seq ${record.event.seq}, ` +
          `taintedAt ${record.ack.taintedAt}). Writs approved at or before that time can no longer spend.\n` +
          `[writ-taint] ${JSON.stringify(record)}`,
      };
      return out({ transformedGatewayResponse: { statusCode: 200, body: { ...body, result: { ...result, content: [notice, ...content] } } } });
    } catch (err) {
      const why = err instanceof Error ? err.message : String(err);
      log({ kind: "WRIT_TAINT_FAILED", why, at: deps.now() });
      return out({ transformedGatewayResponse: rpcError(id, `read_page refused: the taint could not be recorded in Writ (${why}). Page content dropped.`) });
    }
  }

  return async function handler(event: unknown) {
    const mcp = (event as { mcp?: McpInput } | undefined)?.mcp;
    if (!mcp) return out({ transformedGatewayResponse: rpcError(null, "Refused: not an MCP interceptor event.") });
    try {
      return mcp.gatewayResponse ? await onResponse(mcp) : await onRequest(mcp);
    } catch (err) {
      const why = err instanceof Error ? err.message : String(err);
      return out({ transformedGatewayResponse: rpcError(mcp.gatewayRequest?.body?.id, `Refused: interceptor error (${why}).`) });
    }
  };
}
