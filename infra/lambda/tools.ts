// The three Gateway tools. The agent can read a page, propose a writ and read a decision. That is all.
// Team, agent and run come from _identity, which the REQUEST interceptor writes from the verified JWT.
// No Airwallex client, no card id, no key lives here.

import { formatMinor } from "../../src/core/money";
import type { WritProposal } from "../../src/types";
import { IDENTITY_ARG, isCallerIdentity } from "./identity";

export const TOOL_NAMES = ["read_page", "propose_writ", "get_decision"] as const;
export type ToolName = (typeof TOOL_NAMES)[number];

export interface ToolDeps {
  writUrl: string;
  fetch: (url: string, init?: RequestInit) => Promise<Response>;
  now: () => Date;
  uuid: () => string;
  maxPageBytes?: number;
  writTimeoutMs?: number;
  pageTimeoutMs?: number;
}

type Json = Record<string, unknown>;
const fail = (error: string) => ({ ok: false, error });

const PRIVATE_HOST = /^(localhost|.*\.local|.*\.internal|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.|\[)/i;

function pageText(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&#36;/g, "$")
    .replace(/\s+/g, " ")
    .trim();
}

async function readCapped(res: Response, max: number): Promise<{ text: string; truncated: boolean }> {
  if (!res.body) return { text: "", truncated: false };
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (size + value.byteLength > max) {
      chunks.push(value.subarray(0, max - size));
      truncated = true;
      await reader.cancel();
      break;
    }
    chunks.push(value);
    size += value.byteLength;
  }
  return { text: new TextDecoder().decode(Buffer.concat(chunks)), truncated };
}

async function readPage(args: Json, deps: ToolDeps) {
  const url = args.url;
  if (typeof url !== "string" || url.length > 2048) return fail("url must be a string under 2048 characters");
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return fail("url is not a valid URL");
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return fail("only http and https pages can be read");
  if (PRIVATE_HOST.test(parsed.hostname)) return fail("private and local hosts cannot be read");
  const res = await deps.fetch(parsed.href, { redirect: "follow", signal: AbortSignal.timeout(deps.pageTimeoutMs ?? 5000) });
  const finalUrl = res.url || parsed.href;
  const { text, truncated } = await readCapped(res, deps.maxPageBytes ?? 256 * 1024);
  return { ok: true, url: parsed.href, finalUrl, status: res.status, truncated, text: pageText(text).slice(0, 20_000) };
}

async function callWrit(deps: ToolDeps, path: string, init: RequestInit): Promise<{ status: number; body: unknown }> {
  const res = await deps.fetch(`${deps.writUrl}${path}`, { ...init, signal: AbortSignal.timeout(deps.writTimeoutMs ?? 3000) });
  let body: unknown;
  try {
    body = await res.json();
  } catch {
    body = undefined;
  }
  return { status: res.status, body };
}

async function proposeWrit(args: Json, deps: ToolDeps) {
  const who = args[IDENTITY_ARG];
  if (!isCallerIdentity(who)) return fail("no caller identity from the Gateway; refusing");
  const { purpose, merchantName, mcc, amountMinor, currency, minutes } = args;
  if (typeof purpose !== "string" || purpose.trim() === "" || purpose.length > 500) return fail("purpose must be 1 to 500 characters");
  if (typeof merchantName !== "string" || merchantName.trim() === "" || merchantName.length > 100) return fail("merchantName must be 1 to 100 characters");
  if (typeof mcc !== "string" || !/^\d{4}$/.test(mcc)) return fail("mcc must be 4 digits");
  if (typeof amountMinor !== "number" || !Number.isSafeInteger(amountMinor) || amountMinor <= 0) return fail("amountMinor must be a positive whole number of cents");
  if (currency !== "USD") return fail("currency must be USD");
  if (typeof minutes !== "number" || !Number.isSafeInteger(minutes) || minutes < 1 || minutes > 1440) return fail("minutes must be a whole number from 1 to 1440");

  const proposal: WritProposal = {
    id: `writ-${deps.uuid()}`,
    team: who.team,
    agent: who.agent,
    runId: who.runId,
    purpose: purpose.trim(),
    merchantName: merchantName.trim(),
    mcc,
    amountMinor,
    currency: "USD",
    expiresAt: new Date(deps.now().getTime() + minutes * 60_000).toISOString(),
    nonce: deps.uuid(),
  };
  const { status, body } = await callWrit(deps, "/proposals", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(proposal),
  });
  const reply = (body ?? {}) as { proposalId?: unknown; proposal?: Partial<WritProposal> };
  if (status < 200 || status >= 300 || typeof reply.proposalId !== "string") {
    const why = (body as { error?: unknown } | undefined)?.error;
    return fail(`Writ did not accept the proposal (${status}${typeof why === "string" ? `: ${why}` : ""})`);
  }
  const echoed = reply.proposal ?? {};
  if (echoed.id !== proposal.id || echoed.team !== who.team || echoed.agent !== who.agent || echoed.runId !== who.runId || echoed.amountMinor !== amountMinor) {
    return fail("Writ echoed a different proposal; refusing");
  }
  return {
    ok: true,
    writId: proposal.id,
    proposalId: reply.proposalId,
    proposal: echoed,
    summary: `Asked for ${formatMinor(amountMinor)} at ${proposal.merchantName} (MCC ${mcc}) until ${proposal.expiresAt}. A human approves it or not. Check with get_decision using writId ${proposal.id}.`,
  };
}

function agentOf(body: unknown): unknown {
  if (!body || typeof body !== "object") return undefined;
  const b = body as Json;
  const nested = [b.writ, b.proposal].find((x) => x && typeof x === "object") as Json | undefined;
  return b.agent ?? nested?.agent;
}

async function getDecision(args: Json, deps: ToolDeps) {
  const who = args[IDENTITY_ARG];
  if (!isCallerIdentity(who)) return fail("no caller identity from the Gateway; refusing");
  const writId = args.writ_id;
  if (typeof writId !== "string" || !/^[A-Za-z0-9._:-]{1,100}$/.test(writId)) return fail("writ_id must be 1 to 100 letters, digits, dot, dash, colon or underscore");
  const { status, body } = await callWrit(deps, `/decisions/${encodeURIComponent(writId)}`, { method: "GET" });
  if (status === 404) return fail(`no decision for ${writId} yet: a human has not approved it, or it has not been used`);
  if (status < 200 || status >= 300 || body === undefined) return fail(`Writ answered ${status}`);
  const owner = agentOf(body);
  if (owner !== undefined && owner !== who.agent) return fail("that writ belongs to another agent");
  return { ok: true, writId, decision: body };
}

export async function runTool(tool: string, args: unknown, deps: ToolDeps): Promise<Json> {
  const a = args && typeof args === "object" ? (args as Json) : {};
  try {
    if (tool === "read_page") return await readPage(a, deps);
    if (tool === "propose_writ") return await proposeWrit(a, deps);
    if (tool === "get_decision") return await getDecision(a, deps);
    return fail(`unknown tool ${tool}`);
  } catch (err) {
    return fail(`${tool} failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/** Tool schemas for the Gateway targets. _identity is not listed: the model is never told about it. */
export const TOOL_SCHEMAS: Record<ToolName, { description: string; properties: Record<string, { type: string; description: string }>; required: string[] }> = {
  read_page: {
    // No taint warning here: it made Nova Pro refuse to read off-list pages, so the scene never tested taint.
    // The taint notice still arrives in the tool result.
    description: "Fetch a web page and return its text.",
    properties: { url: { type: "string", description: "http or https URL" } },
    required: ["url"],
  },
  propose_writ: {
    description: "Ask Writ for a single-use writ to buy one thing. Writ decides; you cannot approve it.",
    properties: {
      purpose: { type: "string", description: "What the purchase is for, one sentence" },
      merchantName: { type: "string", description: "Merchant name as it will appear on the card swipe" },
      mcc: { type: "string", description: "4 digit merchant category code, for example 5734" },
      amountMinor: { type: "integer", description: "Amount in US cents, for example 18000 for $180" },
      currency: { type: "string", description: "USD only" },
      minutes: { type: "integer", description: "How long the writ stays valid, 1 to 1440" },
    },
    required: ["purpose", "merchantName", "mcc", "amountMinor", "currency", "minutes"],
  },
  get_decision: {
    description: "Read Writ's decision for a writ id returned by propose_writ.",
    properties: { writ_id: { type: "string", description: "The writId from propose_writ" } },
    required: ["writ_id"],
  },
};
