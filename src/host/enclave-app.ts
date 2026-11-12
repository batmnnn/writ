// The enclave's front door, served on the same in-enclave TLS server as POST /remote-auth.
//   POST /proposals      unsigned writ fields from an agent tool. Stored in memory, moves no money.
//   GET  /proposals/:id  the stored proposal.
//   POST /writs          {writ}: a signed writ. The card comes from serve.json, never from the caller.
//   GET  /decisions/:id  the answer for a writ id.
//   POST /taint          {event, signature}: a KMS-signed taint event. Answers an enclave-signed ack.
//   GET  /state          pools, reserve, cards, chain head, recent decisions. What the console reads.
// Every body is capped at 32 KiB and must be UTF-8 JSON. Every failure is a JSON answer, never a stack.
// Nothing here logs, and no answer carries a card id, a PAN, a key or a secret.

import { randomUUID } from "node:crypto";
import type { ApprovedTask, IsoTime, WritProposal } from "../types";
import { isPositiveMinor } from "../core/money";
import { parseIso } from "../core/time";
import { canonicalJson, validateProposal } from "../core/writ";
import type { EnclaveServe, ServeResult } from "./enclave-serve";
import type { LedgerSigner } from "./enclave-keys";
import { parseTaintEvent, type TaintVerifier } from "./enclave-taint";

export const APP_MAX_BODY_BYTES = 32 * 1024;
export const MAX_PROPOSALS = 500;
const MAX_DECISIONS = 1_000;
const ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const PROPOSAL_KEYS = ["id", "team", "agent", "runId", "purpose", "merchantName", "mcc", "amountMinor", "currency", "expiresAt", "evidenceUrl", "nonce"] as const;
const TEXT_LIMITS: Record<string, number> = { purpose: 500, merchantName: 100, evidenceUrl: 2_000 };

export interface WritAnswer {
  writId: string;
  status: "AUTHORIZED" | "DECLINED";
  code?: string;
  reason: string;
  cardLast4?: string;
  seq?: number;
}

export interface AppOptions {
  serve: EnclaveServe;
  signer: LedgerSigner;
  verifyTaint: TaintVerifier;
  clock: () => IsoTime | undefined;
  newId?: () => string;
  maxProposals?: number;
  /** Boot status for /state (balance poll, TLS seal). Codes and times only. */
  status?: () => Record<string, unknown>;
}

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const refuse = (status: number, reason: string) => json(status, { ok: false, status: "DECLINED", reason });

type Body = { ok: true; value: unknown } | { ok: false; res: Response };

async function readJson(req: Request): Promise<Body> {
  const declared = Number(req.headers.get("content-length") ?? "0");
  if (!Number.isFinite(declared) || declared > APP_MAX_BODY_BYTES) return { ok: false, res: refuse(413, "body too large") };
  const bytes = new Uint8Array(await req.arrayBuffer());
  if (bytes.byteLength > APP_MAX_BODY_BYTES) return { ok: false, res: refuse(413, "body too large") };
  try {
    return { ok: true, value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) };
  } catch {
    return { ok: false, res: refuse(400, "body is not UTF-8 JSON") };
  }
}

const isObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

export class EnclaveApp {
  private readonly proposals = new Map<string, WritProposal>();
  private readonly decisions = new Map<string, WritAnswer>();
  private readonly newId: () => string;
  private readonly maxProposals: number;

  constructor(private readonly opts: AppOptions) {
    this.newId = opts.newId ?? (() => randomUUID());
    this.maxProposals = opts.maxProposals ?? MAX_PROPOSALS;
  }

  /** Undefined for a path this file does not own, so the TLS server answers 404. */
  route = async (req: Request, url: URL): Promise<Response | undefined> => {
    try {
      const path = url.pathname;
      if (path === "/proposals") return req.method === "POST" ? await this.postProposal(req) : refuse(405, "method not allowed");
      if (path === "/writs") return req.method === "POST" ? await this.postWrit(req) : refuse(405, "method not allowed");
      if (path === "/taint") return req.method === "POST" ? await this.postTaint(req) : refuse(405, "method not allowed");
      if (path === "/state") return req.method === "GET" ? this.getState() : refuse(405, "method not allowed");
      const p = /^\/proposals\/([^/]+)$/.exec(path);
      if (p) return req.method === "GET" ? this.getProposal(decodeURIComponent(p[1]!)) : refuse(405, "method not allowed");
      const d = /^\/decisions\/([^/]+)$/.exec(path);
      if (d) return req.method === "GET" ? this.getDecision(decodeURIComponent(d[1]!)) : refuse(405, "method not allowed");
      return undefined;
    } catch {
      return refuse(500, "internal error");
    }
  };

  // ---------- proposals ----------

  private async postProposal(req: Request): Promise<Response> {
    const body = await readJson(req);
    if (!body.ok) return body.res;
    if (!isObject(body.value)) return refuse(400, "proposal must be a JSON object");
    const raw = body.value;
    for (const k of Object.keys(raw)) {
      if (!(PROPOSAL_KEYS as readonly string[]).includes(k)) return refuse(400, `unknown field ${k.slice(0, 40)}`);
    }
    const p: Record<string, unknown> = {};
    for (const k of PROPOSAL_KEYS) if (raw[k] !== undefined) p[k] = raw[k];
    p.id ??= `writ-${this.newId()}`;
    p.nonce ??= this.newId();
    for (const k of ["id", "team", "agent", "runId", "nonce"] as const) {
      if (typeof p[k] !== "string" || !ID_RE.test(p[k] as string)) return refuse(400, `${k} must be 1 to 128 letters, digits or ._:-`);
    }
    for (const [k, limit] of Object.entries(TEXT_LIMITS)) {
      if (p[k] !== undefined && (typeof p[k] !== "string" || (p[k] as string).length > limit)) return refuse(400, `${k} must be text of at most ${limit} characters`);
    }
    const proposal = p as unknown as WritProposal;
    const errors = validateProposal(proposal);
    if (errors.length > 0) return refuse(400, `proposal is not valid: ${errors.join("; ")}`);
    if (!this.opts.serve.cardFor(proposal.team, proposal.agent)) return refuse(400, `no card for agent ${proposal.agent} in team ${proposal.team}`);
    const now = parseIso(this.opts.clock());
    if (Number.isFinite(now) && parseIso(proposal.expiresAt) <= now) return refuse(400, "expiresAt is already past");
    const canonical = JSON.parse(canonicalJson(proposal)) as WritProposal;
    const proposalId = `p-${this.newId()}`;
    this.proposals.set(proposalId, canonical);
    while (this.proposals.size > this.maxProposals) {
      const oldest = this.proposals.keys().next().value;
      if (oldest === undefined) break;
      this.proposals.delete(oldest);
    }
    return json(201, { proposalId, proposal: canonical });
  }

  private getProposal(id: string): Response {
    const p = this.proposals.get(id);
    return p ? json(200, { proposalId: id, proposal: p }) : refuse(404, "unknown proposal");
  }

  /** How many proposals are held. */
  get proposalCount(): number {
    return this.proposals.size;
  }

  // ---------- writs ----------

  private async postWrit(req: Request): Promise<Response> {
    const body = await readJson(req);
    if (!body.ok) return body.res;
    if (!isObject(body.value) || !isObject(body.value.writ)) return refuse(400, "body must be {writ}");
    const writ = body.value.writ as unknown as ApprovedTask;
    if (typeof writ.id !== "string" || !ID_RE.test(writ.id)) return refuse(400, "writ.id must be 1 to 128 letters, digits or ._:-");
    if (typeof writ.team !== "string" || typeof writ.agent !== "string") return refuse(400, "writ.team and writ.agent are required");
    if (!isPositiveMinor(writ.amountMinor) || typeof writ.currency !== "string" || typeof writ.mcc !== "string" || typeof writ.merchantName !== "string") {
      return refuse(400, "writ amount, currency, mcc and merchantName are required, amount in whole cents");
    }
    const card = this.opts.serve.cardFor(writ.team, writ.agent);
    if (!card) {
      const answer: WritAnswer = { writId: writ.id, status: "DECLINED", code: "NO_WRIT_FOR_CARD", reason: `No card for agent ${writ.agent} in team ${writ.team}.` };
      this.remember(answer);
      return json(200, answer);
    }
    const result = await this.opts.serve.authorize({ cardId: card.cardId, amountMinor: writ.amountMinor, currency: writ.currency, mcc: writ.mcc, merchantName: writ.merchantName, writ });
    const answer = toAnswer(writ.id, result, card.last4);
    this.remember(answer);
    return json(200, answer);
  }

  /** The first AUTHORIZED answer for a writ id sticks, so a later replay or forgery under the same id cannot hide it. */
  private remember(a: WritAnswer): void {
    const prev = this.decisions.get(a.writId);
    if (prev?.status === "AUTHORIZED") return;
    this.decisions.delete(a.writId);
    this.decisions.set(a.writId, a);
    while (this.decisions.size > MAX_DECISIONS) {
      const oldest = this.decisions.keys().next().value;
      if (oldest === undefined) break;
      this.decisions.delete(oldest);
    }
  }

  private getDecision(writId: string): Response {
    const d = this.decisions.get(writId);
    return d ? json(200, d) : refuse(404, "unknown writ");
  }

  // ---------- taint ----------

  private async postTaint(req: Request): Promise<Response> {
    const body = await readJson(req);
    if (!body.ok) return body.res;
    if (!isObject(body.value) || Object.keys(body.value).sort().join(",") !== "event,signature") return refuse(400, "body must be {event, signature}");
    const event = parseTaintEvent(body.value.event);
    if (!event) return json(400, { ok: false, reason: "event must be {agent, runId, urlSha256, at, seq}" });
    if (!(await this.opts.verifyTaint(event, body.value.signature))) return json(400, { ok: false, reason: "bad signature" });
    const out = await this.opts.serve.acceptTaint(event);
    if (!out.ok) return json(out.status, { ok: false, reason: out.reason });
    const ack = { agent: event.agent, runId: event.runId, seq: event.seq, taintedAt: out.taintedAt, ok: true as const };
    const signature = Buffer.from(this.opts.signer.sign(new TextEncoder().encode(canonicalJson(ack)))).toString("base64");
    return json(200, { ack, signature });
  }

  // ---------- state ----------

  private getState(): Response {
    return json(200, { ...this.opts.serve.state(), ledgerPublicKey: this.opts.signer.publicKey, ...(this.opts.status ? { boot: this.opts.status() } : {}) });
  }
}

function toAnswer(writId: string, r: ServeResult, last4: string | undefined): WritAnswer {
  const a: WritAnswer = { writId, status: r.status, reason: r.reason };
  if (r.status === "DECLINED") a.code = r.code;
  if (last4) a.cardLast4 = last4;
  if (r.seq !== undefined) a.seq = r.seq;
  return a;
}
