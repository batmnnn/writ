// A stand-in for the Writ enclave's agent routes, for tests and `agent-scene.ts --local`.
// It runs the real Gate (and so the real decide()), the real ledger in memory, and the real taint rules.
// What it fakes: the enclave itself, the human approver (a local key signs writs up to $250, bigger
// ones wait for a human who never comes), and the card swipe. One card per run.

import { generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { signedBytes, type TaintAck, type TaintEvent, verifyTaintEvent } from "../infra/lambda/taint";
import { Gate } from "../src/core/gate";
import { Ledger } from "../src/core/ledger";
import { TaintRegistry } from "../src/core/taint";
import { generateApproverKeys, signWrit, validateProposal } from "../src/core/writ";
import type { ApprovedTask, Decision, WritProposal } from "../src/types";

export type MockBehaviour = "ok" | "slow" | "bad-ack-signature" | "not-ok" | "down";

export interface MockWritOptions {
  taintPublicKey: KeyObject;
  behaviour?: MockBehaviour;
  slowMs?: number;
  now?: () => string;
}

interface Entry {
  proposal: WritProposal;
  cardId: string;
  writ?: ApprovedTask;
  decision?: Decision;
}

export interface MockWrit {
  url: string;
  ledgerPublicKey: string;
  behaviour: MockBehaviour;
  taintsReceived: Array<{ event: TaintEvent; ack: TaintAck; receivedAt: string }>;
  taintsRejected: number;
  /** A swipe on the card that belongs to this writ's run. */
  swipe(writId: string, spend: { amountMinor: number; merchantName: string; mcc: string; currency: string }): Promise<Decision>;
  stop(): void;
}

const HUMAN_LIMIT_MINOR = 25_000;

export function startMockWrit(opts: MockWritOptions): MockWrit {
  const now = opts.now ?? (() => new Date().toISOString());
  const ledgerKey = generateKeyPairSync("ed25519");
  const ledgerHex = ledgerKey.publicKey.export({ type: "spki", format: "der" }).subarray(-32).toString("hex");
  const approver = generateApproverKeys();
  const ledger = new Ledger();
  let balanceAt = now();
  ledger.setTeam("research", 50_000, now());
  const taints = new TaintRegistry(ledger);
  const gate = new Gate({
    ledger,
    config: { publicKeyPem: approver.publicKeyPem, autoApproveMinor: 0, ringFenceMinor: 2_500_000, reserveFloorMinor: 2_000_000, maxBalanceAgeMs: 60_000 },
    taint: (runId) => taints.get(runId),
    liveBalance: () => ({ amountMinor: 10_000_000, at: balanceAt }),
  });
  const writs = new Map<string, Entry>();
  const cards = new Set<string>();
  let swipes = 0;

  const state: MockWrit = {
    url: "",
    ledgerPublicKey: `ed25519:${ledgerHex}`,
    behaviour: opts.behaviour ?? "ok",
    taintsReceived: [],
    taintsRejected: 0,
    async swipe(writId, spend) {
      const entry = writs.get(writId);
      if (!entry) return { status: "DECLINED", code: "NO_WRIT_FOR_CARD", reason: "Unknown writ." };
      swipes += 1;
      balanceAt = now();
      balanceAt = now();
      const { decision } = await gate.authorize({ mode: "frozen", cardId: entry.cardId, now: now(), ...spend }, `mock-swipe-${swipes}`);
      entry.decision = decision;
      return decision;
    },
    stop: () => {
      server.stop(true);
      ledger.close();
    },
  };

  const json = (body: unknown, status = 200) => Response.json(body, { status });

  async function onTaint(req: Request): Promise<Response> {
    if (state.behaviour === "down") return json({ error: "down" }, 503);
    const body = (await req.json().catch(() => undefined)) as { event?: unknown; signature?: unknown } | undefined;
    if (!body || !verifyTaintEvent(body.event, body.signature, opts.taintPublicKey)) {
      state.taintsRejected += 1;
      return json({ error: "bad taint signature" }, 401);
    }
    const event = body.event as TaintEvent;
    const taintedAt = now();
    taints.mark(event.runId, `url-sha256:${event.urlSha256}`, taintedAt);
    if (state.behaviour === "slow") await Bun.sleep(opts.slowMs ?? 1500);
    const ack: TaintAck = { agent: event.agent, runId: event.runId, seq: event.seq, taintedAt, ok: true };
    const signer = state.behaviour === "bad-ack-signature" ? generateKeyPairSync("ed25519").privateKey : ledgerKey.privateKey;
    const signature = sign(null, signedBytes(ack), signer).toString("base64");
    state.taintsReceived.push({ event, ack, receivedAt: taintedAt });
    return json({ ack: state.behaviour === "not-ok" ? { ...ack, ok: false } : ack, signature });
  }

  async function onProposal(req: Request): Promise<Response> {
    const p = (await req.json().catch(() => undefined)) as WritProposal | undefined;
    if (!p) return json({ error: "body is not JSON" }, 400);
    const errors = validateProposal(p);
    if (errors.length > 0) return json({ error: errors.join("; ") }, 400);
    if (writs.has(p.id)) return json({ error: "duplicate id" }, 409);
    const cardId = `card-${p.runId}`;
    if (!cards.has(cardId)) {
      ledger.registerCard(cardId, p.team, p.agent, now());
      cards.add(cardId);
    }
    const entry: Entry = { proposal: p, cardId };
    if (p.amountMinor <= HUMAN_LIMIT_MINOR) {
      entry.writ = signWrit(p, now(), approver.privateKeyPem);
      ledger.registerWrit(entry.writ, cardId, entry.writ.approvedAt);
    }
    writs.set(p.id, entry);
    return json({ proposalId: `p-${crypto.randomUUID()}`, proposal: p }, 201);
  }

  function onDecision(id: string): Response {
    const e = writs.get(id);
    if (!e) return json({ error: "unknown writ" }, 404);
    return json({
      writId: id,
      agent: e.proposal.agent,
      status: e.writ ? ledger.writStatus(id) : "PENDING_HUMAN",
      approvedAt: e.writ?.approvedAt ?? null,
      decision: e.decision ?? null,
    });
  }

  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(req) {
      const url = new URL(req.url);
      if (req.method === "POST" && url.pathname === "/taint") return onTaint(req);
      if (req.method === "POST" && url.pathname === "/proposals") return onProposal(req);
      const m = /^\/decisions\/([^/]+)$/.exec(url.pathname);
      if (req.method === "GET" && m?.[1]) return onDecision(decodeURIComponent(m[1]));
      return json({ error: "not found" }, 404);
    },
  });
  state.url = `http://127.0.0.1:${server.port}`;
  return state;
}
