// Red team: each attack is a real decline, or a todo when the product does not enforce it.
// No product code is weakened here. src/host is out of scope.

import { describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { createHmac } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MAX_BODY_BYTES, NonceCache, handleRemoteAuth, type RaRequest } from "../src/airwallex/ra-server";
import { RestAdapter } from "../src/airwallex/rest-adapter";
import type { AirwallexClient } from "../src/airwallex/client";
import { checkClaims, verifyAttestation, type ExpectedPcrs } from "../src/attest/verify";
import { GENESIS_PREV, entryHash, verifyChain, type ChainEntry } from "../src/core/chain";
import type { Committer } from "../src/core/committer";
import { decide } from "../src/core/decide";
import { disarmAndRecord } from "../src/core/disarm";
import { Gate } from "../src/core/gate";
import { Ledger } from "../src/core/ledger";
import { normalizeMerchant } from "../src/core/merchant";
import { TaintRegistry } from "../src/core/taint";
import { signWrit } from "../src/core/writ";
import type { ArmSpec, Decision, DecisionInput, WritProposal } from "../src/types";
import { APPROVED_AT, KEYS, NOW, OTHER_KEYS, input, proposal, signed, state } from "./helpers";

const T0 = "2026-11-12T08:00:00.000Z";
const code = (d: Decision | undefined) => (d?.status === "DECLINED" ? d.code : "AUTHORIZED");

function setup(poolLimitMinor = 50_000) {
  const ledger = new Ledger();
  ledger.setTeam("research", poolLimitMinor, T0);
  ledger.registerCard("card-1", "research", "research-1", T0);
  ledger.registerCard("card-2", "research", "research-2", T0);
  const taint = new TaintRegistry();
  const gate = new Gate({
    ledger,
    config: {
      publicKeyPem: KEYS.publicKeyPem,
      autoApproveMinor: 25_000,
      ringFenceMinor: 2_500_000,
      reserveFloorMinor: 2_000_000,
      maxBalanceAgeMs: 60_000,
    },
    taint: (runId) => taint.get(runId),
    liveBalance: () => ({ amountMinor: 1_000_000_000, at: NOW }),
  });
  return { ledger, gate, taint };
}

async function swipe(over: Partial<DecisionInput> = {}, writOver?: Partial<WritProposal>) {
  const built = setup();
  built.ledger.registerWrit(signed(writOver), "card-1", APPROVED_AT);
  const result = await built.gate.authorize(input(over), "swipe-1");
  return { ...built, decision: result.decision, freezeCard: result.freezeCard };
}

function used(ledger: Ledger): number {
  const snap = ledger.snapshot("research");
  if (!snap) throw new Error("no team snapshot");
  return snap.reservedMinor + snap.pendingMinor + snap.settledMinor;
}

const SECRET = "test-shared-secret-not-real";
const NOW_MS = Date.parse(NOW);
const signNonce = (nonce: string, secret = SECRET) => createHmac("sha256", secret).update(nonce).digest("base64");
let nonceSeq = 0;
const freshNonce = (ts = NOW_MS) => `${ts}.rt${++nonceSeq}`;

function v2(over: Record<string, unknown> = {}): string {
  return JSON.stringify({
    version: 2,
    card_id: "card-1",
    card_transaction_event_id: "evt-rt-1",
    transaction_type: "AUTHORIZATION",
    transaction_amount: 180,
    transaction_currency: "USD",
    merchant: { name: "DataCo", category_code: "5734" },
    ...over,
  });
}

function ra(opts: {
  nonce?: string;
  rawBody?: string;
  headers?: RaRequest["headers"];
  decide?: RaRequest["decide"];
  nonces?: NonceCache;
  nowMs?: number;
  secret?: string;
} = {}): RaRequest {
  const nonce = opts.nonce ?? freshNonce();
  const secret = opts.secret ?? SECRET;
  return {
    headers: opts.headers ?? { "x-nonce": nonce, "x-signature": signNonce(nonce, secret) },
    rawBody: opts.rawBody ?? v2(),
    nowMs: opts.nowMs ?? NOW_MS,
    secret,
    decide: opts.decide ?? (() => ({ status: "AUTHORIZED", writId: "writ-1", reason: "should not run" })),
    nonces: opts.nonces ?? new NonceCache(),
  };
}

const armSpec: ArmSpec = {
  amountMinor: 18_000,
  currency: "USD",
  mcc: "5734",
  activeTo: "2026-11-12T09:00:00.000Z",
  writHashPrefix: "abcd",
};

function updating(
  onBody: (body: Record<string, unknown>) =>
    | { ok: true; value: undefined }
    | { ok: false; error: { kind: "timeout" | "network"; message: string } },
): AirwallexClient {
  return {
    request(_method: string, path: string, opts?: { body?: unknown }) {
      if (!path.endsWith("/update")) {
        return Promise.resolve({ ok: false as const, error: { kind: "http" as const, message: "unexpected" } });
      }
      const body = opts?.body;
      const record = body !== null && typeof body === "object" ? (body as Record<string, unknown>) : {};
      return Promise.resolve(onBody(record));
    },
  } as unknown as AirwallexClient;
}

function linked(seq: number, prev: string, payload: unknown): ChainEntry {
  const at = 1_700_000_000_000 + seq;
  const body = { seq, prev, at, kind: "NOTE", payload };
  return { ...body, hash: entryHash(prev, body) };
}

function expectUnverified(result: ReturnType<typeof verifyChain>): void {
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.code).toBe("STATE_UNVERIFIED");
}

async function withReopened(mutate: (raw: Database) => void): Promise<{ ledger: Ledger; gate: Gate; close: () => void }> {
  const dir = mkdtempSync(join(tmpdir(), "writ-rt-"));
  const path = join(dir, "writ.sqlite");
  const first = new Ledger(path);
  first.setTeam("research", 50_000, T0);
  first.registerCard("card-1", "research", "research-1", T0);
  first.registerWrit(signed(), "card-1", APPROVED_AT);
  first.close();
  const raw = new Database(path);
  mutate(raw);
  raw.close();
  const ledger = new Ledger(path);
  const gate = new Gate({
    ledger,
    config: {
      publicKeyPem: KEYS.publicKeyPem,
      autoApproveMinor: 25_000,
      ringFenceMinor: 2_500_000,
      reserveFloorMinor: 2_000_000,
      maxBalanceAgeMs: 60_000,
    },
    taint: (runId) => ({ runId }),
    liveBalance: () => ({ amountMinor: 1_000_000_000, at: NOW }),
  });
  return {
    ledger,
    gate,
    close: () => {
      ledger.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

describe("price drift", () => {
  test("a $180 writ declines a $195 swipe", async () => {
    const { ledger, decision } = await swipe({ amountMinor: 19_500 });
    expect(code(decision)).toBe("AMOUNT_OVER_WRIT");
    expect(used(ledger)).toBe(0);
  });
});

describe("merchant name swap", () => {
  test("a different merchant name is declined", async () => {
    const { decision } = await swipe({ merchantName: "OtherCo" });
    expect(code(decision)).toBe("MERCHANT_NOT_IN_WRIT");
  });
});

describe("MCC swap", () => {
  test("a different merchant category is declined", async () => {
    const { decision } = await swipe({ mcc: "5999" });
    expect(code(decision)).toBe("MCC_NOT_IN_WRIT");
  });
});

describe("currency swap", () => {
  test("a different currency is declined", async () => {
    const { decision } = await swipe({ currency: "EUR" });
    expect(code(decision)).toBe("CURRENCY_NOT_IN_WRIT");
  });
});

describe("replayed writ", () => {
  test("the second authorization is WRIT_REPLAY and the pool is held once", async () => {
    const { ledger, gate } = setup();
    ledger.registerWrit(signed(), "card-1", APPROVED_AT);
    const first = await gate.authorize(input(), "swipe-1");
    expect(code(first.decision)).toBe("AUTHORIZED");
    const second = await gate.authorize(input(), "swipe-2");
    expect(code(second.decision)).toBe("WRIT_REPLAY");
    expect(ledger.snapshot("research")!.reservedMinor).toBe(18_000);
  });
});

describe("edited writ", () => {
  test("a changed field after the signature is WRIT_HASH_MISMATCH", () => {
    const writ = signed();
    const edited = { ...writ, amountMinor: 100 };
    expect(code(decide(input({ amountMinor: 100 }), state(edited)))).toBe("WRIT_HASH_MISMATCH");
  });

  test("editing the stored writ body is WRIT_HASH_MISMATCH and reserves nothing", async () => {
    const { ledger, gate } = setup();
    const writ = signed();
    ledger.registerWrit(writ, "card-1", APPROVED_AT);
    ledger.db.exec("DROP TRIGGER writs_no_update");
    ledger.db.query(`UPDATE writs SET body = ? WHERE writ_id = ?`).run(JSON.stringify({ ...writ, merchantName: "EditedCo" }), writ.id);
    const result = await gate.authorize(input(), "edited-1");
    expect(code(result.decision)).toBe("WRIT_HASH_MISMATCH");
    expect(used(ledger)).toBe(0);
  });
});

describe("expired writ", () => {
  test("a swipe at the expiry instant is WRIT_EXPIRED", async () => {
    const { decision } = await swipe({ now: "2026-11-12T09:00:00.000Z" });
    expect(code(decision)).toBe("WRIT_EXPIRED");
  });
});

describe("wrong signing key", () => {
  test("a writ signed by another key is WRIT_BAD_SIGNATURE", async () => {
    const { ledger, gate } = setup();
    ledger.registerWrit(signWrit(proposal(), APPROVED_AT, OTHER_KEYS.privateKeyPem), "card-1", APPROVED_AT);
    const result = await gate.authorize(input(), "wrong-key");
    expect(code(result.decision)).toBe("WRIT_BAD_SIGNATURE");
    expect(used(ledger)).toBe(0);
  });
});

describe("pool race", () => {
  test("twelve concurrent authorizations never exceed the team pool", async () => {
    const pool = 50_000;
    const amount = 10_000;
    const n = 12;
    const { ledger, gate } = setup(pool);
    for (let i = 0; i < n; i++) {
      const card = `card-p${i}`;
      ledger.registerCard(card, "research", `agent-${i}`, T0);
      ledger.registerWrit(
        signed({ id: `writ-p${i}`, nonce: `np${i}`, runId: `run-p${i}`, agent: `agent-${i}`, amountMinor: amount }),
        card,
        APPROVED_AT,
      );
    }
    const results = await Promise.all(
      Array.from({ length: n }, (_, i) => gate.authorize(input({ cardId: `card-p${i}`, amountMinor: amount }), `race-${i}`)),
    );
    const authorized = results.filter((r) => r.decision.status === "AUTHORIZED");
    expect(authorized).toHaveLength(Math.floor(pool / amount));
    for (const r of results) {
      if (r.decision.status === "DECLINED") expect(r.decision.code).toBe("TEAM_POOL_EXHAUSTED");
    }
    expect(used(ledger)).toBe(authorized.length * amount);
    expect(used(ledger)).toBeLessThanOrEqual(pool);
  });
});

describe("arm timeout and disarm failure", () => {
  test("an arm timeout is followed by an INACTIVE update and the arm does not succeed", async () => {
    const statuses: string[] = [];
    const adapter = new RestAdapter({
      client: updating((body) => {
        statuses.push(String(body.card_status));
        if (body.card_status === "ACTIVE") return { ok: false, error: { kind: "timeout", message: "no answer within 5000 ms" } };
        return { ok: true, value: undefined };
      }),
      mode: "frozen",
      sleep: async () => {},
      disarmBackoffMs: [0, 0, 0],
    });
    const result = await adapter.arm("card-1", armSpec);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.kind).toBe("timeout");
    expect(statuses).toEqual(["ACTIVE", "INACTIVE"]);
  });

  test("a failed disarm is tried again for each backoff slot", async () => {
    let calls = 0;
    const adapter = new RestAdapter({
      client: updating((body) => {
        calls += 1;
        expect(body.card_status).toBe("INACTIVE");
        return { ok: false, error: { kind: "network", message: "down" } };
      }),
      mode: "frozen",
      sleep: async () => {},
      disarmBackoffMs: [0, 0, 0],
    });
    const result = await adapter.disarm("card-1");
    expect(result.ok).toBe(false);
    expect(calls).toBe(4);
  });

  test("disarm failure emits ALERT after the retries, with reason and time, and no DISARM", async () => {
    const { ledger } = setup();
    let calls = 0;
    const adapter = new RestAdapter({
      client: updating(() => {
        calls += 1;
        return { ok: false, error: { kind: "network", message: "down" } };
      }),
      mode: "frozen",
      sleep: async () => {},
      disarmBackoffMs: [0, 0, 0],
    });
    const ok = await disarmAndRecord(adapter, ledger, "card-1", { opId: "op-1", reason: "swiped once", writId: "writ-1", now: () => NOW });
    expect(ok).toBe(false);
    expect(calls).toBe(4);
    const alerts = ledger.events({ kind: "ALERT" });
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({ team: "research", cardId: "card-1", writId: "writ-1", at: NOW, amountMinor: 0 });
    expect(alerts[0]?.reason).toContain("Disarm failed after retries");
    expect(alerts[0]?.reason).toContain("down");
    expect(ledger.events({ kind: "DISARM" })).toHaveLength(0);
    expect(ledger.snapshot("research")!.alerts).toBe(1);
    expect(() => ledger.db.exec("DELETE FROM events WHERE kind = 'ALERT'")).toThrow("append only");
  });

  test("a disarm that throws is an ALERT too, and a good disarm is a DISARM event with no ALERT", async () => {
    const { ledger } = setup();
    const throwing = { disarm: () => Promise.reject(new Error("socket hang up")) };
    expect(await disarmAndRecord(throwing, ledger, "card-1", { opId: "op-t", reason: "run tainted", now: () => NOW })).toBe(false);
    expect(ledger.events({ kind: "ALERT" })).toHaveLength(1);
    const good = { disarm: () => Promise.resolve({ ok: true as const, value: undefined }) };
    expect(await disarmAndRecord(good, ledger, "card-2", { opId: "op-g", reason: "swiped once", now: () => NOW })).toBe(true);
    expect(ledger.events({ kind: "ALERT" })).toHaveLength(1);
    expect(ledger.events({ kind: "DISARM" })).toHaveLength(1);
  });
});

describe("remote auth request", () => {
  test("a stale nonce is declined and decide() reports RA_STALE_NONCE", async () => {
    let calls = 0;
    const res = await handleRemoteAuth(
      ra({
        nonce: freshNonce(NOW_MS - 30_001),
        decide: () => {
          calls += 1;
          return { status: "AUTHORIZED", writId: "writ-1", reason: "no" };
        },
      }),
    );
    expect(calls).toBe(0);
    expect(res.body).toEqual({ card_transaction_event_id: "evt-rt-1", response_status: "DECLINED", status_reason: "stale nonce" });
    const flagged = decide(input({ mode: "ra", ra: { signatureValid: true, nonceFresh: false, nonceSeen: false } }), state());
    expect(code(flagged)).toBe("RA_STALE_NONCE");
  });

  test("a reused nonce is declined and decide() reports RA_NONCE_REPLAY", async () => {
    let calls = 0;
    const nonces = new NonceCache();
    const nonce = freshNonce();
    const decideOk: RaRequest["decide"] = () => {
      calls += 1;
      return { status: "AUTHORIZED", writId: "writ-1", reason: "ok" };
    };
    const first = await handleRemoteAuth(ra({ nonce, nonces, decide: decideOk }));
    expect(first.body.response_status).toBe("AUTHORIZED");
    const second = await handleRemoteAuth(ra({ nonce, nonces, nowMs: NOW_MS + 1_000, decide: decideOk }));
    expect(calls).toBe(1);
    expect(second.body).toEqual({ card_transaction_event_id: "evt-rt-1", response_status: "DECLINED", status_reason: "nonce replay" });
    const flagged = decide(input({ mode: "ra", ra: { signatureValid: true, nonceFresh: true, nonceSeen: true } }), state());
    expect(code(flagged)).toBe("RA_NONCE_REPLAY");
  });

  test("a bad signature is declined and decide() reports RA_BAD_SIGNATURE", async () => {
    let calls = 0;
    const nonce = freshNonce();
    const res = await handleRemoteAuth(
      ra({
        headers: { "x-nonce": nonce, "x-signature": signNonce(nonce, "wrong-secret") },
        decide: () => {
          calls += 1;
          return { status: "AUTHORIZED", writId: "writ-1", reason: "no" };
        },
      }),
    );
    expect(calls).toBe(0);
    expect(res.body).toEqual({ card_transaction_event_id: "evt-rt-1", response_status: "DECLINED", status_reason: "bad signature" });
    const flagged = decide(input({ mode: "ra", ra: { signatureValid: false, nonceFresh: true, nonceSeen: false } }), state());
    expect(code(flagged)).toBe("RA_BAD_SIGNATURE");
  });

  test("a valid signature for an unknown card is NO_WRIT_FOR_CARD", async () => {
    const { gate } = setup();
    let calls = 0;
    let decision: Decision | undefined;
    const res = await handleRemoteAuth(
      ra({
        rawBody: v2({ card_id: "card-unknown" }),
        decide: async (swipeInput, eventId) => {
          calls += 1;
          expect(swipeInput.cardId).toBe("card-unknown");
          const result = await gate.authorize(swipeInput, eventId);
          decision = result.decision;
          return result.decision;
        },
      }),
    );
    expect(calls).toBe(1);
    expect(code(decision)).toBe("NO_WRIT_FOR_CARD");
    expect(res.body.response_status).toBe("DECLINED");
  });
});

describe("forced capture with no auth", () => {
  test("the amount counts against the pool, an alert is written, and the team is marked frozen", () => {
    const { ledger } = setup();
    const out = ledger.onForcedCapture({ eventId: "fc-rt", cardId: "card-1", amountMinor: 22_000, at: NOW });
    expect(out).toMatchObject({ alert: true, freezeTeam: true, duplicate: false, team: "research" });
    expect(ledger.snapshot("research")).toMatchObject({ settledMinor: 22_000, alerts: 1, reservedMinor: 0, pendingMinor: 0 });
    expect(used(ledger)).toBe(22_000);
    expect(ledger.events({ kind: "ALERT" })).toHaveLength(1);
    const freeze = ledger.events({ kind: "FREEZE" });
    expect(freeze).toHaveLength(1);
    expect(freeze[0]?.reason).toContain("research");
    expect(ledger.teamCards("research").length).toBeGreaterThan(0);
  });

  test("a later swipe on any card of the team is declined after that freeze and reserves nothing", async () => {
    const { ledger, gate } = setup();
    ledger.onForcedCapture({ eventId: "fc-rt", cardId: "card-2", amountMinor: 1_000, at: NOW });
    ledger.registerWrit(signed(), "card-1", APPROVED_AT);
    const result = await gate.authorize(input(), "after-freeze");
    expect(code(result.decision)).toBe("TEAM_POOL_EXHAUSTED");
    expect(result.decision.reason).toContain("frozen");
    expect(result.freezeCard).toBe(true);
    expect(ledger.wasConsumed("writ-1")).toBe(false);
    expect(used(ledger)).toBe(1_000);
  });

  test("an unmatched clearing freezes the team the same way", async () => {
    const { ledger, gate } = setup();
    ledger.onClearing({ eventId: "c-rt", cardId: "card-2", writId: "never-approved", amountMinor: 1_000, at: NOW });
    ledger.registerWrit(signed(), "card-1", APPROVED_AT);
    expect(code((await gate.authorize(input(), "after-clearing")).decision)).toBe("TEAM_POOL_EXHAUSTED");
  });

  test("the freeze survives a ledger reload", async () => {
    const dir = mkdtempSync(join(tmpdir(), "writ-rt-"));
    const path = join(dir, "writ.sqlite");
    try {
      const first = new Ledger(path);
      first.setTeam("research", 50_000, T0);
      first.registerCard("card-1", "research", "research-1", T0);
      first.registerCard("card-2", "research", "research-2", T0);
      first.onForcedCapture({ eventId: "fc-reload", cardId: "card-2", amountMinor: 1_000, at: NOW });
      first.registerWrit(signed(), "card-1", APPROVED_AT);
      first.close();
      const ledger = new Ledger(path);
      const gate = new Gate({
        ledger,
        config: { publicKeyPem: KEYS.publicKeyPem, autoApproveMinor: 25_000, ringFenceMinor: 2_500_000, reserveFloorMinor: 2_000_000, maxBalanceAgeMs: 60_000 },
        taint: (runId) => ({ runId }),
        liveBalance: () => ({ amountMinor: 1_000_000_000, at: NOW }),
      });
      expect(ledger.chainVerified).toBe(true);
      expect(ledger.snapshot("research")?.teamFrozen?.reason).toContain("Forced capture");
      const result = await gate.authorize(input(), "after-reload");
      expect(code(result.decision)).toBe("TEAM_POOL_EXHAUSTED");
      expect(ledger.wasConsumed("writ-1")).toBe(false);
      ledger.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("another team is not frozen by it", async () => {
    const { ledger, gate } = setup();
    ledger.setTeam("growth", 50_000, T0);
    ledger.registerCard("card-g", "growth", "growth-1", T0);
    ledger.onForcedCapture({ eventId: "fc-rt", cardId: "card-2", amountMinor: 1_000, at: NOW });
    ledger.registerWrit(signed({ id: "w-g", team: "growth", agent: "growth-1", runId: "run-g", nonce: "g" }), "card-g", APPROVED_AT);
    expect(code((await gate.authorize(input({ cardId: "card-g" }), "g1")).decision)).toBe("AUTHORIZED");
  });
});

describe("clearing larger than the authorization", () => {
  test("a $195 clearing of a $180 authorization counts in full and raises an alert", () => {
    const { ledger } = setup();
    const writ = signed();
    ledger.registerWrit(writ, "card-1", APPROVED_AT);
    ledger.commitApproval({
      eventId: "d1",
      writ,
      cardId: "card-1",
      amountMinor: 18_000,
      at: NOW,
      decision: { status: "AUTHORIZED", writId: writ.id, reason: "ok" },
    });
    ledger.onAuthorization({ eventId: "a1", cardId: "card-1", writId: writ.id, amountMinor: 18_000, at: NOW });
    const out = ledger.onClearing({ eventId: "c1", cardId: "card-1", writId: writ.id, amountMinor: 19_500, at: NOW });
    expect(out.alert).toBe(true);
    expect(ledger.snapshot("research")).toMatchObject({ settledMinor: 19_500, pendingMinor: 0, alerts: 1 });
    expect(used(ledger)).toBe(19_500);
  });
});

describe("taint after approval", () => {
  test("a taint after approvedAt is TAINTED_RUN, the card is flagged to freeze, and nothing is reserved", async () => {
    const { ledger, gate, taint } = setup();
    ledger.registerWrit(signed(), "card-1", APPROVED_AT);
    taint.mark("run-1", "https://evil.example/page", "2026-11-12T08:32:00.000Z");
    const result = await gate.authorize(input(), "swipe-1");
    expect(code(result.decision)).toBe("TAINTED_RUN");
    expect(result.freezeCard).toBe(true);
    expect(used(ledger)).toBe(0);
  });
});

describe("ledger truncation", () => {
  test("a log shorter than its checkpoint is STATE_UNVERIFIED", () => {
    const first = linked(1, GENESIS_PREV, { n: 1 });
    const second = linked(2, first.hash, { n: 2 });
    expect(verifyChain([first, second]).ok).toBe(true);
    expectUnverified(verifyChain([first], { checkpoint: { seq: 2, head: second.hash } }));
  });

  test("deleting the head of the log on reload makes Gate decline STATE_UNVERIFIED", async () => {
    const opened = await withReopened((raw) => {
      raw.exec("DROP TRIGGER events_no_delete");
      raw.exec("DELETE FROM events WHERE seq = 1");
    });
    try {
      expect(opened.ledger.chainVerified).toBe(false);
      const result = await opened.gate.authorize(input(), "swipe-1");
      expect(code(result.decision)).toBe("STATE_UNVERIFIED");
      expect(result.decision.status).not.toBe("AUTHORIZED");
      expect(opened.ledger.wasConsumed("writ-1")).toBe(false);
    } finally {
      opened.close();
    }
  });

  test.todo(
    "dropping only the tail on reload is STATE_UNVERIFIED: Gate calls verifyChain with no checkpoint, so a shorter valid prefix still verifies",
  );
});

describe("ledger edit", () => {
  test("an edited entry is STATE_UNVERIFIED", () => {
    const first = linked(1, GENESIS_PREV, { n: 1 });
    expectUnverified(verifyChain([{ ...first, payload: { n: 2 } }]));
  });

  test("an edited row on reload makes Gate decline STATE_UNVERIFIED and reserve nothing", async () => {
    const opened = await withReopened((raw) => {
      raw.exec("DROP TRIGGER events_no_update");
      raw.exec("UPDATE events SET reason = 'tampered' WHERE seq = 1");
    });
    try {
      expect(opened.ledger.chainVerified).toBe(false);
      const result = await opened.gate.authorize(input(), "swipe-1");
      expect(code(result.decision)).toBe("STATE_UNVERIFIED");
      expect(used(opened.ledger)).toBe(0);
    } finally {
      opened.close();
    }
  });
});

describe("ledger fork", () => {
  test("a forked entry that disagrees with the checkpoint is STATE_UNVERIFIED", () => {
    const first = linked(1, GENESIS_PREV, { n: 1 });
    const second = linked(2, first.hash, { n: 2 });
    const fork = linked(2, first.hash, { n: 9 });
    expect(verifyChain([first, fork]).ok).toBe(true);
    expectUnverified(verifyChain([first, fork], { checkpoint: { seq: 2, head: second.hash } }));
  });

  test.todo(
    "a forked reload is STATE_UNVERIFIED: Gate calls verifyChain with no checkpoint, so a rewritten last entry that still chains verifies",
  );
});

describe("commit failure", () => {
  function gateWith(committer: Committer) {
    const ledger = new Ledger();
    ledger.setTeam("research", 50_000, T0);
    ledger.registerCard("card-1", "research", "research-1", T0);
    ledger.registerWrit(signed(), "card-1", APPROVED_AT);
    const gate = new Gate({
      ledger,
      config: {
        publicKeyPem: KEYS.publicKeyPem,
        autoApproveMinor: 25_000,
        ringFenceMinor: 2_500_000,
        reserveFloorMinor: 2_000_000,
        maxBalanceAgeMs: 60_000,
      },
      taint: (runId) => ({ runId }),
      liveBalance: () => ({ amountMinor: 1_000_000_000, at: NOW }),
      committer,
    });
    return { ledger, gate };
  }

  test("a commit that throws is COMMIT_FAILED and nothing is authorized", async () => {
    const { ledger, gate } = gateWith({
      commit() {
        throw new Error("checkpoint timeout");
      },
    });
    let armed = false;
    const result = await gate.authorize(input(), "swipe-1");
    if (result.decision.status === "AUTHORIZED") armed = true;
    expect(armed).toBe(false);
    expect(code(result.decision)).toBe("COMMIT_FAILED");
    expect(used(ledger)).toBe(0);
  });

  test("a commit that rejects, or returns a timeout, is COMMIT_FAILED and nothing is authorized", async () => {
    for (const committer of [
      {
        commit: async () => {
          throw new Error("s3 timeout");
        },
      },
      { commit: () => ({ ok: false as const, reason: "checkpoint PUT timed out" }) },
    ]) {
      const { ledger, gate } = gateWith(committer);
      let armed = false;
      const result = await gate.authorize(input(), "swipe-1");
      if (result.decision.status === "AUTHORIZED") armed = true;
      expect(armed).toBe(false);
      expect(code(result.decision)).toBe("COMMIT_FAILED");
      expect(used(ledger)).toBe(0);
    }
  });
});

describe("attestation PCR zeros", () => {
  const zero = "0".repeat(96);
  const p0 = "ab".repeat(48);
  const p1 = "cd".repeat(48);
  const p2 = "ef".repeat(48);
  const now = Date.UTC(2026, 10, 12);
  const nonce = new Uint8Array(32).fill(7);
  const expected: ExpectedPcrs = { pcr0: p0, pcr1: p1, pcr2: p2 };
  const bytes = (hex: string) => new Uint8Array(Buffer.from(hex, "hex"));

  test("an all-zero expected PCR0, PCR1, or PCR2 fails verification", () => {
    for (const name of ["pcr0", "pcr1", "pcr2"] as const) {
      const bad: ExpectedPcrs = { ...expected, [name]: zero };
      const result = verifyAttestation(new Uint8Array([0x01, 0x02, 0x03, 0x04]), { nonce, expected: bad, now });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe("PCR_ZERO");
    }
  });

  test("a crafted payload with an all-zero PCR0, PCR1, or PCR2 fails verification", () => {
    const good = new Map<number, Uint8Array>([
      [0, bytes(p0)],
      [1, bytes(p1)],
      [2, bytes(p2)],
    ]);
    for (const index of [0, 1, 2] as const) {
      const pcrs = new Map(good);
      pcrs.set(index, bytes(zero));
      const result = checkClaims(
        { nonce, timestamp: now - 1_000, pcrs },
        { nonce, expected, now, maxAgeMs: 300_000 },
      );
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe("PCR_ZERO");
    }
  });
});

describe("seal and decrypt key id", () => {
  test("seal-secret passes a key ARN and not an alias", () => {
    const src = readFileSync(new URL("../scripts/seal-secret.ts", import.meta.url), "utf8");
    const ids = [...src.matchAll(/--key-id",\s*"([^"]+)"/g)].map((match) => match[1] ?? "");
    expect(ids.length).toBeGreaterThan(0);
    for (const id of ids) {
      expect(id.includes("alias/")).toBe(false);
      expect(id.includes(":key/")).toBe(true);
      expect(id.startsWith("arn:aws:kms:")).toBe(true);
    }
  });

  test.todo(
    "a decrypt helper that takes a key id refuses an alias: scripts/seal-secret.ts exports none, and the decrypt path is under src/host which this suite must not import",
  );
});

describe("oversized remote auth body", () => {
  test("a body over 32 KiB is declined before parse and before decide", async () => {
    let calls = 0;
    const raw = v2({ card_id: "card-other", padding: "x".repeat(MAX_BODY_BYTES) });
    expect(new TextEncoder().encode(raw).byteLength).toBeGreaterThan(MAX_BODY_BYTES);
    const res = await handleRemoteAuth(
      ra({
        rawBody: raw,
        decide: () => {
          calls += 1;
          return { status: "AUTHORIZED", writId: "writ-1", reason: "no" };
        },
      }),
    );
    expect(calls).toBe(0);
    expect(res.body).toEqual({ card_transaction_event_id: "", response_status: "DECLINED", status_reason: "body too large" });
  });
});

describe("remote auth body for a different card", () => {
  test("a valid nonce whose body names another card reaches decide and is NO_WRIT_FOR_CARD", async () => {
    const { ledger, gate } = setup();
    ledger.registerWrit(signed(), "card-1", APPROVED_AT);
    let calls = 0;
    let decision: Decision | undefined;
    const res = await handleRemoteAuth(
      ra({
        rawBody: v2({ card_id: "card-2" }),
        decide: async (swipeInput, eventId) => {
          calls += 1;
          expect(swipeInput.cardId).toBe("card-2");
          expect(swipeInput.ra).toEqual({ signatureValid: true, nonceFresh: true, nonceSeen: false });
          const result = await gate.authorize(swipeInput, eventId);
          decision = result.decision;
          return result.decision;
        },
      }),
    );
    expect(calls).toBe(1);
    expect(code(decision)).toBe("NO_WRIT_FOR_CARD");
    expect(res.body.response_status).toBe("DECLINED");
    expect(used(ledger)).toBe(0);
  });
});

describe("merchant unicode lookalike", () => {
  test("a Cyrillic a in DataCo is MERCHANT_NOT_IN_WRIT", async () => {
    const lookalike = `D${String.fromCharCode(0x0430)}taCo`;
    expect(normalizeMerchant(lookalike)).not.toBe(normalizeMerchant("DataCo"));
    const { decision } = await swipe({ merchantName: lookalike });
    expect(code(decision)).toBe("MERCHANT_NOT_IN_WRIT");
  });
});

describe("amount is not a positive whole number of cents", () => {
  test("179.99, a negative amount, and zero are declined", async () => {
    for (const amountMinor of [179.99, -19_500, 0]) {
      const { ledger, decision } = await swipe({ amountMinor });
      expect(decision.status).toBe("DECLINED");
      expect(code(decision)).toBe("INTERNAL_ERROR");
      expect(used(ledger)).toBe(0);
    }
  });
});
