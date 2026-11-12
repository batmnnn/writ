import { describe, expect, test } from "bun:test";
import { Gate } from "../src/core/gate";
import { Ledger } from "../src/core/ledger";
import { TaintRegistry } from "../src/core/taint";
import type { Decision } from "../src/types";
import { APPROVED_AT, input, KEYS, NOW, signed } from "./helpers";

const T0 = "2026-11-12T08:00:00.000Z";

function setup(poolLimitMinor = 50000, liveBalanceMinor = 1_000_000_000) {
  const ledger = new Ledger();
  ledger.setTeam("research", poolLimitMinor, T0);
  ledger.registerCard("card-1", "research", "research-1", T0);
  ledger.registerCard("card-2", "research", "research-2", T0);
  const taint = new TaintRegistry();
  const gate = new Gate({
    ledger,
    config: { publicKeyPem: KEYS.publicKeyPem, autoApproveMinor: 25000, ringFenceMinor: 2_500_000, reserveFloorMinor: 2_000_000, maxBalanceAgeMs: 60_000 },
    taint: (runId) => taint.get(runId),
    liveBalance: () => ({ amountMinor: liveBalanceMinor, at: NOW }),
  });
  return { ledger, gate, taint };
}

const code = (d: Decision) => (d.status === "DECLINED" ? d.code : "AUTHORIZED");

describe("ledger: append only and idempotent", () => {
  test("UPDATE and DELETE on events are refused by the database", () => {
    const { ledger } = setup();
    ledger.registerWrit(signed(), "card-1", APPROVED_AT);
    expect(() => ledger.db.exec("UPDATE events SET amount_minor = 0")).toThrow("append only");
    expect(() => ledger.db.exec("UPDATE writs SET body = '{}'")).toThrow("append only");
    expect(() => ledger.db.exec("DELETE FROM events")).toThrow("append only");
    expect(() => ledger.db.exec("DELETE FROM writs")).toThrow("append only");
  });

  test("the same Airwallex event id twice changes nothing", () => {
    const { ledger } = setup();
    const w = signed();
    ledger.registerWrit(w, "card-1", APPROVED_AT);
    ledger.commitApproval({ eventId: "d1", writ: w, cardId: "card-1", amountMinor: 18000, at: NOW, decision: { status: "AUTHORIZED", writId: w.id, reason: "ok" } });
    const e = { eventId: "awx-auth-1", cardId: "card-1", writId: w.id, amountMinor: 18000, at: NOW };
    expect(ledger.onAuthorization(e).duplicate).toBe(false);
    expect(ledger.onAuthorization(e).duplicate).toBe(true);
    expect(ledger.snapshot("research")).toMatchObject({ reservedMinor: 0, pendingMinor: 18000, settledMinor: 0 });
  });

  test("a card holds one open writ at a time and writ ids cannot be reused with new content", () => {
    const { ledger } = setup();
    ledger.registerWrit(signed(), "card-1", APPROVED_AT);
    expect(() => ledger.registerWrit(signed({ id: "writ-2", nonce: "n-2" }), "card-1", APPROVED_AT)).toThrow("open writ");
    expect(() => ledger.registerWrit(signed({ amountMinor: 100 }), "card-2", APPROVED_AT)).toThrow("different content");
  });

  test("a writ cannot be bound to another team's card", () => {
    const { ledger } = setup();
    ledger.setTeam("growth", 200000, T0);
    ledger.registerCard("card-g", "growth", "growth-1", T0);
    expect(() => ledger.registerWrit(signed(), "card-g", APPROVED_AT)).toThrow("belongs to team growth");
  });
});

describe("ledger: money lifecycle", () => {
  function approved() {
    const s = setup();
    const w = signed();
    s.ledger.registerWrit(w, "card-1", APPROVED_AT);
    s.ledger.commitApproval({ eventId: "d1", writ: w, cardId: "card-1", amountMinor: 18000, at: NOW, decision: { status: "AUTHORIZED", writId: w.id, reason: "ok" } });
    return { ...s, w };
  }

  test("approve reserves, authorize moves to pending, clearing settles", () => {
    const { ledger, w } = approved();
    expect(ledger.snapshot("research")).toMatchObject({ reservedMinor: 18000, pendingMinor: 0, settledMinor: 0 });
    ledger.onAuthorization({ eventId: "a1", cardId: "card-1", writId: w.id, amountMinor: 15000, at: NOW });
    expect(ledger.snapshot("research")).toMatchObject({ reservedMinor: 0, pendingMinor: 15000, releasedMinor: 3000 });
    ledger.onClearing({ eventId: "c1", cardId: "card-1", writId: w.id, amountMinor: 10000, at: NOW });
    ledger.onClearing({ eventId: "c2", cardId: "card-1", writId: w.id, amountMinor: 5000, at: NOW });
    expect(ledger.snapshot("research")).toMatchObject({ pendingMinor: 0, settledMinor: 15000, alerts: 0 });
  });

  test("reversal and expiry release, refund credits settled", () => {
    const { ledger, w } = approved();
    ledger.onAuthorization({ eventId: "a1", cardId: "card-1", writId: w.id, amountMinor: 18000, at: NOW });
    ledger.onReversal({ eventId: "r1", cardId: "card-1", writId: w.id, amountMinor: 8000, at: NOW });
    expect(ledger.snapshot("research")).toMatchObject({ pendingMinor: 10000 });
    ledger.onClearing({ eventId: "c1", cardId: "card-1", writId: w.id, amountMinor: 6000, at: NOW });
    ledger.onExpiry({ eventId: "e1", cardId: "card-1", writId: w.id, amountMinor: 4000, at: NOW });
    expect(ledger.snapshot("research")).toMatchObject({ reservedMinor: 0, pendingMinor: 0, settledMinor: 6000 });
    ledger.onRefund({ eventId: "f1", cardId: "card-1", writId: w.id, amountMinor: 2500, at: NOW });
    expect(ledger.snapshot("research")).toMatchObject({ settledMinor: 3500 });
  });

  test("clearing above the approved amount counts in full and raises an alert", () => {
    const { ledger, w } = approved();
    ledger.onAuthorization({ eventId: "a1", cardId: "card-1", writId: w.id, amountMinor: 18000, at: NOW });
    const out = ledger.onClearing({ eventId: "c1", cardId: "card-1", writId: w.id, amountMinor: 19500, at: NOW });
    expect(out.alert).toBe(true);
    expect(ledger.snapshot("research")).toMatchObject({ pendingMinor: 0, settledMinor: 19500, alerts: 1 });
  });

  test("forced capture with no approval counts, alerts and freezes the team", () => {
    const { ledger } = setup();
    const out = ledger.onForcedCapture({ eventId: "fc1", cardId: "card-2", amountMinor: 7000, at: NOW });
    expect(out).toMatchObject({ alert: true, freezeTeam: true, team: "research" });
    expect(ledger.snapshot("research")).toMatchObject({ settledMinor: 7000, alerts: 1 });
    expect(ledger.events({ kind: "FREEZE" })).toHaveLength(1);
    expect(ledger.snapshot("research")!.teamFrozen?.at).toBe(NOW);
  });

  test("a matched clearing does not freeze the team, and commitApproval refuses a frozen team", () => {
    const { ledger, w } = approved();
    ledger.onClearing({ eventId: "c1", cardId: "card-1", writId: w.id, amountMinor: 18000, at: NOW });
    expect(ledger.snapshot("research")!.teamFrozen).toBeUndefined();
    ledger.onForcedCapture({ eventId: "fc1", cardId: "card-2", amountMinor: 100, at: NOW });
    const w2 = signed({ id: "writ-2", nonce: "n-2" });
    ledger.registerWrit(w2, "card-2", APPROVED_AT);
    expect(() =>
      ledger.commitApproval({ eventId: "d2", writ: w2, cardId: "card-2", amountMinor: 100, at: NOW, decision: { status: "AUTHORIZED", writId: w2.id, reason: "ok" } }),
    ).toThrow("frozen");
    expect(ledger.wasConsumed(w2.id)).toBe(false);
  });

  test("clearing with no matching writ counts, alerts and freezes", () => {
    const { ledger } = setup();
    const out = ledger.onClearing({ eventId: "c9", cardId: "card-2", writId: "never-approved", amountMinor: 4000, at: NOW });
    expect(out).toMatchObject({ alert: true, freezeTeam: true });
    expect(ledger.snapshot("research")!.settledMinor).toBe(4000);
  });

  test("a refund with no matching writ frees nothing", () => {
    const { ledger } = setup();
    ledger.onForcedCapture({ eventId: "fc1", cardId: "card-2", amountMinor: 7000, at: NOW });
    ledger.onRefund({ eventId: "f9", cardId: "card-2", amountMinor: 7000, at: NOW });
    expect(ledger.snapshot("research")!.settledMinor).toBe(7000);
  });

  test("revoking an armed writ releases its hold, later card events still match it", () => {
    const { ledger, w } = approved();
    ledger.revokeWrit(w.id, NOW, "Run tainted");
    expect(ledger.snapshot("research")).toMatchObject({ reservedMinor: 0, releasedMinor: 18000 });
    const out = ledger.onClearing({ eventId: "c1", cardId: "card-1", writId: w.id, amountMinor: 18000, at: NOW });
    expect(out.freezeTeam).toBe(false);
    expect(ledger.snapshot("research")!.settledMinor).toBe(18000);
  });
});

describe("gate: the money path", () => {
  test("approves once, then the same writ is a replay", async () => {
    const { ledger, gate } = setup();
    ledger.registerWrit(signed(), "card-1", APPROVED_AT);
    const first = await gate.authorize(input(), "swipe-1");
    expect(code(first.decision)).toBe("AUTHORIZED");
    expect(ledger.writStatus("writ-1")).toBe("consumed");
    expect(ledger.snapshot("research")!.reservedMinor).toBe(18000);
    const again = await gate.authorize(input(), "swipe-2");
    expect(code(again.decision)).toBe("WRIT_REPLAY");
  });

  test("the same event id returns the recorded decision without a second reservation", async () => {
    const { ledger, gate } = setup();
    ledger.registerWrit(signed(), "card-1", APPROVED_AT);
    await gate.authorize(input(), "swipe-1");
    const repeat = await gate.authorize(input(), "swipe-1");
    expect(code(repeat.decision)).toBe("AUTHORIZED");
    expect(ledger.snapshot("research")!.reservedMinor).toBe(18000);
  });

  test("unknown card is declined and logged", async () => {
    const { ledger, gate } = setup();
    const r = await gate.authorize(input({ cardId: "card-x" }), "swipe-x");
    expect(code(r.decision)).toBe("NO_WRIT_FOR_CARD");
    expect(ledger.events({ kind: "DECISION" })).toHaveLength(1);
  });

  test("taint after approval declines and asks for a card freeze", async () => {
    const { ledger, gate, taint } = setup();
    ledger.registerWrit(signed(), "card-1", APPROVED_AT);
    taint.mark("run-1", "https://evil.example/buy", "2026-11-12T08:32:00.000Z");
    const r = await gate.authorize(input(), "swipe-1");
    expect(code(r.decision)).toBe("TAINTED_RUN");
    expect(r.freezeCard).toBe(true);
    expect(ledger.snapshot("research")!.reservedMinor).toBe(0);
  });

  function balanceGate(liveBalance: () => { amountMinor: number; at: string } | undefined) {
    const ledger = new Ledger();
    ledger.setTeam("research", 50000, T0);
    ledger.registerCard("card-1", "research", "research-1", T0);
    ledger.registerWrit(signed(), "card-1", APPROVED_AT);
    return new Gate({
      ledger,
      config: { publicKeyPem: KEYS.publicKeyPem, autoApproveMinor: 25000, ringFenceMinor: 2_500_000, reserveFloorMinor: 2_000_000, maxBalanceAgeMs: 60_000 },
      taint: (runId) => ({ runId }),
      liveBalance,
    });
  }

  test("stale live balance declines BALANCE_STALE", async () => {
    const gate = balanceGate(() => ({ amountMinor: 1_000_000_000, at: "2026-11-12T08:00:00.000Z" }));
    expect(code((await gate.authorize(input(), "s1")).decision)).toBe("BALANCE_STALE");
  });

  test("a live balance with an unreadable time declines BALANCE_STALE", async () => {
    const gate = balanceGate(() => ({ amountMinor: 1_000_000_000, at: "yesterday" }));
    expect(code((await gate.authorize(input(), "s1")).decision)).toBe("BALANCE_STALE");
  });

  test("a balance exactly at the age limit is fresh and passes the floor check", async () => {
    const gate = balanceGate(() => ({ amountMinor: 1_000_000_000, at: "2026-11-12T08:34:00.000Z" }));
    expect(code((await gate.authorize(input(), "s1")).decision)).toBe("AUTHORIZED");
  });

  test("a fresh balance under the floor still declines RESERVE_FLOOR", async () => {
    const gate = balanceGate(() => ({ amountMinor: 2_010_000, at: NOW }));
    expect(code((await gate.authorize(input(), "s1")).decision)).toBe("RESERVE_FLOOR");
  });

  test("a missing live balance stays UPSTREAM_ERROR", async () => {
    const gate = balanceGate(() => undefined);
    expect(code((await gate.authorize(input(), "s1")).decision)).toBe("UPSTREAM_ERROR");
  });

  test("a throwing dependency is declined, not thrown", async () => {
    const { ledger } = setup();
    ledger.registerWrit(signed(), "card-1", APPROVED_AT);
    const gate = new Gate({
      ledger,
      config: { publicKeyPem: KEYS.publicKeyPem, autoApproveMinor: 25000, ringFenceMinor: 2_500_000, reserveFloorMinor: 2_000_000, maxBalanceAgeMs: 60_000 },
      taint: () => {
        throw new Error("taint store down");
      },
      liveBalance: () => ({ amountMinor: 1, at: NOW }),
    });
    expect(code((await gate.authorize(input(), "s1")).decision)).toBe("INTERNAL_ERROR");
  });

  test("open reservations of other teams count against the shared cash reserve", async () => {
    const { ledger, gate } = setup(50000, 2_030_000);
    ledger.setTeam("growth", 200000, T0);
    ledger.registerCard("card-g", "growth", "growth-1", T0);
    ledger.registerWrit(signed({ id: "w-g", team: "growth", agent: "growth-1", runId: "run-g", nonce: "g" }), "card-g", APPROVED_AT);
    expect(code((await gate.authorize(input({ cardId: "card-g" }), "g1")).decision)).toBe("AUTHORIZED");
    ledger.registerWrit(signed(), "card-1", APPROVED_AT);
    expect(code((await gate.authorize(input(), "r1")).decision)).toBe("RESERVE_FLOOR");
  });

  test("decisions and declines are all in the event log with reasons", async () => {
    const { ledger, gate } = setup();
    ledger.registerWrit(signed(), "card-1", APPROVED_AT);
    await gate.authorize(input({ amountMinor: 99900 }), "s1");
    const [d] = ledger.events({ kind: "DECISION" });
    expect(d!.reason).toStartWith("AMOUNT_OVER_WRIT:");
  });
});
