import { describe, expect, test } from "bun:test";
import { decide } from "../src/core/decide";
import { normalizeMerchant } from "../src/core/merchant";
import { verifyWrit } from "../src/core/writ";
import type { ApprovedTask, Decision, DeclineCode } from "../src/types";
import { DECLINE_CODES } from "../src/types";
import { input, OTHER_KEYS, signed, state } from "./helpers";

const code = (d: Decision) => (d.status === "DECLINED" ? d.code : "AUTHORIZED");
const raOk = { nonceFresh: true, nonceSeen: false, signatureValid: true };

describe("decide: happy path", () => {
  test("a matching swipe on a valid writ is authorized with numbers in the reason", () => {
    const d = decide(input(), state());
    expect(d.status).toBe("AUTHORIZED");
    expect(d.reason).toContain("$180");
    expect(d.reason).toContain("$500");
  });

  test("a lower amount than approved passes", () => {
    expect(code(decide(input({ amountMinor: 15000 }), state()))).toBe("AUTHORIZED");
  });

  test("RA mode passes with a valid request", () => {
    expect(code(decide(input({ mode: "ra", ra: raOk }), state()))).toBe("AUTHORIZED");
  });

  test("deterministic: same input, same output", () => {
    const i = input();
    const s = state();
    expect(JSON.stringify(decide(i, s))).toBe(JSON.stringify(decide(i, s)));
  });
});

describe("decide: one test per decline code", () => {
  const cases: [DeclineCode, () => Decision][] = [
    ["STATE_UNVERIFIED", () => decide(input(), state(signed(), { chainVerified: false }))],
    ["RA_BAD_SIGNATURE", () => decide(input({ mode: "ra", ra: { ...raOk, signatureValid: false } }), state())],
    ["RA_STALE_NONCE", () => decide(input({ mode: "ra", ra: { ...raOk, nonceFresh: false } }), state())],
    ["RA_NONCE_REPLAY", () => decide(input({ mode: "ra", ra: { ...raOk, nonceSeen: true } }), state())],
    ["NO_WRIT_FOR_CARD", () => decide(input(), { writSignatureValid: false, writHashValid: false, taint: { runId: "" } })],
    [
      "WRIT_BAD_SIGNATURE",
      () => {
        const w = signed();
        const check = verifyWrit(w, OTHER_KEYS.publicKeyPem, { autoApproveMinor: 25000, knownMerchants: [] });
        return decide(input(), state(w, { writSignatureValid: check.signatureValid, writHashValid: check.hashValid }));
      },
    ],
    [
      "WRIT_HASH_MISMATCH",
      () => {
        const w: ApprovedTask = { ...signed(), amountMinor: 99900 };
        return decide(input({ amountMinor: 99900 }), state(w));
      },
    ],
    ["WRIT_EXPIRED", () => decide(input({ now: "2026-11-12T09:00:00.000Z" }), state())],
    ["WRIT_REPLAY", () => decide(input(), state(signed(), { writStatus: "consumed" }))],
    ["WRIT_REVOKED", () => decide(input(), state(signed(), { writStatus: "revoked" }))],
    ["CURRENCY_NOT_IN_WRIT", () => decide(input({ currency: "EUR" }), state())],
    ["MCC_NOT_IN_WRIT", () => decide(input({ mcc: "5999" }), state())],
    ["MERCHANT_NOT_IN_WRIT", () => decide(input({ merchantName: "Enterprise Plans Inc" }), state())],
    ["AMOUNT_OVER_WRIT", () => decide(input({ amountMinor: 19500 }), state())],
    [
      "TAINTED_RUN",
      () => decide(input(), state(signed(), { taint: { runId: "run-1", taintedAt: "2026-11-12T08:31:00.000Z", source: "https://evil.example" } })),
    ],
    [
      "TEAM_POOL_EXHAUSTED",
      () =>
        decide(
          input({ amountMinor: 6000 }),
          state(signed({ amountMinor: 6000 }), {
            ledger: { team: "research", poolLimitMinor: 50000, reservedMinor: 0, pendingMinor: 18000, settledMinor: 30000, releasedMinor: 0, alerts: 0 },
          }),
        ),
    ],
    [
      "BALANCE_STALE",
      () =>
        decide(
          input(),
          state(signed(), {
            reserve: { liveBalanceMinor: 1_000_000_000, ringFenceMinor: 2_500_000, reserveFloorMinor: 2_000_000, openReservationsMinor: 0, asOf: "2026-11-12T08:33:59.999Z" },
          }),
        ),
    ],
    [
      "RESERVE_FLOOR",
      () =>
        decide(
          input(),
          state(signed(), { reserve: { liveBalanceMinor: 1_000_000_000, ringFenceMinor: 2_010_000, reserveFloorMinor: 2_000_000, openReservationsMinor: 0 } }),
        ),
    ],
    [
      "UPSTREAM_ERROR",
      () => {
        const { reserve: _r, ...rest } = state();
        return decide(input(), rest);
      },
    ],
    ["INTERNAL_ERROR", () => decide(input({ amountMinor: 180.5 }), state())],
  ];

  for (const [expected, run] of cases) {
    test(expected, () => {
      const d = run();
      expect(code(d)).toBe(expected);
      expect(d.reason.length).toBeGreaterThan(0);
    });
  }

  test("every code decide() can return is covered", () => {
    const covered = new Set<DeclineCode>(cases.map(([c]) => c));
    const gateOnly = new Set<DeclineCode>(["COMMIT_FAILED"]); // test/commit-chain.test.ts
    expect(DECLINE_CODES.filter((c) => !covered.has(c) && !gateOnly.has(c))).toEqual([]);
  });

  test("pool reason says how much is used and needed", () => {
    const d = cases.find(([c]) => c === "TEAM_POOL_EXHAUSTED")![1]();
    expect(d.reason).toBe("Team budget used up: $480 of $500 spent or held, this needs $60.");
  });
});

describe("decide: order and edges", () => {
  test("first failure wins: bad RA signature beats a missing writ", () => {
    const d = decide(input({ mode: "ra", ra: { ...raOk, signatureValid: false } }), { writSignatureValid: false, writHashValid: false, taint: { runId: "" } });
    expect(code(d)).toBe("RA_BAD_SIGNATURE");
  });

  test("STATE_UNVERIFIED beats every later failure, including RA auth", () => {
    const d = decide(input({ mode: "ra", ra: { ...raOk, signatureValid: false } }), { chainVerified: false, writSignatureValid: false, writHashValid: false, taint: { runId: "" } });
    expect(code(d)).toBe("STATE_UNVERIFIED");
    expect(code(decide(input({ amountMinor: 99900 }), state(signed(), { chainVerified: false })))).toBe("STATE_UNVERIFIED");
  });

  test("chainVerified absent or true does not decline", () => {
    expect(code(decide(input(), state()))).toBe("AUTHORIZED");
    expect(code(decide(input(), state(signed(), { chainVerified: true })))).toBe("AUTHORIZED");
  });

  test("BALANCE_STALE beats RESERVE_FLOOR, and TEAM_POOL_EXHAUSTED beats BALANCE_STALE", () => {
    const stale = { liveBalanceMinor: 1_000_000_000, ringFenceMinor: 2_010_000, reserveFloorMinor: 2_000_000, openReservationsMinor: 0, asOf: "2026-11-12T08:30:00.000Z" };
    expect(code(decide(input(), state(signed(), { reserve: stale })))).toBe("BALANCE_STALE");
    const full = { team: "research", poolLimitMinor: 50000, reservedMinor: 0, pendingMinor: 0, settledMinor: 40000, releasedMinor: 0, alerts: 0 };
    expect(code(decide(input(), state(signed(), { reserve: stale, ledger: full })))).toBe("TEAM_POOL_EXHAUSTED");
  });

  test("balance age: exactly the limit passes, one ms over is stale, maxAgeMs overrides the 60 s default", () => {
    const base = { liveBalanceMinor: 1_000_000_000, ringFenceMinor: 2_500_000, reserveFloorMinor: 2_000_000, openReservationsMinor: 0 };
    expect(code(decide(input(), state(signed(), { reserve: { ...base, asOf: "2026-11-12T08:34:00.000Z" } })))).toBe("AUTHORIZED");
    expect(code(decide(input(), state(signed(), { reserve: { ...base, asOf: "2026-11-12T08:33:59.999Z" } })))).toBe("BALANCE_STALE");
    expect(code(decide(input(), state(signed(), { reserve: { ...base, asOf: "2026-11-12T08:34:55.000Z", maxAgeMs: 1000 } })))).toBe("BALANCE_STALE");
    expect(code(decide(input(), state(signed(), { reserve: { ...base, asOf: "not a time" } })))).toBe("BALANCE_STALE");
  });

  test("a reserve with no asOf keeps the floor check, and a missing reserve stays UPSTREAM_ERROR", () => {
    const { reserve: _r, ...rest } = state();
    expect(code(decide(input(), rest))).toBe("UPSTREAM_ERROR");
    expect(code(decide(input(), state()))).toBe("AUTHORIZED");
  });

  test("RA mode with no ra block fails closed", () => {
    expect(code(decide(input({ mode: "ra" }), state()))).toBe("RA_BAD_SIGNATURE");
  });

  test("signature is checked before expiry, expiry before replay", () => {
    expect(code(decide(input({ now: "2026-11-12T10:00:00.000Z" }), state(signed(), { writSignatureValid: false })))).toBe("WRIT_BAD_SIGNATURE");
    expect(code(decide(input({ now: "2026-11-12T10:00:00.000Z" }), state(signed(), { writStatus: "consumed" })))).toBe("WRIT_EXPIRED");
  });

  test("taint before approval does not block", () => {
    const s = state(signed(), { taint: { runId: "run-1", taintedAt: "2026-11-12T08:29:59.999Z" } });
    expect(code(decide(input(), s))).toBe("AUTHORIZED");
  });

  test("taint at exactly the approval time blocks", () => {
    const s = state(signed(), { taint: { runId: "run-1", taintedAt: "2026-11-12T08:30:00.000Z" } });
    expect(code(decide(input(), s))).toBe("TAINTED_RUN");
  });

  test("unreadable taint time fails closed", () => {
    const s = state(signed(), { taint: { runId: "run-1", taintedAt: "yesterday" } });
    expect(code(decide(input(), s))).toBe("TAINTED_RUN");
  });

  test("pool exactly full passes, one cent over fails", () => {
    const ledger = { team: "research", poolLimitMinor: 50000, reservedMinor: 10000, pendingMinor: 12000, settledMinor: 10000, releasedMinor: 0, alerts: 0 };
    expect(code(decide(input(), state(signed(), { ledger })))).toBe("AUTHORIZED");
    expect(code(decide(input(), state(signed(), { ledger: { ...ledger, settledMinor: 10001 } })))).toBe("TEAM_POOL_EXHAUSTED");
  });

  test("a frozen team declines TEAM_POOL_EXHAUSTED even with pool room, after taint and before balance checks", () => {
    const ledger = { team: "research", poolLimitMinor: 50000, reservedMinor: 0, pendingMinor: 0, settledMinor: 0, releasedMinor: 0, alerts: 1 };
    const teamFrozen = { at: "2026-11-12T08:20:00.000Z", reason: "Forced capture of $70 with no approval." };
    const d = decide(input(), state(signed(), { ledger: { ...ledger, teamFrozen } }));
    expect(code(d)).toBe("TEAM_POOL_EXHAUSTED");
    expect(d.reason).toContain("frozen");
    expect(d.reason).toContain("Forced capture");
    const tainted = { runId: "run-1", taintedAt: "2026-11-12T08:31:00.000Z" };
    expect(code(decide(input(), state(signed(), { ledger: { ...ledger, teamFrozen }, taint: tainted })))).toBe("TAINTED_RUN");
    const stale = { liveBalanceMinor: 1_000_000_000, ringFenceMinor: 2_500_000, reserveFloorMinor: 2_000_000, openReservationsMinor: 0, asOf: "2026-11-12T08:00:00.000Z" };
    expect(code(decide(input(), state(signed(), { ledger: { ...ledger, teamFrozen }, reserve: stale })))).toBe("TEAM_POOL_EXHAUSTED");
    expect(code(decide(input(), state(signed(), { ledger })))).toBe("AUTHORIZED");
  });

  test("reserve uses the lower of live balance and ring fence, and counts open reservations", () => {
    const reserve = { liveBalanceMinor: 2_030_000, ringFenceMinor: 2_500_000, reserveFloorMinor: 2_000_000, openReservationsMinor: 12_000 };
    expect(code(decide(input(), state(signed(), { reserve })))).toBe("AUTHORIZED");
    expect(code(decide(input(), state(signed(), { reserve: { ...reserve, openReservationsMinor: 12_001 } })))).toBe("RESERVE_FLOOR");
  });

  test("merchant match ignores case and spacing", () => {
    expect(code(decide(input({ merchantName: "  dataco " }), state()))).toBe("AUTHORIZED");
  });

  test("merchant match strips the trailing underscores Airwallex pads names with", () => {
    expect(normalizeMerchant("DATACO_____________________")).toBe(normalizeMerchant("DataCo"));
    expect(code(decide(input({ merchantName: "DATACO_____________________" }), state()))).toBe("AUTHORIZED");
    expect(code(decide(input({ merchantName: "DATACOX____" }), state()))).toBe("MERCHANT_NOT_IN_WRIT");
  });

  test("ledger for another team fails closed", () => {
    const s = state();
    s.ledger = { ...s.ledger!, team: "growth" };
    expect(code(decide(input(), s))).toBe("INTERNAL_ERROR");
  });

  test("taint state for another run fails closed", () => {
    expect(code(decide(input(), state(signed(), { taint: { runId: "run-2" } })))).toBe("INTERNAL_ERROR");
  });

  test("a throwing state getter is caught and declined", () => {
    const s = state();
    Object.defineProperty(s, "ledger", { get: () => { throw new Error("boom"); } });
    expect(code(decide(input(), s))).toBe("INTERNAL_ERROR");
  });
});
