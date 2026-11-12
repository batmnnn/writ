// Property test: 1000 random sequences on one team with concurrent authorizations.
// Along every writ gated path, reserved + pending + settled never exceeds the team pool.

import { describe, expect, test } from "bun:test";
import { Gate } from "../src/core/gate";
import { Ledger } from "../src/core/ledger";
import { KeyedMutex } from "../src/core/mutex";
import { signWrit } from "../src/core/writ";
import type { ApprovedTask } from "../src/types";
import { KEYS, rng } from "./helpers";

const T0 = "2026-11-12T08:00:00.000Z";
const APPROVED = "2026-11-12T08:30:00.000Z";
const NOW = "2026-11-12T08:35:00.000Z";
const CARDS = ["c1", "c2", "c3", "c4"] as const;

function world(poolLimitMinor: number) {
  const ledger = new Ledger();
  ledger.setTeam("t", poolLimitMinor, T0);
  for (const c of CARDS) ledger.registerCard(c, "t", `agent-${c}`, T0);
  const gate = new Gate({
    ledger,
    config: { publicKeyPem: KEYS.publicKeyPem, autoApproveMinor: 0, ringFenceMinor: 1_000_000_000, reserveFloorMinor: 0, maxBalanceAgeMs: 60_000 },
    taint: (runId) => ({ runId }),
    liveBalance: () => ({ amountMinor: 1_000_000_000, at: NOW }),
  });
  return { ledger, gate };
}

let writSeq = 0;
function writFor(card: string, amountMinor: number): ApprovedTask {
  writSeq += 1;
  return signWrit(
    {
      id: `w${writSeq}`,
      team: "t",
      agent: `agent-${card}`,
      runId: `run-${writSeq}`,
      purpose: "property",
      merchantName: "DataCo",
      mcc: "5734",
      amountMinor,
      currency: "USD",
      expiresAt: "2026-11-12T09:00:00.000Z",
      nonce: `n${writSeq}`,
    },
    APPROVED,
    KEYS.privateKeyPem,
  );
}

const swipe = (cardId: string, amountMinor: number) => ({
  mode: "frozen" as const,
  cardId,
  amountMinor,
  currency: "USD",
  mcc: "5734",
  merchantName: "DataCo",
  now: NOW,
});

const used = (l: Ledger) => {
  const s = l.snapshot("t")!;
  return s.reservedMinor + s.pendingMinor + s.settledMinor;
};

describe("team pool property", () => {
  test("1000 random gated sequences with concurrent swipes never exceed the pool", async () => {
    const r = rng(20261112);
    let approvals = 0;
    let poolDeclines = 0;
    for (let seq = 0; seq < 1000; seq++) {
      const pool = r.int(1_000, 60_000);
      const { ledger, gate } = world(pool);
      // per writ: authorized, cleared and still pending amounts, to keep events within what was approved
      const live = new Map<string, { card: string; reserved: number; authorized: number; cleared: number; refunded: number; open: boolean }>();
      let eid = 0;
      const id = () => `e${seq}-${++eid}`;

      for (let step = 0; step < 14; step++) {
        const op = r.pick(["race", "race", "auth", "clear", "reverse", "expire", "refund"] as const);
        if (op === "race") {
          const free = CARDS.filter((c) => {
            const f = ledger.writForCard(c);
            return !f || f.status !== "approved";
          });
          const pickTwo = free.slice(0, 2);
          const ws = pickTwo.map((c) => ({ c, w: writFor(c, r.int(1, Math.max(1, Math.floor(pool * 0.7)))) }));
          for (const { c, w } of ws) ledger.registerWrit(w, c, APPROVED);
          const results = await Promise.all(ws.map(({ c, w }) => gate.authorize(swipe(c, r.int(1, w.amountMinor)), id())));
          results.forEach((res, i) => {
            const { c, w } = ws[i]!;
            if (res.decision.status === "AUTHORIZED") {
              approvals++;
              const reservedEv = ledger.events({ kind: "RESERVE" }).filter((e) => e.writId === w.id);
              live.set(w.id, { card: c, reserved: reservedEv[0]!.amountMinor, authorized: 0, cleared: 0, refunded: 0, open: true });
            } else if (res.decision.code === "TEAM_POOL_EXHAUSTED") {
              poolDeclines++;
              ledger.revokeWrit(w.id, NOW, "declined");
            } else {
              throw new Error(`unexpected decline ${res.decision.code}: ${res.decision.reason}`);
            }
          });
        } else {
          const entries = [...live.entries()].filter(([, v]) => v.open);
          if (entries.length === 0) continue;
          const [writId, v] = r.pick(entries);
          if (op === "auth" && v.authorized === 0 && v.reserved > 0) {
            const amt = r.int(1, v.reserved);
            ledger.onAuthorization({ eventId: id(), cardId: v.card, writId, amountMinor: amt, at: NOW });
            v.authorized = amt;
            v.reserved = 0;
          } else if (op === "clear" && v.authorized > v.cleared) {
            const amt = r.int(1, v.authorized - v.cleared);
            ledger.onClearing({ eventId: id(), cardId: v.card, writId, amountMinor: amt, at: NOW });
            v.cleared += amt;
          } else if (op === "reverse" && v.authorized > v.cleared) {
            const amt = r.int(1, v.authorized - v.cleared);
            ledger.onReversal({ eventId: id(), cardId: v.card, writId, amountMinor: amt, at: NOW });
            v.authorized -= amt;
          } else if (op === "expire") {
            ledger.onExpiry({ eventId: id(), cardId: v.card, writId, amountMinor: v.reserved + v.authorized - v.cleared, at: NOW });
            v.open = false;
          } else if (op === "refund" && v.cleared > v.refunded) {
            const amt = r.int(1, v.cleared - v.refunded);
            ledger.onRefund({ eventId: id(), cardId: v.card, writId, amountMinor: amt, at: NOW });
            v.refunded += amt;
          }
        }
        expect(used(ledger)).toBeLessThanOrEqual(pool);
        expect(ledger.snapshot("t")!.alerts).toBe(0);
      }
      ledger.close();
    }
    expect(approvals).toBeGreaterThan(500);
    expect(poolDeclines).toBeGreaterThan(100);
  });

  test("two concurrent swipes that each fit but not together: exactly one passes", async () => {
    for (let i = 0; i < 50; i++) {
      const { ledger, gate } = world(50_000);
      const a = writFor("c1", 30_000);
      const b = writFor("c2", 30_000);
      ledger.registerWrit(a, "c1", APPROVED);
      ledger.registerWrit(b, "c2", APPROVED);
      const [ra, rb] = await Promise.all([gate.authorize(swipe("c1", 30_000), `a${i}`), gate.authorize(swipe("c2", 30_000), `b${i}`)]);
      const passed = [ra!, rb!].filter((x) => x.decision.status === "AUTHORIZED");
      expect(passed).toHaveLength(1);
      expect(used(ledger)).toBe(30_000);
    }
  });

  test("forced captures and unmatched clearings always alert, and the pool then blocks new spend", () => {
    const r = rng(7);
    for (let i = 0; i < 200; i++) {
      const { ledger } = world(10_000);
      const n = r.int(1, 5);
      for (let k = 0; k < n; k++) {
        const out = r.next() < 0.5
          ? ledger.onForcedCapture({ eventId: `fc${i}-${k}`, cardId: "c1", amountMinor: r.int(1, 8_000), at: NOW })
          : ledger.onClearing({ eventId: `uc${i}-${k}`, cardId: "c2", amountMinor: r.int(1, 8_000), at: NOW });
        expect(out.alert && out.freezeTeam).toBe(true);
      }
      expect(ledger.snapshot("t")!.alerts).toBe(n);
      expect(ledger.events({ kind: "FREEZE" })).toHaveLength(n);
    }
  });

  test("keyed mutex runs one writer per key", async () => {
    const m = new KeyedMutex();
    const log: string[] = [];
    const job = (k: string, tag: string) =>
      m.run(k, async () => {
        log.push(`${tag}+`);
        await Bun.sleep(1);
        log.push(`${tag}-`);
      });
    await Promise.all([job("t", "a"), job("t", "b"), job("t", "c")]);
    expect(log).toEqual(["a+", "a-", "b+", "b-", "c+", "c-"]);
  });
});
