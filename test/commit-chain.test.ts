// Commit before yes, the ledger hash chain, and taint that survives a reopen.

import { Database } from "bun:sqlite";
import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FakeAdapter } from "../src/airwallex/fake-adapter";
import { GENESIS_PREV } from "../src/core/chain";
import { type Committer, SqliteCommitter } from "../src/core/committer";
import { Gate, type GateDeps } from "../src/core/gate";
import { Ledger } from "../src/core/ledger";
import { TaintRegistry } from "../src/core/taint";
import type { ArmSpec, Decision, TaintState } from "../src/types";
import { APPROVED_AT, input, KEYS, NOW, signed } from "./helpers";

const T0 = "2026-11-12T08:00:00.000Z";
const code = (d: Decision) => (d.status === "DECLINED" ? d.code : "AUTHORIZED");

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
function tmpDb(): string {
  const dir = mkdtempSync(join(tmpdir(), "writ-pd-"));
  dirs.push(dir);
  return join(dir, "writ.sqlite");
}

function seed(ledger: Ledger): void {
  ledger.setTeam("research", 50000, T0);
  ledger.registerCard("card-1", "research", "research-1", T0);
}

function gateFor(ledger: Ledger, over: Partial<GateDeps> = {}): Gate {
  return new Gate({
    ledger,
    config: { publicKeyPem: KEYS.publicKeyPem, autoApproveMinor: 25000, ringFenceMinor: 2_500_000, reserveFloorMinor: 2_000_000, maxBalanceAgeMs: 60_000 },
    taint: (runId): TaintState => ({ runId }),
    liveBalance: () => ({ amountMinor: 1_000_000_000, at: NOW }),
    ...over,
  });
}

/** The demo's money path: authorize, and arm only on AUTHORIZED. Counts arm calls. */
async function authorizeThenArm(gate: Gate, adapter: FakeAdapter, eventId: string) {
  const r = await gate.authorize(input(), eventId);
  if (r.decision.status === "AUTHORIZED") {
    const spec: ArmSpec = { amountMinor: 18000, currency: "USD", mcc: "5734", activeTo: "2026-11-12T09:00:00.000Z", writHashPrefix: "x" };
    await adapter.arm("card-1", spec);
  }
  return r;
}

function countingAdapter() {
  const adapter = new FakeAdapter({ mode: "frozen" });
  const calls = { arm: 0 };
  const real = adapter.arm.bind(adapter);
  adapter.arm = async (cardId, spec) => {
    calls.arm += 1;
    return real(cardId, spec);
  };
  return { adapter, calls };
}

describe("COMMIT_FAILED: no AUTHORIZED until the commit succeeds", () => {
  test("a committer that returns ok: false yields COMMIT_FAILED and zero arm calls", async () => {
    const ledger = new Ledger();
    seed(ledger);
    ledger.registerWrit(signed(), "card-1", APPROVED_AT);
    const committer: Committer = { commit: () => ({ ok: false, reason: "checkpoint PUT refused" }) };
    const gate = gateFor(ledger, { committer });
    const { adapter, calls } = countingAdapter();

    const r = await authorizeThenArm(gate, adapter, "swipe-1");
    expect(code(r.decision)).toBe("COMMIT_FAILED");
    expect(calls.arm).toBe(0);
    expect(ledger.snapshot("research")!.reservedMinor).toBe(0);

    const same = await authorizeThenArm(gate, adapter, "swipe-1");
    expect(code(same.decision)).toBe("COMMIT_FAILED");
    const again = await authorizeThenArm(gate, adapter, "swipe-2");
    expect(code(again.decision)).not.toBe("AUTHORIZED");
    expect(calls.arm).toBe(0);
  });

  test("the writ stays unspendable for a fresh Gate on the same ledger", async () => {
    const ledger = new Ledger();
    seed(ledger);
    ledger.registerWrit(signed(), "card-1", APPROVED_AT);
    await gateFor(ledger, { committer: { commit: () => ({ ok: false, reason: "down" }) } }).authorize(input(), "swipe-1");
    const later = await gateFor(ledger).authorize(input(), "swipe-2");
    expect(code(later.decision)).toBe("WRIT_REVOKED");
    expect(ledger.snapshot("research")!.reservedMinor).toBe(0);
  });

  test("a committer that throws yields COMMIT_FAILED", async () => {
    const ledger = new Ledger();
    seed(ledger);
    ledger.registerWrit(signed(), "card-1", APPROVED_AT);
    const committer: Committer = {
      commit: async () => {
        throw new Error("s3 timeout");
      },
    };
    const { adapter, calls } = countingAdapter();
    const r = await authorizeThenArm(gateFor(ledger, { committer }), adapter, "swipe-1");
    expect(code(r.decision)).toBe("COMMIT_FAILED");
    expect(calls.arm).toBe(0);
  });

  test("the default sqlite committer commits once and the swipe arms once", async () => {
    const ledger = new Ledger();
    seed(ledger);
    ledger.registerWrit(signed(), "card-1", APPROVED_AT);
    let commits = 0;
    const sqlite = new SqliteCommitter(ledger);
    const committer: Committer = {
      commit: (entry) => {
        commits += 1;
        return sqlite.commit(entry);
      },
    };
    const { adapter, calls } = countingAdapter();
    const r = await authorizeThenArm(gateFor(ledger, { committer }), adapter, "swipe-1");
    expect(code(r.decision)).toBe("AUTHORIZED");
    expect(commits).toBe(1);
    expect(calls.arm).toBe(1);
    expect(ledger.events({ kind: "WRIT_CONSUMED" })).toHaveLength(1);
    expect(ledger.events({ kind: "RESERVE" })).toHaveLength(1);
    expect(ledger.events({ kind: "DECISION" })).toHaveLength(1);
  });

  test("with no committer passed, Gate still commits through sqlite", async () => {
    const ledger = new Ledger();
    seed(ledger);
    ledger.registerWrit(signed(), "card-1", APPROVED_AT);
    expect(code((await gateFor(ledger).authorize(input(), "swipe-1")).decision)).toBe("AUTHORIZED");
    expect(ledger.writStatus("writ-1")).toBe("consumed");
  });
});

describe("ledger hash chain", () => {
  test("every event carries prev and hash, starting at the genesis prev", () => {
    const ledger = new Ledger();
    seed(ledger);
    ledger.registerWrit(signed(), "card-1", APPROVED_AT);
    const rows = ledger.db.query(`SELECT seq, prev_hash, hash FROM events ORDER BY seq`).all() as { seq: number; prev_hash: string; hash: string }[];
    expect(rows.length).toBe(3);
    expect(rows[0]!.prev_hash).toBe(GENESIS_PREV);
    for (let i = 1; i < rows.length; i++) expect(rows[i]!.prev_hash).toBe(rows[i - 1]!.hash);
    expect(rows.map((r) => r.seq)).toEqual([1, 2, 3]);
    expect(ledger.chainVerified).toBe(true);
  });

  test("an empty ledger is verified", () => {
    expect(new Ledger().chainVerified).toBe(true);
  });

  test("a replayed event id adds no entry and leaves the chain whole", () => {
    const ledger = new Ledger();
    seed(ledger);
    const e = { eventId: "fc1", cardId: "card-1", amountMinor: 100, at: NOW };
    ledger.onForcedCapture(e);
    const n = ledger.events().length;
    ledger.onForcedCapture(e);
    expect(ledger.events().length).toBe(n);
    expect(ledger.reverify()).toBe(true);
  });

  test("a reopened file verifies, the triggers are still there", async () => {
    const path = tmpDb();
    const a = new Ledger(path);
    seed(a);
    a.registerWrit(signed(), "card-1", APPROVED_AT);
    expect(code((await gateFor(a).authorize(input(), "swipe-1")).decision)).toBe("AUTHORIZED");
    a.close();
    const b = new Ledger(path);
    expect(b.chainVerified).toBe(true);
    expect(() => b.db.exec("UPDATE events SET amount_minor = 0")).toThrow("append only");
    expect(() => b.db.exec("DELETE FROM events")).toThrow("append only");
    b.close();
  });

  test("an edited row makes the chain unverified, Gate declines STATE_UNVERIFIED and never arms", async () => {
    const path = tmpDb();
    const a = new Ledger(path);
    seed(a);
    a.registerWrit(signed(), "card-1", APPROVED_AT);
    a.close();

    const raw = new Database(path);
    raw.exec("DROP TRIGGER events_no_update");
    raw.exec("UPDATE events SET amount_minor = 999999 WHERE kind = 'TEAM_CONFIG'");
    raw.close();

    const b = new Ledger(path);
    expect(b.chainVerified).toBe(false);
    const { adapter, calls } = countingAdapter();
    const r = await authorizeThenArm(gateFor(b), adapter, "swipe-1");
    expect(code(r.decision)).toBe("STATE_UNVERIFIED");
    expect(calls.arm).toBe(0);
    expect(b.wasConsumed("writ-1")).toBe(false);
    b.close();
  });

  test("STATE_UNVERIFIED wins over a later failure the same swipe would hit", async () => {
    const path = tmpDb();
    const a = new Ledger(path);
    seed(a);
    a.registerWrit(signed(), "card-1", APPROVED_AT);
    a.close();
    const raw = new Database(path);
    raw.exec("DROP TRIGGER events_no_delete");
    raw.exec("DELETE FROM events WHERE seq = 1");
    raw.close();
    const b = new Ledger(path);
    const r = await gateFor(b).authorize(input({ amountMinor: 99900 }), "swipe-1");
    expect(code(r.decision)).toBe("STATE_UNVERIFIED");
    b.close();
  });
});

describe("taint survives a reopen", () => {
  test("TaintRegistry with a ledger writes TAINT and reads it back from a new Ledger on the same file", () => {
    const path = tmpDb();
    const a = new Ledger(path);
    seed(a);
    new TaintRegistry(a).mark("run-1", "https://evil.example/buy", "2026-11-12T08:32:00.000Z");
    expect(a.events({ kind: "TAINT" })).toHaveLength(1);
    a.close();
    const b = new Ledger(path);
    expect(b.chainVerified).toBe(true);
    const t = new TaintRegistry(b).get("run-1");
    expect(t.taintedAt).toBe("2026-11-12T08:32:00.000Z");
    expect(t.source).toBe("https://evil.example/buy");
    expect(new TaintRegistry(b).get("run-2").taintedAt).toBeUndefined();
    b.close();
  });

  test("a memory registry taint reaches the ledger through Gate, and a reopened ledger still declines TAINTED_RUN", async () => {
    const path = tmpDb();
    const a = new Ledger(path);
    seed(a);
    a.registerWrit(signed(), "card-1", APPROVED_AT);
    const mem = new TaintRegistry();
    mem.mark("run-1", "https://evil.example/enterprise", "2026-11-12T08:31:00.000Z");
    const first = await gateFor(a, { taint: (id) => mem.get(id) }).authorize(input(), "swipe-1");
    expect(code(first.decision)).toBe("TAINTED_RUN");
    expect(first.freezeCard).toBe(true);
    expect(a.events({ kind: "TAINT" })).toHaveLength(1);
    a.close();

    const b = new Ledger(path);
    expect(b.chainVerified).toBe(true);
    const second = await gateFor(b, { taint: (id) => new TaintRegistry().get(id) }).authorize(input(), "swipe-2");
    expect(code(second.decision)).toBe("TAINTED_RUN");
    b.close();
  });
});
