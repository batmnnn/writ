// Per team budget ledger on bun:sqlite. The events table is the source of truth and is append only
// (SQLite triggers refuse UPDATE and DELETE). Balances are folded from events, so a replayed
// event id changes nothing. Amounts are integer minor units.
// Each event row is a chain entry (src/core/chain.ts): seq, prev_hash, hash. The chain is verified on open.

import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { ApprovedTask, BudgetLedger, Decision, EventKind, IsoTime, LedgerEvent, TaintState, WritStatus } from "../types";
import { type ChainEntry, entryHash, GENESIS_PREV, verifyChain } from "./chain";
import { normalizeMerchant } from "./merchant";
import { formatMinor, isMinor } from "./money";
import { cleanRun, markTainted, type TaintStore } from "./taint";
import { parseIso } from "./time";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS teams (
  team TEXT PRIMARY KEY,
  pool_limit_minor INTEGER NOT NULL CHECK (pool_limit_minor >= 0)
);
CREATE TABLE IF NOT EXISTS cards (
  card_id TEXT PRIMARY KEY,
  team TEXT NOT NULL,
  agent TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS writs (
  writ_id TEXT PRIMARY KEY,
  card_id TEXT NOT NULL,
  team TEXT NOT NULL,
  hash TEXT NOT NULL,
  body TEXT NOT NULL,
  seq INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL,
  team TEXT NOT NULL,
  card_id TEXT,
  writ_id TEXT,
  amount_minor INTEGER NOT NULL CHECK (amount_minor >= 0),
  at TEXT NOT NULL,
  reason TEXT NOT NULL,
  data TEXT,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_team ON events (team, seq);
CREATE INDEX IF NOT EXISTS events_writ ON events (writ_id, kind);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
  BEGIN SELECT RAISE(ABORT, 'events are append only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
  BEGIN SELECT RAISE(ABORT, 'events are append only'); END;
CREATE TRIGGER IF NOT EXISTS writs_no_update BEFORE UPDATE ON writs
  BEGIN SELECT RAISE(ABORT, 'writs are append only'); END;
CREATE TRIGGER IF NOT EXISTS writs_no_delete BEFORE DELETE ON writs
  BEGIN SELECT RAISE(ABORT, 'writs are append only'); END;
`;

export const UNKNOWN_TEAM = "__unknown__";

interface EventRow {
  seq: number;
  event_id: string;
  kind: string;
  team: string;
  card_id: string | null;
  writ_id: string | null;
  amount_minor: number;
  at: string;
  reason: string;
  data: string | null;
  prev_hash: string | null;
  hash: string | null;
}

type UnchainedRow = Omit<EventRow, "prev_hash" | "hash">;

/** What the hash covers for one row: every column except seq, prev_hash and hash, which the chain carries itself. */
function rowPayload(r: UnchainedRow) {
  return {
    eventId: r.event_id,
    team: r.team,
    cardId: r.card_id ?? undefined,
    writId: r.writ_id ?? undefined,
    amountMinor: r.amount_minor,
    at: r.at,
    reason: r.reason,
    data: r.data === null ? undefined : JSON.parse(r.data),
  };
}

function toChainEntry(r: EventRow): ChainEntry {
  return { seq: r.seq, prev: r.prev_hash ?? "", at: parseIso(r.at), kind: r.kind, payload: rowPayload(r), hash: r.hash ?? "" };
}

interface Bucket {
  reserved: number;
  pending: number;
  settled: number;
}

interface Fold {
  buckets: Map<string, Bucket>;
  released: number;
  alerts: number;
}

export interface CardEvent {
  eventId: string; // Airwallex card_transaction_event_id or our own id
  cardId: string;
  writId?: string; // the writ this card transaction belongs to, if any
  amountMinor: number;
  at: IsoTime;
  reason?: string;
}

export interface CardEventOutcome {
  duplicate: boolean;
  alert: boolean;
  freezeTeam: boolean;
  team: string;
}

export interface WritForCard {
  writ: ApprovedTask;
  status: WritStatus;
}

export class Ledger implements TaintStore {
  readonly db: Database;
  private verified: { ok: boolean; reason: string };

  constructor(path = ":memory:") {
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
    this.db = new Database(path, { create: true, strict: true });
    if (path !== ":memory:") this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec(SCHEMA);
    this.addChainColumns();
    this.verified = this.verifyNow();
  }

  close(): void {
    this.db.close();
  }

  // ---------- chain ----------

  /** False when the stored hash chain did not verify on open (or on the last reverify). Gate then declines STATE_UNVERIFIED. */
  get chainVerified(): boolean {
    return this.verified.ok;
  }

  get chainReason(): string {
    return this.verified.reason;
  }

  /** Re-reads every event and verifies the chain again. */
  reverify(): boolean {
    this.verified = this.verifyNow();
    return this.verified.ok;
  }

  private verifyNow(): { ok: boolean; reason: string } {
    try {
      const rows = this.db.query(`SELECT * FROM events ORDER BY seq`).all() as EventRow[];
      const r = verifyChain(rows.map(toChainEntry));
      return r.ok ? { ok: true, reason: `chain verified, head ${r.head.slice(0, 12)}` } : { ok: false, reason: r.reason };
    } catch (err) {
      return { ok: false, reason: `chain read failed: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  /** A file made before the chain columns existed gets them as NULL, so its old rows fail verification. */
  private addChainColumns(): void {
    const cols = new Set((this.db.query(`PRAGMA table_info(events)`).all() as { name: string }[]).map((c) => c.name));
    if (!cols.has("prev_hash")) this.db.exec(`ALTER TABLE events ADD COLUMN prev_hash TEXT`);
    if (!cols.has("hash")) this.db.exec(`ALTER TABLE events ADD COLUMN hash TEXT`);
  }

  // ---------- events ----------

  /** Appends one event as the next chain entry. Returns false when the event id already exists (replay, no change). */
  append(e: LedgerEvent): boolean {
    if (!isMinor(e.amountMinor) || e.amountMinor < 0) throw new Error(`append: bad amount for ${e.eventId}`);
    if (Number.isNaN(parseIso(e.at))) throw new Error(`append: bad time for ${e.eventId}`);
    return this.db.transaction((): boolean => {
      if (this.hasEvent(e.eventId)) return false;
      const last = this.db.query(`SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1`).get() as { seq: number; hash: string | null } | null;
      const row: UnchainedRow = {
        seq: (last?.seq ?? 0) + 1,
        event_id: e.eventId,
        kind: e.kind,
        team: e.team,
        card_id: e.cardId ?? null,
        writ_id: e.writId ?? null,
        amount_minor: e.amountMinor,
        at: e.at,
        reason: e.reason,
        data: e.data === undefined ? null : JSON.stringify(e.data),
      };
      const prev = last ? (last.hash ?? "") : GENESIS_PREV;
      const hash = entryHash(prev, { seq: row.seq, prev, at: parseIso(row.at), kind: row.kind, payload: rowPayload(row) });
      this.db
        .query(
          `INSERT INTO events (seq, event_id, kind, team, card_id, writ_id, amount_minor, at, reason, data, prev_hash, hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(row.seq, row.event_id, row.kind, row.team, row.card_id, row.writ_id, row.amount_minor, row.at, row.reason, row.data, prev, hash);
      return true;
    })();
  }

  // ---------- taint ----------

  /** Appends a TAINT event. Idempotent on (runId, at). */
  recordTaint(runId: string, source: string, at: IsoTime, team = UNKNOWN_TEAM): boolean {
    return this.append({
      eventId: `taint:${runId}:${at}`,
      kind: "TAINT",
      team,
      amountMinor: 0,
      at,
      reason: `Run ${runId} read untrusted content: ${source}.`,
      data: { runId, source },
    });
  }

  /** Latest taint for a run, folded from TAINT events. */
  taintFor(runId: string): TaintState {
    const rows = this.db
      .query(`SELECT at, data FROM events WHERE kind = 'TAINT' AND json_extract(data, '$.runId') = ? ORDER BY seq`)
      .all(runId) as { at: string; data: string }[];
    let state = cleanRun(runId);
    for (const r of rows) {
      const d = JSON.parse(r.data) as { source?: unknown };
      state = markTainted(state, typeof d.source === "string" ? d.source : "unknown source", r.at);
    }
    return state;
  }

  hasEvent(eventId: string): boolean {
    return this.db.query(`SELECT 1 FROM events WHERE event_id = ?`).get(eventId) !== null;
  }

  events(filter: { team?: string; kind?: EventKind } = {}): LedgerEvent[] {
    const rows = this.db
      .query(
        `SELECT * FROM events WHERE (?1 IS NULL OR team = ?1) AND (?2 IS NULL OR kind = ?2) ORDER BY seq`,
      )
      .all(filter.team ?? null, filter.kind ?? null) as EventRow[];
    return rows.map(toEvent);
  }

  // ---------- setup ----------

  setTeam(team: string, poolLimitMinor: number, at: IsoTime): void {
    if (!isMinor(poolLimitMinor) || poolLimitMinor < 0) throw new Error("setTeam: pool limit must be whole cents");
    this.db.transaction(() => {
      this.db
        .query(`INSERT INTO teams (team, pool_limit_minor) VALUES (?, ?) ON CONFLICT(team) DO UPDATE SET pool_limit_minor = excluded.pool_limit_minor`)
        .run(team, poolLimitMinor);
      this.append({
        eventId: `team:${team}:${crypto.randomUUID()}`,
        kind: "TEAM_CONFIG",
        team,
        amountMinor: poolLimitMinor,
        at,
        reason: `Team pool set to ${formatMinor(poolLimitMinor)}.`,
      });
    })();
  }

  registerCard(cardId: string, team: string, agent: string, at: IsoTime): void {
    this.db.transaction(() => {
      const existing = this.cardTeam(cardId);
      if (existing !== undefined && existing !== team) throw new Error(`card already belongs to team ${existing}`);
      this.db.query(`INSERT OR IGNORE INTO cards (card_id, team, agent) VALUES (?, ?, ?)`).run(cardId, team, agent);
      this.append({
        eventId: `card:${cardId}`,
        kind: "CARD_REGISTERED",
        team,
        cardId,
        amountMinor: 0,
        at,
        reason: `Card for agent ${agent} added to team ${team}.`,
      });
    })();
  }

  cardTeam(cardId: string): string | undefined {
    const row = this.db.query(`SELECT team FROM cards WHERE card_id = ?`).get(cardId) as { team: string } | null;
    return row?.team;
  }

  teamCards(team: string): string[] {
    return (this.db.query(`SELECT card_id FROM cards WHERE team = ? ORDER BY card_id`).all(team) as { card_id: string }[]).map(
      (r) => r.card_id,
    );
  }

  // ---------- writs ----------

  /** Binds an approved writ to one card. A card holds at most one open writ at a time. */
  registerWrit(writ: ApprovedTask, cardId: string, at: IsoTime): void {
    this.db.transaction(() => {
      const team = this.cardTeam(cardId);
      if (team === undefined) throw new Error(`registerWrit: unknown card`);
      if (team !== writ.team) throw new Error(`registerWrit: card belongs to team ${team}, writ is for ${writ.team}`);
      const existing = this.db.query(`SELECT hash FROM writs WHERE writ_id = ?`).get(writ.id) as { hash: string } | null;
      if (existing) {
        if (existing.hash !== writ.hash) throw new Error("registerWrit: writ id reused with different content");
        return;
      }
      const open = this.openWritForCard(cardId, at);
      if (open) throw new Error(`registerWrit: card already holds open writ ${open.writ.id}`);
      const seq = (this.db.query(`SELECT COALESCE(MAX(seq), 0) + 1 AS n FROM writs`).get() as { n: number }).n;
      this.db
        .query(`INSERT INTO writs (writ_id, card_id, team, hash, body, seq) VALUES (?, ?, ?, ?, ?, ?)`)
        .run(writ.id, cardId, writ.team, writ.hash, JSON.stringify(writ), seq);
      this.append({
        eventId: `writ:${writ.id}`,
        kind: "WRIT_REGISTERED",
        team: writ.team,
        cardId,
        writId: writ.id,
        amountMinor: writ.amountMinor,
        at,
        reason: `Writ ${writ.hash.slice(0, 12)} approved (${writ.approvedBy}): ${formatMinor(writ.amountMinor)} at ${writ.merchantName}, MCC ${writ.mcc}, until ${writ.expiresAt}.`,
        data: { hash: writ.hash, approvedBy: writ.approvedBy },
      });
    })();
  }

  writStatus(writId: string): WritStatus {
    const kinds = (
      this.db.query(`SELECT kind FROM events WHERE writ_id = ? AND kind IN ('WRIT_CONSUMED', 'WRIT_REVOKED')`).all(writId) as {
        kind: string;
      }[]
    ).map((r) => r.kind);
    if (kinds.includes("WRIT_REVOKED")) return "revoked";
    if (kinds.includes("WRIT_CONSUMED")) return "consumed";
    return "approved";
  }

  wasConsumed(writId: string): boolean {
    return this.db.query(`SELECT 1 FROM events WHERE writ_id = ? AND kind = 'WRIT_CONSUMED'`).get(writId) !== null;
  }

  /** The open writ for a card, else the most recent one (so a replay reads as WRIT_REPLAY, not unknown). */
  writForCard(cardId: string): WritForCard | undefined {
    const rows = this.db.query(`SELECT writ_id, body FROM writs WHERE card_id = ? ORDER BY seq DESC`).all(cardId) as {
      writ_id: string;
      body: string;
    }[];
    let latest: WritForCard | undefined;
    for (const row of rows) {
      const entry = { writ: JSON.parse(row.body) as ApprovedTask, status: this.writStatus(row.writ_id) };
      latest ??= entry;
      if (entry.status === "approved") return entry;
    }
    return latest;
  }

  private openWritForCard(cardId: string, at: IsoTime): WritForCard | undefined {
    const found = this.writForCard(cardId);
    if (!found || found.status !== "approved") return undefined;
    return parseIso(found.writ.expiresAt) > parseIso(at) ? found : undefined;
  }

  /** Merchants this team already spent at under a human approved writ. Feeds the auto approval rule. */
  knownMerchants(team: string): string[] {
    const rows = this.db
      .query(
        `SELECT w.body FROM writs w JOIN events e ON e.writ_id = w.writ_id AND e.kind = 'WRIT_CONSUMED' WHERE w.team = ?`,
      )
      .all(team) as { body: string }[];
    const names = new Set<string>();
    for (const r of rows) {
      const w = JSON.parse(r.body) as ApprovedTask;
      if (w.approvedBy === "human") names.add(normalizeMerchant(w.merchantName));
    }
    return [...names];
  }

  private writAmount(writId: string): number | undefined {
    const row = this.db.query(`SELECT body FROM writs WHERE writ_id = ?`).get(writId) as { body: string } | null;
    return row ? (JSON.parse(row.body) as ApprovedTask).amountMinor : undefined;
  }

  // ---------- decisions ----------

  decisionFor(eventId: string): Decision | undefined {
    const row = this.db.query(`SELECT data FROM events WHERE event_id = ? AND kind = 'DECISION'`).get(eventId) as {
      data: string | null;
    } | null;
    return row?.data ? (JSON.parse(row.data) as Decision) : undefined;
  }

  recordDecision(eventId: string, decision: Decision, ctx: { team: string; cardId: string; amountMinor: number; at: IsoTime }): void {
    const e: LedgerEvent = {
      eventId,
      kind: "DECISION",
      team: ctx.team,
      cardId: ctx.cardId,
      amountMinor: ctx.amountMinor,
      at: ctx.at,
      reason: decision.status === "AUTHORIZED" ? `AUTHORIZED: ${decision.reason}` : `${decision.code}: ${decision.reason}`,
      data: decision,
    };
    if (decision.writId !== undefined) e.writId = decision.writId;
    this.append(e);
  }

  /**
   * Consumes the writ and reserves the money in one transaction. Re-checks single use and the pool
   * under the transaction, so a bug upstream cannot overspend. Returns "replay" if already consumed.
   */
  commitApproval(args: {
    eventId: string;
    writ: ApprovedTask;
    cardId: string;
    amountMinor: number;
    at: IsoTime;
    decision: Decision;
  }): "ok" | "replay" {
    const { eventId, writ, cardId, amountMinor, at, decision } = args;
    return this.db.transaction((): "ok" | "replay" => {
      if (this.writStatus(writ.id) !== "approved") return "replay";
      const snap = this.snapshot(writ.team);
      if (!snap) throw new Error(`commitApproval: no team ${writ.team}`);
      if (snap.teamFrozen) throw new Error(`commitApproval: team ${writ.team} is frozen`);
      const used = snap.reservedMinor + snap.pendingMinor + snap.settledMinor;
      if (used + amountMinor > snap.poolLimitMinor) throw new Error("commitApproval: pool would be exceeded");
      this.append({
        eventId: `consume:${writ.id}`,
        kind: "WRIT_CONSUMED",
        team: writ.team,
        cardId,
        writId: writ.id,
        amountMinor,
        at,
        reason: `Writ ${writ.hash.slice(0, 12)} used.`,
      });
      this.append({
        eventId: `reserve:${eventId}`,
        kind: "RESERVE",
        team: writ.team,
        cardId,
        writId: writ.id,
        amountMinor,
        at,
        reason: `Held ${formatMinor(amountMinor)} from the team pool.`,
      });
      this.recordDecision(eventId, decision, { team: writ.team, cardId, amountMinor, at });
      return "ok";
    })();
  }

  /** Revokes a writ and releases anything it still holds. */
  revokeWrit(writId: string, at: IsoTime, reason: string): void {
    this.db.transaction(() => {
      const row = this.db.query(`SELECT team, card_id FROM writs WHERE writ_id = ?`).get(writId) as {
        team: string;
        card_id: string;
      } | null;
      if (!row) throw new Error("revokeWrit: unknown writ");
      this.append({ eventId: `revoke:${writId}`, kind: "WRIT_REVOKED", team: row.team, cardId: row.card_id, writId, amountMinor: 0, at, reason });
      const b = this.fold(row.team).buckets.get(writId);
      const held = b ? b.reserved : 0;
      if (held > 0) {
        this.append({
          eventId: `revoke-release:${writId}`,
          kind: "EXPIRY",
          team: row.team,
          cardId: row.card_id,
          writId,
          amountMinor: held,
          at,
          reason: `Released ${formatMinor(held)} held for a revoked writ.`,
        });
      }
    })();
  }

  // ---------- arm and disarm ----------

  /**
   * Records the end of one disarm operation (after the adapter's retries). Success is a DISARM event.
   * Failure is an ALERT: the card may still be ACTIVE. Idempotent on opId.
   */
  recordDisarm(args: { opId: string; cardId: string; writId?: string; at: IsoTime; ok: boolean; reason: string; error?: string }): boolean {
    const team = this.cardTeam(args.cardId) ?? UNKNOWN_TEAM;
    const e: LedgerEvent = args.ok
      ? { eventId: `disarm:${args.opId}`, kind: "DISARM", team, cardId: args.cardId, amountMinor: 0, at: args.at, reason: `Card set INACTIVE: ${args.reason}.` }
      : {
          eventId: `alert:disarm:${args.opId}`,
          kind: "ALERT",
          team,
          cardId: args.cardId,
          amountMinor: 0,
          at: args.at,
          reason: `Disarm failed after retries, card may still be ACTIVE (${args.reason}): ${args.error ?? "unknown error"}.`,
        };
    if (args.writId !== undefined) e.writId = args.writId;
    return this.append(e);
  }

  // ---------- card transaction events from Airwallex ----------

  onAuthorization(e: CardEvent): CardEventOutcome {
    return this.cardEvent("AUTHORIZATION", e);
  }
  onClearing(e: CardEvent): CardEventOutcome {
    return this.cardEvent("CLEARING", e);
  }
  onReversal(e: CardEvent): CardEventOutcome {
    return this.cardEvent("REVERSAL", e);
  }
  onExpiry(e: CardEvent): CardEventOutcome {
    return this.cardEvent("EXPIRY", e);
  }
  onRefund(e: CardEvent): CardEventOutcome {
    return this.cardEvent("REFUND", e);
  }
  /** A capture with no prior authorization. Always counts, always alerts, always freezes the team. */
  onForcedCapture(e: CardEvent): CardEventOutcome {
    return this.cardEvent("FORCED_CAPTURE", e);
  }

  private cardEvent(kind: "AUTHORIZATION" | "CLEARING" | "REVERSAL" | "EXPIRY" | "REFUND" | "FORCED_CAPTURE", e: CardEvent): CardEventOutcome {
    if (!isMinor(e.amountMinor) || e.amountMinor < 0) throw new Error(`${kind}: bad amount`);
    return this.db.transaction((): CardEventOutcome => {
      const team = this.cardTeam(e.cardId) ?? UNKNOWN_TEAM;
      if (this.hasEvent(e.eventId)) return { duplicate: true, alert: false, freezeTeam: false, team };

      const matched = e.writId !== undefined && this.wasConsumed(e.writId);
      const before = matched ? this.fold(team).buckets.get(e.writId as string) : undefined;
      let alertReason: string | undefined;
      let freezeTeam = false;

      if (kind === "FORCED_CAPTURE") {
        alertReason = `Forced capture of ${formatMinor(e.amountMinor)} with no approval.`;
        freezeTeam = true;
      } else if ((kind === "AUTHORIZATION" || kind === "CLEARING") && !matched) {
        alertReason = `${kind === "CLEARING" ? "Clearing" : "Authorization"} of ${formatMinor(e.amountMinor)} with no matching approval.`;
        freezeTeam = true;
      } else if (kind === "CLEARING" && matched) {
        const approved = this.writAmount(e.writId as string) ?? 0;
        const settledAfter = (before?.settled ?? 0) + e.amountMinor;
        if (settledAfter > approved) alertReason = `Clearing took ${formatMinor(settledAfter)}, writ approved ${formatMinor(approved)}.`;
      }

      const ev: LedgerEvent = {
        eventId: e.eventId,
        kind,
        team,
        cardId: e.cardId,
        amountMinor: e.amountMinor,
        at: e.at,
        reason: e.reason ?? `${kind} ${formatMinor(e.amountMinor)}.`,
      };
      if (matched) ev.writId = e.writId as string;
      this.append(ev);

      if (alertReason !== undefined) {
        const alert: LedgerEvent = { eventId: `alert:${e.eventId}`, kind: "ALERT", team, cardId: e.cardId, amountMinor: e.amountMinor, at: e.at, reason: alertReason };
        if (matched) alert.writId = e.writId as string;
        this.append(alert);
      }
      if (freezeTeam) {
        this.append({ eventId: `freeze:${e.eventId}`, kind: "FREEZE", team, amountMinor: 0, at: e.at, reason: `Freeze every card of team ${team}: ${alertReason}` });
      }
      return { duplicate: false, alert: alertReason !== undefined, freezeTeam, team };
    })();
  }

  // ---------- balances ----------

  private fold(team: string | null): Fold {
    const rows = this.db
      .query(
        `SELECT * FROM events WHERE (?1 IS NULL OR team = ?1)
         AND kind IN ('RESERVE','AUTHORIZATION','CLEARING','REVERSAL','EXPIRY','REFUND','FORCED_CAPTURE','ALERT') ORDER BY seq`,
      )
      .all(team) as EventRow[];
    const buckets = new Map<string, Bucket>();
    let released = 0;
    let alerts = 0;
    const bucket = (key: string): Bucket => {
      let b = buckets.get(key);
      if (!b) buckets.set(key, (b = { reserved: 0, pending: 0, settled: 0 }));
      return b;
    };
    for (const r of rows) {
      const amt = r.amount_minor;
      const b = bucket(r.writ_id ?? `unmatched:${r.event_id}`);
      switch (r.kind) {
        case "RESERVE":
          b.reserved += amt;
          break;
        case "AUTHORIZATION": {
          released += Math.max(0, b.reserved - amt);
          b.reserved = 0;
          b.pending += amt;
          break;
        }
        case "CLEARING": {
          const fromPending = Math.min(b.pending, amt);
          b.pending -= fromPending;
          const fromReserved = Math.min(b.reserved, amt - fromPending);
          b.reserved -= fromReserved;
          b.settled += amt;
          break;
        }
        case "REVERSAL": {
          const m = Math.min(b.pending, amt);
          b.pending -= m;
          released += m;
          break;
        }
        case "EXPIRY": {
          const fromReserved = Math.min(b.reserved, amt);
          b.reserved -= fromReserved;
          const fromPending = Math.min(b.pending, amt - fromReserved);
          b.pending -= fromPending;
          released += fromReserved + fromPending;
          break;
        }
        case "REFUND":
          b.settled -= Math.min(b.settled, amt);
          break;
        case "FORCED_CAPTURE":
          b.settled += amt;
          break;
        case "ALERT":
          alerts += 1;
          break;
      }
    }
    return { buckets, released, alerts };
  }

  snapshot(team: string): BudgetLedger | undefined {
    const row = this.db.query(`SELECT pool_limit_minor FROM teams WHERE team = ?`).get(team) as {
      pool_limit_minor: number;
    } | null;
    if (!row) return undefined;
    const f = this.fold(team);
    let reservedMinor = 0;
    let pendingMinor = 0;
    let settledMinor = 0;
    for (const b of f.buckets.values()) {
      reservedMinor += b.reserved;
      pendingMinor += b.pending;
      settledMinor += b.settled;
    }
    const snap: BudgetLedger = { team, poolLimitMinor: row.pool_limit_minor, reservedMinor, pendingMinor, settledMinor, releasedMinor: f.released, alerts: f.alerts };
    const frozen = this.teamFrozen(team);
    if (frozen) snap.teamFrozen = frozen;
    return snap;
  }

  /**
   * The first FREEZE event for the team, if any. There is no unfreeze event kind yet, so a frozen
   * team stays frozen until one is built (a signed or operator ledger event).
   */
  teamFrozen(team: string): { at: IsoTime; reason: string } | undefined {
    const row = this.db.query(`SELECT at, reason FROM events WHERE kind = 'FREEZE' AND team = ? ORDER BY seq LIMIT 1`).get(team) as {
      at: string;
      reason: string;
    } | null;
    return row ? { at: row.at, reason: row.reason } : undefined;
  }

  /** Money held but not yet debited, across every team. Counts pending too, which errs toward declining. */
  openReservationsMinor(): number {
    let total = 0;
    for (const b of this.fold(null).buckets.values()) total += b.reserved + b.pending;
    return total;
  }
}

function toEvent(r: EventRow): LedgerEvent {
  const e: LedgerEvent = { eventId: r.event_id, kind: r.kind as EventKind, team: r.team, amountMinor: r.amount_minor, at: r.at, reason: r.reason };
  if (r.card_id !== null) e.cardId = r.card_id;
  if (r.writ_id !== null) e.writId = r.writ_id;
  if (r.data !== null) e.data = JSON.parse(r.data);
  return e;
}
