// Disarm after one swipe. Every card EnclaveServe arms is watched here: every 5 s the enclave reads the
// card's Airwallex transactions (through the in-enclave session and bridge). The first transaction after
// the arm, approved or declined, sets the card INACTIVE. So does the writ's expiry, by the enclave clock.
// A failed disarm keeps the card on the list, records an alert and is tried again on the next tick.
// The clock is the Airwallex Date header clock passed in. Nothing here reads the host clock or logs.

import { majorToMinor } from "../airwallex/units";
import type { IsoTime } from "../types";
import type { HttpFetch, SetTimer, TimerHandle } from "./enclave-balance";
import { AIRWALLEX_BASE } from "./enclave-balance";

export const WATCH_INTERVAL_MS = 5_000;
/** The Date header has one second resolution, so the enclave clock can trail Airwallex by up to a second. */
const DATE_HEADER_SLACK_MS = 1_000;
const MAX_BODY_CHARS = 256 * 1024;

export interface CardTx {
  transactionId: string;
  type: string;
  status: string;
  amountMinor: number;
  at: IsoTime;
  failureReason?: string;
  /** Length of matched_authorizations when Airwallex sent the list. 0 on a clearing is a forced capture. */
  matchedAuthorizations?: number;
}

export interface WatchedArm {
  cardId: string;
  writId: string;
  runId: string;
  armedAtMs: number;
  /** NaN when unknown: then only a swipe or a forced disarm ends the watch. */
  expiresAtMs: number;
  /** Set when the card must go INACTIVE on the next attempt, whatever the transactions say. */
  disarmReason?: string;
  /** arm: this boot armed it. resume: a previous boot armed it. sweep: fail closed disarm at boot. */
  origin: "arm" | "resume" | "sweep";
  failures: number;
}

/** The last disarm attempt for a card this boot. */
export interface DisarmResult {
  ok: boolean;
  reason: string;
  attempts: number;
  at: IsoTime | null;
}

export type WatchRecord =
  | { kind: "SWIPE"; arm: WatchedArm; tx: CardTx }
  | { kind: "DISARM"; arm: WatchedArm; reason: string }
  | { kind: "ALERT"; arm: WatchedArm; reason: string; attempt: number };

export interface WatchDeps {
  /** Transactions on the card since the time given. Undefined when the read failed. */
  listTransactions(cardId: string, sinceIso: IsoTime): Promise<CardTx[] | undefined>;
  /** Resolve true when the card is INACTIVE. false or a throw is a failed disarm. */
  disarmCard(cardId: string): Promise<boolean>;
  /** Enclave clock in ms. NaN before the first Airwallex Date header. */
  nowMs(): number;
  record(r: WatchRecord): Promise<void>;
  setTimer?: SetTimer;
  intervalMs?: number;
  /** Every baked card. Cards that are not armed are polled for bank events every bankEvery ticks. */
  allCards?: () => string[];
  /** Every transaction read for a card, armed or not, goes here first (the ledger feed). */
  onTransactions?: (cardId: string, txs: CardTx[]) => Promise<void>;
  /** Default 3: with the 5 s tick, cards that are not armed are read every 15 s. */
  bankEvery?: number;
  /** Runs at the start of every pass (the expired reservation sweep). */
  beforePass?: () => Promise<void>;
}

/** How far back the bank feed reads. Writes are keyed by transaction id, so a re-read changes nothing. */
export const BANK_LOOKBACK_MS = 24 * 3_600_000;

const intervalTimer: SetTimer = (fn, ms) => {
  const t = setInterval(fn, ms);
  return { stop: () => clearInterval(t) };
};

/** Records an alert for the first 10 failures, then one in 60, so a dead card cannot flood the ledger. */
const alertWorthy = (n: number) => n <= 10 || n % 60 === 0;

export class ArmWatcher {
  private readonly arms = new Map<string, WatchedArm>();
  private readonly inflight = new Map<string, Promise<boolean>>();
  private readonly seenTx = new Set<string>();
  private readonly results = new Map<string, DisarmResult>();
  private ticks = 0;
  private timer: TimerHandle | undefined;
  private ticking: Promise<void> | undefined;

  constructor(private readonly deps: WatchDeps) {}

  /** Watch a card from its arm. A second arm of the same card replaces the first. */
  track(arm: Omit<WatchedArm, "failures" | "origin"> & { origin?: WatchedArm["origin"] }): void {
    this.arms.set(arm.cardId, { ...arm, origin: arm.origin ?? "arm", failures: 0 });
  }

  /** True only while a card this boot armed is still watched. */
  isArmed(cardId: string): boolean {
    return this.arms.get(cardId)?.origin === "arm";
  }

  /** The watch entry for a card, if any. */
  watched(cardId: string): WatchedArm | undefined {
    const a = this.arms.get(cardId);
    return a ? { ...a } : undefined;
  }

  lastDisarm(cardId: string): DisarmResult | undefined {
    const r = this.results.get(cardId);
    return r ? { ...r } : undefined;
  }

  armed(): WatchedArm[] {
    return [...this.arms.values()].map((a) => ({ ...a }));
  }

  /** Disarm every card armed for this run, now. Resolves when each first attempt is done. */
  disarmRun(runId: string, reason: string): Promise<boolean[]> {
    return Promise.all([...this.arms.values()].filter((a) => a.runId === runId).map((a) => this.disarmNow(a.cardId, reason)));
  }

  /** One disarm attempt. A failure keeps the card watched with the reason, so the next tick tries again. */
  disarmNow(cardId: string, reason: string): Promise<boolean> {
    const arm = this.arms.get(cardId);
    if (!arm) return Promise.resolve(true);
    arm.disarmReason ??= reason;
    const running = this.inflight.get(cardId);
    if (running) return running;
    const p = this.attempt(arm).finally(() => this.inflight.delete(cardId));
    this.inflight.set(cardId, p);
    return p;
  }

  private async attempt(arm: WatchedArm): Promise<boolean> {
    let ok = false;
    try {
      ok = (await this.deps.disarmCard(arm.cardId)) === true;
    } catch {
      ok = false;
    }
    const reason = arm.disarmReason ?? "disarm";
    const now = this.deps.nowMs();
    const at = Number.isFinite(now) ? new Date(now).toISOString() : null;
    if (ok) {
      if (this.arms.get(arm.cardId) === arm) this.arms.delete(arm.cardId);
      this.results.set(arm.cardId, { ok: true, reason, attempts: arm.failures + 1, at });
      await this.safeRecord({ kind: "DISARM", arm, reason });
      return true;
    }
    this.results.set(arm.cardId, { ok: false, reason, attempts: arm.failures + 1, at });
    arm.failures += 1;
    if (alertWorthy(arm.failures)) {
      await this.safeRecord({ kind: "ALERT", arm, reason: `Disarm failed (${reason}), attempt ${arm.failures}. Retrying in ${Math.round((this.deps.intervalMs ?? WATCH_INTERVAL_MS) / 1000)} s.`, attempt: arm.failures });
    }
    return false;
  }

  private async safeRecord(r: WatchRecord): Promise<void> {
    try {
      await this.deps.record(r);
    } catch {
      // the ledger write failed; the card state above still holds
    }
  }

  /** One pass over every armed card. Concurrent calls share the same pass. */
  tick(): Promise<void> {
    if (!this.ticking) {
      this.ticking = this.pass().finally(() => {
        this.ticking = undefined;
      });
    }
    return this.ticking;
  }

  private async pass(): Promise<void> {
    try {
      await this.deps.beforePass?.();
    } catch {
      // the sweep runs again next pass
    }
    const polled = new Set<string>();
    for (const arm of [...this.arms.values()]) {
      polled.add(arm.cardId);
      try {
        await this.check(arm);
      } catch {
        // one card failing never stops the others
      }
    }
    this.ticks += 1;
    if (!this.deps.allCards || !this.deps.onTransactions || (this.ticks - 1) % (this.deps.bankEvery ?? 3) !== 0) return;
    const now = this.deps.nowMs();
    if (!Number.isFinite(now)) return;
    const since = new Date(now - BANK_LOOKBACK_MS).toISOString();
    for (const cardId of this.deps.allCards()) {
      if (polled.has(cardId)) continue;
      try {
        const txs = await this.deps.listTransactions(cardId, since);
        if (txs && txs.length > 0) await this.deps.onTransactions(cardId, txs);
      } catch {
        // the next bank pass reads it again
      }
    }
  }

  /** Disarm a card whether or not it is watched: a watched card keeps its entry, any other gets a sweep entry. */
  forceDisarm(cardId: string, reason: string, tag: string): Promise<boolean> {
    const a = this.arms.get(cardId);
    if (a) {
      a.disarmReason = reason;
      return this.disarmNow(cardId, reason);
    }
    this.track({ cardId, writId: tag, runId: "", armedAtMs: 0, expiresAtMs: Number.NaN, disarmReason: reason, origin: "sweep" });
    return this.disarmNow(cardId, reason);
  }

  private async check(arm: WatchedArm): Promise<void> {
    if (arm.disarmReason !== undefined) {
      await this.disarmNow(arm.cardId, arm.disarmReason);
      return;
    }
    const since = new Date(arm.armedAtMs - DATE_HEADER_SLACK_MS).toISOString();
    const txs = await this.deps.listTransactions(arm.cardId, since);
    if (txs && txs.length > 0 && this.deps.onTransactions) {
      try {
        await this.deps.onTransactions(arm.cardId, txs);
      } catch {
        // the ledger feed failing never blocks the disarm
      }
    }
    const after = (txs ?? []).filter((t) => {
      const at = Date.parse(t.at);
      return Number.isFinite(at) && at >= arm.armedAtMs - DATE_HEADER_SLACK_MS;
    });
    let fresh = false;
    for (const tx of after) {
      if (this.seenTx.has(tx.transactionId)) continue;
      this.seenTx.add(tx.transactionId);
      fresh = true;
      await this.safeRecord({ kind: "SWIPE", arm, tx });
    }
    if (fresh || after.length > 0) {
      await this.disarmNow(arm.cardId, "swiped once");
      return;
    }
    const now = this.deps.nowMs();
    if (Number.isFinite(now) && Number.isFinite(arm.expiresAtMs) && now >= arm.expiresAtMs) {
      await this.disarmNow(arm.cardId, "writ expired");
    }
  }

  /** Resolves when no disarm is in flight and no pass is running. */
  async idle(): Promise<void> {
    while (this.ticking || this.inflight.size > 0) {
      await Promise.allSettled([this.ticking, ...this.inflight.values()]);
    }
  }

  start(): void {
    if (this.timer) return;
    this.timer = (this.deps.setTimer ?? intervalTimer)(() => {
      void this.tick();
    }, this.deps.intervalMs ?? WATCH_INTERVAL_MS);
  }

  stop(): void {
    this.timer?.stop();
    this.timer = undefined;
  }
}

/**
 * GET /api/v1/issuing/transactions for one card through the enclave session. Amounts come back negative
 * in major units and leave here as positive integer cents. A non 2xx, bad JSON or a bad amount is undefined.
 */
export async function listCardTransactions(fetch: HttpFetch, token: string | undefined, cardId: string, sinceIso: IsoTime): Promise<CardTx[] | undefined> {
  if (token === undefined) return undefined;
  try {
    const since = new Date(Date.parse(sinceIso)).toISOString().replace(/\.\d{3}Z$/, "+0000");
    const qs = new URLSearchParams({ card_id: cardId, from_created_at: since, page_size: "50", page_num: "0" });
    const res = await fetch(`${AIRWALLEX_BASE}/api/v1/issuing/transactions?${qs.toString()}`, { method: "GET", headers: { authorization: `Bearer ${token}` } });
    const text = await res.text();
    if (res.status < 200 || res.status >= 300 || text.length > MAX_BODY_CHARS) return undefined;
    const items = (JSON.parse(text) as { items?: unknown }).items;
    if (!Array.isArray(items)) return undefined;
    const out: CardTx[] = [];
    for (const raw of items) {
      if (raw === null || typeof raw !== "object") continue;
      const t = raw as Record<string, unknown>;
      if (t.card_id !== undefined && t.card_id !== cardId) continue;
      const id = typeof t.transaction_id === "string" ? t.transaction_id : undefined;
      const at = typeof t.transaction_date === "string" ? t.transaction_date : typeof t.created_at === "string" ? t.created_at : undefined;
      const amount = typeof t.transaction_amount === "number" ? majorToMinor(Math.abs(t.transaction_amount)) : undefined;
      if (id === undefined || at === undefined || amount === undefined) return undefined;
      const tx: CardTx = {
        transactionId: id,
        type: typeof t.transaction_type === "string" ? t.transaction_type : "UNKNOWN",
        status: typeof t.status === "string" ? t.status : "UNKNOWN",
        amountMinor: amount,
        at: new Date(Date.parse(at.replace(/([+-]\d{2})(\d{2})$/, "$1:$2"))).toISOString(),
      };
      if (typeof t.failure_reason === "string") tx.failureReason = t.failure_reason;
      if (Array.isArray(t.matched_authorizations)) tx.matchedAuthorizations = t.matched_authorizations.length;
      out.push(tx);
    }
    return out;
  } catch {
    return undefined;
  }
}
