// The money path: look up the writ for the card, verify it, take the team lock, run decide(),
// then hand the consuming entry to the committer. No AUTHORIZED until the commit succeeds. Fails closed.
// No network inside the lock on the plain rung, so the RA handler can call it within its window.

import type { ApprovedTask, Decision, DecisionInput, DecisionState, IsoTime, ReserveState, TaintState } from "../types";
import { type Committer, SqliteCommitter } from "./committer";
import { decide } from "./decide";
import { type Ledger, UNKNOWN_TEAM } from "./ledger";
import { KeyedMutex } from "./mutex";
import { parseIso } from "./time";
import { verifyWrit } from "./writ";

export interface LiveBalance {
  amountMinor: number;
  at: IsoTime; // when it was read from Airwallex
}

export interface GateConfig {
  publicKeyPem: string;
  autoApproveMinor: number;
  ringFenceMinor: number;
  reserveFloorMinor: number;
  maxBalanceAgeMs: number;
}

export interface GateDeps {
  ledger: Ledger;
  config: GateConfig;
  taint: (runId: string) => TaintState;
  liveBalance: () => LiveBalance | undefined; // in memory, refreshed outside the decision path
  committer?: Committer; // default: the SQLite transaction in ledger.commitApproval
}

export interface GateResult {
  decision: Decision;
  freezeCard: boolean;
}

export class Gate {
  private readonly mutex = new KeyedMutex();
  private readonly committer: Committer;
  /** Writs whose commit failed. Never spendable again, even if the durable revoke also failed. */
  private readonly burned = new Set<string>();
  private readonly failedCommits = new Map<string, Decision>();

  constructor(private readonly deps: GateDeps) {
    this.committer = deps.committer ?? new SqliteCommitter(deps.ledger);
  }

  /** eventId is the Airwallex card_transaction_event_id in RA mode, our own id in frozen mode. */
  async authorize(input: DecisionInput, eventId: string): Promise<GateResult> {
    try {
      const prior = this.priorDecision(eventId);
      if (prior) return { decision: prior, freezeCard: false };
      const team = this.deps.ledger.writForCard(input.cardId)?.writ.team ?? this.deps.ledger.cardTeam(input.cardId) ?? UNKNOWN_TEAM;
      return await this.mutex.run(team, () => this.decideLocked(input, eventId));
    } catch (err) {
      return { decision: internalError(err), freezeCard: false };
    }
  }

  private priorDecision(eventId: string): Decision | undefined {
    return this.failedCommits.get(eventId) ?? this.deps.ledger.decisionFor(eventId);
  }

  private async decideLocked(input: DecisionInput, eventId: string): Promise<GateResult> {
    const { ledger } = this.deps;
    const prior = this.priorDecision(eventId);
    if (prior) return { decision: prior, freezeCard: false };

    const found = ledger.writForCard(input.cardId);
    const team = found?.writ.team ?? ledger.cardTeam(input.cardId) ?? UNKNOWN_TEAM;
    const ctx = { team, cardId: input.cardId, amountMinor: input.amountMinor, at: input.now };

    let decision: Decision;
    let teamFrozen = false;
    try {
      if (!ledger.chainVerified) {
        decision = { status: "DECLINED", code: "STATE_UNVERIFIED", reason: `Ledger hash chain did not verify: ${ledger.chainReason}` };
        if (found) decision.writId = found.writ.id;
      } else {
        const state = this.buildState(input, found);
        teamFrozen = state.ledger?.teamFrozen !== undefined;
        decision = decide(input, state);
        if (decision.status === "AUTHORIZED" && found) {
          const committed = await this.commit({ eventId, writ: found.writ, cardId: input.cardId, amountMinor: input.amountMinor, at: input.now, decision });
          if (committed === "ok") return { decision, freezeCard: false };
          decision = committed;
          if (decision.code === "COMMIT_FAILED") this.burn(found.writ, eventId, decision, input.now);
        }
      }
    } catch (err) {
      decision = internalError(err);
    }
    if (!isMinorish(ctx.amountMinor)) ctx.amountMinor = 0;
    ledger.recordDecision(eventId, decision, ctx);
    const freezeCard = decision.status === "DECLINED" && (decision.code === "TAINTED_RUN" || teamFrozen);
    return { decision, freezeCard };
  }

  private async commit(entry: Parameters<Committer["commit"]>[0]): Promise<"ok" | Extract<Decision, { status: "DECLINED" }>> {
    const writId = entry.writ.id;
    try {
      const res = await this.committer.commit(entry);
      if (res.ok) return "ok";
      if (res.replay) return { status: "DECLINED", code: "WRIT_REPLAY", reason: "Writ was already used once.", writId };
      return { status: "DECLINED", code: "COMMIT_FAILED", reason: `Ledger commit failed, so no yes: ${res.reason}`, writId };
    } catch (err) {
      return { status: "DECLINED", code: "COMMIT_FAILED", reason: `Ledger commit failed, so no yes: ${err instanceof Error ? err.message : String(err)}`, writId };
    }
  }

  /** A writ whose commit failed must not get a second yes. Memory first, then a durable revoke if the ledger takes it. */
  private burn(writ: ApprovedTask, eventId: string, decision: Decision, at: IsoTime): void {
    this.burned.add(writ.id);
    this.failedCommits.set(eventId, decision);
    try {
      if (this.deps.ledger.writStatus(writ.id) !== "revoked") this.deps.ledger.revokeWrit(writ.id, at, `Commit failed for event ${eventId}.`);
    } catch {
      // the in memory burn still holds for this Gate
    }
  }

  private buildState(input: DecisionInput, found: ReturnType<Ledger["writForCard"]>): DecisionState {
    const { ledger, config } = this.deps;
    if (!found) return { chainVerified: true, writSignatureValid: false, writHashValid: false, taint: { runId: "" } };
    const { writ, status } = found;
    const check = verifyWrit(writ, config.publicKeyPem, { autoApproveMinor: config.autoApproveMinor, knownMerchants: ledger.knownMerchants(writ.team) });
    const state: DecisionState = {
      chainVerified: true,
      writ,
      writStatus: this.burned.has(writ.id) && status === "approved" ? "revoked" : status,
      writSignatureValid: check.signatureValid,
      writHashValid: check.hashValid,
      taint: this.taintFor(writ),
    };
    const snap = ledger.snapshot(writ.team);
    if (snap) state.ledger = snap;
    const reserve = this.reserveState(input.now);
    if (reserve) state.reserve = reserve;
    return state;
  }

  /** Live taint from the caller, merged with taint stored in the ledger. A live mark is written to the ledger. */
  private taintFor(writ: ApprovedTask): TaintState {
    const { ledger } = this.deps;
    const live = this.deps.taint(writ.runId);
    if (live.runId !== writ.runId) return live;
    if (live.taintedAt !== undefined && !Number.isNaN(parseIso(live.taintedAt))) {
      ledger.recordTaint(writ.runId, live.source ?? "unknown source", live.taintedAt, writ.team);
    }
    const stored = ledger.taintFor(writ.runId);
    if (live.taintedAt === undefined) return stored;
    if (stored.taintedAt === undefined) return live;
    const a = parseIso(live.taintedAt);
    if (Number.isNaN(a)) return live;
    return parseIso(stored.taintedAt) > a ? stored : live;
  }

  private reserveState(nowIso: IsoTime): ReserveState | undefined {
    const { config, ledger } = this.deps;
    const bal = this.deps.liveBalance();
    if (!bal) return undefined;
    const asOf = typeof bal.at === "string" ? bal.at : "";
    // A balance read after the decision time means a clock problem, not a stale read: no usable balance.
    if (parseIso(nowIso) - parseIso(asOf) < 0) return undefined;
    // Stale or unreadable times pass through so decide() declines BALANCE_STALE.
    return {
      liveBalanceMinor: bal.amountMinor,
      ringFenceMinor: config.ringFenceMinor,
      reserveFloorMinor: config.reserveFloorMinor,
      openReservationsMinor: ledger.openReservationsMinor(),
      asOf,
      maxAgeMs: config.maxBalanceAgeMs,
    };
  }
}

const isMinorish = (n: number) => Number.isSafeInteger(n) && n >= 0;

function internalError(err: unknown): Decision {
  return { status: "DECLINED", code: "INTERNAL_ERROR", reason: `Writ could not decide: ${err instanceof Error ? err.message : String(err)}` };
}
