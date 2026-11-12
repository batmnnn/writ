// Long-running serve path inside the enclave. Every card arm goes through Gate.authorize first:
// signed writ, team pool, cash reserve, taint, then a durable S3 checkpoint, then the ledger consume.
// armCard runs only after Gate answers AUTHORIZED. Nothing here reads the host clock or logs.
//
// Trust inputs:
//   The approver public key comes only from the baked approvers.json object. A key on the boot line or
//   in a request is ignored. No baked key, or a key that does not parse, means every request declines.
//   Taint comes only through acceptTaint, after the caller checked the pinned signer. It is never cleared.
//   The live balance comes only from setObservation, fed by the in-enclave poller (enclave-balance.ts).
//   now comes only from the clock option. A balance or now on a request is ignored. No observation
//   declines UPSTREAM_ERROR. A stale one goes to decide() as is, so it declines BALANCE_STALE.
//
// Durable record: consume, taint, arm, disarm, swipe and alert entries all go into one signed S3 chain.
// At boot the caller loads and verifies that chain (loadSignedChain) and passes it as resume. Replay
// rebuilds used writs, held money, taint marks, the taint seq guard and the cards still armed.
// A chain that fails verification, or a resumeError, means every decision is STATE_UNVERIFIED.
//
// The one-shot armAfterUnseal in enclave-arm.ts is separate and unchanged.

import { createPublicKey, randomUUID } from "node:crypto";
import type { ApprovedTask, Decision, DeclineCode, DecisionInput, IsoTime, LedgerEvent, TaintState } from "../types";
import { type ChainEntry, verifyChain } from "../core/chain";
import type { CommitResult, Committer, ConsumeEntry } from "../core/committer";
import { Gate, type LiveBalance } from "../core/gate";
import { Ledger, UNKNOWN_TEAM } from "../core/ledger";
import { isMinor } from "../core/money";
import { KeyedMutex } from "../core/mutex";
import { cleanRun, markTainted, taintedSince } from "../core/taint";
import { parseIso } from "../core/time";
import { verifyWrit } from "../core/writ";
import { S3CheckpointCommitter, type AppendResult, type EntrySigner, type S3CommitterOptions } from "./s3-committer";
import { ArmWatcher, type CardTx, type DisarmResult, type WatchRecord } from "./enclave-watch";
import type { SetTimer } from "./enclave-balance";

/** Config baked into the image, so part of PCR0. approvers is the parsed enclave/config/approvers.json. */
export interface BakedConfig {
  approvers: unknown;
  ringFenceMinor: number;
  reserveFloorMinor: number;
  maxBalanceAgeMs: number;
  teams: { team: string; poolLimitMinor: number }[];
  cards: { cardId: string; team: string; agent: string; last4?: string }[];
  /** PEM of the KMS taint signer public key, from enclave/config/taint-signer.pub.pem. */
  taintSignerPem?: string;
  /** Airwallex client id (an identifier, not a secret). When set it wins over the boot line clientId. */
  airwallexClientId?: string;
}

/** What armCard gets. Terms come from the writ Gate just consumed. */
export interface ArmOrder {
  cardId: string;
  writId: string;
  writHash: string;
  amountMinor: number;
  currency: string;
  mcc: string;
  merchantName: string;
  expiresAt: IsoTime;
}

/** Resolve true when the card is armed. false or a throw is ARM_FAILED. */
export type ArmCardFn = (order: ArmOrder) => Promise<boolean>;

export interface WatchOptions {
  listTransactions(cardId: string, sinceIso: IsoTime): Promise<CardTx[] | undefined>;
  disarmCard(cardId: string): Promise<boolean>;
  setTimer?: SetTimer;
  intervalMs?: number;
  /** Ticks between bank feed reads of cards that are not armed. Default 3 (15 s). */
  bankEvery?: number;
}

/** One bank event as checkpointed. Replay runs it through the same ledger call. */
interface BankPayload extends Record<string, unknown> {
  eventId: string;
  txId: string;
  cardId: string;
  kind: "AUTHORIZATION" | "CLEARING" | "FORCED_CAPTURE" | "REVERSAL" | "REFUND";
  amountMinor: number;
  at: IsoTime;
  writId?: string;
  /**
   * Airwallex changes an AUTHORIZATION row in place: PENDING becomes REVERSED (or a cleared status) with
   * no new transaction id. The first stage of a row is keyed awx:<id>, each later stage awx:<id>:<stage>.
   */
  stage?: "reversed" | "cleared";
}

const bankKey = (txId: string, stage?: BankPayload["stage"]) => (stage ? `awx:${txId}:${stage}` : `awx:${txId}`);
const HOLD_STATUSES = new Set(["PENDING", "APPROVED"]);
const REVERSED_STATUSES = new Set(["REVERSED", "EXPIRED"]);
const CLEARED_STATUSES = new Set(["CLEARED", "POSTED", "SETTLED", "CAPTURED"]);

/** The consume time may trail the bank's clock by the Date header resolution. */
const MATCH_SLACK_MS = 5_000;

/** Disarm reasons after which an unswiped writ gives its money back. Must match the watcher and taint wording. */
const RELEASE_REASONS = new Set(["writ expired", "run tainted", "team frozen"]);
const releaseId = (writId: string) => `release:${writId}`;

interface ReleasePayload extends Record<string, unknown> {
  eventId: string;
  writId: string;
  cardId: string;
  amountMinor: number;
  reason: string;
}

export interface ServeOptions {
  baked: BakedConfig;
  /** Time stamp for the setup entries (teams, cards, resumed consumes). Passed in, never read from a clock. */
  bootAt: IsoTime;
  /** Durable checkpoint. s3 builds an S3CheckpointCommitter with resume. committer is for an injected one. */
  checkpoint: { s3: Omit<S3CommitterOptions, "resume" | "signer"> } | { committer: Committer };
  /** Chain entries already checkpointed, oldest first, loaded by the caller. */
  resume?: ChainEntry[];
  /** Why the caller could not load a verified chain. Set means every decision is STATE_UNVERIFIED. */
  resumeError?: string;
  /** The resumeError was a read failure, not tampering: resume() may finish the boot later. */
  resumeTransient?: boolean;
  /** Enclave ledger key. Signs every new checkpoint, and resume entries must carry its signature. */
  signer?: EntrySigner & { publicKeyRaw: Uint8Array };
  armCard: ArmCardFn;
  /** Disarm after one swipe or at expiry. Without it nothing is watched. */
  watch?: WatchOptions;
  /** Decision time. In the enclave this is BalancePoller.now(): the Airwallex Date header plus monotonic time. */
  clock: () => IsoTime | undefined;
  newEventId?: () => string;
}

/** One arm request from the host. Untrusted. Any other field, such as a public key, a now or a balance, is ignored. */
export interface ArmRequest {
  cardId: string;
  amountMinor: number;
  currency: string;
  mcc: string;
  merchantName: string;
  writ?: ApprovedTask;
}

export type ServeCode = DeclineCode | "ARM_FAILED";

export type ServeResult =
  | { status: "AUTHORIZED"; writId: string; reason: string; armed: true; seq?: number }
  | { status: "DECLINED"; code: ServeCode; reason: string; writId?: string; armed: false; freezeCard: boolean; seq?: number };

export type TaintOutcome =
  | { ok: true; taintedAt: IsoTime; disarmed: Promise<boolean[]> }
  | { ok: false; status: 400 | 503; reason: string };

export interface DecisionView {
  eventId: string;
  at: IsoTime;
  status: "AUTHORIZED" | "DECLINED";
  code?: string;
  reason: string;
  writId?: string;
  agent?: string;
  team: string;
  cardLast4?: string;
  amountMinor: number;
}

export interface StateView {
  verified: boolean;
  unverifiedReason?: string;
  /** teamFrozen is set once an unmatched clearing or forced capture froze the team. Nothing lifts it yet. */
  teams: { team: string; poolLimitMinor: number; reservedMinor: number; pendingMinor: number; settledMinor: number; releasedMinor: number; teamFrozen: { at: IsoTime; reason: string } | null }[];
  reserve: { liveBalanceMinor: number | null; ringFenceMinor: number; reserveFloorMinor: number; openReservationsMinor: number; asOf: IsoTime | null };
  /** retrying: the chain could not be read yet and the enclave keeps trying. tampered: permanent until fixed. */
  ledger: "verified" | "retrying" | "tampered";
  /**
   * armed is true only for a card this boot armed and has not disarmed. "unknown" when this boot cannot
   * know (ledger not verified and no disarm confirmed yet, or a card a previous boot armed). lastDisarm is
   * the last INACTIVE attempt this boot made for the card, including the fail closed sweep.
   */
  cards: { agent: string; team: string; last4: string | null; armed: boolean | "unknown"; lastDisarm: DisarmResult | null }[];
  chain: { seq: number; hash: string };
  decisions: DecisionView[];
}

/** The single Ed25519 public key in approvers.json, or undefined. Anything else fails closed. */
export function bakedApproverKey(approvers: unknown): string | undefined {
  if (approvers === null || typeof approvers !== "object") return undefined;
  const list = (approvers as { approvers?: unknown }).approvers;
  if (!Array.isArray(list) || list.length !== 1) return undefined;
  const pem = (list[0] as { publicKeyPem?: unknown } | null)?.publicKeyPem;
  if (typeof pem !== "string" || pem.includes("PRIVATE KEY")) return undefined;
  try {
    return createPublicKey(pem).asymmetricKeyType === "ed25519" ? pem : undefined;
  } catch {
    return undefined;
  }
}

/** Checkpoint first, then the ledger consume. ok only when both landed. */
class CheckpointThenLedger implements Committer {
  constructor(
    private readonly checkpoint: Committer,
    private readonly ledger: Ledger,
    private readonly consumed: Set<string>,
  ) {}

  async commit(entry: ConsumeEntry): Promise<CommitResult> {
    const writId = entry.writ.id;
    if (this.consumed.has(writId) || this.ledger.writStatus(writId) !== "approved") {
      return { ok: false, reason: "Writ was already used once.", replay: true };
    }
    const durable = await this.checkpoint.commit(entry);
    if (!durable.ok) return durable;
    this.consumed.add(writId);
    // A throw here reaches Gate as COMMIT_FAILED, and Gate revokes the writ. The checkpoint already holds it.
    if (this.ledger.commitApproval(entry) !== "ok") return { ok: false, reason: "Writ was already used once.", replay: true };
    return { ok: true };
  }
}

const declined = (code: ServeCode, reason: string, writId?: string, freezeCard = false): ServeResult => {
  const r: ServeResult = { status: "DECLINED", code, reason, armed: false, freezeCard };
  if (writId !== undefined) r.writId = writId;
  return r;
};

interface ArmRecord {
  eventId: string;
  writId: string;
  cardId: string;
  runId: string;
  approvedAt: IsoTime;
  amountMinor: number;
  expiresAt: IsoTime;
  armedAt: IsoTime;
}

const str = (v: unknown): v is string => typeof v === "string" && v.length > 0;

export class EnclaveServe {
  private readonly ledger = new Ledger(":memory:");
  private readonly lock = new KeyedMutex();
  private readonly taints = new Map<string, TaintState>();
  private readonly taintSeq = new Map<string, number>();
  private readonly consumed = new Set<string>();
  private readonly armAttempted = new Set<string>();
  /** Writs a previous boot declined and closed. The writs table is not replayed, so this keeps them closed. */
  private readonly revokedAtResume = new Set<string>();
  /** expiresAt of every consumed writ that armed a card, from arm records (live and replayed). */
  private readonly writExpiry = new Map<string, IsoTime>();
  private readonly newEventId: () => string;
  private readonly armCard: ArmCardFn;
  private readonly clock: () => IsoTime | undefined;
  private readonly cards: BakedConfig["cards"];
  private readonly teams: BakedConfig["teams"];
  private readonly baked: BakedConfig;
  private checkpointer: S3CheckpointCommitter | undefined;
  private watcher: ArmWatcher | undefined;
  private gate: Gate | undefined;
  private unverified: string | undefined;
  private observation: LiveBalance | undefined;
  private opts: ServeOptions | undefined;
  private publicKeyPem: string | undefined;
  private pending = false;
  private ledgerStatus: "verified" | "retrying" | "tampered" = "tampered";

  constructor(opts: ServeOptions) {
    this.armCard = opts.armCard;
    this.clock = typeof opts.clock === "function" ? opts.clock : () => undefined;
    this.newEventId = opts.newEventId ?? (() => randomUUID());
    this.baked = opts.baked;
    this.cards = Array.isArray(opts.baked?.cards) ? opts.baked.cards : [];
    this.teams = Array.isArray(opts.baked?.teams) ? opts.baked.teams : [];
    try {
      this.boot(opts);
    } catch (err) {
      this.gate = undefined;
      this.unverified = `Serve setup failed: ${err instanceof Error ? err.message : String(err)}`;
    }
  }

  private boot(opts: ServeOptions): void {
    if (opts.watch) {
      const w = opts.watch;
      this.watcher = new ArmWatcher({
        listTransactions: (cardId, since) => w.listTransactions(cardId, since),
        disarmCard: (cardId) => w.disarmCard(cardId),
        nowMs: () => parseIso(this.clock()),
        record: (r) => this.recordWatch(r),
        allCards: () => this.cards.map((c) => c.cardId),
        onTransactions: (cardId, txs) => this.ingestTransactions(cardId, txs),
        beforePass: () => this.releaseExpired(),
        ...(w.setTimer ? { setTimer: w.setTimer } : {}),
        ...(w.intervalMs !== undefined ? { intervalMs: w.intervalMs } : {}),
        ...(w.bankEvery !== undefined ? { bankEvery: w.bankEvery } : {}),
      });
    }
    const publicKeyPem = bakedApproverKey(opts.baked.approvers);
    if (publicKeyPem === undefined) {
      this.unverified = "No valid baked approver key.";
      this.ledgerStatus = "tampered";
      return;
    }
    this.publicKeyPem = publicKeyPem;
    this.opts = opts;
    if (opts.resumeError !== undefined) {
      if (opts.resumeTransient === true) {
        this.pending = true;
        this.ledgerStatus = "retrying";
        this.unverified = `Ledger not read yet (transient, retrying): ${opts.resumeError}`;
      } else {
        this.ledgerStatus = "tampered";
        this.unverified = `Ledger did not verify at boot (tampered, needs a fix): ${opts.resumeError}`;
      }
      this.disarmEveryCard("ledger unverified at boot");
      return;
    }
    try {
      this.applyResume(opts.resume ?? [], opts.bootAt);
    } catch (err) {
      this.ledgerStatus = "tampered";
      this.disarmEveryCard("ledger unverified at boot");
      throw err;
    }
  }

  /**
   * Finish a boot that could not read the chain yet. Only allowed while the reason was transient. The
   * entries must verify with the ledger key, exactly as at boot. A failure here is tampering and permanent.
   */
  resume(entries: ChainEntry[]): { ok: true } | { ok: false; reason: string } {
    if (!this.pending || this.opts === undefined) return { ok: false, reason: "not waiting for a resume" };
    this.pending = false;
    try {
      this.applyResume(entries, this.clock() ?? this.opts.bootAt);
      this.unverified = undefined;
      return { ok: true };
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      this.gate = undefined;
      this.ledgerStatus = "tampered";
      this.unverified = `Ledger did not verify (tampered, needs a fix): ${reason}`;
      return { ok: false, reason };
    }
  }

  /** A retry read the chain and found it wrong. No more retries: unverified until a human fixes it. */
  markTampered(reason: string): void {
    if (!this.pending) return;
    this.pending = false;
    this.ledgerStatus = "tampered";
    this.unverified = `Ledger did not verify (tampered, needs a fix): ${reason}`;
  }

  /** A retry failed for a transient reason. Keeps waiting and updates the reason shown in /state. */
  noteTransient(reason: string): void {
    if (this.pending) this.unverified = `Ledger not read yet (transient, retrying): ${reason}`;
  }

  /** verified, retrying (transient, the caller keeps trying) or tampered (permanent). */
  get ledgerState(): "verified" | "retrying" | "tampered" {
    return this.verified ? "verified" : this.ledgerStatus === "retrying" && this.pending ? "retrying" : "tampered";
  }

  get waitingForResume(): boolean {
    return this.pending;
  }

  private applyResume(resume: ChainEntry[], at: IsoTime): void {
    const opts = this.opts!;
    const publicKeyPem = this.publicKeyPem!;
    const check = opts.signer ? verifyChain(resume, { pubKey: opts.signer.publicKeyRaw, requireSignature: true }) : verifyChain(resume);
    if (!check.ok) throw new Error(`resume chain does not verify: ${check.reason}`);
    let checkpoint: Committer;
    if ("s3" in opts.checkpoint) {
      const c = new S3CheckpointCommitter({ ...opts.checkpoint.s3, resume, ...(opts.signer ? { signer: opts.signer } : {}) });
      this.checkpointer = c;
      checkpoint = c;
    } else {
      checkpoint = opts.checkpoint.committer;
    }

    for (const t of this.teams) this.ledger.setTeam(t.team, t.poolLimitMinor, at);
    for (const c of this.cards) this.ledger.registerCard(c.cardId, c.team, c.agent, at);
    this.replay(resume);

    this.ledgerStatus = "verified";
    this.gate = new Gate({
      ledger: this.ledger,
      config: {
        publicKeyPem,
        autoApproveMinor: 0, // no auto writs in the enclave: every arm needs a human signature
        ringFenceMinor: opts.baked.ringFenceMinor,
        reserveFloorMinor: opts.baked.reserveFloorMinor,
        maxBalanceAgeMs: opts.baked.maxBalanceAgeMs,
      },
      taint: (runId) => this.taints.get(runId) ?? cleanRun(runId),
      liveBalance: () => this.observation,
      committer: new CheckpointThenLedger(checkpoint, this.ledger, this.consumed),
    });
  }

  // ---------- resume ----------

  /** Without a verified chain there is no record of what a previous run armed, so every baked card goes INACTIVE. */
  private disarmEveryCard(reason: string): void {
    if (!this.watcher) return;
    for (const c of this.cards) {
      this.watcher.track({ cardId: c.cardId, writId: `boot:${c.cardId}`, runId: "", armedAtMs: 0, expiresAtMs: Number.NaN, disarmReason: reason, origin: "sweep" });
    }
  }

  private replay(resume: ChainEntry[]): void {
    const openConsumes = new Map<string, { cardId: string; at: number }>();
    const openArms = new Map<string, ArmRecord>();
    for (const e of resume) {
      const p = (e.payload ?? {}) as Record<string, unknown>;
      switch (e.kind) {
        case "consume":
          this.replayConsume(e);
          openConsumes.set(p.writId as string, { cardId: p.cardId as string, at: e.at });
          break;
        case "arm": {
          const a = this.armFromPayload(p, e.seq);
          this.appendLocal({ eventId: a.eventId, kind: "ARM", cardId: a.cardId, writId: a.writId, amountMinor: a.amountMinor, at: a.armedAt, reason: `Card armed for writ ${a.writId} (checkpoint ${e.seq}).` });
          openArms.set(a.writId, a);
          this.writExpiry.set(a.writId, a.expiresAt);
          break;
        }
        case "disarm": {
          if (!str(p.eventId) || !str(p.writId) || !str(p.cardId)) throw new Error(`resume entry ${e.seq} is a bad disarm`);
          this.appendLocal({ eventId: p.eventId, kind: "DISARM", cardId: p.cardId, writId: p.writId, amountMinor: 0, at: new Date(e.at).toISOString(), reason: `Card disarmed: ${String(p.reason ?? "disarm")} (checkpoint ${e.seq}).` });
          openArms.delete(p.writId);
          openConsumes.delete(p.writId);
          break;
        }
        case "swipe":
        case "alert": {
          if (!str(p.eventId) || !str(p.cardId)) throw new Error(`resume entry ${e.seq} is a bad ${e.kind}`);
          const amount = isMinor(p.amountMinor) && p.amountMinor >= 0 ? p.amountMinor : 0;
          const ev: Omit<LedgerEvent, "team"> = { eventId: p.eventId, kind: e.kind === "swipe" ? "SWIPE" : "ALERT", cardId: p.cardId, amountMinor: amount, at: new Date(e.at).toISOString(), reason: `${String(p.reason ?? e.kind)} (checkpoint ${e.seq}).` };
          if (str(p.writId)) ev.writId = p.writId;
          this.appendLocal(ev);
          break;
        }
        case "taint": {
          if (!str(p.agent) || !str(p.runId) || !str(p.taintedAt) || !isMinor(p.seq) || Number.isNaN(parseIso(p.taintedAt))) {
            throw new Error(`resume entry ${e.seq} is a bad taint`);
          }
          this.setTaint(p.runId, p.taintedAt, `signed taint seq ${p.seq}`);
          this.taintSeq.set(p.agent, Math.max(this.taintSeq.get(p.agent) ?? 0, p.seq));
          this.ledger.recordTaint(p.runId, `signed taint seq ${p.seq}`, p.taintedAt, this.teamOfAgent(p.agent));
          break;
        }
        case "bank":
          this.applyBank(this.bankFromPayload(p, e.seq));
          break;
        case "revoke": {
          if (!str(p.eventId) || !str(p.writId) || p.eventId !== `revoke:${p.writId}`) throw new Error(`resume entry ${e.seq} is a bad revoke`);
          this.revokedAtResume.add(p.writId);
          break;
        }
        case "release": {
          if (!str(p.eventId) || !str(p.writId) || !str(p.cardId) || !str(p.reason) || !isMinor(p.amountMinor) || p.amountMinor <= 0 || p.eventId !== releaseId(p.writId)) {
            throw new Error(`resume entry ${e.seq} is a bad release`);
          }
          this.applyRelease(p as ReleasePayload, new Date(e.at).toISOString());
          break;
        }
        case "freeze": {
          if (!str(p.eventId) || !str(p.team) || !str(p.reason)) throw new Error(`resume entry ${e.seq} is a bad freeze`);
          this.ledger.append({ eventId: p.eventId, kind: "FREEZE", team: p.team, amountMinor: 0, at: new Date(e.at).toISOString(), reason: p.reason });
          break;
        }
        default:
          throw new Error(`resume entry ${e.seq} has unknown kind ${e.kind}`);
      }
    }
    if (!this.watcher) return;
    // A team frozen before the restart: its cards go INACTIVE again, to be sure.
    for (const t of this.teams) {
      if (this.ledger.teamFrozen(t.team)) {
        for (const c of this.cards.filter((x) => x.team === t.team)) {
          this.watcher.track({ cardId: c.cardId, writId: `frozen:boot:${this.clock() ?? this.opts?.bootAt ?? ""}:${c.cardId}`, runId: "", armedAtMs: 0, expiresAtMs: Number.NaN, disarmReason: "team frozen", origin: "sweep" });
        }
      }
    }
    for (const a of openArms.values()) {
      openConsumes.delete(a.writId);
      this.watcher.track({ cardId: a.cardId, writId: a.writId, runId: a.runId, armedAtMs: parseIso(a.armedAt), expiresAtMs: parseIso(a.expiresAt), origin: "resume" });
      if (taintedSince(this.taints.get(a.runId) ?? cleanRun(a.runId), a.approvedAt)) void this.watcher.disarmNow(a.cardId, "run tainted");
    }
    // A consume with no arm record may still have armed the card before a restart. Disarm it to be sure.
    for (const [writId, c] of openConsumes) {
      this.watcher.track({ cardId: c.cardId, writId, runId: "", armedAtMs: c.at, expiresAtMs: Number.NaN, disarmReason: "restart: consumed writ with no arm record", origin: "resume" });
    }
  }

  private bankFromPayload(p: Record<string, unknown>, seq: number): BankPayload {
    const kinds = ["AUTHORIZATION", "CLEARING", "FORCED_CAPTURE", "REVERSAL", "REFUND"];
    if (!str(p.eventId) || !str(p.txId) || !str(p.cardId) || !str(p.at) || typeof p.kind !== "string" || !kinds.includes(p.kind)) {
      throw new Error(`resume entry ${seq} is a bad bank event`);
    }
    if (!isMinor(p.amountMinor) || p.amountMinor < 0 || (p.writId !== undefined && !str(p.writId))) throw new Error(`resume entry ${seq} is a bad bank event`);
    if (p.stage !== undefined && p.stage !== "reversed" && p.stage !== "cleared") throw new Error(`resume entry ${seq} is a bad bank event`);
    return p as BankPayload;
  }

  // ---------- bank events ----------

  /** The ledger call for one bank event. Keyed by the Airwallex transaction id and stage, so a second call is a no-op. */
  private applyBank(b: BankPayload) {
    const e = { eventId: bankKey(b.txId, b.stage), cardId: b.cardId, amountMinor: b.amountMinor, at: b.at, reason: `Airwallex ${b.kind} ${b.txId}${b.stage ? ` (${b.stage})` : ""}.`, ...(b.writId ? { writId: b.writId } : {}) };
    switch (b.kind) {
      case "AUTHORIZATION":
        return this.ledger.onAuthorization(e);
      case "CLEARING":
        return this.ledger.onClearing(e);
      case "FORCED_CAPTURE":
        return this.ledger.onForcedCapture(e);
      case "REVERSAL":
        return this.ledger.onReversal(e);
      case "REFUND":
        return this.ledger.onRefund(e);
    }
  }

  /**
   * The writ a bank event belongs to: the newest writ consumed on this card at or before the event. An
   * authorization matches only if that writ has none yet (one swipe per writ). Undefined means no approval.
   */
  private matchWrit(cardId: string, kind: BankPayload["kind"], atMs: number): string | undefined {
    const consumed = this.ledger.events({ kind: "WRIT_CONSUMED" }).filter((e) => e.cardId === cardId && e.writId !== undefined && parseIso(e.at) <= atMs + MATCH_SLACK_MS);
    const w = consumed[consumed.length - 1]?.writId;
    if (w === undefined) return undefined;
    // A released writ's card was set INACTIVE first, so any later bank event on it has no approval.
    if (this.ledger.hasEvent(releaseId(w))) return undefined;
    if (kind === "AUTHORIZATION" && this.ledger.events({ kind: "AUTHORIZATION" }).some((e) => e.writId === w)) return undefined;
    return w;
  }

  /**
   * Every new transaction read for a baked card goes into the ledger, then into the signed chain.
   * A clearing or forced capture with no matching approval counts against the pool, raises ALERT and
   * FREEZE (Ledger.cardEvent), and every card of that team is disarmed at once. Declined swipes move no
   * money and are skipped. Nothing is fed while the ledger is not verified.
   */
  async ingestTransactions(cardId: string, txs: CardTx[]): Promise<void> {
    if (!this.verified || !this.cards.some((c) => c.cardId === cardId)) return;
    const sorted = [...txs].sort((a, b) => parseIso(a.at) - parseIso(b.at));
    const frozen = new Map<string, string>();
    await this.lock.run("serve", async () => {
      for (const tx of sorted) {
        const team = await this.ingestOne(cardId, tx);
        if (team !== undefined && !frozen.has(team)) frozen.set(team, `${tx.transactionId}:${tx.status}`);
      }
    });
    for (const [team, txId] of frozen) await this.disarmTeam(team, txId);
  }

  private async ingestOne(cardId: string, tx: CardTx): Promise<string | undefined> {
    if (!str(tx.transactionId)) return undefined;
    const atMs = parseIso(tx.at);
    if (Number.isNaN(atMs) || !isMinor(tx.amountMinor) || tx.amountMinor < 0) return undefined;
    let kind: BankPayload["kind"];
    let stage: BankPayload["stage"];
    let writId: string | undefined;
    let amountMinor = tx.amountMinor;
    if (tx.type === "AUTHORIZATION") {
      const hold = this.ledger.events({ kind: "AUTHORIZATION" }).find((e) => e.eventId === bankKey(tx.transactionId));
      if (HOLD_STATUSES.has(tx.status)) {
        if (hold) return undefined;
        kind = "AUTHORIZATION";
        writId = this.matchWrit(cardId, kind, atMs);
      } else if (REVERSED_STATUSES.has(tx.status)) {
        // Only a hold we recorded can be reversed. Without one, no money ever moved here.
        if (!hold) return undefined;
        kind = "REVERSAL";
        stage = "reversed";
        writId = hold.writId;
        amountMinor = hold.amountMinor;
      } else if (CLEARED_STATUSES.has(tx.status)) {
        kind = "CLEARING";
        stage = "cleared";
        writId = hold ? hold.writId : this.matchWrit(cardId, kind, atMs);
      } else return undefined;
    } else if (tx.type === "CLEARING" && tx.status === "APPROVED") kind = tx.matchedAuthorizations === 0 ? "FORCED_CAPTURE" : "CLEARING";
    else if (tx.type === "REVERSAL" && tx.status === "APPROVED") kind = "REVERSAL";
    else if (tx.type === "REFUND" && tx.status === "APPROVED") kind = "REFUND";
    else return undefined;
    if (this.ledger.hasEvent(bankKey(tx.transactionId, stage))) return undefined;
    if (tx.type !== "AUTHORIZATION" && kind !== "FORCED_CAPTURE") writId = this.matchWrit(cardId, kind, atMs);
    const b: BankPayload = {
      eventId: stage ? `bank:${tx.transactionId}:${stage}` : `bank:${tx.transactionId}`,
      txId: tx.transactionId,
      cardId,
      kind,
      amountMinor,
      at: new Date(atMs).toISOString(),
      ...(writId ? { writId } : {}),
      ...(stage ? { stage } : {}),
    };
    const outcome = this.applyBank(b);
    if (outcome.duplicate) return undefined;
    const now = this.clock() ?? b.at;
    if (this.checkpointer) {
      const r = await this.checkpointer.append("bank", b, now);
      if (!r.ok && !r.replay) this.localAlert(`alert:checkpoint:${b.eventId}`, cardId, `Checkpoint of bank event failed: ${r.reason}`, b.at);
    }
    if (!outcome.freezeTeam) return undefined;
    const freeze = this.ledger.teamFrozen(outcome.team);
    if (this.checkpointer) {
      const reason = freeze?.reason ?? `Freeze every card of team ${outcome.team}.`;
      const r = await this.checkpointer.append("freeze", { eventId: `freeze:${bankKey(tx.transactionId, stage)}`, team: outcome.team, txId: tx.transactionId, reason }, now);
      if (!r.ok && !r.replay) this.localAlert(`alert:checkpoint:freeze:${tx.transactionId}`, cardId, `Checkpoint of freeze failed: ${r.reason}`, b.at);
    }
    return outcome.team;
  }

  /** Money still held for a writ: its RESERVE minus what was already released. 0 once any authorization or clearing touched it. */
  private heldUnswiped(writId: string): number {
    let held = 0;
    for (const e of this.ledger.events()) {
      if (e.writId !== writId) continue;
      if (e.kind === "AUTHORIZATION" || e.kind === "CLEARING" || e.kind === "FORCED_CAPTURE") return 0;
      if (e.kind === "RESERVE") held += e.amountMinor;
      if (e.kind === "EXPIRY" || e.kind === "REVERSAL") held -= e.amountMinor;
    }
    return Math.max(0, held);
  }

  /**
   * After a confirmed INACTIVE for expiry, taint or a team freeze, a consumed writ that never saw a bank
   * authorization gives its reservation back to the pool (reserved to released). Once per writ, keyed by
   * the writ id, checkpointed, and replayed. A failed disarm never releases: the card may still spend.
   */
  private async releaseUnswiped(writId: string, cardId: string, reason: string): Promise<void> {
    if (!this.verified) return;
    await this.lock.run("serve", async () => {
      if (!this.ledger.wasConsumed(writId) || this.ledger.hasEvent(releaseId(writId))) return;
      const amountMinor = this.heldUnswiped(writId);
      if (amountMinor <= 0) return;
      const at = this.clock();
      if (at === undefined) return;
      const p: ReleasePayload = { eventId: releaseId(writId), writId, cardId, amountMinor, reason };
      this.applyRelease(p, at);
      if (this.checkpointer) {
        const r = await this.checkpointer.append("release", p, at);
        if (!r.ok && !r.replay) this.localAlert(`alert:checkpoint:${p.eventId}`, cardId, `Checkpoint of release failed: ${r.reason}`, at);
      }
    });
  }

  /**
   * Every consumed writ past its expiresAt (enclave clock) with no bank authorization gives its hold back,
   * even when its card was disarmed long ago, for example by an older image that did not release. A writ
   * the watcher still has to disarm is skipped: its disarm releases it. Same release:<writId> key, so it
   * happens once whichever path gets there first.
   */
  async releaseExpired(): Promise<void> {
    if (!this.verified) return;
    const now = parseIso(this.clock());
    if (Number.isNaN(now)) return;
    const due: { writId: string; cardId: string }[] = [];
    for (const e of this.ledger.events({ kind: "WRIT_CONSUMED" })) {
      if (e.writId === undefined || e.cardId === undefined || this.ledger.hasEvent(releaseId(e.writId))) continue;
      const exp = parseIso(this.writExpiry.get(e.writId));
      if (Number.isNaN(exp) || now < exp) continue;
      if (this.watcher?.watched(e.cardId)?.writId === e.writId) continue;
      due.push({ writId: e.writId, cardId: e.cardId });
    }
    for (const d of due) await this.releaseUnswiped(d.writId, d.cardId, "writ expired");
  }

  private applyRelease(p: ReleasePayload, at: IsoTime): void {
    this.ledger.onExpiry({ eventId: p.eventId, cardId: p.cardId, writId: p.writId, amountMinor: p.amountMinor, at, reason: `Released ${p.amountMinor} cents held for writ ${p.writId}: ${p.reason}, no authorization came.` });
  }

  private localAlert(eventId: string, cardId: string, reason: string, at: IsoTime): void {
    try {
      this.appendLocal({ eventId, kind: "ALERT", cardId, amountMinor: 0, at, reason });
    } catch {
      // already recorded
    }
  }

  /** Every card of a frozen team goes INACTIVE now. Failures are retried by the watcher. */
  private async disarmTeam(team: string, txId: string): Promise<void> {
    if (!this.watcher) return;
    await Promise.all(this.cards.filter((c) => c.team === team).map((c) => this.watcher!.forceDisarm(c.cardId, "team frozen", `frozen:${txId}:${c.cardId}`)));
  }

  private armFromPayload(p: Record<string, unknown>, seq: number): ArmRecord {
    for (const k of ["eventId", "writId", "cardId", "runId", "approvedAt", "expiresAt", "armedAt"] as const) {
      if (!str(p[k])) throw new Error(`resume entry ${seq} is a bad arm`);
    }
    if (!isMinor(p.amountMinor) || p.amountMinor < 0) throw new Error(`resume entry ${seq} is a bad arm`);
    return p as unknown as ArmRecord;
  }

  /** A checkpointed consume from before a restart: the writ stays used and its money stays held. */
  private replayConsume(e: ChainEntry): void {
    const p = e.payload as { eventId?: unknown; writId?: unknown; cardId?: unknown; amountMinor?: unknown } | null;
    if (typeof p?.writId !== "string" || typeof p.eventId !== "string" || typeof p.cardId !== "string") {
      throw new Error(`resume entry ${e.seq} has no writ`);
    }
    if (!isMinor(p.amountMinor) || p.amountMinor < 0) throw new Error(`resume entry ${e.seq} has a bad amount`);
    const team = this.ledger.cardTeam(p.cardId) ?? UNKNOWN_TEAM;
    const at = new Date(e.at).toISOString();
    this.consumed.add(p.writId);
    const base = { team, cardId: p.cardId, writId: p.writId, amountMinor: p.amountMinor, at };
    this.ledger.append({ ...base, eventId: `consume:${p.writId}`, kind: "WRIT_CONSUMED", reason: `Writ used before restart (checkpoint ${e.seq}).` });
    this.ledger.append({ ...base, eventId: `reserve:${p.eventId}`, kind: "RESERVE", reason: `Held before restart (checkpoint ${e.seq}).` });
  }

  private appendLocal(e: Omit<LedgerEvent, "team">): void {
    const team = (e.cardId !== undefined ? this.ledger.cardTeam(e.cardId) : undefined) ?? UNKNOWN_TEAM;
    this.ledger.append({ ...e, team });
  }

  private teamOfAgent(agent: string): string {
    return this.cards.find((c) => c.agent === agent)?.team ?? UNKNOWN_TEAM;
  }

  // ---------- taint ----------

  private setTaint(runId: string, at: IsoTime, source: string): void {
    this.taints.set(runId, markTainted(this.taints.get(runId) ?? cleanRun(runId), source, at));
  }

  /** Marks a run tainted at a time. There is no way to clear it. The latest mark wins, so an older one cannot hide a newer one. */
  markTaint(runId: string, at: IsoTime, source = "host report"): void {
    if (typeof runId !== "string" || runId === "") return;
    try {
      this.setTaint(runId, at, source);
    } catch {
      // unreadable time: keep whatever taint is already there
    }
  }

  /** True when the agent has a baked card. Taint and proposals for anyone else are refused. */
  knowsAgent(agent: string): boolean {
    return this.cards.some((c) => c.agent === agent);
  }

  /**
   * A taint event whose KMS signature the caller already checked. seq must beat the last accepted seq for
   * the agent. The mark is the later of event.at and the enclave clock, so a backdated event cannot slip
   * under a writ approval. The run is marked in memory first, so even a failed checkpoint leaves it tainted.
   * Armed cards of the run are disarmed at once.
   */
  async acceptTaint(ev: { agent: string; runId: string; urlSha256: string; at: IsoTime; seq: number }): Promise<TaintOutcome> {
    try {
      return await this.lock.run("serve", async (): Promise<TaintOutcome> => {
        if (!this.knowsAgent(ev.agent)) return { ok: false, status: 400, reason: "unknown agent" };
        const last = this.taintSeq.get(ev.agent) ?? 0;
        if (!(ev.seq > last)) return { ok: false, status: 400, reason: `seq ${ev.seq} is not after ${last}: replay refused` };
        const eventMs = parseIso(ev.at);
        const nowIso = this.clock();
        const nowMs = parseIso(nowIso);
        const source = `url sha256 ${ev.urlSha256.slice(0, 16)}`;
        if (Number.isNaN(eventMs)) return { ok: false, status: 400, reason: "at is not an ISO time" };
        if (Number.isNaN(nowMs)) {
          this.markTaint(ev.runId, new Date(eventMs).toISOString(), source);
          return { ok: false, status: 503, reason: "no time read from Airwallex yet, taint held in memory only" };
        }
        const taintedAt = new Date(Math.max(eventMs, nowMs)).toISOString();
        this.markTaint(ev.runId, taintedAt, source);
        const disarmed = this.watcher ? this.watcher.disarmRun(ev.runId, "run tainted") : Promise.resolve([]);
        if (this.unverified !== undefined || !this.checkpointer) {
          return { ok: false, status: 503, reason: "ledger is not verified, taint held in memory only" };
        }
        const durable = await this.checkpointer.append(
          "taint",
          { eventId: `taint:${ev.agent}:${ev.seq}`, agent: ev.agent, runId: ev.runId, urlSha256: ev.urlSha256, seq: ev.seq, eventAt: ev.at, taintedAt },
          nowIso as IsoTime,
        );
        if (!durable.ok) return { ok: false, status: 503, reason: `taint not durable: ${durable.reason}` };
        this.taintSeq.set(ev.agent, ev.seq);
        this.ledger.recordTaint(ev.runId, source, taintedAt, this.teamOfAgent(ev.agent));
        return { ok: true, taintedAt, disarmed };
      });
    } catch (err) {
      return { ok: false, status: 503, reason: `taint failed: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  // ---------- balance ----------

  /** The latest balance read inside the enclave. Anything that is not whole cents with a readable time clears it. */
  setObservation(obs: LiveBalance | undefined): void {
    if (obs === null || typeof obs !== "object" || !isMinor(obs.amountMinor) || obs.amountMinor < 0 || typeof obs.at !== "string" || Number.isNaN(parseIso(obs.at))) {
      this.observation = undefined;
      return;
    }
    this.observation = { amountMinor: obs.amountMinor, at: obs.at };
  }

  // ---------- decisions ----------

  /**
   * One Remote Authorization swipe on the same ledger and lock as arms. handleRemoteAuth calls this only
   * after the signature, nonce window and replay checks pass. now is replaced with the enclave clock.
   */
  async authorizeRa(input: DecisionInput, eventId: string): Promise<Decision> {
    try {
      return await this.lock.run("serve", async () => {
        const gate = this.gate;
        if (gate === undefined || this.unverified !== undefined) {
          return { status: "DECLINED", code: "STATE_UNVERIFIED", reason: this.unverified ?? "Serve is not ready." } as Decision;
        }
        if (input === null || typeof input !== "object" || input.mode !== "ra" || typeof eventId !== "string" || eventId === "") {
          return { status: "DECLINED", code: "INTERNAL_ERROR", reason: "Remote Authorization input is malformed." } as Decision;
        }
        const now = this.clock();
        if (now === undefined) return { status: "DECLINED", code: "UPSTREAM_ERROR", reason: "No time read from Airwallex yet." } as Decision;
        const result = await gate.authorize({ ...input, now }, eventId);
        return result.decision;
      });
    } catch (err) {
      return { status: "DECLINED", code: "INTERNAL_ERROR", reason: `Writ could not decide: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  async authorize(req: ArmRequest): Promise<ServeResult> {
    let order: ArmOrder;
    let seq: number | undefined;
    let writ: ApprovedTask;
    try {
      const gated = await this.lock.run("serve", () => this.authorizeLocked(req));
      if ("status" in gated) return gated;
      ({ order, seq, writ } = gated);
    } catch (err) {
      return declined("INTERNAL_ERROR", `Writ could not decide: ${err instanceof Error ? err.message : String(err)}`);
    }
    const withSeq = (r: ServeResult): ServeResult => (seq !== undefined ? { ...r, seq } : r);
    this.writExpiry.set(order.writId, order.expiresAt);
    // The checkpoint already consumed this writ. Whatever happens next, no second authorize can arm it.
    let armed = false;
    try {
      armed = (await this.armCard(order)) === true;
    } catch {
      return withSeq(declined("ARM_FAILED", "Writ committed but arming the card threw.", order.writId));
    }
    if (!armed) return withSeq(declined("ARM_FAILED", "Writ committed but the card did not arm.", order.writId));
    await this.afterArm(order, writ);
    return withSeq({ status: "AUTHORIZED", writId: order.writId, reason: "Writ checked and committed, card armed.", armed: true });
  }

  /** Records the arm, starts the one-swipe watch, and disarms at once if the run was tainted meanwhile. */
  private async afterArm(order: ArmOrder, writ: ApprovedTask): Promise<void> {
    const armedAt = this.clock() ?? writ.approvedAt;
    const rec: ArmRecord = {
      eventId: `arm:${order.writId}`,
      writId: order.writId,
      cardId: order.cardId,
      runId: writ.runId,
      approvedAt: writ.approvedAt,
      amountMinor: order.amountMinor,
      expiresAt: order.expiresAt,
      armedAt,
    };
    this.watcher?.track({ cardId: order.cardId, writId: order.writId, runId: writ.runId, armedAtMs: parseIso(armedAt), expiresAtMs: parseIso(order.expiresAt) });
    await this.record("arm", { ...rec }, { eventId: rec.eventId, kind: "ARM", cardId: rec.cardId, writId: rec.writId, amountMinor: rec.amountMinor, at: armedAt, reason: `Card armed for writ ${writ.hash.slice(0, 12)}: one swipe up to the writ amount until ${order.expiresAt}.` });
    if (this.watcher && taintedSince(this.taints.get(writ.runId) ?? cleanRun(writ.runId), writ.approvedAt)) {
      await this.watcher.disarmNow(order.cardId, "run tainted");
    }
  }

  private async authorizeLocked(req: ArmRequest): Promise<ServeResult | { order: ArmOrder; seq: number | undefined; writ: ApprovedTask }> {
    const gate = this.gate;
    if (gate === undefined || this.unverified !== undefined) {
      return declined("STATE_UNVERIFIED", this.unverified ?? "Serve is not ready.");
    }
    if (req === null || typeof req !== "object" || typeof req.cardId !== "string") {
      return declined("INTERNAL_ERROR", "Arm request is malformed.");
    }
    const now = this.clock();
    if (now === undefined || Number.isNaN(parseIso(now))) return declined("UPSTREAM_ERROR", "No time read from Airwallex yet.");
    if (req.writ !== undefined) {
      // A writ that fails its signature or hash never binds to the card, so junk from the internet cannot block it.
      const forged = this.forgedWrit(req, now);
      if (forged) return forged;
      if (typeof req.writ.id === "string" && this.revokedAtResume.has(req.writ.id)) {
        return declined("WRIT_REVOKED", "This writ was declined and closed before a restart.", req.writ.id);
      }
      try {
        this.ledger.registerWrit(req.writ, req.cardId, now);
      } catch (err) {
        return declined("NO_WRIT_FOR_CARD", `Writ could not be bound to this card: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    const input: DecisionInput = {
      mode: "frozen",
      cardId: req.cardId,
      amountMinor: req.amountMinor,
      currency: req.currency,
      mcc: req.mcc,
      merchantName: req.merchantName,
      now,
    };
    const eventId = `serve:${this.newEventId()}`;
    const result = await gate.authorize(input, eventId);
    const d: Decision = result.decision;
    if (d.status !== "AUTHORIZED") {
      await this.closeDeclined(d, req.cardId, now);
      return declined(d.code, d.reason, d.writId, result.freezeCard);
    }

    const found = this.ledger.writForCard(req.cardId);
    if (!found || found.writ.id !== d.writId) return declined("INTERNAL_ERROR", "Authorized writ not found for the card.", d.writId);
    if (this.armAttempted.has(d.writId)) return declined("WRIT_REPLAY", "This writ already armed the card once.", d.writId);
    this.armAttempted.add(d.writId);
    const w = found.writ;
    return {
      order: {
        cardId: req.cardId,
        writId: w.id,
        writHash: w.hash,
        amountMinor: req.amountMinor,
        currency: w.currency,
        mcc: w.mcc,
        merchantName: w.merchantName,
        expiresAt: w.expiresAt,
      },
      seq: this.checkpointer?.seqOf(eventId),
      writ: w,
    };
  }

  /** A writ that failed its signature or hash can never become valid. Revoke it so it does not hold the card. */
  /**
   * Signature and hash are checked before the writ binds. A failure is recorded as a decision (so the
   * console shows it) but the writ is never registered. Same codes and order as decide().
   */
  private forgedWrit(req: ArmRequest, now: IsoTime): ServeResult | undefined {
    const writ = req.writ!;
    const writId = writ !== null && typeof writ === "object" && typeof writ.id === "string" ? writ.id : undefined;
    const check = writ !== null && typeof writ === "object" && this.publicKeyPem ? verifyWrit(writ, this.publicKeyPem, { autoApproveMinor: 0, knownMerchants: [] }) : { signatureValid: false, hashValid: false };
    if (check.signatureValid && check.hashValid) return undefined;
    const code: DeclineCode = !check.signatureValid ? "WRIT_BAD_SIGNATURE" : "WRIT_HASH_MISMATCH";
    const reason = code === "WRIT_BAD_SIGNATURE" ? "Writ signature does not verify with the baked approver key." : "Writ contents do not match its signed hash.";
    const d: Decision = { status: "DECLINED", code, reason, ...(writId ? { writId } : {}) };
    try {
      const team = this.ledger.cardTeam(req.cardId) ?? UNKNOWN_TEAM;
      this.ledger.recordDecision(`serve:${this.newEventId()}`, d, { team, cardId: req.cardId, amountMinor: isMinor(req.amountMinor) && req.amountMinor >= 0 ? req.amountMinor : 0, at: now });
    } catch {
      // the decline stands without the record
    }
    return declined(code, reason, writId);
  }

  /**
   * Any decline closes the writ's binding so the card can take a new writ: the writ is revoked with the
   * decline reason and the revoke is checkpointed. A consumed writ (armed, or a replay) is never touched.
   */
  private async closeDeclined(d: Extract<Decision, { status: "DECLINED" }>, cardId: string, at: IsoTime): Promise<void> {
    if (d.writId === undefined) return;
    try {
      if (this.ledger.writStatus(d.writId) !== "approved") return;
      this.ledger.revokeWrit(d.writId, at, `${d.code}: ${d.reason}`);
    } catch {
      return;
    }
    if (!this.checkpointer) return;
    const p = { eventId: `revoke:${d.writId}`, writId: d.writId, cardId, code: d.code, reason: d.reason };
    const r = await this.checkpointer.append("revoke", p, at);
    if (!r.ok && !r.replay) this.localAlert(`alert:checkpoint:${p.eventId}`, cardId, `Checkpoint of revoke failed: ${r.reason}`, at);
  }

  // ---------- records ----------

  /** Local ledger event, then the signed checkpoint. A failed checkpoint is a local alert, never a throw. */
  private async record(kind: "arm" | "disarm" | "swipe" | "alert", payload: { eventId: string } & Record<string, unknown>, local: Omit<LedgerEvent, "team">): Promise<AppendResult | undefined> {
    try {
      this.appendLocal(local);
    } catch {
      // duplicate or unreadable: the checkpoint below is still attempted
    }
    if (!this.checkpointer || this.unverified !== undefined) return undefined;
    const at = this.clock() ?? local.at;
    const r = await this.checkpointer.append(kind, payload, at);
    if (!r.ok && !r.replay) {
      try {
        this.appendLocal({ eventId: `alert:checkpoint:${payload.eventId}`, kind: "ALERT", ...(local.cardId ? { cardId: local.cardId } : {}), amountMinor: 0, at: local.at, reason: `Checkpoint of ${kind} failed: ${r.reason}` });
      } catch {
        // already recorded
      }
    }
    return r;
  }

  private async recordWatch(r: WatchRecord): Promise<void> {
    const at = this.clock() ?? new Date(r.arm.armedAtMs).toISOString();
    const base = { cardId: r.arm.cardId, writId: r.arm.writId };
    if (r.kind === "SWIPE") {
      const eventId = `swipe:${r.tx.transactionId}`;
      const reason = `Swipe seen: ${r.tx.type} ${r.tx.status}${r.tx.failureReason ? ` (${r.tx.failureReason})` : ""}.`;
      await this.record("swipe", { eventId, ...base, transactionId: r.tx.transactionId, type: r.tx.type, status: r.tx.status, amountMinor: r.tx.amountMinor, reason }, { eventId, kind: "SWIPE", ...base, amountMinor: r.tx.amountMinor, at: r.tx.at, reason });
    } else if (r.kind === "DISARM") {
      const eventId = `disarm:${r.arm.writId}`;
      await this.record("disarm", { eventId, ...base, reason: r.reason }, { eventId, kind: "DISARM", ...base, amountMinor: 0, at, reason: `Card set INACTIVE: ${r.reason}.` });
      if (RELEASE_REASONS.has(r.reason)) await this.releaseUnswiped(r.arm.writId, r.arm.cardId, r.reason);
    } else {
      const eventId = `alert:disarm:${r.arm.writId}:${r.attempt}`;
      await this.record("alert", { eventId, ...base, reason: r.reason }, { eventId, kind: "ALERT", ...base, amountMinor: 0, at, reason: r.reason });
    }
  }

  // ---------- reads ----------

  /** Read only view of the ledger events. */
  get events() {
    return this.ledger.events();
  }

  get verified(): boolean {
    return this.gate !== undefined && this.unverified === undefined;
  }

  get unverifiedReason(): string | undefined {
    return this.gate === undefined ? (this.unverified ?? "Serve is not ready.") : this.unverified;
  }

  get armWatcher(): ArmWatcher | undefined {
    return this.watcher;
  }

  chainHead(): { seq: number; hash: string } | undefined {
    return this.checkpointer?.head();
  }

  cardFor(team: string, agent: string): BakedConfig["cards"][number] | undefined {
    return this.cards.find((c) => c.team === team && c.agent === agent);
  }

  /** Last n DECISION events, newest first. Card ids become the card's last 4. */
  recentDecisions(n = 50): DecisionView[] {
    const out: DecisionView[] = [];
    const rows = this.ledger.events({ kind: "DECISION" });
    for (let i = rows.length - 1; i >= 0 && out.length < n; i--) {
      const e = rows[i]!;
      const d = (e.data ?? {}) as Partial<Decision> & { code?: string };
      const card = e.cardId !== undefined ? this.cards.find((c) => c.cardId === e.cardId) : undefined;
      const v: DecisionView = {
        eventId: e.eventId,
        at: e.at,
        status: d.status === "AUTHORIZED" ? "AUTHORIZED" : "DECLINED",
        reason: typeof d.reason === "string" ? d.reason : e.reason,
        team: e.team,
        amountMinor: e.amountMinor,
      };
      if (d.status !== "AUTHORIZED" && typeof d.code === "string") v.code = d.code;
      if (e.writId !== undefined) v.writId = e.writId;
      if (card?.agent) v.agent = card.agent;
      if (card?.last4) v.cardLast4 = card.last4;
      out.push(v);
    }
    return out;
  }

  private armedView(cardId: string): boolean | "unknown" {
    const w = this.watcher?.watched(cardId);
    if (w?.origin === "arm") return true;
    if (w) return "unknown";
    if (this.verified) return false;
    return this.watcher?.lastDisarm(cardId)?.ok === true ? false : "unknown";
  }

  /** What the console reads. No card id, no PAN, no key, no secret. */
  state(): StateView {
    const obs = this.observation;
    const unverifiedReason = this.unverifiedReason;
    const view: StateView = {
      verified: this.verified,
      teams: this.teams.map((t) => {
        const s = this.ledger.snapshot(t.team);
        return {
          team: t.team,
          poolLimitMinor: s?.poolLimitMinor ?? t.poolLimitMinor,
          reservedMinor: s?.reservedMinor ?? 0,
          pendingMinor: s?.pendingMinor ?? 0,
          settledMinor: s?.settledMinor ?? 0,
          releasedMinor: s?.releasedMinor ?? 0,
          teamFrozen: s?.teamFrozen ?? null,
        };
      }),
      reserve: {
        liveBalanceMinor: obs?.amountMinor ?? null,
        ringFenceMinor: this.baked.ringFenceMinor,
        reserveFloorMinor: this.baked.reserveFloorMinor,
        openReservationsMinor: this.ledger.openReservationsMinor(),
        asOf: obs?.at ?? null,
      },
      ledger: this.ledgerState,
      cards: this.cards.map((c) => ({ agent: c.agent, team: c.team, last4: c.last4 ?? null, armed: this.armedView(c.cardId), lastDisarm: this.watcher?.lastDisarm(c.cardId) ?? null })),
      chain: this.chainHead() ?? { seq: 0, hash: "0".repeat(64) },
      decisions: this.recentDecisions(50),
    };
    if (unverifiedReason !== undefined) view.unverifiedReason = unverifiedReason;
    return view;
  }
}
