// Shared types for Writ. Money is always integer minor units (cents) inside Writ.
// Conversion to Airwallex major units happens only in src/airwallex/.

export type Currency = "USD";
export type Mcc = string; // 4 digit Visa merchant category code, e.g. "5734"
export type IsoTime = string; // ISO 8601 with offset
export type Mode = "ra" | "frozen";

export type Result<T, E = AdapterError> =
  | { ok: true; value: T }
  | { ok: false; error: E };

export interface AdapterError {
  kind: "timeout" | "http" | "network" | "invalid_response" | "config";
  status?: number;
  code?: string;
  message: string;
  requestId?: string;
}

/** What an agent may ask for. The agent never sees a card number or a key. */
export interface WritProposal {
  id: string;
  team: string;
  agent: string;
  runId: string;
  purpose: string;
  merchantName: string;
  mcc: Mcc;
  amountMinor: number;
  currency: Currency;
  expiresAt: IsoTime;
  evidenceUrl?: string;
  nonce: string;
}

/** A writ after approval. hash covers every proposal field plus approvedAt. */
export interface ApprovedTask extends WritProposal {
  approvedAt: IsoTime;
  approvedBy: "auto" | "human";
  hash: string; // sha256 hex of canonical JSON
  signature: string; // Ed25519 over hash, base64, made on the approver's device
  singleUse: true;
}

export type WritStatus = "approved" | "armed" | "consumed" | "revoked" | "expired";

export const DECLINE_CODES = [
  "STATE_UNVERIFIED",
  "RA_BAD_SIGNATURE",
  "RA_STALE_NONCE",
  "RA_NONCE_REPLAY",
  "NO_WRIT_FOR_CARD",
  "WRIT_BAD_SIGNATURE",
  "WRIT_HASH_MISMATCH",
  "WRIT_EXPIRED",
  "WRIT_REPLAY",
  "WRIT_REVOKED",
  "CURRENCY_NOT_IN_WRIT",
  "MCC_NOT_IN_WRIT",
  "MERCHANT_NOT_IN_WRIT",
  "AMOUNT_OVER_WRIT",
  "TAINTED_RUN",
  "TEAM_POOL_EXHAUSTED",
  "BALANCE_STALE",
  "RESERVE_FLOOR",
  "COMMIT_FAILED", // Gate only: the consuming entry did not commit, so no AUTHORIZED
  "UPSTREAM_ERROR",
  "INTERNAL_ERROR",
] as const;
export type DeclineCode = (typeof DECLINE_CODES)[number];

export type Decision =
  | { status: "AUTHORIZED"; writId: string; reason: string }
  | { status: "DECLINED"; code: DeclineCode; reason: string; writId?: string };

/** Fail closed default. Use this whenever anything is unknown. */
export const failClosed = (code: DeclineCode, reason: string): Decision => ({
  status: "DECLINED",
  code,
  reason,
});

/** Per team budget across all of that team's agent cards. */
export interface BudgetLedger {
  team: string;
  poolLimitMinor: number;
  reservedMinor: number; // approved or armed, not yet authorized
  pendingMinor: number; // authorized, not yet cleared
  settledMinor: number; // cleared, net of refunds
  releasedMinor: number; // reversed or expired, informational
  alerts: number; // forced captures or other unmatched events
  /**
   * Set when a FREEZE event exists for the team (unmatched clearing, authorization or forced capture).
   * decide() then declines every spend for the team. Folded from events, so it survives a reload.
   * Nothing lifts it yet: an unfreeze needs a new signed or operator ledger event, which is not built.
   */
  teamFrozen?: { at: IsoTime; reason: string };
}

export type LedgerEventKind =
  | "RESERVE"
  | "AUTHORIZATION"
  | "CLEARING"
  | "REVERSAL"
  | "EXPIRY"
  | "REFUND"
  | "FORCED_CAPTURE"
  | "ALERT";

/** Events that move no money but must be on the record. */
export type AuditEventKind =
  | "DECISION"
  | "TEAM_CONFIG"
  | "CARD_REGISTERED"
  | "WRIT_REGISTERED"
  | "WRIT_CONSUMED"
  | "WRIT_REVOKED"
  | "ARM"
  | "DISARM"
  | "SWIPE"
  | "TAINT"
  | "FREEZE";

export type EventKind = LedgerEventKind | AuditEventKind;

export interface LedgerEvent {
  eventId: string; // Airwallex event id or our own id; writes are idempotent on it
  kind: EventKind;
  team: string;
  cardId?: string;
  writId?: string;
  amountMinor: number;
  at: IsoTime;
  reason: string;
  data?: unknown;
}

export interface TaintState {
  runId: string;
  taintedAt?: IsoTime;
  source?: string; // the untrusted URL or input that caused it
}

export interface ReserveState {
  liveBalanceMinor: number;
  ringFenceMinor: number;
  reserveFloorMinor: number;
  openReservationsMinor: number;
  asOf?: IsoTime; // when the live balance was read
  maxAgeMs?: number; // default 60000 when asOf is set
}

/** One swipe (RA mode) or one arm request (frozen mode), normalized. */
export interface DecisionInput {
  mode: Mode;
  cardId: string;
  amountMinor: number;
  currency: string;
  mcc: Mcc;
  merchantName: string;
  now: IsoTime;
  ra?: { nonceFresh: boolean; nonceSeen: boolean; signatureValid: boolean };
}

export interface DecisionState {
  /** false when the ledger hash chain did not verify. Absent means not checked by this caller. */
  chainVerified?: boolean;
  writ?: ApprovedTask;
  writStatus?: WritStatus;
  writSignatureValid: boolean;
  writHashValid: boolean;
  ledger?: BudgetLedger;
  taint: TaintState;
  reserve?: ReserveState;
}

export interface ArmSpec {
  amountMinor: number;
  currency: Currency;
  mcc: Mcc;
  activeTo: IsoTime;
  writHashPrefix: string;
  /** Spend already on the card. The sandbox counts it against a re-armed ALL_TIME limit. */
  priorSpendMinor?: number;
}

export interface SwipeSpec {
  cardId: string;
  amountMinor: number;
  currency: string;
  mcc: Mcc;
  merchantName: string;
}

export interface SwipeOutcome {
  transactionId: string;
  accepted: boolean; // transaction_type CLEARING or authorized
  failureReason?: string; // Airwallex failure_reason, e.g. CARD_INACTIVE
  remoteAuth?: { defaultActionUsed: boolean; responseStatus?: string; statusReason?: string };
  raw: unknown;
}

export interface IssuingConfig {
  remoteAuthEnabled: boolean;
  perTransactionMaxMinor?: number;
  raw: unknown;
}

/** The only door to Airwallex. RA and frozen modes share it. */
export interface AirwallexAdapter {
  readonly mode: Mode;
  getIssuingConfig(): Promise<Result<IssuingConfig>>;
  getBalance(currency: Currency): Promise<Result<number>>;
  createCardholder(name: string): Promise<Result<{ cardholderId: string }>>;
  createAgentCard(input: {
    cardholderId: string;
    team: string;
    agent: string;
  }): Promise<Result<{ cardId: string; last4?: string; startedActive: boolean }>>;
  arm(cardId: string, spec: ArmSpec): Promise<Result<void>>;
  disarm(cardId: string): Promise<Result<void>>;
  simulateSwipe(spec: SwipeSpec): Promise<Result<SwipeOutcome>>;
  /** Sandbox only: clear an approved authorization. */
  simulateCapture(authorization: SwipeOutcome, amountMinor: number, merchantName: string): Promise<Result<SwipeOutcome>>;
  readTransaction(cardId: string, sinceIso: IsoTime): Promise<Result<SwipeOutcome | undefined>>;
}
