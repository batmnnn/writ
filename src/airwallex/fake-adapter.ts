// In memory AirwallexAdapter for tests and replay. It mimics the bank side refusals of a frozen card:
// CARD_INACTIVE, LIMIT_EXCEEDED, MERCHANT_CATEGORY_NOT_ALLOWED, CURRENCY_NOT_ALLOWED.

import type {
  AdapterError,
  AirwallexAdapter,
  ArmSpec,
  Currency,
  IsoTime,
  IssuingConfig,
  Mode,
  Result,
  SwipeOutcome,
  SwipeSpec,
} from "../types";

interface FakeCard {
  cardId: string;
  team: string;
  agent: string;
  status: "ACTIVE" | "INACTIVE";
  perTransactionMinor: number;
  allTimeMinor: number;
  /** Spend counted against ALL_TIME. Reset on arm unless allTimeCountsPriorSpend. */
  allTimeSpentMinor: number;
  currency: string;
  mcc: string;
}

interface FakeTx {
  outcome: SwipeOutcome;
  cardId: string;
  at: number;
}

export type FakeOp = "getIssuingConfig" | "getBalance" | "createCardholder" | "createAgentCard" | "arm" | "disarm" | "simulateSwipe" | "simulateCapture" | "readTransaction";

export interface FakeAdapterOptions {
  mode?: Mode;
  balanceMinor?: number;
  perTransactionMaxMinor?: number;
  remoteAuthEnabled?: boolean;
  /** True when the sandbox counts spend from before a rearm against the new ALL_TIME limit. */
  allTimeCountsPriorSpend?: boolean;
  now?: () => number;
}

export class FakeAdapter implements AirwallexAdapter {
  readonly mode: Mode;
  readonly cards = new Map<string, FakeCard>();
  readonly transactions: FakeTx[] = [];
  /** Ops listed here fail once with the given error, then clear. */
  readonly failNext = new Map<FakeOp, AdapterError>();
  balanceMinor: number;
  private seq = 0;
  private readonly opts: FakeAdapterOptions;
  private readonly now: () => number;

  constructor(opts: FakeAdapterOptions = {}) {
    this.opts = opts;
    this.mode = opts.mode ?? "frozen";
    this.balanceMinor = opts.balanceMinor ?? 1_000_000_000;
    this.now = opts.now ?? (() => Date.now());
  }

  private injected(op: FakeOp): { ok: false; error: AdapterError } | undefined {
    const e = this.failNext.get(op);
    if (!e) return undefined;
    this.failNext.delete(op);
    return { ok: false, error: e };
  }

  private id(prefix: string): string {
    this.seq += 1;
    return `${prefix}-${String(this.seq).padStart(4, "0")}`;
  }

  async getIssuingConfig(): Promise<Result<IssuingConfig>> {
    const f = this.injected("getIssuingConfig");
    if (f) return f;
    const max = this.opts.perTransactionMaxMinor ?? 5_000_000;
    return { ok: true, value: { remoteAuthEnabled: this.opts.remoteAuthEnabled ?? false, perTransactionMaxMinor: max, raw: { fake: true } } };
  }

  async getBalance(_currency: Currency): Promise<Result<number>> {
    return this.injected("getBalance") ?? { ok: true, value: this.balanceMinor };
  }

  async createCardholder(_name: string): Promise<Result<{ cardholderId: string }>> {
    return this.injected("createCardholder") ?? { ok: true, value: { cardholderId: this.id("fake-cardholder") } };
  }

  async createAgentCard(input: { cardholderId: string; team: string; agent: string }) {
    const f = this.injected("createAgentCard");
    if (f) return f;
    const cardId = this.id("fake-card");
    this.cards.set(cardId, {
      cardId,
      team: input.team,
      agent: input.agent,
      status: this.mode === "frozen" ? "INACTIVE" : "ACTIVE",
      perTransactionMinor: 100,
      allTimeMinor: 100,
      allTimeSpentMinor: 0,
      currency: "USD",
      mcc: "5734",
    });
    const value: { cardId: string; last4?: string; startedActive: boolean } = { cardId, last4: "0000", startedActive: false };
    return { ok: true as const, value };
  }

  async arm(cardId: string, spec: ArmSpec): Promise<Result<void>> {
    const f = this.injected("arm");
    if (f) return f;
    const card = this.cards.get(cardId);
    if (!card) return { ok: false, error: { kind: "http", status: 404, message: "card not found" } };
    card.status = "ACTIVE";
    card.perTransactionMinor = spec.amountMinor;
    card.allTimeMinor = spec.amountMinor + (spec.priorSpendMinor ?? 0);
    if (!this.opts.allTimeCountsPriorSpend) card.allTimeSpentMinor = 0;
    card.currency = spec.currency;
    card.mcc = spec.mcc;
    return { ok: true, value: undefined };
  }

  async disarm(cardId: string): Promise<Result<void>> {
    const f = this.injected("disarm");
    if (f) return f;
    const card = this.cards.get(cardId);
    if (!card) return { ok: false, error: { kind: "http", status: 404, message: "card not found" } };
    card.status = "INACTIVE";
    return { ok: true, value: undefined };
  }

  async simulateSwipe(spec: SwipeSpec): Promise<Result<SwipeOutcome>> {
    const f = this.injected("simulateSwipe");
    if (f) return f;
    const card = this.cards.get(spec.cardId);
    if (!card) return { ok: false, error: { kind: "http", status: 404, message: "card not found" } };
    let failureReason: string | undefined;
    if (card.status !== "ACTIVE") failureReason = "CARD_INACTIVE";
    else if (spec.amountMinor > card.perTransactionMinor || card.allTimeSpentMinor + spec.amountMinor > card.allTimeMinor) {
      failureReason = "LIMIT_EXCEEDED";
    } else if (spec.mcc !== card.mcc) failureReason = "MERCHANT_CATEGORY_NOT_ALLOWED";
    else if (spec.currency !== card.currency) failureReason = "CURRENCY_NOT_ALLOWED";

    const transactionId = this.id("fake-tx");
    const accepted = failureReason === undefined;
    if (accepted) {
      card.allTimeSpentMinor += spec.amountMinor;
      this.balanceMinor -= spec.amountMinor;
    }
    const outcome: SwipeOutcome = {
      transactionId,
      accepted,
      ...(failureReason ? { failureReason } : {}),
      raw: {
        transaction_id: transactionId,
        transaction_type: "CLEARING",
        status: accepted ? "APPROVED" : "FAILED",
        ...(failureReason ? { failure_reason: failureReason } : {}),
        card_id: spec.cardId,
        merchant: { name: spec.merchantName, category_code: spec.mcc },
        transaction_currency: spec.currency,
        transaction_amount_minor: spec.amountMinor,
      },
    };
    this.transactions.push({ outcome, cardId: spec.cardId, at: this.now() });
    return { ok: true, value: outcome };
  }

  /** An accepted swipe already counted its amount, so a capture adds nothing. A declined one cannot be captured. */
  async simulateCapture(authorization: SwipeOutcome, amountMinor: number, merchantName: string): Promise<Result<SwipeOutcome>> {
    const f = this.injected("simulateCapture");
    if (f) return f;
    const auth = this.transactions.find((t) => t.outcome.transactionId === authorization.transactionId);
    if (!auth || !auth.outcome.accepted) {
      return { ok: false, error: { kind: "http", status: 400, message: "authorization was not approved, nothing to capture" } };
    }
    if (!Number.isSafeInteger(amountMinor) || amountMinor <= 0) {
      return { ok: false, error: { kind: "config", message: "capture amount must be positive minor units" } };
    }
    const transactionId = this.id("fake-tx");
    const prior = auth.outcome.raw as Record<string, unknown>;
    const outcome: SwipeOutcome = {
      transactionId,
      accepted: true,
      raw: {
        ...prior,
        transaction_id: transactionId,
        transaction_type: "CLEARING",
        status: "APPROVED",
        merchant: { name: merchantName, category_code: (prior.merchant as { category_code?: string } | undefined)?.category_code },
        transaction_amount_minor: amountMinor,
        captured_from: authorization.transactionId,
      },
    };
    this.transactions.push({ outcome, cardId: auth.cardId, at: this.now() });
    return { ok: true, value: outcome };
  }

  async readTransaction(cardId: string, sinceIso: IsoTime): Promise<Result<SwipeOutcome | undefined>> {
    const f = this.injected("readTransaction");
    if (f) return f;
    const since = Date.parse(sinceIso);
    const rows = this.transactions.filter((t) => t.cardId === cardId && (!Number.isFinite(since) || t.at >= since));
    return { ok: true, value: rows.at(-1)?.outcome };
  }
}
