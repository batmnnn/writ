// AirwallexAdapter over the REST API. The only code that maps Writ types to Airwallex payloads.
// Amounts leave here in major units and come back as integer minor units.

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
import type { AirwallexClient } from "./client";
import { last4, redact } from "./redact";
import { majorToMinor, minorToMajor } from "./units";

export interface ListedTransaction {
  lifecycleId?: string;
  amountMinor?: number;
  at?: string;
  type?: string;
  status?: string;
}

export interface RestAdapterOptions {
  client: AirwallexClient;
  mode: Mode;
  uuid?: () => string;
  sleep?: (ms: number) => Promise<void>;
  /** Polls while a new card goes PENDING to ACTIVE. */
  pollIntervalMs?: number;
  pollAttempts?: number;
  /** Backoff before each disarm retry. Three retries after the first try. */
  disarmBackoffMs?: number[];
  createdBy?: string;
  /** Per-call timeout for simulation create, capture and reverse. Default 20 s. */
  simulationTimeoutMs?: number;
}

/** What the probe wants to know about the last card create, beyond the adapter contract. */
export interface CardCreateTrace {
  cardId: string;
  createStatus: string | undefined;
  statusTrail: string[];
  frozenAfterCreate: boolean;
}

type Json = Record<string, unknown>;

const fail = (error: AdapterError): { ok: false; error: AdapterError } => ({ ok: false, error });
const asObj = (v: unknown): Json | undefined => (v && typeof v === "object" && !Array.isArray(v) ? (v as Json) : undefined);
const asStr = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

/** Placeholder controls for a new card. Arm replaces them. 1 USD is the smallest round limit. */
const NEW_CARD_LIMIT_MAJOR = 1;
const NEW_CARD_MCC = "5734";
/** Create, capture and reverse can sit past the 5 s card-update default. */
const SIMULATION_TIMEOUT_MS = 20_000;

export class RestAdapter implements AirwallexAdapter {
  readonly mode: Mode;
  lastCardCreate: CardCreateTrace | undefined;
  private readonly client: AirwallexClient;
  private readonly uuid: () => string;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly pollIntervalMs: number;
  private readonly pollAttempts: number;
  private readonly disarmBackoffMs: number[];
  private readonly createdBy: string;
  private readonly simulationTimeoutMs: number;

  constructor(o: RestAdapterOptions) {
    this.client = o.client;
    this.mode = o.mode;
    this.uuid = o.uuid ?? (() => crypto.randomUUID());
    this.sleep = o.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.pollIntervalMs = o.pollIntervalMs ?? 1000;
    this.pollAttempts = o.pollAttempts ?? 20;
    this.disarmBackoffMs = o.disarmBackoffMs ?? [250, 500, 1000];
    this.createdBy = o.createdBy ?? "Writ";
    this.simulationTimeoutMs = o.simulationTimeoutMs ?? SIMULATION_TIMEOUT_MS;
  }

  async getIssuingConfig(): Promise<Result<IssuingConfig>> {
    const r = await this.client.request<unknown>("GET", "/api/v1/issuing/config");
    if (!r.ok) return r;
    const raw = asObj(r.value);
    if (!raw) return fail({ kind: "invalid_response", message: "issuing config is not an object" });
    const ra = asObj(raw.remote_auth_settings);
    const limits = asObj(raw.spending_limit_settings)?.per_transaction_limits;
    const usd = Array.isArray(limits) ? limits.map(asObj).find((l) => l?.currency === "USD") : undefined;
    const max = majorToMinor(usd?.maximum);
    return {
      ok: true,
      value: {
        remoteAuthEnabled: ra?.enabled === true,
        ...(max !== undefined ? { perTransactionMaxMinor: max } : {}),
        raw: redact(raw),
      },
    };
  }

  async getBalance(currency: Currency): Promise<Result<number>> {
    const r = await this.client.request<unknown>("GET", "/api/v1/balances/current");
    if (!r.ok) return r;
    if (!Array.isArray(r.value)) return fail({ kind: "invalid_response", message: "balances is not a list" });
    const row = r.value.map(asObj).find((b) => b?.currency === currency);
    if (!row) return fail({ kind: "invalid_response", message: `no ${currency} balance row` });
    const minor = majorToMinor(row.available_amount);
    if (minor === undefined) return fail({ kind: "invalid_response", message: "available_amount is not a 2 decimal amount" });
    return { ok: true, value: minor };
  }

  async createCardholder(name: string): Promise<Result<{ cardholderId: string }>> {
    const parts = name.trim().split(/\s+/).filter(Boolean);
    const first = parts[0] ?? "Writ";
    const lastName = parts.length > 1 ? parts.slice(1).join(" ") : "Agent";
    const body = {
      type: "INDIVIDUAL",
      email: `writ-probe-${this.uuid().slice(0, 8)}@example.com`,
      individual: {
        name: { first_name: first, last_name: lastName },
        date_of_birth: "1990-01-15",
        address: { line1: "100 Market St", city: "San Francisco", state: "CA", postcode: "94105", country: "US" },
        express_consent_obtained: "yes",
      },
    };
    const r = await this.client.request<unknown>("POST", "/api/v1/issuing/cardholders/create", { body });
    if (!r.ok) return r;
    const id = asStr(asObj(r.value)?.cardholder_id);
    if (!id) return fail({ kind: "invalid_response", message: "cardholder create returned no cardholder_id" });
    return { ok: true, value: { cardholderId: id } };
  }

  async createAgentCard(input: {
    cardholderId: string;
    team: string;
    agent: string;
  }): Promise<Result<{ cardId: string; last4?: string; startedActive: boolean }>> {
    const requestId = this.uuid();
    const limit = NEW_CARD_LIMIT_MAJOR;
    const body = {
      request_id: requestId,
      cardholder_id: input.cardholderId,
      created_by: this.createdBy,
      form_factor: "VIRTUAL",
      is_personalized: true,
      program: { purpose: "COMMERCIAL" },
      authorization_controls: {
        allowed_transaction_count: "MULTIPLE",
        transaction_limits: {
          currency: "USD",
          limits: [
            { amount: limit, interval: "PER_TRANSACTION" },
            { amount: limit, interval: "ALL_TIME" },
          ],
        },
        allowed_currencies: ["USD"],
        allowed_merchant_categories: [NEW_CARD_MCC],
      },
      metadata: { team: input.team, agent: input.agent },
    };
    const r = await this.client.request<unknown>("POST", "/api/v1/issuing/cards/create", { body, requestId });
    if (!r.ok) return r;
    const created = asObj(r.value);
    const cardId = asStr(created?.card_id);
    if (!cardId) return fail({ kind: "invalid_response", message: "card create returned no card_id", requestId });
    const createStatus = asStr(created?.card_status);
    const trace: CardCreateTrace = { cardId, createStatus, statusTrail: [createStatus ?? "?"], frozenAfterCreate: false };
    this.lastCardCreate = trace;
    let mask = last4(created?.masked_card_number) ?? last4(created?.card_number);

    let status = createStatus;
    for (let i = 0; status !== "ACTIVE" && i < this.pollAttempts; i++) {
      await this.sleep(this.pollIntervalMs);
      const g = await this.getCard(cardId);
      if (!g.ok) continue;
      status = asStr(g.value.card_status);
      trace.statusTrail.push(status ?? "?");
      mask ??= last4(g.value.masked_card_number);
    }
    if (status !== "ACTIVE") {
      return fail({ kind: "invalid_response", message: `card ${cardId} stayed ${status ?? "unknown"}, never ACTIVE`, requestId });
    }

    if (this.mode === "frozen") {
      const frozen = await this.disarm(cardId);
      if (!frozen.ok) return frozen;
      trace.frozenAfterCreate = true;
    }
    return {
      ok: true,
      value: { cardId, ...(mask ? { last4: mask } : {}), startedActive: createStatus === "ACTIVE" },
    };
  }

  async getCard(cardId: string): Promise<Result<Json>> {
    const r = await this.client.request<unknown>("GET", `/api/v1/issuing/cards/${encodeURIComponent(cardId)}`);
    if (!r.ok) return r;
    const o = asObj(r.value);
    if (!o) return fail({ kind: "invalid_response", message: "card is not an object" });
    // Card reads can carry card_number. Keep only the last 4 and drop the rest before anyone sees it.
    const mask = last4(o.masked_card_number) ?? last4(o.card_number);
    const safe = redact(o) as Json;
    if (mask) safe.masked_card_number = `************${mask}`;
    return { ok: true, value: safe };
  }

  async arm(cardId: string, spec: ArmSpec): Promise<Result<void>> {
    const amount = minorToMajor(spec.amountMinor);
    if (amount === undefined || spec.amountMinor <= 0) {
      return fail({ kind: "config", message: "arm amount must be a positive integer of minor units" });
    }
    const priorSpendMinor = spec.priorSpendMinor ?? 0;
    // ALL_TIME counts spend from before a re-arm, so it must cover that spend plus this writ.
    const allTime = Number.isSafeInteger(priorSpendMinor) && priorSpendMinor >= 0 ? minorToMajor(spec.amountMinor + priorSpendMinor) : undefined;
    if (allTime === undefined) {
      return fail({ kind: "config", message: "prior spend must be a non negative integer of minor units" });
    }
    const requestId = this.uuid();
    const body = {
      request_id: requestId,
      card_status: "ACTIVE",
      authorization_controls: {
        transaction_limits: {
          currency: spec.currency,
          limits: [
            { amount, interval: "PER_TRANSACTION" },
            { amount: allTime, interval: "ALL_TIME" },
          ],
        },
        allowed_currencies: [spec.currency],
        allowed_merchant_categories: [spec.mcc],
        active_to: toAirwallexTime(spec.activeTo),
      },
    };
    const r = await this.update(cardId, body, requestId);
    if (r.ok) return { ok: true, value: undefined };
    // Fail closed: a half applied arm must not leave the card spendable.
    await this.disarm(cardId);
    return r;
  }

  async disarm(cardId: string): Promise<Result<void>> {
    const requestId = this.uuid();
    const body = { request_id: requestId, card_status: "INACTIVE" };
    let last: Result<void> = fail({ kind: "network", message: "disarm not attempted" });
    for (let attempt = 0; attempt <= this.disarmBackoffMs.length; attempt++) {
      if (attempt > 0) await this.sleep(this.disarmBackoffMs[attempt - 1] ?? 1000);
      const r = await this.update(cardId, body, requestId);
      if (r.ok) return { ok: true, value: undefined };
      last = r;
    }
    return last;
  }

  private async update(cardId: string, body: Json, requestId: string): Promise<Result<void>> {
    const r = await this.client.request<unknown>("POST", `/api/v1/issuing/cards/${encodeURIComponent(cardId)}/update`, {
      body,
      requestId,
    });
    return r.ok ? { ok: true, value: undefined } : r;
  }

  async simulateSwipe(spec: SwipeSpec): Promise<Result<SwipeOutcome>> {
    const amount = minorToMajor(spec.amountMinor);
    if (amount === undefined || spec.amountMinor <= 0) {
      return fail({ kind: "config", message: "swipe amount must be a positive integer of minor units" });
    }
    const body = {
      card_id: spec.cardId,
      transaction_amount: amount,
      transaction_currency: spec.currency,
      merchant_category_code: spec.mcc,
      merchant_info: spec.merchantName,
    };
    const r = await this.client.request<unknown>("POST", "/api/v1/simulation/issuing/create", {
      body,
      timeoutMs: this.simulationTimeoutMs,
    });
    if (!r.ok) return r;
    const tx = asObj(r.value);
    if (!tx) return fail({ kind: "invalid_response", message: "simulation returned no transaction" });
    return { ok: true, value: toOutcome(tx) };
  }

  /** Sandbox only: clear an approved authorization. Without merchant_info the clearing shows the generator merchant. */
  async simulateCapture(authorization: SwipeOutcome, amountMinor: number, merchantName: string): Promise<Result<SwipeOutcome>> {
    const lifecycleId = asStr(asObj(authorization.raw)?.card_transaction_lifecycle_id);
    const amount = minorToMajor(amountMinor);
    if (!lifecycleId) return fail({ kind: "config", message: "authorization has no card_transaction_lifecycle_id" });
    if (amount === undefined || amountMinor <= 0) return fail({ kind: "config", message: "capture amount must be positive minor units" });
    const r = await this.client.request<unknown>(
      "POST",
      `/api/v1/simulation/issuing/card_transaction_lifecycles/${encodeURIComponent(lifecycleId)}/capture`,
      { body: { transaction_amount: amount, merchant_info: merchantName }, timeoutMs: this.simulationTimeoutMs },
    );
    if (!r.ok) return r;
    const tx = asObj(r.value);
    if (!tx) return fail({ kind: "invalid_response", message: "capture returned no transaction" });
    return { ok: true, value: toOutcome(tx) };
  }

  /** Sandbox only: reverse an approved authorization so the pending hold is released. */
  async reverseSwipe(lifecycleId: string, amountMinor: number): Promise<Result<SwipeOutcome>> {
    const amount = minorToMajor(amountMinor);
    if (lifecycleId.trim() === "") return fail({ kind: "config", message: "reverse needs a lifecycle id" });
    if (amount === undefined || amountMinor <= 0) {
      return fail({ kind: "config", message: "reverse amount must be a positive integer of minor units" });
    }
    const requestId = this.uuid();
    const r = await this.client.request<unknown>(
      "POST",
      `/api/v1/simulation/issuing/card_transaction_lifecycles/${encodeURIComponent(lifecycleId)}/reverse`,
      { body: { request_id: requestId, transaction_amount: amount }, requestId, timeoutMs: this.simulationTimeoutMs },
    );
    if (!r.ok) return r;
    const tx = asObj(r.value);
    if (!tx) return fail({ kind: "invalid_response", message: "reverse returned no transaction", requestId });
    return { ok: true, value: toOutcome(tx) };
  }

  /** Legacy transaction list since a time, amounts already in minor units. A few pages, then stop. */
  async listTransactions(cardId: string, sinceIso: IsoTime): Promise<Result<ListedTransaction[]>> {
    const all: ListedTransaction[] = [];
    for (let page = 0; page < 3; page++) {
      const r = await this.client.request<unknown>("GET", "/api/v1/issuing/transactions", {
        query: { card_id: cardId, from_created_at: toAirwallexTime(sinceIso), page_size: 50, page_num: page },
      });
      if (!r.ok) return r;
      const body = asObj(r.value);
      const items = body?.items;
      if (!Array.isArray(items)) return fail({ kind: "invalid_response", message: "transactions has no items list" });
      for (const item of items) all.push(toListedTransaction(item));
      if (body?.has_more !== true || items.length === 0) break;
    }
    return { ok: true, value: all };
  }

  async readTransaction(cardId: string, sinceIso: IsoTime): Promise<Result<SwipeOutcome | undefined>> {
    const r = await this.client.request<unknown>("GET", "/api/v1/issuing/transactions", {
      query: { card_id: cardId, from_created_at: toAirwallexTime(sinceIso), page_size: 50, page_num: 0 },
    });
    if (!r.ok) return r;
    const items = asObj(r.value)?.items;
    if (!Array.isArray(items)) return fail({ kind: "invalid_response", message: "transactions has no items list" });
    const since = Date.parse(sinceIso);
    const rows = items
      .map(asObj)
      .filter((t): t is Json => !!t)
      .filter((t) => {
        const at = Date.parse(asStr(t.transaction_date) ?? asStr(t.created_at) ?? "");
        return !Number.isFinite(since) || !Number.isFinite(at) || at >= since;
      })
      .sort((a, b) => Date.parse(asStr(b.transaction_date) ?? "") - Date.parse(asStr(a.transaction_date) ?? ""));
    const latest = rows[0];
    return { ok: true, value: latest ? toOutcome(latest) : undefined };
  }
}

/** One legacy transaction row. Lifecycle id may sit on the row or under card_transaction_data. Amounts come back in major units, often negative for a debit. */
export function toListedTransaction(tx: unknown): ListedTransaction {
  const row = asObj(tx);
  if (!row) return {};
  const nested = asObj(row.card_transaction_data);
  const lifecycleId =
    asStr(row.card_transaction_lifecycle_id) ??
    asStr(row.lifecycle_id) ??
    (nested ? (asStr(nested.card_transaction_lifecycle_id) ?? asStr(nested.lifecycle_id)) : undefined);
  const rawAmount = row.transaction_amount ?? row.billing_amount;
  let amountMinor: number | undefined;
  if (typeof rawAmount === "number" && Number.isFinite(rawAmount)) {
    amountMinor = majorToMinor(Math.abs(rawAmount));
  } else if (typeof rawAmount === "string" && rawAmount.trim() !== "") {
    const parsed = majorToMinor(rawAmount.trim().replace(/^-/, ""));
    if (parsed !== undefined) amountMinor = Math.abs(parsed);
  }
  const at = asStr(row.transaction_date) ?? asStr(row.created_at) ?? asStr(row.posted_date);
  const type = asStr(row.transaction_type) ?? asStr(row.type);
  const status = asStr(row.status) ?? asStr(row.process_result);
  const out: ListedTransaction = {};
  if (lifecycleId !== undefined) out.lifecycleId = lifecycleId;
  if (amountMinor !== undefined) out.amountMinor = amountMinor;
  if (at !== undefined) out.at = at;
  if (type !== undefined) out.type = type;
  if (status !== undefined) out.status = status;
  return out;
}

/**
 * CLEARING plus APPROVED is a pass. A FAILED or DECLINED result is a decline with its failure_reason.
 * Anything else, including an approved AUTHORIZATION, is held: money is reserved, not yet debited.
 * Reads both shapes: the legacy list (transaction_type, status) and the simulation response
 * (type, process_result).
 */
export function toOutcome(tx: Json): SwipeOutcome {
  const type = asStr(tx.transaction_type) ?? asStr(tx.type);
  const status = asStr(tx.status) ?? asStr(tx.process_result);
  const ra = asObj(tx.remote_auth);
  const declined = status === "FAILED" || status === "DECLINED";
  const failureReason = asStr(tx.failure_reason) ?? (declined ? "UNKNOWN" : undefined);
  return {
    transactionId: asStr(tx.transaction_id) ?? asStr(tx.card_transaction_id) ?? asStr(tx.card_transaction_event_id) ?? "",
    accepted: type === "CLEARING" && status === "APPROVED" && !failureReason,
    ...(failureReason ? { failureReason } : {}),
    ...(ra
      ? {
          remoteAuth: {
            defaultActionUsed: ra.default_action_used === true,
            ...(asStr(ra.response_status) ? { responseStatus: asStr(ra.response_status)! } : {}),
            ...(asStr(ra.status_reason) ? { statusReason: asStr(ra.status_reason)! } : {}),
          },
        }
      : {}),
    raw: redact(tx),
  };
}

/** Airwallex examples use "2018-10-31T00:00:00+0000". */
export function toAirwallexTime(iso: IsoTime): string {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return iso;
  return new Date(t).toISOString().replace(/\.\d{3}Z$/, "+0000");
}
