// The only place money rules live. Pure: inputs in, Decision out.
// No network, no SQLite, no clock (input.now is passed in), no LLM.
// Check order is fixed by .cursor/rules/product-invariants.mdc; the first failure wins.

import type { BudgetLedger, Decision, DecisionInput, DecisionState, DeclineCode, ReserveState } from "../types";
import { normalizeMerchant } from "./merchant";
import { formatMinor, isMinor, isPositiveMinor } from "./money";
import { parseIso } from "./time";

function decline(code: DeclineCode, reason: string, writId?: string): Decision {
  return writId === undefined ? { status: "DECLINED", code, reason } : { status: "DECLINED", code, reason, writId };
}

const ledgerIsWhole = (l: BudgetLedger): boolean =>
  [l.poolLimitMinor, l.reservedMinor, l.pendingMinor, l.settledMinor].every((n) => isMinor(n) && n >= 0);

const reserveIsWhole = (r: ReserveState): boolean =>
  [r.liveBalanceMinor, r.ringFenceMinor, r.reserveFloorMinor, r.openReservationsMinor].every(isMinor);

export function decide(input: DecisionInput, state: DecisionState): Decision {
  try {
    return evaluate(input, state);
  } catch (err) {
    return decline("INTERNAL_ERROR", `decide failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

const DEFAULT_MAX_BALANCE_AGE_MS = 60_000;

function evaluate(input: DecisionInput, state: DecisionState): Decision {
  // 0. Ledger state. Only an explicit false declines; callers that do not check omit the field.
  if (state.chainVerified === false) return decline("STATE_UNVERIFIED", "Ledger hash chain did not verify.");

  // 1. Remote Authorization request auth.
  if (input.mode === "ra") {
    const ra = input.ra;
    if (!ra || ra.signatureValid !== true) return decline("RA_BAD_SIGNATURE", "Request signature did not verify.");
    if (ra.nonceFresh !== true) return decline("RA_STALE_NONCE", "Request nonce is outside the 30 s window.");
    if (ra.nonceSeen !== false) return decline("RA_NONCE_REPLAY", "Request nonce was already used.");
  }

  const amount = input.amountMinor;
  if (!isPositiveMinor(amount)) return decline("INTERNAL_ERROR", "Amount is not a positive whole number of cents.");
  const now = parseIso(input.now);
  if (Number.isNaN(now)) return decline("INTERNAL_ERROR", "Decision time is missing or unreadable.");

  // 2. Card to writ lookup.
  const writ = state.writ;
  if (!writ) return decline("NO_WRIT_FOR_CARD", "No approved writ for this card.");
  const id = writ.id;
  if (!state.writStatus) return decline("INTERNAL_ERROR", "Writ status is missing.", id);

  // 3 and 4. Signature, then hash.
  if (state.writSignatureValid !== true) return decline("WRIT_BAD_SIGNATURE", "Writ approval signature did not verify.", id);
  if (state.writHashValid !== true) return decline("WRIT_HASH_MISMATCH", "Writ was changed after it was approved.", id);

  // 5. Expiry.
  const expiresAt = parseIso(writ.expiresAt);
  if (Number.isNaN(expiresAt)) return decline("WRIT_EXPIRED", "Writ expiry is unreadable.", id);
  if (state.writStatus === "expired" || now >= expiresAt) {
    return decline("WRIT_EXPIRED", `Writ expired at ${writ.expiresAt}.`, id);
  }

  // 6. Single use and revocation.
  if (state.writStatus === "consumed") return decline("WRIT_REPLAY", "Writ was already used once.", id);
  if (state.writStatus === "revoked") return decline("WRIT_REVOKED", "Writ was revoked.", id);

  // 7 to 10. The swipe must match the writ.
  if (input.currency.trim().toUpperCase() !== writ.currency) {
    return decline("CURRENCY_NOT_IN_WRIT", `Currency ${input.currency} is not ${writ.currency}.`, id);
  }
  if (input.mcc.trim() !== writ.mcc) {
    return decline("MCC_NOT_IN_WRIT", `Merchant category ${input.mcc} is not ${writ.mcc}.`, id);
  }
  if (normalizeMerchant(input.merchantName) !== normalizeMerchant(writ.merchantName)) {
    return decline("MERCHANT_NOT_IN_WRIT", `Merchant "${input.merchantName}" is not "${writ.merchantName}".`, id);
  }
  if (amount > writ.amountMinor) {
    return decline("AMOUNT_OVER_WRIT", `Amount ${formatMinor(amount)} is over the approved ${formatMinor(writ.amountMinor)}.`, id);
  }

  // 11. Taint at or after approval blocks spend.
  if (state.taint.runId !== writ.runId) return decline("INTERNAL_ERROR", "Taint state belongs to a different run.", id);
  if (state.taint.taintedAt !== undefined) {
    const taintedAt = parseIso(state.taint.taintedAt);
    const approvedAt = parseIso(writ.approvedAt);
    if (Number.isNaN(taintedAt) || Number.isNaN(approvedAt) || taintedAt >= approvedAt) {
      const source = state.taint.source ? ` (${state.taint.source})` : "";
      return decline("TAINTED_RUN", `Agent read untrusted content${source} after this writ was approved.`, id);
    }
  }

  // 12. Team pool across every card of the team. A frozen team has no pool left at all.
  const ledger = state.ledger;
  if (!ledger || ledger.team !== writ.team || !ledgerIsWhole(ledger)) {
    return decline("INTERNAL_ERROR", `No usable budget row for team ${writ.team}.`, id);
  }
  if (ledger.teamFrozen !== undefined) {
    const why = typeof ledger.teamFrozen?.reason === "string" ? ledger.teamFrozen.reason : "unknown reason";
    return decline("TEAM_POOL_EXHAUSTED", `Team ${writ.team} is frozen, no card of the team may spend: ${why}`, id);
  }
  const used = ledger.reservedMinor + ledger.pendingMinor + ledger.settledMinor;
  if (used + amount > ledger.poolLimitMinor) {
    return decline(
      "TEAM_POOL_EXHAUSTED",
      `Team budget used up: ${formatMinor(used)} of ${formatMinor(ledger.poolLimitMinor)} spent or held, this needs ${formatMinor(amount)}.`,
      id,
    );
  }

  // 13. Cash reserve: the balance must be fresh, then the floor must hold.
  const reserve = state.reserve;
  if (!reserve || !reserveIsWhole(reserve)) {
    return decline("UPSTREAM_ERROR", "Live balance is unknown or stale.", id);
  }
  if (typeof reserve.asOf === "string") {
    const maxAge = reserve.maxAgeMs ?? DEFAULT_MAX_BALANCE_AGE_MS;
    const age = now - parseIso(reserve.asOf);
    if (!isMinor(maxAge) || maxAge < 0 || Number.isNaN(age) || age > maxAge) {
      return decline("BALANCE_STALE", `Live balance read at ${reserve.asOf} is older than ${maxAge} ms.`, id);
    }
  }
  const after = Math.min(reserve.liveBalanceMinor, reserve.ringFenceMinor) - reserve.openReservationsMinor - amount;
  if (after < reserve.reserveFloorMinor) {
    return decline(
      "RESERVE_FLOOR",
      `Cash reserve would fall to ${formatMinor(after)}, floor is ${formatMinor(reserve.reserveFloorMinor)}.`,
      id,
    );
  }

  return {
    status: "AUTHORIZED",
    writId: id,
    reason: `${formatMinor(amount)} at ${writ.merchantName}. Team pool ${formatMinor(used + amount)} of ${formatMinor(ledger.poolLimitMinor)}. Reserve stays at ${formatMinor(after)}.`,
  };
}
