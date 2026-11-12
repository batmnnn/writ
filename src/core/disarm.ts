// Frozen mode: set a card INACTIVE through the adapter (which retries) and put the outcome on the ledger.
// A disarm that still fails after the retries is an ALERT event, because the card may still be spendable.

import type { AirwallexAdapter, IsoTime } from "../types";
import type { Ledger } from "./ledger";

export interface DisarmContext {
  /** Our own id for this disarm operation. The ledger write is idempotent on it. */
  opId: string;
  reason: string;
  writId?: string;
  now: () => IsoTime;
}

/** Returns true only when the card is confirmed INACTIVE. Never throws. */
export async function disarmAndRecord(
  adapter: Pick<AirwallexAdapter, "disarm">,
  ledger: Ledger,
  cardId: string,
  ctx: DisarmContext,
): Promise<boolean> {
  let ok = false;
  let error: string | undefined;
  try {
    const r = await adapter.disarm(cardId);
    ok = r.ok;
    if (!r.ok) error = `${r.error.kind}: ${r.error.message}`.slice(0, 200);
  } catch (err) {
    error = (err instanceof Error ? err.message : String(err)).slice(0, 200);
  }
  const record = { opId: ctx.opId, cardId, at: ctx.now(), ok, reason: ctx.reason, ...(ctx.writId !== undefined ? { writId: ctx.writId } : {}) };
  try {
    ledger.recordDisarm(error === undefined ? record : { ...record, error });
  } catch {
    // the adapter result still decides what the caller does next
  }
  return ok;
}
