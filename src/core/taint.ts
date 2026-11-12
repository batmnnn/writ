// Per run taint state. A run is tainted from the moment its agent reads untrusted content.
// We keep the latest taint time, so a fresh taint after an approval is never hidden by an older one.

import type { IsoTime, TaintState } from "../types";
import { parseIso } from "./time";

export const cleanRun = (runId: string): TaintState => ({ runId });

export function markTainted(state: TaintState, source: string, at: IsoTime): TaintState {
  const next = parseIso(at);
  if (Number.isNaN(next)) throw new Error("markTainted: unreadable time");
  const prev = parseIso(state.taintedAt);
  if (!Number.isNaN(prev) && prev >= next) return state;
  return { runId: state.runId, taintedAt: at, source };
}

/** True when the run was tainted at or after the given time, or when either time is unreadable. */
export function taintedSince(state: TaintState, sinceIso: IsoTime): boolean {
  if (state.taintedAt === undefined) return false;
  const t = parseIso(state.taintedAt);
  const since = parseIso(sinceIso);
  return Number.isNaN(t) || Number.isNaN(since) || t >= since;
}

/** Durable taint. The Ledger implements it with TAINT events, so a mark survives a reopen. */
export interface TaintStore {
  recordTaint(runId: string, source: string, at: IsoTime): boolean;
  taintFor(runId: string): TaintState;
}

/** With a store, every mark is a TAINT event and reads fold from it. Without one, marks live in memory. */
export class TaintRegistry {
  private readonly runs = new Map<string, TaintState>();

  constructor(private readonly store?: TaintStore) {}

  get(runId: string): TaintState {
    return this.store ? this.store.taintFor(runId) : (this.runs.get(runId) ?? cleanRun(runId));
  }

  mark(runId: string, source: string, at: IsoTime): TaintState {
    const next = markTainted(this.get(runId), source, at);
    if (this.store) {
      this.store.recordTaint(runId, source, at);
      return this.store.taintFor(runId);
    }
    this.runs.set(runId, next);
    return next;
  }
}
