import { generateApproverKeys, signWrit, verifyWrit } from "../src/core/writ";
import type { ApprovedTask, DecisionInput, DecisionState, WritProposal } from "../src/types";

export const KEYS = generateApproverKeys();
export const OTHER_KEYS = generateApproverKeys();

export const APPROVED_AT = "2026-11-12T08:30:00.000Z";
export const NOW = "2026-11-12T08:35:00.000Z";

export function proposal(over: Partial<WritProposal> = {}): WritProposal {
  return {
    id: "writ-1",
    team: "research",
    agent: "research-1",
    runId: "run-1",
    purpose: "Dataset licence for the churn study",
    merchantName: "DataCo",
    mcc: "5734",
    amountMinor: 18000,
    currency: "USD",
    expiresAt: "2026-11-12T09:00:00.000Z",
    nonce: "n-1",
    ...over,
  };
}

export function signed(over: Partial<WritProposal> = {}, approvedAt = APPROVED_AT): ApprovedTask {
  return signWrit(proposal(over), approvedAt, KEYS.privateKeyPem);
}

export function input(over: Partial<DecisionInput> = {}): DecisionInput {
  return {
    mode: "frozen",
    cardId: "card-1",
    amountMinor: 18000,
    currency: "USD",
    mcc: "5734",
    merchantName: "DataCo",
    now: NOW,
    ...over,
  };
}

/** A state where everything passes. */
export function state(writ: ApprovedTask = signed(), over: Partial<DecisionState> = {}): DecisionState {
  const check = verifyWrit(writ, KEYS.publicKeyPem, { autoApproveMinor: 25000, knownMerchants: [] });
  return {
    writ,
    writStatus: "approved",
    writSignatureValid: check.signatureValid,
    writHashValid: check.hashValid,
    taint: { runId: writ.runId },
    ledger: { team: writ.team, poolLimitMinor: 50000, reservedMinor: 0, pendingMinor: 0, settledMinor: 0, releasedMinor: 0, alerts: 0 },
    reserve: { liveBalanceMinor: 1_000_000_000, ringFenceMinor: 2_500_000, reserveFloorMinor: 2_000_000, openReservationsMinor: 0 },
    ...over,
  };
}

/** Small seeded PRNG so property tests are reproducible. */
export function rng(seed: number) {
  let s = seed >>> 0;
  const next = () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return {
    next,
    int: (lo: number, hi: number) => lo + Math.floor(next() * (hi - lo + 1)),
    pick: <T>(xs: readonly T[]): T => xs[Math.floor(next() * xs.length)] as T,
  };
}
