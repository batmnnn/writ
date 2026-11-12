// Commit before yes. Gate hands the consuming entry to a Committer and answers AUTHORIZED only
// when it reports ok. Plain rungs use the SQLite transaction in Ledger.commitApproval. An enclave
// rung can pass a committer that also lands the S3 checkpoint before it reports ok.

import type { ApprovedTask, Decision, IsoTime } from "../types";
import type { Ledger } from "./ledger";

export interface ConsumeEntry {
  eventId: string;
  writ: ApprovedTask;
  cardId: string;
  amountMinor: number;
  at: IsoTime;
  decision: Decision;
}

/** On ok: false nothing durable may say AUTHORIZED for this event id. replay means the writ was already used. */
export type CommitResult = { ok: true } | { ok: false; reason: string; replay?: boolean };

export interface Committer {
  commit(entry: ConsumeEntry): CommitResult | Promise<CommitResult>;
}

/** One SQLite transaction: consume the writ, reserve the money, record the decision. */
export class SqliteCommitter implements Committer {
  constructor(private readonly ledger: Ledger) {}

  commit(entry: ConsumeEntry): CommitResult {
    const outcome = this.ledger.commitApproval(entry);
    return outcome === "ok" ? { ok: true } : { ok: false, reason: "Writ was already used once.", replay: true };
  }
}
