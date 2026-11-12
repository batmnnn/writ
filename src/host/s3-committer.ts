// Commit before yes, enclave rung. The consuming entry is chained with entryHash from src/core/chain.ts,
// then written to S3 as a checkpoint with a conditional PUT (If-None-Match: *). commit() reports ok only
// after S3 accepts that write. A second PUT of the same key answers 412 and is a failure, never a success.
// Object Lock retention is the bucket's job. This file never sends a retention header.
// No money decision here. Amounts are integer minor units, passed through into the entry payload.
//
// With a signer, every checkpoint body is {seq, head, entry, signature}: signature is the enclave ledger
// Ed25519 key over entrySigningMessage(hash). loadSignedChain reads the whole prefix back at boot and
// refuses a gap, an unsigned or badly signed entry, an edit, a fork or a stray object.

import { GENESIS_PREV, entryHash, entrySigningMessage, verifyChain, type ChainEntry } from "../core/chain";
import type { CommitResult, Committer, ConsumeEntry } from "../core/committer";

export interface S3PutRequest {
  bucket: string;
  key: string;
  body: string;
  contentType: string;
  /** Always "*": write only if no object exists under this key. */
  ifNoneMatch: "*";
}

/** status 200 or 201 means accepted. 412 means the key exists. A client that throws on 412 may set status or httpStatusCode on the error. */
export interface S3PutResponse {
  status: number;
}

/** Narrow client the host injects. The real one signs and sends from inside the enclave. */
export interface S3Client {
  putObject(req: S3PutRequest): Promise<S3PutResponse>;
}

/** The reads resume and TLS reuse need. Same signed client, same bridge. */
export interface S3Store extends S3Client {
  /** Every key under the prefix, all pages. A failure throws. */
  listKeys(bucket: string, prefix: string): Promise<string[]>;
  /** Object body, or undefined on 404. Any other failure throws. */
  getObject(bucket: string, key: string): Promise<string | undefined>;
}

export interface EntrySigner {
  sign(message: Uint8Array): Uint8Array;
}

export interface S3CommitterOptions {
  client: S3Client;
  bucket: string;
  /** Key prefix, no leading or trailing slash needed. */
  prefix?: string;
  /** Entries already checkpointed, oldest first. They must verify, or the constructor throws. */
  resume?: ChainEntry[];
  /** Enclave ledger key. When set, every new checkpoint carries its signature. */
  signer?: EntrySigner;
}

export const CHECKPOINT_KIND = "consume";
/** New chain prefix for signed checkpoints. checkpoints/serve/ from older images is unsigned and never read. */
export const SIGNED_CHECKPOINT_PREFIX = "checkpoints/v2";
const SEQ_DIGITS = 12;
const MAX_CHECKPOINT_BYTES = 64 * 1024;

function statusOf(err: unknown): number | undefined {
  if (err === null || typeof err !== "object") return undefined;
  const e = err as { status?: unknown; statusCode?: unknown; httpStatusCode?: unknown; $metadata?: { httpStatusCode?: unknown } };
  for (const v of [e.status, e.statusCode, e.httpStatusCode, e.$metadata?.httpStatusCode]) {
    if (typeof v === "number") return v;
  }
  return undefined;
}

export type AppendResult = { ok: true; seq: number; hash: string } | { ok: false; reason: string; replay?: boolean };

export class S3CheckpointCommitter implements Committer {
  private readonly client: S3Client;
  private readonly bucket: string;
  private readonly prefix: string;
  private readonly signer: EntrySigner | undefined;
  private entries: ChainEntry[];
  private readonly committedIds = new Set<string>();
  private readonly seqByEvent = new Map<string, number>();
  private queue: Promise<unknown> = Promise.resolve();

  constructor(opts: S3CommitterOptions) {
    this.client = opts.client;
    this.bucket = opts.bucket;
    this.signer = opts.signer;
    this.prefix = (opts.prefix ?? "checkpoints").replace(/^\/+|\/+$/g, "");
    this.entries = opts.resume ? [...opts.resume] : [];
    const check = verifyChain(this.entries);
    if (!check.ok) throw new Error(`resume chain does not verify: ${check.reason}`);
    for (const e of this.entries) {
      const id = (e.payload as { eventId?: unknown } | null)?.eventId;
      if (typeof id === "string") {
        this.committedIds.add(id);
        this.seqByEvent.set(id, e.seq);
      }
    }
  }

  /** Object key for a sequence number. Same seq, same key, so a forked writer gets a 412. */
  keyFor(seq: number): string {
    const name = `${String(seq).padStart(SEQ_DIGITS, "0")}.json`;
    return this.prefix ? `${this.prefix}/${name}` : name;
  }

  /** Last checkpointed entry. seq 0 and the genesis hash before the first one. */
  head(): { seq: number; hash: string } {
    const last = this.entries[this.entries.length - 1];
    return last ? { seq: last.seq, hash: last.hash } : { seq: 0, hash: GENESIS_PREV };
  }

  /** Seq of the checkpoint that carried this event id, if any. */
  seqOf(eventId: string): number | undefined {
    return this.seqByEvent.get(eventId);
  }

  /** One commit at a time so seq and prev never race. */
  commit(entry: ConsumeEntry): Promise<CommitResult> {
    return this.enqueue(() => this.commitOne(entry));
  }

  /**
   * Any other ledger record (taint, arm, disarm, swipe, alert). payload.eventId must be unique: a second
   * append with the same id is a replay and writes nothing.
   */
  append(kind: string, payload: { eventId: string } & Record<string, unknown>, at: string): Promise<AppendResult> {
    return this.enqueue(async () => {
      if (typeof kind !== "string" || kind === "" || kind === CHECKPOINT_KIND) return { ok: false, reason: "bad entry kind" };
      if (typeof payload?.eventId !== "string" || payload.eventId === "") return { ok: false, reason: "entry has no event id" };
      if (this.committedIds.has(payload.eventId)) return { ok: false, reason: "event id was already checkpointed", replay: true };
      const atMs = Date.parse(at);
      if (!Number.isFinite(atMs)) return { ok: false, reason: "entry time is not a valid ISO time" };
      return this.write(kind, payload, atMs, payload.eventId);
    });
  }

  private enqueue<T extends CommitResult | AppendResult>(fn: () => Promise<T>): Promise<T | { ok: false; reason: string }> {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => undefined);
    return run.catch((err) => ({
      ok: false as const,
      reason: `checkpoint commit threw: ${err instanceof Error ? err.message : String(err)}`,
    }));
  }

  private async commitOne(entry: ConsumeEntry): Promise<CommitResult> {
    if (typeof entry.eventId !== "string" || entry.eventId === "") {
      return { ok: false, reason: "entry has no event id" };
    }
    if (!Number.isSafeInteger(entry.amountMinor)) {
      return { ok: false, reason: "amountMinor is not an integer count of minor units" };
    }
    if (this.committedIds.has(entry.eventId)) {
      return { ok: false, reason: "event id was already checkpointed", replay: true };
    }
    const at = Date.parse(entry.at);
    if (!Number.isFinite(at)) return { ok: false, reason: "entry time is not a valid ISO time" };
    const payload = {
      eventId: entry.eventId,
      writId: entry.writ.id,
      writHash: entry.writ.hash,
      cardId: entry.cardId,
      amountMinor: entry.amountMinor,
      decision: entry.decision.status,
    };
    const r = await this.write(CHECKPOINT_KIND, payload, at, entry.eventId);
    return r.ok ? { ok: true } : r;
  }

  private async write(kind: string, payload: unknown, at: number, eventId: string): Promise<AppendResult> {
    const last = this.entries[this.entries.length - 1];
    const prev = last ? last.hash : GENESIS_PREV;
    const body = { seq: this.entries.length + 1, prev, at, kind, payload };
    const hash = entryHash(prev, body);
    const next: ChainEntry = { ...body, hash };
    let signature: Uint8Array | undefined;
    if (this.signer) {
      signature = this.signer.sign(entrySigningMessage(hash));
      next.signature = signature;
    }

    const candidate = [...this.entries, next];
    const check = verifyChain(candidate);
    if (!check.ok) return { ok: false, reason: `chain does not verify: ${check.reason}` };

    const key = this.keyFor(next.seq);
    const stored = { ...body, hash };
    const text = JSON.stringify(
      signature ? { seq: next.seq, head: hash, entry: stored, signature: Buffer.from(signature).toString("base64") } : { seq: next.seq, head: hash, entry: stored },
    );

    let status: number;
    try {
      const res = await this.client.putObject({
        bucket: this.bucket,
        key,
        body: text,
        contentType: "application/json",
        ifNoneMatch: "*",
      });
      status = res.status;
    } catch (err) {
      const s = statusOf(err);
      if (s === 412) return this.precondition(key);
      return { ok: false, reason: `checkpoint write failed${s !== undefined ? ` with status ${s}` : ""}` };
    }

    if (status === 412) return this.precondition(key);
    if (status !== 200 && status !== 201) return { ok: false, reason: `checkpoint write refused with status ${status}` };

    // Only now does local state move, and only now may the caller say AUTHORIZED.
    this.entries = candidate;
    this.committedIds.add(eventId);
    this.seqByEvent.set(eventId, next.seq);
    return { ok: true, seq: next.seq, hash };
  }

  private precondition(key: string): { ok: false; reason: string } {
    return { ok: false, reason: `checkpoint ${key} already exists (412), refusing to overwrite` };
  }
}

/**
 * transient: the chain could not be read (no trusted time to sign yet, network, timeout, S3 refusal).
 * Retrying may fix it. Not transient: what was read is wrong (gap, stray object, edit, fork, unsigned or
 * badly signed entry). That stays unverified until a human fixes the bucket.
 */
export type LoadResult = { ok: true; entries: ChainEntry[] } | { ok: false; reason: string; transient: boolean };

const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * Reads every checkpoint under prefix and verifies it from GENESIS_PREV with the ledger public key.
 * The keys must be exactly 1..N with no gap, each body must name its own seq, head must equal the entry
 * hash, and every entry must carry a signature that verifies. A stray object under the prefix, a gap,
 * an edit, a fork, a missing signature or any read failure is a failure: the caller stays unverified.
 */
export async function loadSignedChain(store: S3Store, bucket: string, prefix: string, publicKeyRaw: Uint8Array): Promise<LoadResult> {
  const tampered = (reason: string): LoadResult => ({ ok: false, reason, transient: false });
  const unread = (err: unknown): LoadResult => ({ ok: false, reason: `checkpoint read failed: ${err instanceof Error ? err.message : String(err)}`, transient: true });
  const p = prefix.replace(/^\/+|\/+$/g, "");
  let keys: string[];
  try {
    keys = await store.listKeys(bucket, `${p}/`);
  } catch (err) {
    return unread(err);
  }
  try {
    const re = new RegExp(`^${p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/(\\d{${SEQ_DIGITS}})\\.json$`);
    const seqs: number[] = [];
    for (const k of keys) {
      const m = re.exec(k);
      if (!m) return tampered(`unexpected object under ${p}/`);
      seqs.push(Number(m[1]));
    }
    seqs.sort((a, b) => a - b);
    for (let i = 0; i < seqs.length; i++) {
      if (seqs[i] !== i + 1) return tampered(`checkpoint gap: expected seq ${i + 1}, found ${seqs[i]}`);
    }
    const entries: ChainEntry[] = [];
    for (const seq of seqs) {
      const key = `${p}/${String(seq).padStart(SEQ_DIGITS, "0")}.json`;
      let text: string | undefined;
      try {
        text = await store.getObject(bucket, key);
      } catch (err) {
        return unread(err);
      }
      if (text === undefined) return tampered(`checkpoint ${seq} is listed but cannot be read`);
      if (text.length > MAX_CHECKPOINT_BYTES) return tampered(`checkpoint ${seq} is too large`);
      const entry = parseCheckpoint(text, seq);
      if (typeof entry === "string") return tampered(entry);
      entries.push(entry);
    }
    const check = verifyChain(entries, { pubKey: publicKeyRaw, requireSignature: true });
    if (!check.ok) return tampered(check.reason);
    return { ok: true, entries };
  } catch (err) {
    return tampered(`checkpoint check failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

function parseCheckpoint(text: string, seq: number): ChainEntry | string {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return `checkpoint ${seq} is not JSON`;
  }
  const b = raw as { seq?: unknown; head?: unknown; entry?: unknown; signature?: unknown } | null;
  if (b === null || typeof b !== "object" || b.seq !== seq) return `checkpoint ${seq} names another seq`;
  const e = b.entry as Partial<ChainEntry> | null;
  if (e === null || typeof e !== "object" || e.seq !== seq) return `checkpoint ${seq} entry names another seq`;
  if (b.head !== e.hash) return `checkpoint ${seq} head does not match its entry`;
  if (typeof b.signature !== "string" || !B64_RE.test(b.signature) || b.signature.length % 4 !== 0) return `checkpoint ${seq} has no signature`;
  const signature = new Uint8Array(Buffer.from(b.signature, "base64"));
  if (signature.length !== 64) return `checkpoint ${seq} signature is not 64 bytes`;
  return { seq: e.seq as number, prev: e.prev as string, at: e.at as number, kind: e.kind as string, payload: e.payload, hash: e.hash as string, signature };
}
