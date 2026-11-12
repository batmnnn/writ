// Accumulative linear hash chain (immudb style, not a Merkle tree). docs/REFERENCES.md section 2.
// Each entry commits to the previous entry's hash, so a reader holding a checkpoint can prove the log only grew.
// Pure: no clock, no fs, no network, no sqlite. It never appends, repairs or skips an entry.

import { createHash, createPublicKey, verify, type KeyObject } from "node:crypto";
import { canonicalJson } from "./writ";

export const GENESIS_PREV = "0".repeat(64);

export interface ChainEntry {
  seq: number;
  prev: string;
  at: number;
  kind: string;
  payload: unknown;
  hash: string;
  signature?: Uint8Array;
}

export type UnhashedEntry = Omit<ChainEntry, "hash" | "signature">;

export interface ChainCheckpoint {
  seq: number;
  head: string;
  signature?: Uint8Array;
}

export interface VerifyChainOptions {
  pubKey?: Uint8Array; // raw 32 byte Ed25519 public key
  checkpoint?: ChainCheckpoint;
  requireSignature?: boolean; // every entry, and the checkpoint if given, must carry a signature that verifies
}

export type ChainResult = { ok: true; head: string } | { ok: false; code: "STATE_UNVERIFIED"; reason: string };

const HEX64 = /^[0-9a-f]{64}$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/**
 * sha256 hex of canonicalJson({ at, kind, payload, prev, seq }).
 * canonicalJson (src/core/writ.ts): keys sorted by code unit at every level, no whitespace,
 * array order kept, undefined object fields dropped, undefined array items become null,
 * non finite numbers and non JSON types throw. The hash is over the UTF-8 bytes of that string.
 */
export function entryHash(prev: string, entry: UnhashedEntry): string {
  const body = { seq: entry.seq, prev, at: entry.at, kind: entry.kind, payload: entry.payload };
  return createHash("sha256").update(canonicalJson(body)).digest("hex");
}

/** Bytes the enclave signs for an entry: the UTF-8 of its hex hash, as writ.ts does for writs. */
export function entrySigningMessage(hash: string): Uint8Array {
  return Buffer.from(hash, "utf8");
}

/** Bytes the enclave signs for a checkpoint: canonicalJson({ head, seq }) in UTF-8. */
export function checkpointSigningMessage(seq: number, head: string): Uint8Array {
  return Buffer.from(canonicalJson({ head, seq }), "utf8");
}

function fail(reason: string): ChainResult {
  return { ok: false, code: "STATE_UNVERIFIED", reason };
}

function publicKeyFromRaw(raw: Uint8Array): KeyObject | null {
  if (raw.length !== 32) return null;
  try {
    return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]), format: "der", type: "spki" });
  } catch {
    return null;
  }
}

function signatureOk(key: KeyObject, message: Uint8Array, signature: Uint8Array): boolean {
  try {
    return verify(null, message, key, signature);
  } catch {
    return false;
  }
}

export function verifyChain(entries: ChainEntry[], opts: VerifyChainOptions = {}): ChainResult {
  try {
    return verifyChainUnsafe(entries, opts);
  } catch (err) {
    return fail(`verify threw: ${err instanceof Error ? err.message : String(err)}`);
  }
}

function verifyChainUnsafe(entries: ChainEntry[], opts: VerifyChainOptions): ChainResult {
  if (!Array.isArray(entries)) return fail("entries is not an array");

  let key: KeyObject | null = null;
  if (opts.pubKey !== undefined) {
    key = publicKeyFromRaw(opts.pubKey);
    if (!key) return fail("public key is not a 32 byte Ed25519 key");
  }
  if (opts.requireSignature && !key) return fail("signatures required but no public key given");

  const cp = opts.checkpoint;
  if (cp !== undefined) {
    if (!Number.isSafeInteger(cp.seq) || cp.seq < 0) return fail(`checkpoint seq ${cp.seq} is not a whole number`);
    if (typeof cp.head !== "string" || !HEX64.test(cp.head)) return fail("checkpoint head is not 64 hex chars");
    if (cp.seq === 0 && cp.head !== GENESIS_PREV) return fail("checkpoint at seq 0 must carry the genesis head");
    if (cp.signature !== undefined && key && !signatureOk(key, checkpointSigningMessage(cp.seq, cp.head), cp.signature)) {
      return fail(`checkpoint signature at seq ${cp.seq} does not verify`);
    }
    if (cp.signature === undefined && opts.requireSignature) return fail(`checkpoint at seq ${cp.seq} has no signature`);
  }

  let prevHash = GENESIS_PREV;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    const want = i + 1;
    if (e === null || typeof e !== "object") return fail(`entry ${want} is not an object`);
    if (e.seq !== want) return fail(`seq ${String(e.seq)} at position ${want}, expected ${want}`);
    if (typeof e.at !== "number" || !Number.isFinite(e.at)) return fail(`entry ${want} has no finite at`);
    if (typeof e.kind !== "string") return fail(`entry ${want} kind is not a string`);
    if (typeof e.prev !== "string" || !HEX64.test(e.prev)) return fail(`entry ${want} prev is not 64 hex chars`);
    if (typeof e.hash !== "string" || !HEX64.test(e.hash)) return fail(`entry ${want} hash is not 64 hex chars`);
    if (e.prev !== prevHash) return fail(`entry ${want} prev does not match the hash of entry ${want - 1}`);
    if (entryHash(e.prev, e) !== e.hash) return fail(`entry ${want} hash does not match its content`);
    if (e.signature !== undefined) {
      if (key && !signatureOk(key, entrySigningMessage(e.hash), e.signature)) return fail(`entry ${want} signature does not verify`);
    } else if (opts.requireSignature) {
      return fail(`entry ${want} has no signature`);
    }
    if (cp !== undefined && cp.seq === want && e.hash !== cp.head) {
      return fail(`entry ${want} hash does not match the checkpoint head: log forked or edited`);
    }
    prevHash = e.hash;
  }

  if (cp !== undefined && entries.length < cp.seq) {
    return fail(`log has ${entries.length} entries, shorter than the checkpoint at seq ${cp.seq}`);
  }
  return { ok: true, head: prevHash };
}
