// Taint event and ack wire format, shared by the interceptor and by Writ.
// The interceptor signs the event with KMS (ECDSA_SHA_256, MessageType RAW). Writ answers with an
// ack signed by its Ed25519 ledger key. Both signatures cover the UTF-8 bytes of canonicalJson.

import { createHash, createPublicKey, type KeyObject, verify } from "node:crypto";
import { canonicalJson } from "../../src/core/writ";

export interface TaintEvent {
  agent: string;
  runId: string;
  urlSha256: string;
  at: string;
  seq: number;
}

export interface TaintAck {
  agent: string;
  runId: string;
  seq: number;
  taintedAt: string;
  ok: true;
}

export const sha256Hex = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");

export const signedBytes = (value: TaintEvent | TaintAck): Uint8Array => new TextEncoder().encode(canonicalJson(value));

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** "ed25519:<64 hex>" to a public key. Throws on anything else. */
export function parseLedgerPublicKey(text: string): KeyObject {
  const m = /^ed25519:([0-9a-f]{64})$/i.exec(text.trim());
  if (!m?.[1]) throw new Error("ledger public key must be ed25519:<64 hex>");
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(m[1], "hex")]), format: "der", type: "spki" });
}

export function isTaintEvent(v: unknown): v is TaintEvent {
  if (!v || typeof v !== "object") return false;
  const e = v as Record<string, unknown>;
  return (
    Object.keys(e).length === 5 &&
    typeof e.agent === "string" &&
    e.agent !== "" &&
    typeof e.runId === "string" &&
    e.runId !== "" &&
    typeof e.urlSha256 === "string" &&
    /^[0-9a-f]{64}$/.test(e.urlSha256) &&
    typeof e.at === "string" &&
    !Number.isNaN(Date.parse(e.at)) &&
    typeof e.seq === "number" &&
    Number.isSafeInteger(e.seq) &&
    e.seq > 0
  );
}

/**
 * Writ side: accept a taint event only with a valid ECDSA P-256 signature (DER, base64) from the taint key.
 * Any doubt is a rejection.
 */
export function verifyTaintEvent(event: unknown, signatureB64: unknown, taintPublicKey: KeyObject): boolean {
  try {
    if (!isTaintEvent(event) || typeof signatureB64 !== "string" || signatureB64 === "") return false;
    return verify("sha256", signedBytes(event), { key: taintPublicKey, dsaEncoding: "der" }, Buffer.from(signatureB64, "base64"));
  } catch {
    return false;
  }
}

/** Interceptor side: the ack must match the event, say ok, and carry a valid Ed25519 signature from the ledger key. */
export function checkAck(event: TaintEvent, reply: unknown, ledgerKey: KeyObject): { ok: true; ack: TaintAck; signature: string } | { ok: false; why: string } {
  try {
    if (!reply || typeof reply !== "object") return { ok: false, why: "ack is not an object" };
    const { ack, signature } = reply as { ack?: unknown; signature?: unknown };
    if (!ack || typeof ack !== "object") return { ok: false, why: "no ack" };
    const a = ack as Record<string, unknown>;
    if (a.ok !== true) return { ok: false, why: "ack ok is not true" };
    if (a.agent !== event.agent || a.runId !== event.runId || a.seq !== event.seq) return { ok: false, why: "ack does not match the event" };
    if (typeof a.taintedAt !== "string" || Number.isNaN(Date.parse(a.taintedAt))) return { ok: false, why: "ack taintedAt unreadable" };
    if (typeof signature !== "string" || signature === "") return { ok: false, why: "ack has no signature" };
    const clean: TaintAck = { agent: event.agent, runId: event.runId, seq: event.seq, taintedAt: a.taintedAt, ok: true };
    if (Object.keys(a).length !== 5) return { ok: false, why: "ack has extra fields" };
    const good = verify(null, signedBytes(clean), ledgerKey, Buffer.from(signature, "base64"));
    return good ? { ok: true, ack: clean, signature } : { ok: false, why: "ack signature did not verify" };
  } catch (err) {
    return { ok: false, why: `ack check failed: ${err instanceof Error ? err.message : String(err)}` };
  }
}
