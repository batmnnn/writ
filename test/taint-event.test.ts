// Writ side of the signed taint wire format. Sits next to taint.test.ts, which covers taint state.

import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import vector from "../fixtures/taint-vector.json";
import { checkAck, parseLedgerPublicKey, sha256Hex, signedBytes, type TaintEvent, verifyTaintEvent } from "../infra/lambda/taint";
import { startMockWrit } from "../scripts/agent-mock-writ";
import { canonicalJson } from "../src/core/writ";

const kms = generateKeyPairSync("ec", { namedCurve: "P-256" });
const other = generateKeyPairSync("ec", { namedCurve: "P-256" });
const event: TaintEvent = vector.event.value;
// Same output as KMS Sign with ECDSA_SHA_256 and MessageType RAW: SHA-256 then ECDSA, DER encoded.
const kmsSign = (e: unknown, key = kms.privateKey) => sign("sha256", signedBytes(e as TaintEvent), { key, dsaEncoding: "der" }).toString("base64");

describe("taint wire format", () => {
  test("canonical bytes match the cross-language vector and canonicalJson in src/core/writ.ts", () => {
    expect(canonicalJson(event)).toBe(vector.event.canonical);
    expect(new TextDecoder().decode(signedBytes(event))).toBe(vector.event.canonical);
    expect(sha256Hex(vector.event.canonical)).toBe(vector.event.sha256);
    expect(canonicalJson(vector.ack.value)).toBe(vector.ack.canonical);
    expect(event.urlSha256).toBe(sha256Hex(vector.url));
  });
});

describe("Writ rejects taint events without a good KMS signature", () => {
  test("a valid signature is accepted", () => {
    expect(verifyTaintEvent(event, kmsSign(event), kms.publicKey)).toBe(true);
  });

  test("a signature from another key is rejected", () => {
    expect(verifyTaintEvent(event, kmsSign(event, other.privateKey), kms.publicKey)).toBe(false);
  });

  test("garbage, empty or missing signatures are rejected", () => {
    for (const sig of ["", "AAAA", Buffer.alloc(72, 1).toString("base64"), undefined, 42]) {
      expect(verifyTaintEvent(event, sig, kms.publicKey)).toBe(false);
    }
  });

  test("an edited event is rejected", () => {
    const sig = kmsSign(event);
    expect(verifyTaintEvent({ ...event, seq: event.seq + 1 }, sig, kms.publicKey)).toBe(false);
    expect(verifyTaintEvent({ ...event, runId: "another-run" }, sig, kms.publicKey)).toBe(false);
  });

  test("extra or missing fields are rejected even when signed", () => {
    const extra = { ...event, ok: true };
    expect(verifyTaintEvent(extra, kmsSign(extra), kms.publicKey)).toBe(false);
    const { seq: _s, ...missing } = event;
    expect(verifyTaintEvent(missing, kmsSign(missing), kms.publicKey)).toBe(false);
  });

  test("the /taint route answers 401 to a bad signature and records nothing", async () => {
    const writ = startMockWrit({ taintPublicKey: kms.publicKey });
    try {
      const res = await fetch(`${writ.url}/taint`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ event, signature: kmsSign(event, other.privateKey) }),
      });
      expect(res.status).toBe(401);
      expect(writ.taintsReceived).toHaveLength(0);
      expect(writ.taintsRejected).toBe(1);

      const good = await fetch(`${writ.url}/taint`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ event, signature: kmsSign(event) }),
      });
      const reply = await good.json();
      expect(checkAck(event, reply, parseLedgerPublicKey(writ.ledgerPublicKey)).ok).toBe(true);
    } finally {
      writ.stop();
    }
  });
});

describe("the enclave verifier agrees with the interceptor's signatures", () => {
  const pem = kms.publicKey.export({ type: "spki", format: "pem" }).toString();

  test("good signature accepted, other key and edits rejected", async () => {
    const { taintVerifier } = await import("../src/host/enclave-taint");
    const verify = taintVerifier(pem);
    expect(await verify(event, kmsSign(event))).toBe(true);
    expect(await verify(event, kmsSign(event, other.privateKey))).toBe(false);
    expect(await verify({ ...event, seq: event.seq + 1 }, kmsSign(event))).toBe(false);
    expect(await verify(event, "not base64!")).toBe(false);
  });
});

describe("ledger public key", () => {
  test("only ed25519:<64 hex> parses", () => {
    expect(() => parseLedgerPublicKey(`ed25519:${"ab".repeat(32)}`)).not.toThrow();
    for (const bad of ["", "ed25519:abc", `x25519:${"ab".repeat(32)}`, "ab".repeat(32)]) {
      expect(() => parseLedgerPublicKey(bad)).toThrow();
    }
  });
});
