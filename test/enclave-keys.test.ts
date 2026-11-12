import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { createTlsIdentity, openTlsIdentity, RA_HOSTNAME, sealTlsIdentity, selfSignedCertPem } from "../src/host/enclave-tls";
import { deriveLedgerSigner, deriveTlsSealKey, openSealed, sealText, verifyEd25519 } from "../src/host/enclave-keys";

const KEY_A = new TextEncoder().encode("fake-airwallex-key-a");
const KEY_B = new TextEncoder().encode("fake-airwallex-key-b");
const NOW = Date.parse("2026-11-12T08:35:00.000Z");
const HOUR = 3_600_000;

describe("ledger key", () => {
  test("is the same for the same API key and different for another", () => {
    const a1 = deriveLedgerSigner(KEY_A);
    const a2 = deriveLedgerSigner(KEY_A);
    const b = deriveLedgerSigner(KEY_B);
    expect(a1.publicKey).toBe(a2.publicKey);
    expect(a1.publicKey).toMatch(/^ed25519:[0-9a-f]{64}$/);
    expect(a1.publicKey).not.toBe(b.publicKey);
  });

  test("signs, and only its own public key verifies", () => {
    const a = deriveLedgerSigner(KEY_A);
    const msg = new TextEncoder().encode("hash");
    const sig = a.sign(msg);
    expect(sig.length).toBe(64);
    expect(verifyEd25519(a.publicKeyRaw, msg, sig)).toBe(true);
    expect(verifyEd25519(deriveLedgerSigner(KEY_B).publicKeyRaw, msg, sig)).toBe(false);
    expect(verifyEd25519(a.publicKeyRaw, new TextEncoder().encode("other"), sig)).toBe(false);
  });

  test("exposes no private key material", () => {
    const a = deriveLedgerSigner(KEY_A);
    expect(Object.keys(a).sort()).toEqual(["publicKey", "publicKeyRaw", "sign"]);
    expect(() => deriveLedgerSigner(new Uint8Array(0))).toThrow();
  });

  test("the TLS seal key differs from the ledger seed", () => {
    const seal = deriveTlsSealKey(KEY_A);
    expect(seal.length).toBe(32);
    expect(Buffer.from(seal).toString("hex")).not.toBe(deriveLedgerSigner(KEY_A).publicKey.slice(8));
    expect(Buffer.from(deriveTlsSealKey(KEY_A)).equals(Buffer.from(seal))).toBe(true);
  });
});

describe("sealing", () => {
  test("opens under the same key and aad only", () => {
    const k = deriveTlsSealKey(KEY_A);
    const blob = sealText(k, "hello", "aad-1");
    expect(openSealed(k, blob, "aad-1")).toBe("hello");
    expect(openSealed(k, blob, "aad-2")).toBeUndefined();
    expect(openSealed(deriveTlsSealKey(KEY_B), blob, "aad-1")).toBeUndefined();
    const flipped = { ...blob, ct: Buffer.from(Buffer.from(blob.ct, "base64").map((b, i) => (i === 0 ? b ^ 1 : b))).toString("base64") };
    expect(openSealed(k, flipped, "aad-1")).toBeUndefined();
    expect(openSealed(k, { nope: 1 }, "aad-1")).toBeUndefined();
  });

  test("a sealed TLS identity reopens with the same key, the certificate still carries it", () => {
    const k = deriveTlsSealKey(KEY_A);
    const id = createTlsIdentity();
    const cert = selfSignedCertPem(id, [RA_HOSTNAME], NOW);
    const blob = sealTlsIdentity(id, cert, k);
    expect(blob).not.toContain("PRIVATE");
    const opened = openTlsIdentity(blob, k, NOW);
    expect(opened).toBeDefined();
    expect(opened!.identity.spkiSha256).toBe(id.spkiSha256);
    expect(opened!.certificatePem).toBe(cert);
  });

  test("a certificate with 72 hours or less left, another host name, or another seal key is not reused", () => {
    const k = deriveTlsSealKey(KEY_A);
    const id = createTlsIdentity();
    const shortLived = sealTlsIdentity(id, selfSignedCertPem(id, [RA_HOSTNAME], NOW - 4 * 24 * HOUR), k);
    expect(openTlsIdentity(shortLived, k, NOW)).toBeUndefined();
    const otherName = sealTlsIdentity(id, selfSignedCertPem(id, ["example.com"], NOW), k);
    expect(openTlsIdentity(otherName, k, NOW)).toBeUndefined();
    const good = sealTlsIdentity(id, selfSignedCertPem(id, [RA_HOSTNAME], NOW), k);
    expect(openTlsIdentity(good, deriveTlsSealKey(KEY_B), NOW)).toBeUndefined();
    expect(openTlsIdentity(good, k, Number.NaN)).toBeUndefined();
  });

  test("a certificate for another key cannot be sealed", () => {
    const k = deriveTlsSealKey(KEY_A);
    const a = createTlsIdentity();
    const b = createTlsIdentity();
    expect(() => sealTlsIdentity(a, selfSignedCertPem(b, [RA_HOSTNAME], NOW), k)).toThrow();
  });

  test("the key module does not log or read the host clock", () => {
    const src = readFileSync(new URL("../src/host/enclave-keys.ts", import.meta.url), "utf8");
    expect(/Date\.now|new Date\(\)|console\.|process\.(stdout|stderr)/.test(src)).toBe(false);
    expect(src.includes("\u2014")).toBe(false);
  });
});
