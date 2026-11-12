// Keys the enclave derives from the unsealed Airwallex API key. KMS decrypts that key only for the
// pinned PCR0, so only the attested image can derive these. No new KMS call and no new IAM.
//   Ledger key: HKDF-SHA256, info "writ-ledger-ed25519-v1", 32 bytes, used as the Ed25519 seed.
//   TLS seal key: HKDF-SHA256, info "writ-tls-v1", 32 bytes, AES-256-GCM for the sealed TLS key and cert.
// The ledger key follows the API key: rotating the Airwallex API key gives a new ledger key, and every
// checkpoint signed by the old one then fails resume (STATE_UNVERIFIED) until the old chain is retired.
// Nothing here logs, and no private key or derived secret leaves this file except through sign and seal.

import { createCipheriv, createDecipheriv, createPrivateKey, createPublicKey, hkdfSync, randomBytes, sign, verify } from "node:crypto";

export const LEDGER_KEY_INFO = "writ-ledger-ed25519-v1";
export const TLS_SEAL_INFO = "writ-tls-v1";
const HKDF_SALT = Buffer.alloc(0);
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface LedgerSigner {
  /** Raw 32 byte Ed25519 public key. */
  readonly publicKeyRaw: Uint8Array;
  /** "ed25519:<hex>", the form that goes into the attestation user_data. */
  readonly publicKey: string;
  sign(message: Uint8Array): Uint8Array;
}

function hkdf32(secret: Uint8Array, info: string): Buffer {
  if (!(secret instanceof Uint8Array) || secret.length === 0) throw new Error("no secret to derive from");
  return Buffer.from(hkdfSync("sha256", secret, HKDF_SALT, Buffer.from(info, "utf8"), 32));
}

/** Same input, same key. The seed is zeroed once the key object holds it. */
export function deriveLedgerSigner(secret: Uint8Array): LedgerSigner {
  const seed = hkdf32(secret, LEDGER_KEY_INFO);
  const der = Buffer.concat([PKCS8_ED25519_PREFIX, seed]);
  const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  seed.fill(0);
  der.fill(0);
  const spki = createPublicKey(privateKey).export({ type: "spki", format: "der" });
  const publicKeyRaw = new Uint8Array(spki.subarray(spki.length - 32));
  return Object.freeze({
    publicKeyRaw,
    publicKey: `ed25519:${Buffer.from(publicKeyRaw).toString("hex")}`,
    sign: (message: Uint8Array) => new Uint8Array(sign(null, message, privateKey)),
  });
}

/** Ed25519 verify against a raw 32 byte public key. Any problem is false. */
export function verifyEd25519(publicKeyRaw: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  try {
    if (publicKeyRaw.length !== 32) return false;
    const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(publicKeyRaw)]), format: "der", type: "spki" });
    return verify(null, message, key, signature);
  } catch {
    return false;
  }
}

/** 32 byte AES key for sealing the TLS key and certificate. The caller zeroes it. */
export function deriveTlsSealKey(secret: Uint8Array): Uint8Array {
  return new Uint8Array(hkdf32(secret, TLS_SEAL_INFO));
}

export interface SealedBlob {
  v: 1;
  alg: "A256GCM";
  iv: string;
  ct: string;
  tag: string;
}

/** AES-256-GCM with a fresh 12 byte IV. aad binds the blob to its purpose. */
export function sealText(key: Uint8Array, plaintext: string, aad: string): SealedBlob {
  if (key.length !== 32) throw new Error("seal key must be 32 bytes");
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  c.setAAD(Buffer.from(aad, "utf8"));
  const ct = Buffer.concat([c.update(plaintext, "utf8"), c.final()]);
  return { v: 1, alg: "A256GCM", iv: iv.toString("base64"), ct: ct.toString("base64"), tag: c.getAuthTag().toString("base64") };
}

/** Undefined when the blob is malformed, sealed under another key, or edited. */
export function openSealed(key: Uint8Array, blob: unknown, aad: string): string | undefined {
  try {
    if (key.length !== 32 || blob === null || typeof blob !== "object") return undefined;
    const b = blob as Partial<SealedBlob>;
    if (b.v !== 1 || b.alg !== "A256GCM" || typeof b.iv !== "string" || typeof b.ct !== "string" || typeof b.tag !== "string") return undefined;
    const iv = Buffer.from(b.iv, "base64");
    const tag = Buffer.from(b.tag, "base64");
    if (iv.length !== 12 || tag.length !== 16) return undefined;
    const d = createDecipheriv("aes-256-gcm", key, iv);
    d.setAAD(Buffer.from(aad, "utf8"));
    d.setAuthTag(tag);
    return Buffer.concat([d.update(Buffer.from(b.ct, "base64")), d.final()]).toString("utf8");
  } catch {
    return undefined;
  }
}
