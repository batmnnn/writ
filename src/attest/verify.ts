// Verifies an AWS Nitro Enclaves attestation document. Pure: no network, no file reads,
// no clock. The caller passes the document bytes, the nonce it sent, the expected PCRs and now.
//
// Spec: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
// The document is COSE_Sign1 (RFC 9052) signed with ES384. The payload is a CBOR map with
// module_id, digest, timestamp, pcrs, certificate, cabundle, and optional public_key,
// user_data and nonce. cabundle starts at the AWS root and ends at the issuer of certificate.
//
// Every failure is a typed result. Nothing throws past verifyAttestation.

import { X509Certificate, timingSafeEqual, verify as cryptoVerify } from "node:crypto";
import type { Result } from "../types";

/**
 * AWS Nitro Enclaves Root-G1, from root.pem inside
 * https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
 * linked from https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
 * Downloaded Wed Nov 11 2026, 10:10 IST. Valid until Oct 28 2049.
 */
export const AWS_NITRO_ROOT_G1_PEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----
`;

/** SHA-256 fingerprint AWS publishes on the verify-root page for Root-G1. */
export const AWS_NITRO_ROOT_G1_SHA256 =
  "64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B";

export const DEFAULT_MAX_AGE_MS = 300_000;
/** A document stamped further than this ahead of opts.now is refused. */
export const MAX_FUTURE_SKEW_MS = 30_000;
export const MIN_NONCE_BYTES = 32;
export const PCR_HEX_LENGTH = 96;
export const MAX_DOCUMENT_BYTES = 32 * 1024;

const COSE_SIGN1_TAG = 18;
const COSE_HEADER_ALG = 1;
const COSE_ALG_ES384 = -35;
const ES384_SIGNATURE_BYTES = 96;
const MAX_CBOR_DEPTH = 16;

export type AttestationFailure =
  | "ROOT_PIN_BROKEN"
  | "BAD_OPTIONS"
  | "NONCE_TOO_SHORT"
  | "PCR_MISSING"
  | "PCR_MALFORMED"
  | "PCR_ZERO"
  | "DOCUMENT_TOO_LARGE"
  | "NOT_COSE_SIGN1"
  | "UNSUPPORTED_ALG"
  | "MALFORMED_PAYLOAD"
  | "CHAIN_NOT_PINNED_ROOT"
  | "CHAIN_INVALID"
  | "CERT_NOT_VALID_NOW"
  | "BAD_SIGNATURE"
  | "NONCE_MISMATCH"
  | "TIMESTAMP_STALE"
  | "TIMESTAMP_IN_FUTURE"
  | "PCR_MISMATCH"
  | "USER_DATA_MISMATCH"
  | "VERIFIER_ERROR";

export type AttestationError = { code: AttestationFailure; message: string };

/** All three are required. A check on PCR0 alone can miss a kernel or ramdisk swap. */
export type ExpectedPcrs = { pcr0: string; pcr1: string; pcr2: string };

export type VerifyOptions = {
  /** The nonce the verifier sent to the enclave. At least 32 bytes. */
  nonce: Uint8Array;
  expected: ExpectedPcrs;
  /** Milliseconds since the epoch. Passed in so the verifier stays pure. */
  now: number;
  /** Defaults to 300000. */
  maxAgeMs?: number;
  /**
   * When set, the document's user_data must equal these bytes. When omitted, user_data is not
   * checked at all, so a document with null user_data still verifies.
   */
  expectedUserData?: Uint8Array;
};

export type VerifiedAttestation = {
  moduleId: string;
  timestamp: number;
  digest: "SHA384";
  pcr0: string;
  pcr1: string;
  pcr2: string;
  publicKey: Uint8Array | null;
  userData: Uint8Array | null;
};

/** The payload after structural parsing. Nothing in it is trusted yet. */
export type AttestationPayload = {
  moduleId: string;
  digest: string;
  timestamp: number;
  pcrs: Map<number, Uint8Array>;
  certificate: Uint8Array;
  cabundle: Uint8Array[];
  publicKey: Uint8Array | null;
  userData: Uint8Array | null;
  nonce: Uint8Array | null;
};

export type CoseSign1 = {
  protectedBytes: Uint8Array;
  alg: number;
  payloadBytes: Uint8Array;
  signature: Uint8Array;
};

type Fail = { ok: false; error: AttestationError };
const fail = (code: AttestationFailure, message: string): Fail => ({ ok: false, error: { code, message } });

// ---------------------------------------------------------------------------
// CBOR (RFC 8949). Floats are refused. Indefinite lengths are accepted because the
// NSM payload map is an indefinite-length map (0xbf).

export type CborTagged = { tag: number; value: Cbor };
export type Cbor = number | string | boolean | null | undefined | Uint8Array | Cbor[] | Map<Cbor, Cbor> | CborTagged;

class CborError extends Error {}

class CborReader {
  private pos = 0;
  private readonly view: DataView;
  constructor(private readonly buf: Uint8Array) {
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  readAll(): Cbor {
    const v = this.item(0);
    if (this.pos !== this.buf.length) throw new CborError("trailing bytes");
    return v;
  }

  private need(n: number): void {
    if (n < 0 || this.pos + n > this.buf.length) throw new CborError("truncated");
  }

  private arg(info: number): number {
    if (info < 24) return info;
    if (info === 24) {
      this.need(1);
      return this.view.getUint8(this.pos++);
    }
    if (info === 25) {
      this.need(2);
      const v = this.view.getUint16(this.pos);
      this.pos += 2;
      return v;
    }
    if (info === 26) {
      this.need(4);
      const v = this.view.getUint32(this.pos);
      this.pos += 4;
      return v;
    }
    if (info === 27) {
      this.need(8);
      const v = this.view.getBigUint64(this.pos);
      this.pos += 8;
      if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new CborError("integer too large");
      return Number(v);
    }
    throw new CborError("indefinite or reserved length");
  }

  private item(depth: number): Cbor {
    if (depth > MAX_CBOR_DEPTH) throw new CborError("too deep");
    this.need(1);
    const ib = this.view.getUint8(this.pos++);
    const major = ib >> 5;
    const info = ib & 0x1f;
    if (info === 31) {
      if (major === 2 || major === 3) return this.indefiniteString(major === 3, depth);
      if (major === 4) return this.indefiniteArray(depth);
      if (major === 5) return this.indefiniteMap(depth);
      throw new CborError("indefinite or reserved length");
    }
    if (major === 7) {
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      if (info === 23) return undefined;
      throw new CborError("unsupported simple or float");
    }
    const n = this.arg(info);
    switch (major) {
      case 0:
        return n;
      case 1:
        return -1 - n;
      case 2: {
        this.need(n);
        const out = this.buf.slice(this.pos, this.pos + n);
        this.pos += n;
        return out;
      }
      case 3: {
        this.need(n);
        const s = new TextDecoder("utf-8", { fatal: true }).decode(this.buf.subarray(this.pos, this.pos + n));
        this.pos += n;
        return s;
      }
      case 4: {
        this.need(n);
        const out: Cbor[] = [];
        for (let i = 0; i < n; i++) out.push(this.item(depth + 1));
        return out;
      }
      case 5: {
        this.need(n * 2);
        const out = new Map<Cbor, Cbor>();
        for (let i = 0; i < n; i++) {
          const k = this.item(depth + 1);
          if (typeof k !== "number" && typeof k !== "string") throw new CborError("map key type");
          if (out.has(k)) throw new CborError("duplicate map key");
          out.set(k, this.item(depth + 1));
        }
        return out;
      }
      case 6:
        return { tag: n, value: this.item(depth + 1) };
      default:
        throw new CborError("bad major type");
    }
  }

  private peekBreak(): boolean {
    this.need(1);
    if (this.view.getUint8(this.pos) !== 0xff) return false;
    this.pos++;
    return true;
  }

  private indefiniteString(text: boolean, depth: number): Uint8Array | string {
    const parts: Uint8Array[] = [];
    let total = 0;
    for (let n = 0; n < 10_000; n++) {
      if (this.peekBreak()) {
        const all = new Uint8Array(total);
        let at = 0;
        for (const p of parts) {
          all.set(p, at);
          at += p.length;
        }
        if (!text) return all;
        return new TextDecoder("utf-8", { fatal: true }).decode(all);
      }
      const chunk = this.item(depth + 1);
      if (!(chunk instanceof Uint8Array) && typeof chunk !== "string") throw new CborError("bad indefinite chunk");
      const bytes = typeof chunk === "string" ? new TextEncoder().encode(chunk) : chunk;
      if (!text && typeof chunk === "string") throw new CborError("bad indefinite chunk");
      if (text && chunk instanceof Uint8Array) throw new CborError("bad indefinite chunk");
      total += bytes.length;
      if (total > 1_000_000) throw new CborError("indefinite string too large");
      parts.push(bytes);
    }
    throw new CborError("indefinite string too long");
  }

  private indefiniteArray(depth: number): Cbor[] {
    const out: Cbor[] = [];
    for (let n = 0; n < 10_000; n++) {
      if (this.peekBreak()) return out;
      out.push(this.item(depth + 1));
    }
    throw new CborError("indefinite array too long");
  }

  private indefiniteMap(depth: number): Map<Cbor, Cbor> {
    const out = new Map<Cbor, Cbor>();
    for (let n = 0; n < 10_000; n++) {
      if (this.peekBreak()) return out;
      const k = this.item(depth + 1);
      if (typeof k !== "number" && typeof k !== "string") throw new CborError("map key type");
      if (out.has(k)) throw new CborError("duplicate map key");
      out.set(k, this.item(depth + 1));
    }
    throw new CborError("indefinite map too long");
  }
}

export function decodeCbor(bytes: Uint8Array): Cbor {
  return new CborReader(bytes).readAll();
}

function head(major: number, n: number): number[] {
  if (!Number.isSafeInteger(n) || n < 0) throw new CborError("bad length");
  const m = major << 5;
  if (n < 24) return [m | n];
  if (n < 0x100) return [m | 24, n];
  if (n < 0x10000) return [m | 25, n >> 8, n & 0xff];
  if (n < 0x100000000) return [m | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
  const out = [m | 27];
  const big = BigInt(n);
  for (let i = 7; i >= 0; i--) out.push(Number((big >> BigInt(i * 8)) & 0xffn));
  return out;
}

/** Encoder for the same subset the decoder accepts. Used for the COSE Sig_structure. */
export function encodeCbor(value: Cbor): Uint8Array {
  const parts: number[] = [];
  const push = (bytes: ArrayLike<number>) => {
    for (let i = 0; i < bytes.length; i++) parts.push(bytes[i]!);
  };
  const walk = (v: Cbor): void => {
    if (v === false) return push([0xf4]);
    if (v === true) return push([0xf5]);
    if (v === null) return push([0xf6]);
    if (v === undefined) return push([0xf7]);
    if (typeof v === "number") {
      if (!Number.isSafeInteger(v)) throw new CborError("only safe integers");
      return push(v >= 0 ? head(0, v) : head(1, -1 - v));
    }
    if (typeof v === "string") {
      const b = new TextEncoder().encode(v);
      push(head(3, b.length));
      return push(b);
    }
    if (v instanceof Uint8Array) {
      push(head(2, v.length));
      return push(v);
    }
    if (Array.isArray(v)) {
      push(head(4, v.length));
      for (const x of v) walk(x);
      return;
    }
    if (v instanceof Map) {
      push(head(5, v.size));
      for (const [k, x] of v) {
        walk(k);
        walk(x);
      }
      return;
    }
    push(head(6, v.tag));
    walk(v.value);
  };
  walk(value);
  return Uint8Array.from(parts);
}

// ---------------------------------------------------------------------------
// COSE_Sign1

export function parseCoseSign1(bytes: Uint8Array): Result<CoseSign1, AttestationError> {
  let top: Cbor;
  try {
    top = decodeCbor(bytes);
  } catch (e) {
    return fail("NOT_COSE_SIGN1", `not valid CBOR: ${(e as Error).message}`);
  }
  if (top !== null && typeof top === "object" && !Array.isArray(top) && !(top instanceof Uint8Array) && !(top instanceof Map)) {
    if (top.tag !== COSE_SIGN1_TAG) return fail("NOT_COSE_SIGN1", `CBOR tag ${top.tag} is not COSE_Sign1 (18)`);
    top = top.value;
  }
  if (!Array.isArray(top) || top.length !== 4) return fail("NOT_COSE_SIGN1", "COSE_Sign1 must be a 4 item array");
  const [prot, unprot, payload, sig] = top;
  if (!(prot instanceof Uint8Array)) return fail("NOT_COSE_SIGN1", "protected header is not a byte string");
  if (!(unprot instanceof Map)) return fail("NOT_COSE_SIGN1", "unprotected header is not a map");
  if (!(payload instanceof Uint8Array)) return fail("NOT_COSE_SIGN1", "payload is not an attached byte string");
  if (!(sig instanceof Uint8Array)) return fail("NOT_COSE_SIGN1", "signature is not a byte string");

  let protMap: Cbor;
  try {
    protMap = decodeCbor(prot);
  } catch (e) {
    return fail("NOT_COSE_SIGN1", `protected header is not CBOR: ${(e as Error).message}`);
  }
  if (!(protMap instanceof Map)) return fail("NOT_COSE_SIGN1", "protected header is not a map");
  const alg = protMap.get(COSE_HEADER_ALG);
  if (alg !== COSE_ALG_ES384) return fail("UNSUPPORTED_ALG", `protected alg ${String(alg)} is not ES384 (-35)`);
  if (unprot.has(COSE_HEADER_ALG)) return fail("UNSUPPORTED_ALG", "alg must not appear in the unprotected header");
  if (sig.length !== ES384_SIGNATURE_BYTES) return fail("BAD_SIGNATURE", `ES384 signature must be ${ES384_SIGNATURE_BYTES} bytes, got ${sig.length}`);
  return { ok: true, value: { protectedBytes: prot, alg, payloadBytes: payload, signature: sig } };
}

/** RFC 9052 section 4.4: ["Signature1", protected, external_aad, payload]. */
export function sigStructure(sign1: Pick<CoseSign1, "protectedBytes" | "payloadBytes">): Uint8Array {
  return encodeCbor(["Signature1", sign1.protectedBytes, new Uint8Array(0), sign1.payloadBytes]);
}

export function verifyCoseSignature(sign1: CoseSign1, leaf: X509Certificate): boolean {
  const key = leaf.publicKey;
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "secp384r1") return false;
  try {
    return cryptoVerify("sha384", sigStructure(sign1), { key, dsaEncoding: "ieee-p1363" }, sign1.signature);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Payload

function bytesOrNull(v: Cbor): Uint8Array | null | "bad" {
  if (v === undefined || v === null) return null;
  return v instanceof Uint8Array ? v : "bad";
}

export function parsePayload(bytes: Uint8Array): Result<AttestationPayload, AttestationError> {
  let m: Cbor;
  try {
    m = decodeCbor(bytes);
  } catch (e) {
    return fail("MALFORMED_PAYLOAD", `payload is not CBOR: ${(e as Error).message}`);
  }
  if (!(m instanceof Map)) return fail("MALFORMED_PAYLOAD", "payload is not a map");

  const moduleId = m.get("module_id");
  if (typeof moduleId !== "string" || moduleId.length === 0) return fail("MALFORMED_PAYLOAD", "module_id missing");
  const digest = m.get("digest");
  if (digest !== "SHA384") return fail("MALFORMED_PAYLOAD", `digest ${String(digest)} is not SHA384`);
  const timestamp = m.get("timestamp");
  if (typeof timestamp !== "number" || !Number.isSafeInteger(timestamp) || timestamp <= 0) {
    return fail("MALFORMED_PAYLOAD", "timestamp missing or not a positive integer");
  }

  const rawPcrs = m.get("pcrs");
  if (!(rawPcrs instanceof Map) || rawPcrs.size === 0 || rawPcrs.size > 32) return fail("MALFORMED_PAYLOAD", "pcrs missing");
  const pcrs = new Map<number, Uint8Array>();
  for (const [k, v] of rawPcrs) {
    if (typeof k !== "number" || !Number.isInteger(k) || k < 0 || k > 31) return fail("MALFORMED_PAYLOAD", "pcr index out of range");
    if (!(v instanceof Uint8Array) || ![32, 48, 64].includes(v.length)) return fail("MALFORMED_PAYLOAD", `pcr ${k} has a bad length`);
    pcrs.set(k, v);
  }

  const certificate = m.get("certificate");
  if (!(certificate instanceof Uint8Array) || certificate.length === 0 || certificate.length > 1024) {
    return fail("MALFORMED_PAYLOAD", "certificate missing");
  }
  const rawBundle = m.get("cabundle");
  if (!Array.isArray(rawBundle) || rawBundle.length === 0) return fail("MALFORMED_PAYLOAD", "cabundle missing");
  const cabundle: Uint8Array[] = [];
  for (const c of rawBundle) {
    if (!(c instanceof Uint8Array) || c.length === 0 || c.length > 1024) return fail("MALFORMED_PAYLOAD", "cabundle entry is not a certificate");
    cabundle.push(c);
  }

  const publicKey = bytesOrNull(m.get("public_key"));
  const userData = bytesOrNull(m.get("user_data"));
  const nonce = bytesOrNull(m.get("nonce"));
  if (publicKey === "bad" || userData === "bad" || nonce === "bad") {
    return fail("MALFORMED_PAYLOAD", "public_key, user_data and nonce must be byte strings when present");
  }
  return { ok: true, value: { moduleId, digest, timestamp, pcrs, certificate, cabundle, publicKey, userData, nonce } };
}

// ---------------------------------------------------------------------------
// Certificate chain

const PINNED_ROOT: X509Certificate | null = (() => {
  try {
    const root = new X509Certificate(AWS_NITRO_ROOT_G1_PEM);
    return root.fingerprint256 === AWS_NITRO_ROOT_G1_SHA256 ? root : null;
  } catch {
    return null;
  }
})();

function validAt(cert: X509Certificate, now: number): boolean {
  const from = Date.parse(cert.validFrom);
  const to = Date.parse(cert.validTo);
  return Number.isFinite(from) && Number.isFinite(to) && from <= now && now <= to;
}

/**
 * cabundle[0] must be the pinned AWS root, byte for byte. Each later entry must be a CA
 * signed by the one before it, and the leaf must be signed by the last entry. Every
 * certificate must be valid at now. Returns the leaf on success.
 */
export function verifyChain(
  leafDer: Uint8Array,
  cabundle: readonly Uint8Array[],
  now: number,
): Result<X509Certificate, AttestationError> {
  if (!PINNED_ROOT) return fail("ROOT_PIN_BROKEN", "pinned AWS root does not match its published fingerprint");
  let certs: X509Certificate[];
  let leaf: X509Certificate;
  try {
    certs = cabundle.map((der) => new X509Certificate(der));
    leaf = new X509Certificate(leafDer);
  } catch {
    return fail("CHAIN_INVALID", "a certificate in the chain does not parse");
  }
  const first = certs[0];
  if (!first || first.fingerprint256 !== AWS_NITRO_ROOT_G1_SHA256 || !Buffer.from(first.raw).equals(PINNED_ROOT.raw)) {
    return fail("CHAIN_NOT_PINNED_ROOT", "certificate chain does not start at the pinned AWS Nitro root");
  }

  const chain = [PINNED_ROOT, ...certs.slice(1)];
  for (let i = 1; i < chain.length; i++) {
    const issuer = chain[i - 1]!;
    const cert = chain[i]!;
    if (!cert.ca) return fail("CHAIN_INVALID", `cabundle entry ${i} is not a CA certificate`);
    if (!cert.checkIssued(issuer) || !cert.verify(issuer.publicKey)) {
      return fail("CHAIN_INVALID", `cabundle entry ${i} is not signed by entry ${i - 1}`);
    }
  }
  const issuer = chain[chain.length - 1]!;
  if (leaf.ca) return fail("CHAIN_INVALID", "leaf certificate is a CA");
  if (!leaf.checkIssued(issuer) || !leaf.verify(issuer.publicKey)) {
    return fail("CHAIN_INVALID", "leaf certificate is not signed by the last cabundle entry");
  }
  for (const [i, cert] of [...chain, leaf].entries()) {
    if (!validAt(cert, now)) return fail("CERT_NOT_VALID_NOW", `certificate ${i} is outside its validity window at now`);
  }
  return { ok: true, value: leaf };
}

// ---------------------------------------------------------------------------
// PCRs, nonce, timestamp

const HEX96 = /^[0-9a-f]{96}$/;

function checkPcrHex(name: string, hex: string | undefined): AttestationError | null {
  if (hex === undefined || hex === "") return { code: "PCR_MISSING", message: `${name} is missing` };
  if (!HEX96.test(hex)) return { code: "PCR_MALFORMED", message: `${name} is not ${PCR_HEX_LENGTH} lowercase hex characters` };
  if (/^0+$/.test(hex)) return { code: "PCR_ZERO", message: `${name} is all zeros, which is debug mode or a missing measurement` };
  return null;
}

export function normalizeExpected(expected: Partial<ExpectedPcrs> | undefined): Result<ExpectedPcrs, AttestationError> {
  const out: Partial<ExpectedPcrs> = {};
  for (const name of ["pcr0", "pcr1", "pcr2"] as const) {
    const raw = expected?.[name];
    const hex = typeof raw === "string" ? raw.trim().toLowerCase() : undefined;
    const err = checkPcrHex(`expected ${name}`, hex);
    if (err || hex === undefined) return { ok: false, error: err ?? { code: "PCR_MISSING", message: `expected ${name} is missing` } };
    out[name] = hex;
  }
  return { ok: true, value: out as ExpectedPcrs };
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Nonce echo, freshness, PCR and optional user_data checks on a payload whose signature already verified. */
export function checkClaims(
  payload: Pick<AttestationPayload, "nonce" | "timestamp" | "pcrs"> & { userData?: Uint8Array | null },
  opts: { nonce: Uint8Array; expected: ExpectedPcrs; now: number; maxAgeMs: number; expectedUserData?: Uint8Array },
): Result<{ pcr0: string; pcr1: string; pcr2: string }, AttestationError> {
  if (opts.nonce.length < MIN_NONCE_BYTES) return fail("NONCE_TOO_SHORT", `nonce must be at least ${MIN_NONCE_BYTES} bytes`);
  if (!payload.nonce) return fail("NONCE_MISMATCH", "document carries no nonce");
  if (!sameBytes(payload.nonce, opts.nonce)) return fail("NONCE_MISMATCH", "document nonce does not echo the nonce we sent");

  const age = opts.now - payload.timestamp;
  if (age > opts.maxAgeMs) return fail("TIMESTAMP_STALE", `document is ${age} ms old, limit ${opts.maxAgeMs} ms`);
  if (age < -MAX_FUTURE_SKEW_MS) return fail("TIMESTAMP_IN_FUTURE", `document is stamped ${-age} ms ahead of now`);

  const got: string[] = [];
  for (const i of [0, 1, 2] as const) {
    const bytes = payload.pcrs.get(i);
    const hex = bytes ? Buffer.from(bytes).toString("hex") : undefined;
    const err = checkPcrHex(`document PCR${i}`, hex);
    if (err) return { ok: false, error: err };
    got.push(hex!);
  }
  const [pcr0, pcr1, pcr2] = got as [string, string, string];
  if (pcr0 !== opts.expected.pcr0) return fail("PCR_MISMATCH", "PCR0 does not match the published image hash");
  if (pcr1 !== opts.expected.pcr1) return fail("PCR_MISMATCH", "PCR1 does not match the expected kernel and boot ramdisk");
  if (pcr2 !== opts.expected.pcr2) return fail("PCR_MISMATCH", "PCR2 does not match the expected application");

  if (opts.expectedUserData !== undefined) {
    if (!payload.userData) return fail("USER_DATA_MISMATCH", "document carries no user_data");
    if (!sameBytes(payload.userData, opts.expectedUserData)) return fail("USER_DATA_MISMATCH", "document user_data does not match the expected binding");
  }
  return { ok: true, value: { pcr0, pcr1, pcr2 } };
}

// ---------------------------------------------------------------------------

/**
 * Order: options, size, COSE_Sign1 shape and alg, payload shape, chain to the pinned root,
 * ES384 signature by the leaf, nonce echo, freshness, PCR0 to PCR2, then user_data only when
 * opts.expectedUserData is set. First failure wins.
 */
export function verifyAttestation(doc: Uint8Array, opts: VerifyOptions): Result<VerifiedAttestation, AttestationError> {
  try {
    if (!opts || typeof opts.now !== "number" || !Number.isFinite(opts.now)) return fail("BAD_OPTIONS", "opts.now must be a finite number");
    const maxAgeMs = opts.maxAgeMs ?? DEFAULT_MAX_AGE_MS;
    if (!Number.isFinite(maxAgeMs) || maxAgeMs <= 0) return fail("BAD_OPTIONS", "opts.maxAgeMs must be a positive number");
    if (!(opts.nonce instanceof Uint8Array) || opts.nonce.length < MIN_NONCE_BYTES) {
      return fail("NONCE_TOO_SHORT", `nonce must be at least ${MIN_NONCE_BYTES} bytes`);
    }
    const expected = normalizeExpected(opts.expected);
    if (!expected.ok) return expected;
    if (opts.expectedUserData !== undefined && !(opts.expectedUserData instanceof Uint8Array)) {
      return fail("BAD_OPTIONS", "opts.expectedUserData must be bytes when set");
    }

    if (!(doc instanceof Uint8Array)) return fail("NOT_COSE_SIGN1", "document is not bytes");
    if (doc.length > MAX_DOCUMENT_BYTES) return fail("DOCUMENT_TOO_LARGE", `document is over ${MAX_DOCUMENT_BYTES} bytes`);

    const sign1 = parseCoseSign1(doc);
    if (!sign1.ok) return sign1;
    const payload = parsePayload(sign1.value.payloadBytes);
    if (!payload.ok) return payload;

    const leaf = verifyChain(payload.value.certificate, payload.value.cabundle, opts.now);
    if (!leaf.ok) return leaf;
    if (!verifyCoseSignature(sign1.value, leaf.value)) return fail("BAD_SIGNATURE", "COSE_Sign1 signature does not verify under the leaf key");

    const claims = checkClaims(payload.value, {
      nonce: opts.nonce,
      expected: expected.value,
      now: opts.now,
      maxAgeMs,
      ...(opts.expectedUserData !== undefined ? { expectedUserData: opts.expectedUserData } : {}),
    });
    if (!claims.ok) return claims;

    return {
      ok: true,
      value: {
        moduleId: payload.value.moduleId,
        timestamp: payload.value.timestamp,
        digest: "SHA384",
        ...claims.value,
        publicKey: payload.value.publicKey,
        userData: payload.value.userData,
      },
    };
  } catch (e) {
    return fail("VERIFIER_ERROR", `verifier threw: ${(e as Error)?.message ?? "unknown"}`);
  }
}
