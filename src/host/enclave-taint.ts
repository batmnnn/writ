// Taint events from the Gateway interceptor. The interceptor signs canonicalJson(event) with the KMS key
// writ-taint-signer (ECDSA_SHA_256, MessageType RAW), so the signature is DER. WebCrypto wants P1363
// (r || s, 32 bytes each), so it is converted here before the verify. The public key is pinned in
// enclave/config/taint-signer.pub.pem and baked into the image. A taint the host invents fails here.

import { canonicalJson } from "../core/writ";
import { parseIso } from "../core/time";

export interface TaintEvent {
  agent: string;
  runId: string;
  urlSha256: string;
  at: string;
  seq: number;
}

const HEX64 = /^[0-9a-f]{64}$/;
const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const MAX_SIG_B64 = 200;

/** Exactly the five fields, each well formed. Anything else is undefined. */
export function parseTaintEvent(raw: unknown): TaintEvent | undefined {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const r = raw as Record<string, unknown>;
  const keys = Object.keys(r).sort();
  if (keys.join(",") !== "agent,at,runId,seq,urlSha256") return undefined;
  if (typeof r.agent !== "string" || !ID_RE.test(r.agent)) return undefined;
  if (typeof r.runId !== "string" || !ID_RE.test(r.runId)) return undefined;
  if (typeof r.urlSha256 !== "string" || !HEX64.test(r.urlSha256)) return undefined;
  if (typeof r.at !== "string" || Number.isNaN(parseIso(r.at))) return undefined;
  if (typeof r.seq !== "number" || !Number.isSafeInteger(r.seq) || r.seq < 1) return undefined;
  return { agent: r.agent, runId: r.runId, urlSha256: r.urlSha256, at: r.at, seq: r.seq };
}

function readLen(der: Uint8Array, i: number): [number, number] | undefined {
  const b = der[i];
  if (b === undefined) return undefined;
  if (b < 0x80) return [b, i + 1];
  if (b === 0x81) {
    const n = der[i + 1];
    return n === undefined || n < 0x80 ? undefined : [n, i + 2];
  }
  return undefined;
}

function readInt(der: Uint8Array, i: number): [Uint8Array, number] | undefined {
  if (der[i] !== 0x02) return undefined;
  const l = readLen(der, i + 1);
  if (!l) return undefined;
  const [len, start] = l;
  if (len === 0 || start + len > der.length) return undefined;
  let v = der.subarray(start, start + len);
  if (v[0]! & 0x80) return undefined;
  if (v.length > 1 && v[0] === 0 && !(v[1]! & 0x80)) return undefined;
  while (v.length > 1 && v[0] === 0) v = v.subarray(1);
  if (v.length > 32) return undefined;
  return [v, start + len];
}

/** DER ECDSA-Sig-Value to 64 byte P1363. Strict DER only: any other form is undefined. */
export function derToP1363(der: Uint8Array): Uint8Array<ArrayBuffer> | undefined {
  if (der.length < 8 || der[0] !== 0x30) return undefined;
  const l = readLen(der, 1);
  if (!l || l[1] + l[0] !== der.length) return undefined;
  const r = readInt(der, l[1]);
  if (!r) return undefined;
  const s = readInt(der, r[1]);
  if (!s || s[1] !== der.length) return undefined;
  const out = new Uint8Array(64);
  out.set(r[0], 32 - r[0].length);
  out.set(s[0], 64 - s[0].length);
  return out;
}

function pemToSpki(pem: string): Uint8Array<ArrayBuffer> | undefined {
  const m = /-----BEGIN PUBLIC KEY-----([A-Za-z0-9+/=\s]+)-----END PUBLIC KEY-----/.exec(pem);
  if (!m) return undefined;
  return new Uint8Array(Buffer.from(m[1]!.replace(/\s+/g, ""), "base64"));
}

export type TaintVerifier = (event: TaintEvent, signatureB64: unknown) => Promise<boolean>;

/** Verifier for the pinned P-256 key. A missing or bad key gives a verifier that refuses everything. */
export function taintVerifier(publicKeyPem: string | undefined): TaintVerifier {
  const spki = typeof publicKeyPem === "string" ? pemToSpki(publicKeyPem) : undefined;
  const keyP = spki
    ? crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]).catch(() => undefined)
    : Promise.resolve(undefined);
  return async (event, signatureB64) => {
    try {
      const key = await keyP;
      if (!key) return false;
      if (typeof signatureB64 !== "string" || signatureB64.length > MAX_SIG_B64 || !B64_RE.test(signatureB64) || signatureB64.length % 4 !== 0) return false;
      const sig = derToP1363(new Uint8Array(Buffer.from(signatureB64, "base64")));
      if (!sig) return false;
      const msg = new Uint8Array(new TextEncoder().encode(canonicalJson(event)));
      return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, msg);
    } catch {
      return false;
    }
  };
}
