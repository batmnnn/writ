// In-enclave HTTPS for Remote Authorization, and the attestation binding for its TLS key.
//
// Dockerfile lines the parent still has to add to enclave/Dockerfile (this file does not edit it):
//   COPY src/host/enclave-tls.ts /app/src/host/enclave-tls.ts
//   (and stage "src/host/enclave-tls.ts" in scripts/eif.ts next to the other COPY sources)
//   The runtime stage already installs socat and iproute, which the ACME bridges in boot.sh use.
//   No new package is needed for this file: it uses node:crypto and Bun.serve only.
//   The ACME client (lego) is pinned by version and sha256 in the legofetch stage of the Dockerfile.
//   src/host/enclave-acme.ts runs it with a CSR from csrPem below. Nothing in this file runs it.
//
// Why TLS ends here: the Remote Authorization HMAC covers x-nonce only, not the body. If TLS ended
// on the host, root could keep a valid nonce and signature and rewrite the amount and merchant.
// So the host forwards raw TCP (443 to vsock 443 to 127.0.0.1:8443 here) and never sees plaintext.
//
// The TLS key is generated inside this process and never accepted from a caller. Its SPKI sha256,
// the enclave ledger public key, the RA URL and the rung are hashed into user_data, and every
// attestation document this server returns carries that user_data. A verifier who checks the
// document against the published PCRs and compares user_data with the certificate it was served
// knows the TLS key was made inside the measured image.

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, X509Certificate, type KeyObject } from "node:crypto";
import { canonicalJson } from "../core/writ";
import { openSealed, sealText } from "./enclave-keys";

/** Elastic IP of the enclave host. */
export const RA_EIP = "35.95.168.131";
/** Hostname for the RA certificate. Resolves to RA_EIP through sslip.io. */
export const RA_HOSTNAME = "35-95-168-131.sslip.io";
export const DEFAULT_RA_URL = `https://${RA_HOSTNAME}`;
/** R2: enclave plus frozen-card arming. Remote Authorization at swipe time has not run, so R1 is not claimed. Baked, so part of PCR0. */
export const RUNG = "R2" as const;

/** Loopback only. The host reaches it through the vsock 443 forward, never directly. */
export const TLS_BIND_HOST = "127.0.0.1";
export const TLS_PORT = 8443;
export const HTTP_PORT = 8080;
export const MAX_RA_BODY_BYTES = 64 * 1024;
export const NONCE_MIN_BYTES = 32;
export const NONCE_MAX_BYTES = 512;

export type AcmeMode = "staging" | "production";

export interface AcmeLoopback {
  readonly mode: AcmeMode;
  readonly host: string;
  readonly directoryUrl: string;
  /** Loopback address inside the enclave, mapped to host in /etc/hosts by boot.sh. */
  readonly loopback: string;
  readonly port: 443;
  /** vsock port on CID 3 where the parent runs vsock-proxy for this host. */
  readonly vsockPort: number;
}

/** Data only. Nothing in this file talks to an ACME server. */
export const ACME_PLAN: Readonly<Record<AcmeMode, AcmeLoopback>> = Object.freeze({
  production: Object.freeze({
    mode: "production",
    host: "acme-v02.api.letsencrypt.org",
    directoryUrl: "https://acme-v02.api.letsencrypt.org/directory",
    loopback: "127.0.0.4",
    port: 443,
    vsockPort: 8445,
  }),
  staging: Object.freeze({
    mode: "staging",
    host: "acme-staging-v02.api.letsencrypt.org",
    directoryUrl: "https://acme-staging-v02.api.letsencrypt.org/directory",
    loopback: "127.0.0.5",
    port: 443,
    vsockPort: 8446,
  }),
});

/** Inbound forwards. The parent runs TCP to vsock CID 16, boot.sh runs vsock to these loopback ports. */
export const INBOUND_PLAN = Object.freeze([
  Object.freeze({ name: "ra-https", publicTcpPort: 443, vsockPort: 443, target: `${TLS_BIND_HOST}:${TLS_PORT}` }),
  Object.freeze({ name: "acme-http-01", publicTcpPort: 80, vsockPort: 80, target: `${TLS_BIND_HOST}:${HTTP_PORT}` }),
]);

export function acmePlan(mode: AcmeMode = "staging"): AcmeLoopback {
  if (mode !== "staging" && mode !== "production") throw new Error(`acme mode must be staging or production, got ${String(mode)}`);
  return ACME_PLAN[mode];
}

// ---------------------------------------------------------------------------
// TLS identity

/** Public view of a key made by createTlsIdentity. The private half is not reachable from here. */
export interface TlsIdentity {
  readonly spkiDer: Uint8Array;
  /** Lowercase hex sha256 of the DER SubjectPublicKeyInfo. */
  readonly spkiSha256: string;
}

const privateKeys = new WeakMap<TlsIdentity, KeyObject>();

/** Generates a P-256 TLS key in this process. There is no way to pass a key in. */
export function createTlsIdentity(): TlsIdentity {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return registerIdentity(publicKey, privateKey);
}

function registerIdentity(publicKey: KeyObject, privateKey: KeyObject): TlsIdentity {
  const spkiDer = new Uint8Array(publicKey.export({ type: "spki", format: "der" }));
  const identity: TlsIdentity = Object.freeze({ spkiDer, spkiSha256: spkiSha256Hex(spkiDer) });
  privateKeys.set(identity, privateKey);
  return identity;
}

// ---------------------------------------------------------------------------
// Sealed TLS identity. A key made by createTlsIdentity and its certificate, sealed with AES-256-GCM under
// the key from deriveTlsSealKey, so a restart can reuse a Let's Encrypt certificate instead of asking for
// a new one. The seal key derives from the attested API key, so only this image can open the blob. The
// private key is only ever plaintext inside this module.

export const TLS_SEAL_AAD = "writ-tls-v1";
export const TLS_BLOB_PREFIX = "tls/";
/** A sealed certificate is reused only with more than this much life left. */
export const TLS_REUSE_MIN_LIFE_MS = 72 * 3_600_000;

/** Sealed JSON for the identity's key and its certificate. The certificate must carry that key. */
export function sealTlsIdentity(identity: TlsIdentity, certificatePem: string, sealKey: Uint8Array): string {
  const key = privateKeys.get(identity);
  if (!key) throw new Error("identity was not created by createTlsIdentity");
  if (certSpkiSha256(certificatePem) !== identity.spkiSha256) throw new Error("certificate does not carry the identity key");
  const plain = JSON.stringify({ keyPkcs8: key.export({ type: "pkcs8", format: "der" }).toString("base64"), certificatePem });
  return JSON.stringify(sealText(sealKey, plain, TLS_SEAL_AAD));
}

export type OpenedTls = { identity: TlsIdentity; certificatePem: string; notAfterMs: number };

/**
 * Opens a sealed blob. Undefined unless it decrypts under sealKey, holds a P-256 key whose public half is
 * the certificate's, the certificate names RA_HOSTNAME, and it has more than 72 hours left at nowMs.
 */
export function openTlsIdentity(blob: string, sealKey: Uint8Array, nowMs: number): OpenedTls | undefined {
  try {
    if (!Number.isFinite(nowMs)) return undefined;
    const plain = openSealed(sealKey, JSON.parse(blob), TLS_SEAL_AAD);
    if (plain === undefined) return undefined;
    const p = JSON.parse(plain) as { keyPkcs8?: unknown; certificatePem?: unknown };
    if (typeof p.keyPkcs8 !== "string" || typeof p.certificatePem !== "string") return undefined;
    const privateKey = createPrivateKey({ key: Buffer.from(p.keyPkcs8, "base64"), format: "der", type: "pkcs8" });
    if (privateKey.asymmetricKeyType !== "ec") return undefined;
    const x = new X509Certificate(p.certificatePem);
    if (x.checkHost(RA_HOSTNAME) === undefined) return undefined;
    const notAfterMs = Date.parse(x.validTo);
    const notBeforeMs = Date.parse(x.validFrom);
    if (!Number.isFinite(notAfterMs) || notAfterMs - nowMs <= TLS_REUSE_MIN_LIFE_MS || !(notBeforeMs <= nowMs)) return undefined;
    const identity = registerIdentity(createPublicKey(privateKey), privateKey);
    if (certSpkiSha256(p.certificatePem) !== identity.spkiSha256) return undefined;
    return { identity, certificatePem: p.certificatePem, notAfterMs };
  } catch {
    return undefined;
  }
}

export function spkiSha256Hex(spkiDer: Uint8Array): string {
  return createHash("sha256").update(spkiDer).digest("hex");
}

/** SPKI sha256 of a PEM or DER certificate. */
export function certSpkiSha256(cert: string | Uint8Array): string {
  const x = new X509Certificate(typeof cert === "string" ? cert : Buffer.from(cert));
  return spkiSha256Hex(new Uint8Array(x.publicKey.export({ type: "spki", format: "der" })));
}

// ---------------------------------------------------------------------------
// user_data binding

export interface UserDataFields {
  spkiSha256: string;
  ledgerPublicKey: string;
  raUrl: string;
  rung: typeof RUNG;
}

/** sha256(canonicalJson({ ledgerPublicKey, raUrl, rung, spkiSha256 })). 32 bytes. */
export function computeUserData(fields: UserDataFields): Uint8Array {
  for (const k of ["spkiSha256", "ledgerPublicKey", "raUrl"] as const) {
    if (typeof fields[k] !== "string" || fields[k].length === 0) throw new Error(`user_data field ${k} must be a non-empty string`);
  }
  if (fields.rung !== RUNG) throw new Error(`user_data rung must be ${RUNG}`);
  const json = canonicalJson({ spkiSha256: fields.spkiSha256, ledgerPublicKey: fields.ledgerPublicKey, raUrl: fields.raUrl, rung: fields.rung });
  return new Uint8Array(createHash("sha256").update(json).digest());
}

// ---------------------------------------------------------------------------
// Bootstrap certificate. Self-signed, for the loopback listener before ACME has run and for tests.
// Relying parties trust the SPKI through the attestation, not through this certificate's issuer.

function derLen(n: number): number[] {
  if (n < 0x80) return [n];
  const out: number[] = [];
  while (n > 0) {
    out.unshift(n & 0xff);
    n >>= 8;
  }
  return [0x80 | out.length, ...out];
}
const tlv = (tag: number, ...parts: Uint8Array[]): Uint8Array => {
  const body = Buffer.concat(parts);
  return new Uint8Array([tag, ...derLen(body.length), ...body]);
};
const seq = (...p: Uint8Array[]) => tlv(0x30, ...p);
const bytes = (...b: number[]) => new Uint8Array(b);
const OID_ECDSA_SHA256 = bytes(0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02);
const OID_CN = bytes(0x06, 0x03, 0x55, 0x04, 0x03);
const OID_SAN = bytes(0x06, 0x03, 0x55, 0x1d, 0x11);

function utcTime(ms: number): Uint8Array {
  const d = new Date(ms).toISOString();
  const s = d.slice(2, 4) + d.slice(5, 7) + d.slice(8, 10) + d.slice(11, 13) + d.slice(14, 16) + d.slice(17, 19) + "Z";
  return tlv(0x17, new TextEncoder().encode(s));
}

function ipv4(addr: string): Uint8Array | null {
  const parts = addr.split(".");
  if (parts.length !== 4 || !parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)) return null;
  return new Uint8Array(parts.map(Number));
}

function sanNames(names: readonly string[]): Uint8Array[] {
  return names.map((n) => {
    const ip = ipv4(n);
    return ip ? tlv(0x87, ip) : tlv(0x82, new TextEncoder().encode(n));
  });
}

const OID_EXTENSION_REQUEST = bytes(0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e);

function pemBlock(label: string, der: Uint8Array): string {
  const b64 = Buffer.from(der).toString("base64").match(/.{1,64}/g)!.join("\n");
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

/**
 * PKCS#10 request for the identity's own key, signed in this process. An ACME client given this
 * CSR gets a certificate for this key and never sees the private half.
 */
export function csrPem(identity: TlsIdentity, names: readonly string[]): string {
  const key = privateKeys.get(identity);
  if (!key) throw new Error("identity was not created by createTlsIdentity");
  if (names.length === 0) throw new Error("at least one name is required");
  const subject = seq(tlv(0x31, seq(OID_CN, tlv(0x0c, new TextEncoder().encode(names[0]!)))));
  const extReq = seq(OID_EXTENSION_REQUEST, tlv(0x31, seq(seq(OID_SAN, tlv(0x04, seq(...sanNames(names)))))));
  const info = seq(bytes(0x02, 0x01, 0x00), subject, identity.spkiDer, tlv(0xa0, extReq));
  const sig = sign("sha256", info, key);
  return pemBlock("CERTIFICATE REQUEST", seq(info, seq(OID_ECDSA_SHA256), tlv(0x03, bytes(0x00), new Uint8Array(sig))));
}

/** Self-signed certificate for the identity's own key. Valid from nowMs minus 1 hour for 7 days. */
export function selfSignedCertPem(identity: TlsIdentity, names: readonly string[], nowMs: number): string {
  const key = privateKeys.get(identity);
  if (!key) throw new Error("identity was not created by createTlsIdentity");
  if (names.length === 0) throw new Error("at least one name is required");
  const serial = randomBytes(16);
  // Positive and minimal DER: a leading 0x00 before a byte under 0x80 is rejected by strict parsers.
  serial[0] = (serial[0]! & 0x3f) | 0x40;
  const san = sanNames(names);
  const name = seq(tlv(0x31, seq(OID_CN, tlv(0x0c, new TextEncoder().encode(names[0]!)))));
  const tbs = seq(
    tlv(0xa0, bytes(0x02, 0x01, 0x02)),
    tlv(0x02, serial),
    seq(OID_ECDSA_SHA256),
    name,
    seq(utcTime(nowMs - 3_600_000), utcTime(nowMs + 7 * 86_400_000)),
    name,
    identity.spkiDer,
    tlv(0xa3, seq(seq(OID_SAN, tlv(0x04, seq(...san))))),
  );
  const sig = sign("sha256", tbs, key);
  return pemBlock("CERTIFICATE", seq(tbs, seq(OID_ECDSA_SHA256), tlv(0x03, bytes(0x00), new Uint8Array(sig))));
}

// ---------------------------------------------------------------------------
// Register guard

export interface RaReplyBody {
  card_transaction_event_id: string;
  response_status: "AUTHORIZED" | "DECLINED";
  status_reason: string;
}

/** Same shape as RaResult from src/airwallex/ra-server.ts, so handleRemoteAuth fits without an import. */
export interface RaReply {
  status: number;
  body: RaReplyBody;
}

export type RegisterGuardResult = { ok: true } | { ok: false; reason: string };

/**
 * Stays shut until the RA handler itself has declined at least one request for a bad signature,
 * which shows the public URL reaches this enclave and the handler checks signatures. Only then
 * may the caller register the URL with Airwallex. This file never calls Airwallex.
 */
export class RaRegisterGuard {
  private badSignatureDeclines = 0;

  /** Counts the reply only when the handler said DECLINED with status_reason "bad signature". */
  noteBadSignatureDecline(body: RaReplyBody): void {
    if (body.response_status === "DECLINED" && body.status_reason === "bad signature") this.badSignatureDeclines++;
  }

  get count(): number {
    return this.badSignatureDeclines;
  }

  registerRaAllowed(): boolean {
    return this.badSignatureDeclines > 0;
  }

  registerRaGuard(): RegisterGuardResult {
    if (this.registerRaAllowed()) return { ok: true };
    return {
      ok: false,
      reason: "no request has been declined for a bad signature yet: send one unsigned probe to POST /remote-auth on the public URL first",
    };
  }
}

// ---------------------------------------------------------------------------
// Server

export interface RaTlsRequest {
  headers: Headers;
  rawBody: Uint8Array;
}

export type RaTlsHandler = (req: RaTlsRequest) => RaReply | Promise<RaReply>;
/** Returns the raw COSE_Sign1 bytes from NSM for this nonce and user_data. Called fresh per request. */
export type AttestFn = (nonce: Uint8Array, userData: Uint8Array) => Uint8Array | Promise<Uint8Array>;

export interface EnclaveTlsOptions {
  /** Hex or base64 of the enclave ledger public key. Goes into user_data as given. */
  ledgerPublicKey: string;
  handler: RaTlsHandler;
  attest: AttestFn;
  /** Origin of the public RA URL. Default https://35-95-168-131.sslip.io. */
  raUrl?: string;
  acme?: AcmeMode;
  /** Default 8443. 0 picks a free port (tests). */
  port?: number;
  /** A certificate for the generated key, for example from ACME. Default is a self-signed bootstrap. */
  certificatePem?: (identity: TlsIdentity) => string;
  /** An identity this module already created. A key from outside the process is refused. */
  identity?: TlsIdentity;
  /** For the bootstrap certificate only. Default Date.now. */
  now?: () => number;
  /**
   * Every other path. Undefined means 404. A throw is a JSON decline, never a stack trace. The routes
   * handler enforces its own body cap; this server caps every body at MAX_RA_BODY_BYTES.
   */
  routes?: (req: Request, url: URL) => Response | undefined | Promise<Response | undefined>;
}

export interface EnclaveTlsHandle {
  readonly port: number;
  readonly identity: TlsIdentity;
  readonly userData: Uint8Array;
  readonly userDataFields: UserDataFields;
  readonly acme: AcmeLoopback;
  readonly certificatePem: string;
  registerRaAllowed(): boolean;
  registerRaGuard(): RegisterGuardResult;
  stop(): Promise<void>;
}

const REFUSED_OPTION_KEYS = ["key", "privateKey", "keyPem", "pem", "tlsKey", "hostname", "host", "bind", "debug", "debugMode"];

function declinedReply(reason: string): RaReply {
  return { status: 200, body: { card_transaction_event_id: "", response_status: "DECLINED", status_reason: reason } };
}

function parseNonceHex(raw: string | null): Uint8Array | null {
  if (raw === null) return null;
  if (raw.length < NONCE_MIN_BYTES * 2 || raw.length > NONCE_MAX_BYTES * 2 || !/^(?:[0-9a-fA-F]{2})+$/.test(raw)) return null;
  return new Uint8Array(Buffer.from(raw, "hex"));
}

const text = (status: number, body: string) => new Response(body, { status, headers: { "content-type": "text/plain" } });

/**
 * Starts HTTPS on 127.0.0.1 with a key generated here. POST /remote-auth goes to the handler,
 * GET /attestation?nonce=<hex> returns a fresh attestation document bound to user_data.
 */
export function startEnclaveTls(opts: EnclaveTlsOptions): EnclaveTlsHandle {
  for (const k of REFUSED_OPTION_KEYS) {
    if (Object.prototype.hasOwnProperty.call(opts, k)) throw new Error(`option ${k} is refused: the TLS key is generated inside and the bind address is fixed`);
  }
  if (typeof opts.handler !== "function" || typeof opts.attest !== "function") throw new Error("handler and attest are required");
  const acme = acmePlan(opts.acme ?? "staging");
  const raUrl = opts.raUrl ?? DEFAULT_RA_URL;
  const parsed = new URL(raUrl);
  if (parsed.protocol !== "https:" || parsed.origin !== raUrl) throw new Error("raUrl must be an https origin with no path");

  const identity = opts.identity ?? createTlsIdentity();
  if (!privateKeys.has(identity)) throw new Error("identity was not created by createTlsIdentity");
  const userDataFields: UserDataFields = { spkiSha256: identity.spkiSha256, ledgerPublicKey: opts.ledgerPublicKey, raUrl, rung: RUNG };
  const userData = computeUserData(userDataFields);
  const now = opts.now ?? Date.now;
  const certificatePem = opts.certificatePem ? opts.certificatePem(identity) : selfSignedCertPem(identity, [RA_HOSTNAME, TLS_BIND_HOST], now());
  if (certSpkiSha256(certificatePem) !== identity.spkiSha256) throw new Error("certificate does not carry the generated TLS key");

  const guard = new RaRegisterGuard();
  const handler = opts.handler;
  const attest = opts.attest;
  const routes = opts.routes;

  const server = Bun.serve({
    hostname: TLS_BIND_HOST,
    port: opts.port ?? TLS_PORT,
    tls: { key: privateKeys.get(identity)!.export({ type: "pkcs8", format: "pem" }).toString(), cert: certificatePem },
    maxRequestBodySize: MAX_RA_BODY_BYTES,
    async fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === "/remote-auth") {
        if (req.method !== "POST") return text(405, "method not allowed");
        const declared = Number(req.headers.get("content-length") ?? "0");
        if (!Number.isFinite(declared) || declared > MAX_RA_BODY_BYTES) return Response.json(declinedReply("body too large").body);
        let reply: RaReply;
        try {
          const rawBody = new Uint8Array(await req.arrayBuffer());
          if (rawBody.byteLength > MAX_RA_BODY_BYTES) return Response.json(declinedReply("body too large").body);
          reply = await handler({ headers: req.headers, rawBody });
          if (!reply || !reply.body || (reply.body.response_status !== "AUTHORIZED" && reply.body.response_status !== "DECLINED")) {
            reply = declinedReply("internal error");
          }
        } catch {
          reply = declinedReply("internal error");
        }
        guard.noteBadSignatureDecline(reply.body);
        return Response.json(reply.body, { status: 200 });
      }
      if (url.pathname === "/attestation") {
        if (req.method !== "GET") return text(405, "method not allowed");
        const nonce = parseNonceHex(url.searchParams.get("nonce"));
        if (!nonce) return text(400, `nonce must be ${NONCE_MIN_BYTES} to ${NONCE_MAX_BYTES} bytes of hex`);
        try {
          const doc = await attest(nonce, userData);
          if (!(doc instanceof Uint8Array) || doc.length === 0) return text(503, "attestation unavailable");
          return new Response(doc, { status: 200, headers: { "content-type": "application/cbor", "cache-control": "no-store" } });
        } catch {
          return text(503, "attestation unavailable");
        }
      }
      if (routes) {
        try {
          const r = await routes(req, url);
          if (r) return r;
        } catch {
          return Response.json({ ok: false, status: "DECLINED", reason: "internal error" }, { status: 500 });
        }
      }
      return Response.json({ ok: false, reason: "not found" }, { status: 404 });
    },
    error() {
      return Response.json({ ok: false, status: "DECLINED", reason: "internal error" }, { status: 500 });
    },
  });

  return {
    port: server.port ?? opts.port ?? TLS_PORT,
    identity,
    userData,
    userDataFields,
    acme,
    certificatePem,
    registerRaAllowed: () => guard.registerRaAllowed(),
    registerRaGuard: () => guard.registerRaGuard(),
    stop: async () => {
      await server.stop(true);
    },
  };
}
