// In-enclave entry. Runs as the last step of enclave/boot.sh.
// main() reads the PCRs from NSM, reads one boot line from the host over the socat bridge that
// boot.sh starts (127.0.0.1:5000 to vsock CID 3 port 5000), calls unsealApiKey, replies
// `UNSEALED <bytes> LEDGER_PUB <key>` and keeps running (runServe):
//   1. derive the ledger Ed25519 key and the TLS seal key from the API key (enclave-keys.ts),
//   2. start the balance poller, which is also the enclave clock,
//   3. read and verify the signed checkpoint chain under checkpoints/v2/ and replay it (only then is
//      state verified; any failure means every decision is STATE_UNVERIFIED),
//   4. start the one-swipe disarm watcher,
//   5. reuse a sealed TLS certificate from tls/ or run ACME and seal the new one,
//   6. serve HTTPS on 127.0.0.1:8443: /remote-auth, /attestation and the routes in enclave-app.ts,
//   7. listen for host credential refreshes on 127.0.0.1:5001 (vsock 5001 only),
//   8. then an optional boot line arm through EnclaveServe.authorize.
// runBoot is the older one-shot path (checkpoint, arm, two swipes, disarm via armAfterUnseal). main()
// does not call it. Tests still do.
// A line of {"attestOnly": true, "nonce": "<hex>"} skips all of that: it runs writ-attest once and
// answers `ATTEST <base64 COSE>`.
// Any failure before serving prints `DECLINED <code>` to stderr and exits 1. Fail closed.
// Plaintext, ciphertext, credentials and argv never go to stdout or stderr.

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { connect } from "node:net";
import { join } from "node:path";
import type { AdapterError, ApprovedTask, Result } from "../types";
import { NonceCache, handleRemoteAuth } from "../airwallex/ra-server";
import { EnclaveApp } from "./enclave-app";
import { CredentialBox, startCredsListener, type CredsListenerHandle } from "./enclave-creds";
import { deriveLedgerSigner, deriveTlsSealKey } from "./enclave-keys";
import { taintVerifier } from "./enclave-taint";
import { ArmWatcher, listCardTransactions, type CardTx } from "./enclave-watch";
import {
  kmstoolReplyRunner,
  unsealApiKey,
  type AwsCredentials,
  type KmstoolExec,
  type KmstoolReply,
} from "./kms-unseal";
import { enclaveNsm, fixedNsm, type NsmPort } from "./nsm";
import { LEDGER_BUCKET, UUID_RE, armAfterUnseal, armOrderCard, disarmCard, sigV4S3Store, timedFetch, type ArmDeps } from "./enclave-arm";
import {
  AirwallexSession,
  BalancePoller,
  enclaveHttpFetch,
  type HttpFetch,
  type PollerOptions,
  type SetTimer,
  type TimerHandle,
} from "./enclave-balance";
import { EnclaveServe, type ArmOrder, type BakedConfig, type ServeOptions, type ServeResult, type WatchOptions } from "./enclave-serve";
import { runAcme, type AcmeResult } from "./enclave-acme";
import {
  TLS_BLOB_PREFIX,
  createTlsIdentity,
  openTlsIdentity,
  sealTlsIdentity,
  startEnclaveTls,
  type AttestFn,
  type EnclaveTlsHandle,
  type EnclaveTlsOptions,
  type OpenedTls,
  type TlsIdentity,
} from "./enclave-tls";
import { SIGNED_CHECKPOINT_PREFIX, loadSignedChain, type S3Store } from "./s3-committer";

export interface BootDeps {
  nsm: NsmPort;
  ciphertext: Uint8Array;
  credentials: AwsCredentials;
  runKmstool(argv: readonly string[]): Promise<Result<KmstoolReply>>;
}

const KMSTOOL_TIMEOUT_MS = 15_000;
const KMSTOOL_STDOUT_LIMIT = 64 * 1024;

/**
 * Run one process with Bun.spawn. No shell, empty environment, stderr dropped (it never holds
 * plaintext, but it is not ours to log). Over the time or size limit, the process is killed and
 * the result is a failure.
 */
export const bunSpawnExec: KmstoolExec = (argv) => cappedSpawn(argv, KMSTOOL_STDOUT_LIMIT);

async function cappedSpawn(argv: readonly string[], stdoutLimit: number): Promise<{ exitCode: number; stdout: string }> {
  const proc = Bun.spawn([...argv], { stdin: "ignore", stdout: "pipe", stderr: "ignore", env: {} });
  const timer = setTimeout(() => proc.kill(), KMSTOOL_TIMEOUT_MS);
  try {
    const chunks: Uint8Array[] = [];
    let size = 0;
    for await (const chunk of proc.stdout) {
      size += chunk.length;
      if (size > stdoutLimit) {
        proc.kill();
        for (const c of chunks) c.fill(0);
        throw new Error("helper output too long");
      }
      chunks.push(chunk);
    }
    const exitCode = await proc.exited;
    const all = Buffer.concat(chunks);
    const stdout = all.toString("utf8");
    all.fill(0);
    for (const c of chunks) c.fill(0);
    return { exitCode, stdout };
  } finally {
    clearTimeout(timer);
  }
}

/** The runner the enclave uses: kmstool_reply, both stdout lines parsed. */
export const enclaveKmstoolRunner = kmstoolReplyRunner(bunSpawnExec);

/** PCRs come from NSM, never from the host. Any failure or zero PCR ends in a declined result. */
export async function unsealAtBoot(deps: BootDeps): Promise<Result<Uint8Array>> {
  const pcrs = await deps.nsm.readPcrs();
  if (!pcrs.ok) return pcrs;
  return unsealApiKey(deps.ciphertext, {
    pcr0: pcrs.value.pcr0,
    pcrs: { pcr1: pcrs.value.pcr1, pcr2: pcrs.value.pcr2 },
    credentials: deps.credentials,
    runKmstool: deps.runKmstool,
  });
}

export const BOOT_LINE_HOST = "127.0.0.1";
export const BOOT_LINE_PORT = 5000;
export const BOOT_LINE_MAX_BYTES = 64 * 1024;
const BOOT_LINE_TIMEOUT_MS = 30_000;

export type BootCode = "RELAY_FAILED" | "LINE_TOO_LONG" | "BAD_INPUT";

const bootDeclined = (code: BootCode, message: string): { ok: false; error: AdapterError } => ({
  ok: false,
  error: { kind: "config", code, message: `Declined: ${message}` },
});

export interface BootLineOptions {
  host?: string;
  port?: number;
  maxBytes?: number;
  timeoutMs?: number;
}

/**
 * Connect once and read one line. Returns the bytes before the first newline. The caller owns the
 * buffer and must zero it. More than maxBytes before a newline, a close before a newline, an error
 * or the time limit is a failure, and every byte read so far is zeroed.
 */
export function readBootLine(opts: BootLineOptions = {}): Promise<Result<Buffer>> {
  const host = opts.host ?? BOOT_LINE_HOST;
  const port = opts.port ?? BOOT_LINE_PORT;
  const maxBytes = opts.maxBytes ?? BOOT_LINE_MAX_BYTES;
  const timeoutMs = opts.timeoutMs ?? BOOT_LINE_TIMEOUT_MS;
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    const sock = connect({ host, port });
    const finish = (r: Result<Buffer>) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock.destroy();
      for (const c of chunks) c.fill(0);
      resolve(r);
    };
    const timer = setTimeout(() => finish(bootDeclined("RELAY_FAILED", "boot line timed out")), timeoutMs);
    sock.on("data", (chunk: Buffer) => {
      if (done) {
        chunk.fill(0);
        return;
      }
      const nl = chunk.indexOf(0x0a);
      const take = nl === -1 ? chunk.length : nl;
      if (size + take > maxBytes) {
        chunk.fill(0);
        finish(bootDeclined("LINE_TOO_LONG", `boot line is over ${maxBytes} bytes`));
        return;
      }
      chunks.push(Buffer.from(chunk.subarray(0, take)));
      size += take;
      chunk.fill(0);
      if (nl !== -1) {
        const line = Buffer.concat(chunks, size);
        finish({ ok: true, value: line });
      }
    });
    sock.on("end", () => finish(bootDeclined("RELAY_FAILED", "boot line closed before a newline")));
    sock.on("close", () => finish(bootDeclined("RELAY_FAILED", "boot line closed before a newline")));
    sock.on("error", () => finish(bootDeclined("RELAY_FAILED", "boot line connection failed")));
  });
}

/** One connection: read the host's line, then send one status line back. The console is debug-only. */
export function openBootSession(opts: BootLineOptions = {}): Promise<Result<{ line: Buffer; reply(status: string): void }>> {
  const host = opts.host ?? BOOT_LINE_HOST;
  const port = opts.port ?? BOOT_LINE_PORT;
  const maxBytes = opts.maxBytes ?? BOOT_LINE_MAX_BYTES;
  const timeoutMs = opts.timeoutMs ?? BOOT_LINE_TIMEOUT_MS;
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    const sock = connect({ host, port });
    const fail = (r: { ok: false; error: AdapterError }) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock.destroy();
      for (const c of chunks) c.fill(0);
      resolve(r);
    };
    const timer = setTimeout(() => fail(bootDeclined("RELAY_FAILED", "boot line timed out")), timeoutMs);
    sock.on("data", (chunk: Buffer) => {
      if (done) {
        chunk.fill(0);
        return;
      }
      const nl = chunk.indexOf(0x0a);
      const take = nl === -1 ? chunk.length : nl;
      if (size + take > maxBytes) {
        chunk.fill(0);
        fail(bootDeclined("LINE_TOO_LONG", `boot line is over ${maxBytes} bytes`));
        return;
      }
      chunks.push(Buffer.from(chunk.subarray(0, take)));
      size += take;
      chunk.fill(0);
      if (nl === -1) return;
      done = true;
      clearTimeout(timer);
      const line = Buffer.concat(chunks, size);
      resolve({
        ok: true,
        value: {
          line,
          reply(status: string) {
            sock.write(`${status}\n`);
            sock.end();
          },
        },
      });
    });
    sock.on("end", () => fail(bootDeclined("RELAY_FAILED", "boot line closed before a newline")));
    sock.on("close", () => fail(bootDeclined("RELAY_FAILED", "boot line closed before a newline")));
    sock.on("error", () => fail(bootDeclined("RELAY_FAILED", "boot line connection failed")));
  });
}

export interface BootPayload {
  ciphertext: Uint8Array;
  credentials: AwsCredentials;
  cardId?: string;
  clientId?: string;
}

const PAYLOAD_KEYS = ["ciphertextB64", "accessKeyId", "secretAccessKey", "sessionToken"] as const;
const ARM_KEYS = ["cardId", "clientId"] as const;
const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * Parse the boot line JSON. The four string fields are required; cardId (uuid) and clientId are the
 * only other fields allowed. runBoot requires those two when it arms. Messages never echo values.
 */
export function parseBootPayload(line: Uint8Array): Result<BootPayload> {
  const r = parseBootObject(line);
  if (!r.ok) return r;
  return payloadFromRecord(r.value);
}

function parseBootObject(line: Uint8Array): Result<Record<string, unknown>> {
  let raw: unknown;
  try {
    raw = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(line));
  } catch {
    return bootDeclined("BAD_INPUT", "boot line is not UTF-8 JSON");
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return bootDeclined("BAD_INPUT", "boot line is not a JSON object");
  }
  return { ok: true, value: raw as Record<string, unknown> };
}

function payloadFromRecord(r: Record<string, unknown>): Result<BootPayload> {
  const keys = Object.keys(r);
  if (!PAYLOAD_KEYS.every((k) => keys.includes(k)) || !keys.every((k) => (PAYLOAD_KEYS as readonly string[]).includes(k) || (ARM_KEYS as readonly string[]).includes(k))) {
    return bootDeclined("BAD_INPUT", "boot line must have ciphertextB64, accessKeyId, secretAccessKey, sessionToken, and only cardId and clientId besides");
  }
  for (const k of [...PAYLOAD_KEYS, ...ARM_KEYS]) {
    if (!(k in r) && (ARM_KEYS as readonly string[]).includes(k)) continue;
    if (typeof r[k] !== "string" || (r[k] as string).length === 0) return bootDeclined("BAD_INPUT", `${k} is not a non-empty string`);
  }
  if (typeof r.cardId === "string" && !UUID_RE.test(r.cardId)) return bootDeclined("BAD_INPUT", "cardId is not a uuid");
  const b64 = r.ciphertextB64 as string;
  if (!B64_RE.test(b64) || b64.length % 4 !== 0) return bootDeclined("BAD_INPUT", "ciphertextB64 is not base64");
  const ciphertext = new Uint8Array(Buffer.from(b64, "base64"));
  if (ciphertext.length === 0) return bootDeclined("BAD_INPUT", "ciphertext is empty");
  return {
    ok: true,
    value: {
      ciphertext,
      credentials: {
        accessKeyId: r.accessKeyId as string,
        secretAccessKey: r.secretAccessKey as string,
        sessionToken: r.sessionToken as string,
      },
      ...(typeof r.cardId === "string" ? { cardId: r.cardId } : {}),
      ...(typeof r.clientId === "string" ? { clientId: r.clientId } : {}),
    },
  };
}

export interface ServeBootPayload extends BootPayload {
  writ?: ApprovedTask;
  /** KMS ciphertext of the RA shared secret. Plaintext is never on the boot line. */
  raCiphertext?: Uint8Array;
}

/**
 * Boot line for the serve entry. Takes the BootPayload fields and an optional signed writ. Every other
 * field (a public key, a now, a balance) is dropped unread: those come only from the image and from
 * Airwallex. The writ is checked by EnclaveServe against the baked key, not here.
 */
export function parseServeBoot(line: Uint8Array): Result<ServeBootPayload> {
  const r = parseBootObject(line);
  if (!r.ok) return r;
  const picked: Record<string, unknown> = {};
  for (const k of [...PAYLOAD_KEYS, ...ARM_KEYS]) if (k in r.value) picked[k] = r.value[k];
  const payload = payloadFromRecord(picked);
  if (!payload.ok) return payload;
  const serve: ServeBootPayload = { ...payload.value };
  const raRaw = r.value.raCiphertextB64;
  if (raRaw !== undefined) {
    if (typeof raRaw !== "string" || !B64_RE.test(raRaw) || raRaw.length % 4 !== 0) {
      payload.value.ciphertext.fill(0);
      return bootDeclined("BAD_INPUT", "raCiphertextB64 is not base64");
    }
    const raCiphertext = new Uint8Array(Buffer.from(raRaw, "base64"));
    if (raCiphertext.length === 0) {
      payload.value.ciphertext.fill(0);
      return bootDeclined("BAD_INPUT", "ra ciphertext is empty");
    }
    serve.raCiphertext = raCiphertext;
  }
  const writ = r.value.writ;
  if (writ === undefined) return { ok: true, value: serve };
  if (typeof writ !== "object" || writ === null || Array.isArray(writ)) {
    payload.value.ciphertext.fill(0);
    return bootDeclined("BAD_INPUT", "writ is not a JSON object");
  }
  return { ok: true, value: { ...serve, writ: writ as ApprovedTask } };
}

export const ATTEST_PATH = "/usr/bin/writ-attest";
export const ATTEST_NONCE_MIN_BYTES = 32;
export const ATTEST_NONCE_MAX_BYTES = 512;
/** writ-attest holds at most 48 KiB of COSE, which is 65,536 base64 characters plus the newline. */
const ATTEST_STDOUT_LIMIT = 96 * 1024;

export type AttestExec = (argv: readonly string[]) => Promise<{ exitCode: number; stdout: string }>;

/** Runs /usr/bin/writ-attest with the same spawn rules as kmstool_reply. */
export const enclaveAttestExec: AttestExec = (argv) => cappedSpawn(argv, ATTEST_STDOUT_LIMIT);

const HEX_RE = /^[0-9a-fA-F]+$/;
const ATTEST_STDOUT_RE = /^([A-Za-z0-9+/]+={0,2})\n$/;

/**
 * Undefined when the line is not an attest-only request, so the unseal path parses it as before.
 * Otherwise the nonce hex, or a failure when the request has other keys or a bad nonce.
 */
export function parseAttestOnly(line: Uint8Array): Result<string> | undefined {
  let raw: unknown;
  try {
    raw = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(line));
  } catch {
    return undefined;
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return undefined;
  const r = raw as Record<string, unknown>;
  if (!("attestOnly" in r)) return undefined;
  const failed = (message: string) => ({ ok: false as const, error: { kind: "config" as const, code: "ATTEST_FAILED", message: `Declined: ${message}` } });
  if (r.attestOnly !== true) return failed("attestOnly must be true");
  const keys = Object.keys(r);
  if (keys.length !== 2 || !keys.includes("nonce")) return failed("attest-only line must have only attestOnly and nonce");
  const nonce = r.nonce;
  if (
    typeof nonce !== "string" ||
    !HEX_RE.test(nonce) ||
    nonce.length % 2 !== 0 ||
    nonce.length < ATTEST_NONCE_MIN_BYTES * 2 ||
    nonce.length > ATTEST_NONCE_MAX_BYTES * 2
  ) {
    return failed(`nonce must be hex of ${ATTEST_NONCE_MIN_BYTES} to ${ATTEST_NONCE_MAX_BYTES} bytes`);
  }
  return { ok: true, value: nonce };
}

/** One attestation document for the host's nonce. No unseal, no Airwallex call, no arm. */
async function attestOnly(nonceHex: string, exec: AttestExec | undefined): Promise<Result<string>> {
  const failed = { ok: false as const, error: { kind: "config" as const, code: "ATTEST_FAILED", message: "Declined: writ-attest failed" } };
  if (!exec) return failed;
  let ran: { exitCode: number; stdout: string };
  try {
    ran = await exec([ATTEST_PATH, nonceHex]);
  } catch {
    return failed;
  }
  if (ran.exitCode !== 0 || typeof ran.stdout !== "string") return failed;
  const m = ATTEST_STDOUT_RE.exec(ran.stdout);
  if (!m || !m[1] || m[1].length % 4 !== 0) return failed;
  return { ok: true, value: `ATTEST ${m[1]}` };
}

/**
 * AttestFn for the TLS server: writ-attest with the request nonce and the TLS user_data, both hex.
 * Any failure throws, which startEnclaveTls answers with 503.
 */
export function tlsAttest(exec: AttestExec): AttestFn {
  return async (nonce, userData) => {
    const ran = await exec([ATTEST_PATH, Buffer.from(nonce).toString("hex"), Buffer.from(userData).toString("hex")]);
    const m = ran.exitCode === 0 && typeof ran.stdout === "string" ? ATTEST_STDOUT_RE.exec(ran.stdout) : null;
    if (!m || !m[1] || m[1].length % 4 !== 0) throw new Error("writ-attest failed");
    return new Uint8Array(Buffer.from(m[1], "base64"));
  };
}

export interface BootIo {
  nsm: NsmPort;
  readLine(): Promise<Result<Buffer>>;
  runKmstool: BootDeps["runKmstool"];
  stdout(line: string): void;
  stderr(line: string): void;
  /** Status back to the host. The console only exists in debug mode, which zeroes PCRs. */
  reply?(line: string): void;
  /** When set, the boot line must carry cardId and clientId, and a successful unseal goes on to checkpoint, arm and disarm. */
  arm?: ArmDeps;
  /** Runs writ-attest for an attest-only boot line. Missing means attest-only declines ATTEST_FAILED. */
  attest?: AttestExec;
}

const codeOf = (e: AdapterError): string => e.code ?? e.kind.toUpperCase();

/** The boot sequence with every outside effect injected. Returns the process exit code. */
export async function runBoot(io: BootIo): Promise<number> {
  const decline = (code: string): number => {
    const line = `DECLINED ${code}`;
    io.stderr(line);
    io.reply?.(line);
    return 1;
  };
  try {
    const pcrs = await io.nsm.readPcrs();
    if (!pcrs.ok) return decline(codeOf(pcrs.error));

    const line = await io.readLine();
    if (!line.ok) return decline(codeOf(line.error));
    const attestReq = parseAttestOnly(line.value);
    if (attestReq !== undefined) {
      line.value.fill(0);
      if (!attestReq.ok) return decline("ATTEST_FAILED");
      const doc = await attestOnly(attestReq.value, io.attest);
      if (!doc.ok) return decline("ATTEST_FAILED");
      io.stdout(doc.value);
      io.reply?.(doc.value);
      return 0;
    }
    const payload = parseBootPayload(line.value);
    line.value.fill(0);
    if (!payload.ok) return decline(codeOf(payload.error));
    const { cardId, clientId } = payload.value;
    if (io.arm && (cardId === undefined || clientId === undefined)) {
      payload.value.ciphertext.fill(0);
      return decline("BAD_INPUT");
    }

    const result = await unsealAtBoot({
      nsm: fixedNsm(pcrs.value),
      ciphertext: payload.value.ciphertext,
      credentials: payload.value.credentials,
      runKmstool: io.runKmstool,
    });
    payload.value.ciphertext.fill(0);
    if (!result.ok) return decline(codeOf(result.error));

    let status = `UNSEALED ${result.value.length}`;
    if (io.arm && cardId !== undefined && clientId !== undefined) {
      const armed = await armAfterUnseal(result.value, { cardId, clientId }, payload.value.credentials, io.arm);
      result.value.fill(0);
      if (!armed.ok) return decline(armed.code);
      status = "ARMED";
    }
    io.stdout(status);
    io.reply?.(status);
    result.value.fill(0);
    return 0;
  } catch {
    return decline("BOOT_FAILED");
  }
}

// ---------------------------------------------------------------------------
// Serve entry: unseal, then stay up. Every arm and every Remote Authorization goes through EnclaveServe,
// which calls Gate.authorize and commits the S3 checkpoint before it says yes.

/** The arm EnclaveServe calls after AUTHORIZED. Gets the order and the session that holds the key. */
export type ServeArmFn = (order: ArmOrder, session: AirwallexSession) => Promise<boolean>;
/** One INACTIVE update for a card, with the session that holds the key. */
export type ServeDisarmFn = (cardId: string, session: AirwallexSession) => Promise<boolean>;

export interface ServeIo {
  nsm: NsmPort;
  readLine(): Promise<Result<Buffer>>;
  runKmstool: BootDeps["runKmstool"];
  stdout(line: string): void;
  stderr(line: string): void;
  /** One status line back to the host. Called at most once. */
  reply?(line: string): void;
  /** writ-attest runner, for an attest-only boot line and for GET /attestation. */
  attest?: AttestExec;
  /** Parsed enclave/config/approvers.json plus enclave/config/serve.json. Never from the boot line. */
  baked: BakedConfig;
  /** Airwallex fetch for login and the balance poll. */
  fetch: HttpFetch;
  /**
   * Signed S3 client for the ledger bucket. credentials is read per call (the host can refresh it over
   * vsock 5001); clock is the enclave clock. Checkpoints, resume and the sealed TLS blobs all use it.
   */
  s3(credentials: () => AwsCredentials | undefined, clock: () => Date | undefined): S3Store;
  /** Default LEDGER_BUCKET. */
  bucket?: string;
  armCard: ServeArmFn;
  disarmCard: ServeDisarmFn;
  /** Default: GET /api/v1/issuing/transactions through io.fetch with the session token. */
  listTransactions?: (cardId: string, sinceIso: string, session: AirwallexSession) => Promise<CardTx[] | undefined>;
  /** Watch timer for disarm after one swipe. Default setInterval every 5 s. */
  watchTimer?: SetTimer;
  watchIntervalMs?: number;
  /** Host-only credential refresh listener. Unset means none (tests that do not need it). */
  startCreds?: (box: CredentialBox, nowMs: () => number) => CredsListenerHandle;
  /** Pinned taint signer public key PEM. Default baked.taintSignerPem. */
  taintSignerPem?: string;
  /** Default startEnclaveTls. Tests pass one that sets port 0. */
  startTls?: (opts: EnclaveTlsOptions) => EnclaveTlsHandle;
  /** RA shared secret. Default empty, so every RA request declines "bad signature" until one is provisioned. */
  raSecret?: () => string;
  /**
   * When set, called with a fresh in-process TLS identity before the server listens.
   * A returned certificate is the one the server presents. A failure keeps the bootstrap certificate.
   * Tests leave this unset, so they never spawn lego.
   */
  issueCertificate?: (identity: TlsIdentity) => Promise<AcmeResult>;
  /** Balance poll timer. Default setInterval every 10 s. */
  setTimer?: SetTimer;
  pollIntervalMs?: number;
  mono?: () => number;
  /** Boot waits for the first Airwallex Date header before any S3 call. Default up to 60 s, a poll every 2 s. */
  clockWaitMs?: number;
  clockRetryMs?: number;
  /** Default setTimeout. Tests pass one that resolves at once. */
  sleep?: (ms: number) => Promise<void>;
  /** Retry timer for a transient resume failure and a pending TLS seal. Default setInterval every 10 s. */
  retryTimer?: SetTimer;
  resumeRetryMs?: number;
}

export interface ServeHandle {
  serve: EnclaveServe;
  tls: EnclaveTlsHandle;
  poller: BalancePoller;
  /** Result of the boot line arm. Undefined when the boot line carried none. */
  armResult?: ServeResult;
  app: EnclaveApp;
  ledgerPublicKey: string;
  creds?: CredsListenerHandle;
  /** Runs one pass of the resume and TLS seal retry now (tests, and the timer). */
  retryNow(): Promise<void>;
  /** Stops the poller, the watcher, the listeners and the TLS server and zeroes the API key. */
  stop(): Promise<void>;
}

/** Setup entry time when no Airwallex Date header has been read yet. Informational only. */
const NO_TIME = "1970-01-01T00:00:00.000Z";
const TLS_BLOB_RE = /^tls\/(\d{1,12})\.json$/;
const MAX_TLS_BLOBS_TRIED = 10;
const CLOCK_WAIT_MS = 60_000;
const CLOCK_RETRY_MS = 2_000;
const RESUME_RETRY_MS = 10_000;
const TLS_LIST_TRIES = 3;

const intervalTimerFn: SetTimer = (fn, ms) => {
  const t = setInterval(fn, ms);
  return { stop: () => clearInterval(t) };
};

/**
 * The newest sealed TLS blob that opens, names RA_HOSTNAME and has more than 72 hours left.
 * "unreadable" when the tls/ prefix could not be listed (no time yet, S3 down): then the caller must not
 * ask Let's Encrypt for a new certificate, because a good sealed one may be sitting there.
 */
async function reuseSealedTls(store: S3Store, bucket: string, sealKey: Uint8Array, nowMs: number, sleep: (ms: number) => Promise<void>): Promise<OpenedTls | "none" | "unreadable"> {
  if (!Number.isFinite(nowMs)) return "unreadable";
  let keys: string[] | undefined;
  for (let i = 0; i < TLS_LIST_TRIES && keys === undefined; i++) {
    if (i > 0) await sleep(CLOCK_RETRY_MS);
    try {
      keys = await store.listKeys(bucket, TLS_BLOB_PREFIX);
    } catch {
      keys = undefined;
    }
  }
  if (keys === undefined) return "unreadable";
  const named = keys
    .map((k) => ({ k, m: TLS_BLOB_RE.exec(k) }))
    .filter((x): x is { k: string; m: RegExpExecArray } => x.m !== null)
    .sort((a, b) => Number(b.m[1]) - Number(a.m[1]))
    .slice(0, MAX_TLS_BLOBS_TRIED);
  for (const { k } of named) {
    try {
      const blob = await store.getObject(bucket, k);
      const opened = blob === undefined ? undefined : openTlsIdentity(blob, sealKey, nowMs);
      if (opened) return opened;
    } catch {
      // try the next one
    }
  }
  return "none";
}

/** One conditional PUT of a sealed blob as tls/<unix seconds>.json on the enclave clock. */
async function putSealedTls(store: S3Store, bucket: string, body: string, nowMs: number): Promise<boolean> {
  try {
    const put = await store.putObject({ bucket, key: `${TLS_BLOB_PREFIX}${Math.floor(nowMs / 1000)}.json`, body, contentType: "application/json", ifNoneMatch: "*" });
    return put.status === 200 || put.status === 201;
  } catch {
    return false;
  }
}

interface ServingCert {
  serving: { identity: TlsIdentity; certificatePem?: string } | undefined;
  source: "reused" | "acme" | "bootstrap";
  sealed: boolean | "n/a";
  /** Sealed body of a new ACME certificate whose PUT has not landed yet. The retry loop writes it. */
  pendingBody?: string;
}

/**
 * The serving identity: a sealed one from S3 when it is still good, else a fresh key and ACME. A new
 * ACME certificate is sealed at once (the seal needs no clock) and written as tls/<unix seconds>.json,
 * now or by the retry loop once the clock and S3 work. ACME is skipped when tls/ could not be read, so
 * an S3 or clock problem never burns a Let's Encrypt issuance. Any failure serves the bootstrap certificate.
 */
async function servingCertificate(io: ServeIo, store: S3Store, bucket: string, sealKey: Uint8Array, nowMs: number, sleep: (ms: number) => Promise<void>): Promise<ServingCert> {
  const reused = await reuseSealedTls(store, bucket, sealKey, nowMs, sleep);
  if (typeof reused === "object") {
    io.stdout("TLS_REUSED");
    return { serving: { identity: reused.identity, certificatePem: reused.certificatePem }, source: "reused", sealed: true };
  }
  if (!io.issueCertificate) return { serving: undefined, source: "bootstrap", sealed: "n/a" };
  if (reused === "unreadable") {
    io.stderr("ACME_SKIPPED TLS_BLOBS_UNREADABLE");
    return { serving: undefined, source: "bootstrap", sealed: "n/a" };
  }
  const identity = createTlsIdentity();
  try {
    const result = await io.issueCertificate(identity);
    if (result.ok) {
      io.stdout("ACME_OK");
      const out: ServingCert = { serving: { identity, certificatePem: result.certificatePem }, source: "acme", sealed: false };
      let body: string | undefined;
      try {
        body = sealTlsIdentity(identity, result.certificatePem, sealKey);
      } catch {
        io.stderr("TLS_SEAL_FAILED");
      }
      if (body !== undefined && Number.isFinite(nowMs) && (await putSealedTls(store, bucket, body, nowMs))) {
        io.stdout("TLS_SEALED");
        out.sealed = true;
      } else if (body !== undefined) {
        io.stderr("TLS_SEAL_PENDING");
        out.pendingBody = body;
      }
      return out;
    }
    io.stderr(`ACME_FAILED ${result.reason}`);
  } catch {
    io.stderr("ACME_FAILED lego did not start");
  }
  return { serving: { identity }, source: "bootstrap", sealed: "n/a" };
}

/**
 * Returns { code } to exit with, or { code: 0, handle } to keep running. The attest-only line keeps
 * today's behaviour and never starts the server. Never calls armAfterUnseal.
 */
export async function runServe(io: ServeIo): Promise<{ code: number; handle?: ServeHandle }> {
  let replied = false;
  const reply = (line: string) => {
    if (replied) return;
    replied = true;
    io.reply?.(line);
  };
  const decline = (code: string): { code: number } => {
    io.stderr(`DECLINED ${code}`);
    reply(`DECLINED ${code}`);
    return { code: 1 };
  };
  let key: Uint8Array | undefined;
  let session: AirwallexSession | undefined;
  let poller: BalancePoller | undefined;
  let tls: EnclaveTlsHandle | undefined;
  let watcher: ArmWatcher | undefined;
  let creds: CredsListenerHandle | undefined;
  let sealKey: Uint8Array | undefined;
  let retryTimer: TimerHandle | undefined;
  let retryNow: (() => Promise<void>) | undefined;
  const shutdown = async () => {
    retryTimer?.stop();
    poller?.stop();
    watcher?.stop();
    creds?.stop();
    session?.zero();
    key?.fill(0);
    sealKey?.fill(0);
    await tls?.stop().catch(() => undefined);
  };
  try {
    const pcrs = await io.nsm.readPcrs();
    if (!pcrs.ok) return decline(codeOf(pcrs.error));

    const line = await io.readLine();
    if (!line.ok) return decline(codeOf(line.error));
    const attestReq = parseAttestOnly(line.value);
    if (attestReq !== undefined) {
      line.value.fill(0);
      if (!attestReq.ok) return decline("ATTEST_FAILED");
      const doc = await attestOnly(attestReq.value, io.attest);
      if (!doc.ok) return decline("ATTEST_FAILED");
      io.stdout(doc.value);
      reply(doc.value);
      return { code: 0 };
    }
    const payload = parseServeBoot(line.value);
    line.value.fill(0);
    if (!payload.ok) return decline(codeOf(payload.error));
    const { cardId, clientId, writ, credentials, raCiphertext } = payload.value;

    const unsealed = await unsealAtBoot({ nsm: fixedNsm(pcrs.value), ciphertext: payload.value.ciphertext, credentials, runKmstool: io.runKmstool });
    payload.value.ciphertext.fill(0);
    if (!unsealed.ok) return decline(codeOf(unsealed.error));
    key = unsealed.value;
    let raPlain = "";
    if (raCiphertext !== undefined) {
      const opened = await unsealAtBoot({ nsm: fixedNsm(pcrs.value), ciphertext: raCiphertext, credentials, runKmstool: io.runKmstool });
      raCiphertext.fill(0);
      if (!opened.ok) {
        key.fill(0);
        return decline(codeOf(opened.error));
      }
      raPlain = new TextDecoder().decode(opened.value);
      opened.value.fill(0);
      if (raPlain.length === 0) {
        key.fill(0);
        return decline("BAD_INPUT");
      }
    }
    const signer = deriveLedgerSigner(key);
    const tlsSealKey = deriveTlsSealKey(key);
    sealKey = tlsSealKey;
    const ledgerPublicKey = signer.publicKey;
    const status = `UNSEALED ${key.length}`;
    io.stdout(status);
    io.stdout(`LEDGER_PUB ${ledgerPublicKey}`);

    // The baked client id wins: it is part of PCR0, so the host cannot drop or swap it.
    const airwallexClientId = io.baked.airwallexClientId || clientId || "";
    if (airwallexClientId === "") io.stderr("NO_CLIENT_ID");
    reply(`${status} LEDGER_PUB ${ledgerPublicKey}${airwallexClientId === "" ? " NO_CLIENT_ID" : ""}`);

    const sess = new AirwallexSession(key, airwallexClientId, io.fetch, io.mono);
    session = sess;
    let serve: EnclaveServe | undefined;
    const pollerOpts: PollerOptions = { session: sess, fetch: io.fetch, onObservation: (obs) => serve?.setObservation(obs) };
    if (io.setTimer) pollerOpts.setTimer = io.setTimer;
    if (io.pollIntervalMs !== undefined) pollerOpts.intervalMs = io.pollIntervalMs;
    if (io.mono) pollerOpts.mono = io.mono;
    const p = new BalancePoller(pollerOpts);
    poller = p;
    // The poller starts first and keeps running whatever happens below. Every S3 call is signed with its clock.
    await p.start();
    const sleep = io.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
    if (airwallexClientId !== "") {
      const retryMs = io.clockRetryMs ?? CLOCK_RETRY_MS;
      const tries = Math.ceil((io.clockWaitMs ?? CLOCK_WAIT_MS) / retryMs);
      for (let i = 0; i < tries && !Number.isFinite(p.nowMs()); i++) {
        await sleep(retryMs);
        await p.pollOnce();
      }
    }
    io.stdout(Number.isFinite(p.nowMs()) ? "CLOCK_OK" : `CLOCK_MISSING ${p.lastError ?? "UNKNOWN"}`);

    const box = new CredentialBox(credentials, () => p.nowMs());
    const clockDate = () => {
      const ms = p.nowMs();
      return Number.isFinite(ms) ? new Date(ms) : undefined;
    };
    const store = io.s3(() => box.get(), clockDate);
    const bucket = io.bucket ?? LEDGER_BUCKET;
    const loaded = await loadSignedChain(store, bucket, SIGNED_CHECKPOINT_PREFIX, signer.publicKeyRaw);
    io.stdout(loaded.ok ? `LEDGER_VERIFIED ${loaded.entries.length}` : `LEDGER_UNVERIFIED ${loaded.transient ? "transient" : "tampered"}`);

    const list = io.listTransactions ?? (async (id: string, since: string, ss: AirwallexSession) => listCardTransactions(io.fetch, await ss.token(), id, since));
    const watch: WatchOptions = {
      listTransactions: (id, since) => list(id, since, sess),
      disarmCard: (id) => io.disarmCard(id, sess),
    };
    if (io.watchTimer) watch.setTimer = io.watchTimer;
    if (io.watchIntervalMs !== undefined) watch.intervalMs = io.watchIntervalMs;
    const serveOpts: ServeOptions = {
      baked: io.baked,
      bootAt: p.latest()?.at ?? NO_TIME,
      checkpoint: { s3: { client: store, bucket, prefix: SIGNED_CHECKPOINT_PREFIX } },
      signer,
      armCard: (order) => io.armCard(order, sess),
      watch,
      clock: () => p.now(),
    };
    if (loaded.ok) serveOpts.resume = loaded.entries;
    else {
      serveOpts.resumeError = loaded.reason;
      serveOpts.resumeTransient = loaded.transient;
    }
    const s = new EnclaveServe(serveOpts);
    serve = s;
    s.setObservation(p.latest());
    watcher = s.armWatcher;
    watcher?.start();
    void watcher?.tick();

    const cert = await servingCertificate(io, store, bucket, tlsSealKey, p.nowMs(), sleep);
    tlsSealKey.fill(0);
    const issued = cert.serving;
    const boot = { tls: cert.source, tlsSealed: cert.sealed as boolean | "pending" | "n/a", resumeAttempts: 0 };
    let pendingSeal = cert.pendingBody;
    if (pendingSeal !== undefined) boot.tlsSealed = "pending";

    // Retries every 10 s, forever: a resume that failed for a transient reason, and a TLS seal that could
    // not be written yet. Tampering is never retried. The timer stops once nothing is pending.
    let retrying = false;
    const retryOnce = async (): Promise<void> => {
      if (retrying) return;
      retrying = true;
      try {
        const nowMs = p.nowMs();
        if (s.waitingForResume) {
          boot.resumeAttempts += 1;
          if (!Number.isFinite(nowMs)) s.noteTransient(`no trusted time yet (balance poll: ${p.lastError ?? "none yet"})`);
          else {
            const again = await loadSignedChain(store, bucket, SIGNED_CHECKPOINT_PREFIX, signer.publicKeyRaw);
            if (again.ok) {
              const r = s.resume(again.entries);
              io.stdout(r.ok ? `LEDGER_VERIFIED ${again.entries.length}` : "LEDGER_TAMPERED");
            } else if (again.transient) s.noteTransient(again.reason);
            else {
              s.markTampered(again.reason);
              io.stdout("LEDGER_TAMPERED");
            }
          }
        }
        if (pendingSeal !== undefined && Number.isFinite(p.nowMs())) {
          const ok = await putSealedTls(store, bucket, pendingSeal, p.nowMs());
          if (ok) {
            pendingSeal = undefined;
            boot.tlsSealed = true;
            io.stdout("TLS_SEALED");
          }
        }
        if (!s.waitingForResume && pendingSeal === undefined) retryTimer?.stop();
      } catch {
        // the next tick tries again
      } finally {
        retrying = false;
      }
    };
    if (s.waitingForResume || pendingSeal !== undefined) {
      retryTimer = (io.retryTimer ?? intervalTimerFn)(() => void retryOnce(), io.resumeRetryMs ?? RESUME_RETRY_MS);
    }
    retryNow = retryOnce;

    const nonces = new NonceCache();
    const raSecret = io.raSecret ?? (() => raPlain);
    const app = new EnclaveApp({
      serve: s,
      signer,
      verifyTaint: taintVerifier(io.taintSignerPem ?? io.baked.taintSignerPem),
      clock: () => p.now(),
      status: () => ({
        clientId: airwallexClientId !== "",
        clock: p.now() ?? null,
        balancePoll: { lastError: p.lastError ?? null, ...p.counts },
        tls: boot.tls,
        tlsSealed: boot.tlsSealed,
        resumeAttempts: boot.resumeAttempts,
      }),
    });
    const tlsOpts: EnclaveTlsOptions = {
      ledgerPublicKey,
      handler: ({ headers, rawBody }) =>
        handleRemoteAuth({ headers, rawBody, nowMs: p.nowMs(), secret: raSecret(), decide: (input, eventId) => s.authorizeRa(input, eventId), nonces }),
      attest: io.attest ? tlsAttest(io.attest) : () => Promise.reject(new Error("no writ-attest")),
      routes: app.route,
    };
    if (issued !== undefined) {
      tlsOpts.identity = issued.identity;
      if (issued.certificatePem !== undefined) {
        const pem = issued.certificatePem;
        tlsOpts.certificatePem = () => pem;
      }
    }
    tls = (io.startTls ?? startEnclaveTls)(tlsOpts);
    if (io.startCreds) creds = io.startCreds(box, () => p.nowMs());

    const handle: ServeHandle = { serve: s, tls, poller: p, app, ledgerPublicKey, retryNow: () => (retryNow ? retryNow() : Promise.resolve()), stop: shutdown };
    if (creds) handle.creds = creds;
    if (cardId !== undefined && clientId !== undefined && writ !== undefined) {
      const armed = await s.authorize({ cardId, amountMinor: writ.amountMinor, currency: writ.currency, mcc: writ.mcc, merchantName: writ.merchantName, writ });
      handle.armResult = armed;
      if (armed.status === "AUTHORIZED") io.stdout("ARMED");
      else io.stderr(`DECLINED ${armed.code}`);
    }
    return { code: 0, handle };
  } catch {
    await shutdown();
    return decline("BOOT_FAILED");
  }
}

const CONFIG_DIR = join(import.meta.dir, "..", "..", "enclave", "config");

/** approvers.json and serve.json from the image. Missing or bad files give a config that declines everything. */
export function loadBakedConfig(dir = CONFIG_DIR): BakedConfig {
  const read = (name: string): unknown => {
    try {
      return JSON.parse(readFileSync(join(dir, name), "utf8"));
    } catch {
      return undefined;
    }
  };
  const serve = (read("serve.json") ?? {}) as Partial<BakedConfig>;
  const baked: BakedConfig = {
    approvers: read("approvers.json"),
    ringFenceMinor: serve.ringFenceMinor ?? 0,
    reserveFloorMinor: serve.reserveFloorMinor ?? Number.MAX_SAFE_INTEGER,
    maxBalanceAgeMs: serve.maxBalanceAgeMs ?? 0,
    teams: Array.isArray(serve.teams) ? serve.teams : [],
    cards: Array.isArray(serve.cards) ? serve.cards : [],
  };
  if (typeof serve.airwallexClientId === "string" && serve.airwallexClientId.length > 0) baked.airwallexClientId = serve.airwallexClientId;
  try {
    baked.taintSignerPem = readFileSync(join(dir, "taint-signer.pub.pem"), "utf8");
  } catch {
    // no pinned key: every taint event is refused as a bad signature
  }
  return baked;
}

/** The arm main() injects: one ACTIVE update with the order's limits, using the session token. */
const enclaveServeArm: ServeArmFn = async (order, session) => {
  const token = await session.token();
  if (token === undefined) return false;
  return armOrderCard(order, token, { fetch: enclaveHttpFetch, uuid: () => randomUUID() });
};

/** The disarm main() injects: one INACTIVE update. A failure is retried by the watcher. */
const enclaveServeDisarm: ServeDisarmFn = async (cardId, session) => {
  const token = await session.token();
  if (token === undefined) return false;
  return disarmCard(cardId, token, { fetch: enclaveHttpFetch, uuid: () => randomUUID() });
};

async function main(): Promise<number | "serving"> {
  const pcrs = await enclaveNsm.readPcrs();
  if (!pcrs.ok) {
    process.stderr.write(`DECLINED ${pcrs.error.code ?? "NSM_READ_FAILED"}\n`);
    return 1;
  }
  const session = await openBootSession();
  if (!session.ok) {
    const code = session.error.code ?? "RELAY_FAILED";
    process.stderr.write(`DECLINED ${code}\n`);
    return 1;
  }
  const result = await runServe({
    nsm: fixedNsm(pcrs.value),
    readLine: async () => ({ ok: true, value: session.value.line }),
    runKmstool: enclaveKmstoolRunner,
    stdout: (l) => process.stdout.write(`${l}\n`),
    stderr: (l) => process.stderr.write(`${l}\n`),
    reply: session.value.reply,
    attest: enclaveAttestExec,
    baked: loadBakedConfig(),
    fetch: enclaveHttpFetch,
    s3: (credentials, clock) => sigV4S3Store(credentials, { fetch: timedFetch, now: clock }),
    bucket: LEDGER_BUCKET,
    armCard: enclaveServeArm,
    disarmCard: enclaveServeDisarm,
    startCreds: (box, nowMs) => startCredsListener({ box, nowMs }),
    issueCertificate: (identity) => runAcme({ identity, acme: "production" }),
  });
  const handle = result.handle;
  if (!handle) return result.code;
  const stop = (signal: string) => {
    void handle.stop().finally(() => process.exit(signal === "SIGTERM" ? 0 : 1));
  };
  process.once("SIGTERM", () => stop("SIGTERM"));
  process.once("SIGINT", () => stop("SIGINT"));
  return "serving";
}

if (import.meta.main) {
  const code = await main();
  if (code !== "serving") {
    // A natural exit flushes stdout and stderr. The unref timer forces the exit if a handle lingers.
    process.exitCode = code;
    setTimeout(() => process.exit(code), 2_000).unref();
  }
}
