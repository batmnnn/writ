// Host-root attacks on a running Writ enclave. Run as root on the EC2 host (us-west-2), for example
// over SSM. Each attack prints one line:
//   FAILED <name>: <evidence>    the attack was stopped (good)
//   PROBLEM <name>: <evidence>   the attack worked, or the run could not show that it was stopped
//   SKIPPED <name>: <reason>     the attack needs a flag or an input that was not given
// Exit 0 only when no line is PROBLEM.
//
//   bun run scripts/host-attack.ts [--with-debug] [--with-restart] [--allow-ledger-write]
//     [--signed-writ <path>] [--save <path>] [--boot-script <path>] [--checkpoint-prefix <prefix>]
//
// --with-debug        terminates the production enclave, runs the same EIF in debug mode, offers it the
//                     real boot line, then restarts production with --boot-script. No debug flag is
//                     ever passed to the restart.
// --allow-ledger-write the ledger forge writes one object into the checkpoint prefix. Object Lock
//                     compliance keeps it for 30 days and nobody can delete it, so it is opt in.
// --with-restart      after the forge, restart the enclave and check it reports STATE_UNVERIFIED.
// --signed-writ       a writ the real approver signed. Its amount is edited and posted. The running
//                     enclave revokes that writ id, so use a spare writ.
//
// Never prints a key, a credential, ciphertext, a PAN or the boot line. Temp files are mode 600,
// zeroed and removed.

import { createHash, randomBytes as nodeRandomBytes, randomUUID } from "node:crypto";
import { chmodSync, closeSync, lstatSync, mkdtempSync, openSync, readFileSync, readSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createConnection, createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GENESIS_PREV, entryHash } from "../src/core/chain";
import { generateApproverKeys, signWrit, writHash } from "../src/core/writ";
import type { ApprovedTask, WritProposal } from "../src/types";

// Enclave routes. The /writs, /state and checkpoint v2 contract is new: adjust here if it moves.
export const ROUTES = {
  writs: "/writs",
  taint: "/taint",
  state: "/state",
  remoteAuth: "/remote-auth",
  attestation: "/attestation",
} as const;
export const CHECKPOINT_PREFIX = "checkpoints/v2/";
export const LEGACY_CHECKPOINT_KEY = "checkpoints/arm/3a33056d-243e-4425-a8b6-b833753cc22e.json";

export const REGION = "us-west-2";
export const PUBLIC_HOST = "35-95-168-131.sslip.io";
export const SECRET_ID = "writ/airwallex/api-key.kms";
export const KMS_KEY_ARN = "arn:aws:kms:us-west-2:401046276943:key/04d013d8-fb9b-4261-bf67-4d87370a31bb";
export const LEDGER_BUCKET = "writ-ledger-401046276943";
export const ROOT = join(import.meta.dir, "..");
export const EIF_PATH = join(ROOT, "writ.eif");
export const UNSEAL_EXCHANGE = join(ROOT, "scripts", "unseal-exchange.py");
export const BOOT_SCRIPT = join(ROOT, "scripts", "boot-serve-host.sh");
export const REPLY_LOG = "/var/log/writ-unseal-reply.log";
export const ENCLAVE_CID = "16";
export const SCAN_ROOTS = ["/opt/writ", "/etc", "/root", "/home"] as const;
export const ATTACK_TEAM = "research";
export const ATTACK_AGENT = "research-3";
const ZERO_PCR = "0".repeat(96);
const DEBUG_FLAG = "--" + "debug-mode";

export type Status = "FAILED" | "PROBLEM" | "SKIPPED";
export interface AttackResult {
  name: string;
  status: Status;
  evidence: string;
}

export interface ExecOptions {
  stdin?: string;
  timeoutMs?: number;
}
export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
}
export type Exec = (argv: readonly string[], opts?: ExecOptions) => Promise<ExecResult>;
export interface HttpReply {
  status: number;
  body: string;
}
export interface FetchInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}
/** Requests to the enclave. path is a route plus query, for example "/state". */
export type Fetch = (path: string, init?: FetchInit) => Promise<HttpReply>;

export interface HostDeps {
  exec: Exec;
  fetch: Fetch;
  /** Starts a long-lived helper (the vsock boot line feeder). */
  spawnBackground(argv: readonly string[]): { stop(): void };
  processEnvs(): { pid: number; vars: string[] }[];
  /** Regular files under root. Never follows a symlink. */
  walkFiles(root: string): string[];
  /** File text, or undefined when missing, unreadable or over maxBytes. */
  readSmall(path: string, maxBytes: number): string | undefined;
  /** Writes a mode 600 temp file and returns its path. */
  writeTemp(data: string | Uint8Array): string;
  /** Zeroes and removes a file. Missing is fine. */
  wipe(path: string): void;
  readDevMem(offset: number, length: number): { ok: true } | { ok: false; code: string };
  /**
   * Starts a relay on a free 127.0.0.1 port to the public 443 relay, runs fn with that port, and
   * returns every byte that went through in both directions. This is what root on the host sees.
   */
  tee(fn: (port: number) => Promise<void>): Promise<Uint8Array>;
  sleep(ms: number): Promise<void>;
  now(): Date;
  randomBytes(n: number): Uint8Array;
  uuid(): string;
  ownPid: number;
}

export interface Options {
  withDebug: boolean;
  withRestart: boolean;
  allowLedgerWrite: boolean;
  signedWrit?: string;
  save?: string;
  bootScript: string;
  checkpointPrefix: string;
}

// ---------------------------------------------------------------------------
// Output hygiene

const AWS_KEY_ID = /(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Za-z0-9]{16}(?![A-Za-z0-9])/g;
const DIGIT_RUN = /(?<![0-9a-f])\d{13,19}(?![0-9a-f])/g;
const LONG_TOKEN = /[A-Za-z0-9+/=_-]{40,}/g;

/** Base64 or a key: mixed case with digits, or base64 padding or plus signs. Paths and hex digests are neither. */
function tokenLooksSecret(t: string): boolean {
  if (/^[0-9a-f]+$/.test(t)) return false;
  if (/[+]/.test(t) || /=$/.test(t)) return true;
  return /[a-z]/.test(t) && /[A-Z]/.test(t) && /[0-9]/.test(t);
}

/** Removes anything that could be a credential, ciphertext or card number. Hex digests and paths stay. */
export function scrub(text: string): string {
  return text
    .replace(AWS_KEY_ID, "[aws key id removed]")
    .replace(LONG_TOKEN, (m) => (tokenLooksSecret(m) ? "[removed]" : m))
    .replace(DIGIT_RUN, "[digits removed]");
}

const result = (name: string, status: Status, evidence: string): AttackResult => ({ name, status, evidence: scrub(evidence) });
const failed = (name: string, evidence: string) => result(name, "FAILED", evidence);
const problem = (name: string, evidence: string) => result(name, "PROBLEM", evidence);
const skipped = (name: string, evidence: string) => result(name, "SKIPPED", evidence);

export function formatLine(r: AttackResult): string {
  return `${r.status} ${r.name}: ${r.evidence}`;
}

/** 0 when every attack failed or was skipped. */
export function exitCodeFor(results: readonly AttackResult[]): number {
  return results.length > 0 && results.every((r) => r.status !== "PROBLEM") ? 0 : 1;
}

/** "Thu Nov 12, 15:40 IST" */
export function istLabel(d: Date): string {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: "Asia/Kolkata",
    weekday: "short",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  }).formatToParts(d);
  const get = (t: string) => parts.find((p) => p.type === t)?.value ?? "";
  return `${get("weekday")} ${get("month")} ${get("day")}, ${get("hour")}:${get("minute")} IST`;
}

/** The AWS error code from CLI stderr, for example AccessDeniedException. Nothing else is kept. */
export function awsErrorCode(stderr: string): string {
  const m = /An error occurred \(([A-Za-z0-9.]+)\)/.exec(stderr);
  if (m?.[1]) return m[1];
  if (/access ?denied/i.test(stderr)) return "AccessDenied";
  if (/precondition/i.test(stderr) || /\b412\b/.test(stderr)) return "PreconditionFailed";
  return "unknown error";
}

// ---------------------------------------------------------------------------
// Enclaves

export interface EnclaveInfo {
  id: string;
  state: string;
  flags: string;
  pcr0: string;
}

export function parseEnclaves(stdout: string): EnclaveInfo[] {
  let raw: unknown;
  try {
    raw = JSON.parse(stdout.trim() || "[]");
  } catch {
    return [];
  }
  const list = Array.isArray(raw) ? raw : [];
  return list.flatMap((e) => {
    if (e === null || typeof e !== "object") return [];
    const o = e as Record<string, unknown>;
    const m = (o.Measurements ?? {}) as Record<string, unknown>;
    return [
      {
        id: typeof o.EnclaveID === "string" ? o.EnclaveID : "",
        state: typeof o.State === "string" ? o.State : "",
        flags: typeof o.Flags === "string" ? o.Flags : "",
        pcr0: typeof m.PCR0 === "string" ? m.PCR0.toLowerCase() : "",
      },
    ];
  });
}

async function describe(deps: HostDeps): Promise<EnclaveInfo[]> {
  const r = await deps.exec(["nitro-cli", "describe-enclaves"], { timeoutMs: 20_000 });
  return r.code === 0 ? parseEnclaves(r.stdout) : [];
}

const isDebug = (flags: string) => /debug/i.test(flags);

/** The only argv that may carry the debug flag. Used by the debug unseal attack and nowhere else. */
export function debugRunArgv(eif = EIF_PATH): string[] {
  return ["nitro-cli", "run-enclave", "--eif-path", eif, "--cpu-count", "2", "--memory", "3072", "--enclave-cid", ENCLAVE_CID, DEBUG_FLAG, "--attach-console"];
}

/** Production restart. Throws if anything in it mentions debug. */
export function restartArgv(bootScript: string): string[] {
  const argv = ["bash", bootScript];
  assertNoDebug(argv);
  return argv;
}

export function assertNoDebug(argv: readonly string[]): void {
  if (argv.some((a) => /debug/i.test(a))) throw new Error("refusing: the production restart must not mention debug");
}

/** Boot script must exist and must not start anything in debug mode. */
export function checkBootScript(deps: HostDeps, path: string): string | undefined {
  const text = deps.readSmall(path, 256 * 1024);
  if (text === undefined) return `boot script ${path} is missing or unreadable`;
  if (/debug/i.test(text)) return `boot script ${path} mentions debug, refusing to use it`;
  if (!text.includes("run-enclave")) return `boot script ${path} does not run an enclave`;
  return undefined;
}

async function restartProduction(deps: HostDeps, opts: Options): Promise<{ ok: boolean; info?: EnclaveInfo; evidence: string }> {
  let argv: string[];
  try {
    argv = restartArgv(opts.bootScript);
  } catch (err) {
    return { ok: false, evidence: err instanceof Error ? err.message : "restart refused" };
  }
  const r = await deps.exec(argv, { timeoutMs: 420_000 });
  const running = (await describe(deps)).find((e) => e.state === "RUNNING");
  if (r.code !== 0 || !running) return { ok: false, evidence: `boot script exited ${r.code}, running enclave ${running ? "present" : "absent"}` };
  if (isDebug(running.flags)) return { ok: false, info: running, evidence: `restarted enclave has Flags ${running.flags}` };
  const ready = await waitServing(deps, 240_000);
  return { ok: ready, info: running, evidence: ready ? `production back, Flags ${running.flags || "NONE"}` : "production enclave started but HTTPS did not answer" };
}

async function waitServing(deps: HostDeps, maxMs: number): Promise<boolean> {
  const start = deps.now().getTime();
  while (deps.now().getTime() - start <= maxMs) {
    const r = await deps.fetch(`${ROUTES.attestation}?nonce=${hex(deps.randomBytes(32))}`).catch(() => undefined);
    if (r?.status === 200) return true;
    await deps.sleep(5_000);
  }
  return false;
}

// ---------------------------------------------------------------------------
// Shared helpers

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");

interface SealedSecret {
  fields: Record<string, Buffer>;
  names: string[];
}

/** Secrets Manager value: base64 blobs decoded per field. Plain strings are kept out. */
async function fetchSealedSecret(deps: HostDeps): Promise<{ ok: true; secret: SealedSecret } | { ok: false; code: string }> {
  const r = await deps.exec(["aws", "secretsmanager", "get-secret-value", "--region", REGION, "--secret-id", SECRET_ID, "--query", "SecretString", "--output", "text"], {
    timeoutMs: 30_000,
  });
  if (r.code !== 0) return { ok: false, code: awsErrorCode(r.stderr) };
  let data: unknown;
  try {
    data = JSON.parse(r.stdout.trim());
  } catch {
    return { ok: false, code: "secret is not JSON" };
  }
  if (data === null || typeof data !== "object" || Array.isArray(data)) return { ok: false, code: "secret is not a JSON object" };
  const fields: Record<string, Buffer> = {};
  for (const [k, v] of Object.entries(data as Record<string, unknown>)) {
    if (typeof v === "string" && /^[A-Za-z0-9+/]+={0,2}$/.test(v) && v.length % 4 === 0) fields[k] = Buffer.from(v, "base64");
  }
  return { ok: true, secret: { fields, names: Object.keys(data as object) } };
}

/** KMS ciphertext is binary. A key or a token pasted in plain text is mostly printable. */
export function looksLikeCiphertext(bytes: Uint8Array): boolean {
  if (bytes.length < 64) return false;
  let printable = 0;
  for (const b of bytes) if (b >= 0x20 && b < 0x7f) printable++;
  return printable / bytes.length < 0.85;
}

const KEY_NAME = /(airwallex|awx|x[-_]api[-_]key|ra[-_]shared[-_]secret)/i;
const KEY_KIND = /(key|secret|token)/i;
const KEY_LINE = /^\s*(?:export\s+)?([A-Z0-9_]*(?:AIRWALLEX|AWX)[A-Z0-9_]*(?:KEY|SECRET|TOKEN)[A-Z0-9_]*)\s*[=:]\s*["']?([^\s"'#,;]+)/gm;
const JSON_KEY = /"(x-api-key|api_key|apiKey|AIRWALLEX_API_KEY|AIRWALLEX_RA_SHARED_SECRET)"\s*:\s*"([^"]+)"/g;

/** A value that is a real secret, not an empty slot or a placeholder like <sandbox-api-key>. */
export function isRealValue(v: string): boolean {
  const t = v.trim();
  if (t.length < 16) return false;
  if (/^[<${[]/.test(t) || /^(SEAL_ME|changeme|xxx+|\*+|\[removed\])$/i.test(t)) return false;
  if (/^(process\.env|Bun\.env|env\.|os\.environ)/.test(t) || t.includes("(")) return false;
  return true;
}

/** Variable names in a file that hold what looks like an Airwallex key. Values are never returned. */
export function keyHitsInText(text: string): string[] {
  const hits = new Set<string>();
  for (const m of text.matchAll(KEY_LINE)) if (m[1] && m[2] && isRealValue(m[2])) hits.add(m[1]);
  for (const m of text.matchAll(JSON_KEY)) if (m[1] && m[2] && isRealValue(m[2])) hits.add(m[1]);
  return [...hits];
}

async function postJson(deps: HostDeps, path: string, body: unknown, headers: Record<string, string> = {}): Promise<{ status: number; json: unknown; text: string }> {
  const r = await deps.fetch(path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
  let json: unknown;
  try {
    json = JSON.parse(r.body);
  } catch {
    json = undefined;
  }
  return { status: r.status, json, text: r.body };
}

async function getState(deps: HostDeps): Promise<{ status: number; json: unknown }> {
  const r = await deps.fetch(ROUTES.state).catch(() => ({ status: 0, body: "" }));
  let json: unknown;
  try {
    json = JSON.parse(r.body);
  } catch {
    json = undefined;
  }
  return { status: r.status, json };
}

function pick(obj: unknown, path: string): unknown {
  let cur: unknown = obj;
  for (const k of path.split(".")) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[k];
  }
  return cur;
}

/** The chain head the enclave reports, whatever the /state field is called. */
export function stateHead(json: unknown): string | undefined {
  for (const p of ["head", "chainHead", "headHash", "ledgerHead", "chain.head", "ledger.head", "checkpoint.head"]) {
    const v = pick(json, p);
    if (typeof v === "string" && v.length > 0) return v;
  }
  return undefined;
}

export function stateUnverified(json: unknown): boolean {
  if (json === null || typeof json !== "object") return false;
  if (pick(json, "verified") === false || pick(json, "unverified") === true) return true;
  return JSON.stringify(json).includes("STATE_UNVERIFIED");
}

/** A writ for the baked team, signed by a key the enclave has never seen. */
export function forgedKeyWrit(deps: HostDeps): ApprovedTask {
  const now = deps.now();
  const id = `host-attack-${deps.uuid()}`;
  const p: WritProposal = {
    id,
    team: ATTACK_TEAM,
    agent: ATTACK_AGENT,
    runId: id,
    purpose: "Host attack: writ signed by a fresh random key",
    merchantName: "DataCo",
    mcc: "5734",
    amountMinor: 1_000,
    currency: "USD",
    expiresAt: new Date(now.getTime() + 10 * 60_000).toISOString(),
    nonce: hex(deps.randomBytes(16)),
  };
  return signWrit(p, now.toISOString(), generateApproverKeys().privateKeyPem);
}

function writVerdict(name: string, r: { status: number; json: unknown }, expected: readonly string[]): AttackResult {
  if (r.status === 404) return problem(name, `POST ${ROUTES.writs} answered HTTP 404, route not live, cannot show the refusal`);
  const status = pick(r.json, "status");
  const code = pick(r.json, "code");
  const armed = pick(r.json, "armed");
  if (status === "AUTHORIZED" || armed === true) return problem(name, `enclave answered ${String(status)} armed=${String(armed)}: disarm the card now`);
  if (status !== "DECLINED") return problem(name, `HTTP ${r.status} with no decline in the body, cannot show the refusal`);
  if (typeof code === "string" && expected.includes(code)) return failed(name, `HTTP ${r.status} DECLINED ${code}, no arm`);
  return problem(name, `DECLINED ${String(code)}, which is not ${expected.join(" or ")}, so this run does not show that check`);
}

// ---------------------------------------------------------------------------
// Attacks

/** 1. Find the Airwallex key in process env, on disk, or in Secrets Manager. */
export async function attackReadKey(deps: HostDeps): Promise<AttackResult> {
  const name = "read-key";
  const envHits: string[] = [];
  const procs = deps.processEnvs().filter((p) => p.pid !== deps.ownPid);
  for (const p of procs) {
    for (const kv of p.vars) {
      const eq = kv.indexOf("=");
      if (eq <= 0) continue;
      const k = kv.slice(0, eq);
      const v = kv.slice(eq + 1);
      if (KEY_NAME.test(k) && KEY_KIND.test(k) && isRealValue(v)) envHits.push(`pid ${p.pid} ${k}`);
    }
  }
  const fileHits: string[] = [];
  let files = 0;
  for (const root of SCAN_ROOTS) {
    for (const f of deps.walkFiles(root)) {
      const text = deps.readSmall(f, 1024 * 1024);
      if (text === undefined || text.includes("\u0000")) continue;
      files++;
      for (const k of keyHitsInText(text)) fileHits.push(`${f} ${k}`);
    }
  }
  const sealed = await fetchSealedSecret(deps);
  let secretNote: string;
  let secretBad = false;
  if (!sealed.ok) {
    secretNote = `Secrets Manager refused (${sealed.code})`;
  } else {
    const parts: string[] = [];
    for (const n of sealed.secret.names) {
      const blob = sealed.secret.fields[n];
      if (n === "clientId") parts.push("clientId (an identifier, not a key)");
      else if (blob && looksLikeCiphertext(blob)) parts.push(`${n} ${blob.length} bytes`);
      else secretBad = true;
    }
    for (const b of Object.values(sealed.secret.fields)) b.fill(0);
    secretNote = secretBad
      ? `Secrets Manager holds a field that is not KMS ciphertext (${sealed.secret.names.join(", ")})`
      : `Secrets Manager holds KMS ciphertext only: ${parts.join(", ") || "no fields"}`;
  }
  const scanned = `scanned env of ${procs.length} processes and ${files} files under ${SCAN_ROOTS.join(" ")}`;
  if (envHits.length > 0 || fileHits.length > 0 || secretBad) {
    const where = [...envHits, ...fileHits].slice(0, 5).join("; ");
    return problem(name, `${scanned}; key-shaped value found: ${where || "none on disk"}; ${secretNote}`);
  }
  return failed(name, `${scanned}: no Airwallex key; ${secretNote}`);
}

/** 2. Decrypt the sealed key with the instance role and no attestation. */
export async function attackKmsDecrypt(deps: HostDeps): Promise<AttackResult> {
  const name = "kms-decrypt";
  const sealed = await fetchSealedSecret(deps);
  if (!sealed.ok) return problem(name, `could not fetch the ciphertext to try (${sealed.code}), cannot show the refusal`);
  const targets = Object.entries(sealed.secret.fields).filter(([k]) => /ciphertext/i.test(k));
  if (targets.length === 0) return problem(name, "no ciphertext field in the secret, cannot show the refusal");
  const codes: string[] = [];
  let worked = false;
  for (const [field, blob] of targets) {
    const path = deps.writeTemp(blob);
    blob.fill(0);
    try {
      // --query KeyId keeps any plaintext off stdout even if KMS said yes.
      const r = await deps.exec(
        ["aws", "kms", "decrypt", "--region", REGION, "--key-id", KMS_KEY_ARN, "--ciphertext-blob", `fileb://${path}`, "--query", "KeyId", "--output", "text"],
        { timeoutMs: 30_000 },
      );
      if (r.code === 0) {
        worked = true;
        codes.push(`${field}: decrypt succeeded`);
      } else codes.push(`${field}: ${awsErrorCode(r.stderr)}`);
    } finally {
      deps.wipe(path);
    }
  }
  for (const b of Object.values(sealed.secret.fields)) b.fill(0);
  if (worked) return problem(name, codes.join(", "));
  if (codes.every((c) => /AccessDenied/.test(c))) return failed(name, codes.join(", "));
  return problem(name, `expected AccessDeniedException, got ${codes.join(", ")}`);
}

/** 3. Run the same EIF in debug mode and offer it the real boot line. */
export async function attackDebugUnseal(deps: HostDeps, opts: Options): Promise<AttackResult[]> {
  const name = "debug-unseal";
  if (!opts.withDebug) return [skipped(name, "needs --with-debug (terminates the production enclave and restarts it)")];
  const bootProblem = checkBootScript(deps, opts.bootScript);
  if (bootProblem) return [problem(name, `${bootProblem}; production left running, cannot run this attack`)];

  const before = await describe(deps);
  const prod = before.find((e) => e.state === "RUNNING");
  const sealed = await fetchSealedSecret(deps);
  if (!sealed.ok) return [problem(name, `could not fetch the ciphertext (${sealed.code}); production left running`)];
  const creds = await instanceCredentials(deps);
  if (!creds) return [problem(name, "could not read instance role credentials; production left running")];
  const blob = sealed.secret.fields.ciphertext;
  if (!blob) return [problem(name, "secret has no ciphertext field; production left running")];
  const payload: Record<string, string> = { ciphertextB64: b64(blob), ...creds };
  const ra = sealed.secret.fields.raCiphertext;
  if (ra) payload.raCiphertextB64 = b64(ra);
  for (const b of Object.values(sealed.secret.fields)) b.fill(0);
  const payloadPath = deps.writeTemp(`${JSON.stringify(payload)}\n`);
  for (const k of Object.keys(payload)) payload[k] = "";

  let feeder: { stop(): void } | undefined;
  let debugId = "";
  let debugInfo: EnclaveInfo | undefined;
  let reply = "";
  let consoleMark = "none";
  let consoleText = "";
  try {
    for (const e of before) await deps.exec(["nitro-cli", "terminate-enclave", "--enclave-id", e.id], { timeoutMs: 60_000 });
    deps.wipe(REPLY_LOG);
    feeder = deps.spawnBackground(["socat", "VSOCK-LISTEN:5000,reuseaddr", `EXEC:python3 ${UNSEAL_EXCHANGE} ${payloadPath}`]);
    // --attach-console streams the enclave console (debug mode only) until the enclave stops.
    let done = false;
    const running = deps.exec(debugRunArgv(), { timeoutMs: 90_000 }).finally(() => {
      done = true;
    });
    for (let i = 0; i < 40 && !debugInfo; i++) {
      debugInfo = (await describe(deps)).find((e) => isDebug(e.flags));
      if (debugInfo || done) break;
      await deps.sleep(500);
    }
    debugInfo ??= (await describe(deps)).find((e) => isDebug(e.flags));
    if (debugInfo) debugId = debugInfo.id;
    else if (!done) debugId = (await describe(deps)).find((e) => e.state === "RUNNING")?.id ?? "";
    for (let i = 0; i < 12 && !reply; i++) {
      reply = (deps.readSmall(REPLY_LOG, 4096) ?? "").trim();
      if (reply || done) break;
      await deps.sleep(2_500);
    }
    if (debugId && !done) await deps.exec(["nitro-cli", "terminate-enclave", "--enclave-id", debugId], { timeoutMs: 60_000 });
    const run = await running;
    debugId ||= /"EnclaveID"\s*:\s*"([^"]+)"/.exec(run.stdout)?.[1] ?? "";
    reply ||= (deps.readSmall(REPLY_LOG, 4096) ?? "").trim();
    consoleText = run.stdout;
    const mark = /\b(DECLINED [A-Z_]+|UNSEALED|ARMED)\b/.exec(consoleText);
    consoleMark = mark?.[1] ?? "none";
  } finally {
    feeder?.stop();
    deps.wipe(payloadPath);
    if (debugId) await deps.exec(["nitro-cli", "terminate-enclave", "--enclave-id", debugId], { timeoutMs: 60_000 });
  }
  const restart = await restartProduction(deps, opts);
  const replyMark = /^(UNSEALED|ARMED|DECLINED [A-Z_]+)/.exec(reply)?.[1] ?? "none";
  const restartLine = restart.ok
    ? failed("production-restart", `${restart.evidence}, PCR0 ${restart.info?.pcr0 ?? "unknown"}`)
    : problem("production-restart", restart.evidence);

  const prodFlags = prod ? prod.flags || "NONE" : "no production enclave was running";
  const opened = replyMark === "UNSEALED" || replyMark === "ARMED" || consoleMark === "UNSEALED" || consoleMark === "ARMED" || /\b(UNSEALED|ARMED)\b/.test(consoleText);
  const zeroInConsole = consoleText.includes("PCR is all zeros");
  const debugPcr = debugInfo ? (debugInfo.pcr0 === ZERO_PCR ? "all zeros" : debugInfo.pcr0) : zeroInConsole ? "all zeros (console)" : "not read";
  const evidence = `debug Flags ${debugInfo?.flags ?? "not read"}, debug PCR0 ${debugPcr}, vsock reply ${replyMark}, console ${consoleMark}${zeroInConsole ? ", writ-nsm-pcrs: PCR is all zeros" : ""}; production Flags ${prodFlags}`;
  if (opened) return [problem(name, `debug enclave unsealed: ${evidence}`), restartLine];
  const shownByDescribe = debugInfo !== undefined && isDebug(debugInfo.flags) && debugInfo.pcr0 === ZERO_PCR;
  const shownZero = shownByDescribe || consoleMark === "DECLINED PCR_ZERO" || zeroInConsole;
  if (!shownZero) return [problem(name, `could not show a debug enclave with zero PCRs, cannot show the refusal: ${evidence}`), restartLine];
  // This image refuses an all-zero PCR inside the enclave, before it asks KMS. The KMS pin is a separate fact.
  const why = zeroInConsole && consoleMark !== "DECLINED PCR_ZERO"
    ? "writ-nsm-pcrs refused an all-zero PCR and the enclave declined before unseal, so the debug image never asked KMS"
    : "KMS Decrypt needs ImageSha384 equal to the published PCR0, zeros never match";
  return [failed(name, `${evidence}; ${why}`), restartLine];
}

async function instanceCredentials(deps: HostDeps): Promise<{ accessKeyId: string; secretAccessKey: string; sessionToken: string } | undefined> {
  const base = "http://169.254.169.254/latest";
  const tok = await deps.exec(["curl", "-fsS", "-X", "PUT", `${base}/api/token`, "-H", "X-aws-ec2-metadata-token-ttl-seconds: 300"], { timeoutMs: 10_000 });
  if (tok.code !== 0) return undefined;
  const h = `X-aws-ec2-metadata-token: ${tok.stdout.trim()}`;
  const role = await deps.exec(["curl", "-fsS", "-H", h, `${base}/meta-data/iam/security-credentials/`], { timeoutMs: 10_000 });
  if (role.code !== 0) return undefined;
  const c = await deps.exec(["curl", "-fsS", "-H", h, `${base}/meta-data/iam/security-credentials/${role.stdout.trim()}`], { timeoutMs: 10_000 });
  if (c.code !== 0) return undefined;
  try {
    const j = JSON.parse(c.stdout) as Record<string, unknown>;
    if (typeof j.AccessKeyId !== "string" || typeof j.SecretAccessKey !== "string" || typeof j.Token !== "string") return undefined;
    return { accessKeyId: j.AccessKeyId, secretAccessKey: j.SecretAccessKey, sessionToken: j.Token };
  } catch {
    return undefined;
  }
}

/** 4. A writ signed by a fresh random key. */
export async function attackForgedKeyWrit(deps: HostDeps): Promise<AttackResult> {
  const r = await postJson(deps, ROUTES.writs, { writ: forgedKeyWrit(deps) });
  return writVerdict("writ-forged-key", r, ["WRIT_BAD_SIGNATURE"]);
}

/** 5. A real signed writ with its amount edited after signing. */
export async function attackEditedWrit(deps: HostDeps, opts: Options): Promise<AttackResult> {
  const name = "writ-edited-amount";
  if (!opts.signedWrit) return skipped(name, "needs --signed-writ <path> (a spare writ the real approver signed)");
  const text = deps.readSmall(opts.signedWrit, 64 * 1024);
  let writ: ApprovedTask | undefined;
  try {
    const raw = JSON.parse(text ?? "") as { writ?: unknown };
    const w = (raw && typeof raw === "object" && "writ" in raw ? raw.writ : raw) as ApprovedTask;
    if (w && typeof w.hash === "string" && typeof w.signature === "string" && w.signature !== "" && Number.isSafeInteger(w.amountMinor)) writ = w;
  } catch {
    writ = undefined;
  }
  if (!writ) return problem(name, `${opts.signedWrit} is not a signed writ, cannot run the attack`);
  const edited: ApprovedTask = { ...writ, amountMinor: writ.amountMinor + 10_000 };
  if (writHash(edited) === edited.hash) return problem(name, "edited writ still matches its hash, which should be impossible");
  const r = await postJson(deps, ROUTES.writs, { writ: edited });
  const v = writVerdict(name, r, ["WRIT_HASH_MISMATCH", "WRIT_BAD_SIGNATURE"]);
  return v.status === "FAILED" ? failed(name, `amount edited ${writ.amountMinor} to ${edited.amountMinor} cents: ${v.evidence}`) : v;
}

interface Checkpoint {
  key: string;
  seq: number;
}

async function listCheckpoints(deps: HostDeps, prefix: string): Promise<Checkpoint[] | undefined> {
  const r = await deps.exec(["aws", "s3api", "list-objects-v2", "--region", REGION, "--bucket", LEDGER_BUCKET, "--prefix", prefix, "--query", "Contents[].Key", "--output", "json"], {
    timeoutMs: 30_000,
  });
  if (r.code !== 0) return undefined;
  let keys: unknown;
  try {
    keys = JSON.parse(r.stdout.trim() || "null");
  } catch {
    return undefined;
  }
  if (!Array.isArray(keys)) return [];
  return keys
    .filter((k): k is string => typeof k === "string")
    .flatMap((key) => {
      const m = /(\d{12})\.json$/.exec(key);
      return m?.[1] ? [{ key, seq: Number(m[1]) }] : [];
    })
    .sort((a, b) => a.seq - b.seq);
}

async function headEtag(deps: HostDeps, key: string): Promise<string | undefined> {
  const r = await deps.exec(["aws", "s3api", "head-object", "--region", REGION, "--bucket", LEDGER_BUCKET, "--key", key, "--query", "ETag", "--output", "text"], { timeoutMs: 30_000 });
  const t = r.stdout.trim();
  return r.code === 0 && t && t !== "None" ? t : undefined;
}

function md5b64(body: string): string {
  return createHash("md5").update(body).digest("base64");
}

async function putIfAbsent(deps: HostDeps, key: string, body: string): Promise<ExecResult> {
  const path = deps.writeTemp(body);
  try {
    return await deps.exec(
      ["aws", "s3api", "put-object", "--region", REGION, "--bucket", LEDGER_BUCKET, "--key", key, "--body", path, "--content-md5", md5b64(body), "--content-type", "application/json", "--if-none-match", "*"],
      { timeoutMs: 30_000 },
    );
  } finally {
    deps.wipe(path);
  }
}

/** A checkpoint that chains onto the head with a correct hash and a random 64 byte signature. */
export function forgedCheckpoint(prevSeq: number, prevHead: string, at: number, sig: Uint8Array, uuid: string) {
  const seq = prevSeq + 1;
  const body = {
    seq,
    prev: prevHead,
    at,
    kind: "consume",
    payload: { eventId: `host-attack:${uuid}`, writId: `host-attack-${uuid}`, writHash: "0".repeat(64), cardId: uuid, amountMinor: 1, decision: "AUTHORIZED" },
  };
  const hash = entryHash(prevHead, body);
  const signature = b64(sig);
  return { seq, hash, object: { seq, head: hash, signature, entry: { ...body, hash, signature } } };
}

/** 6. Forge a ledger entry in the checkpoint prefix. */
export async function attackLedgerForge(deps: HostDeps, opts: Options): Promise<AttackResult[]> {
  const name = "ledger-forge";
  if (!opts.allowLedgerWrite) {
    return [skipped(name, `needs --allow-ledger-write: it writes one object under ${opts.checkpointPrefix} that Object Lock keeps for 30 days`)];
  }
  if (opts.withRestart) {
    const bootProblem = checkBootScript(deps, opts.bootScript);
    if (bootProblem) return [problem(name, `${bootProblem}; nothing written`)];
  }
  const before = await getState(deps);
  const headBefore = stateHead(before.json);
  if (before.status !== 200 || headBefore === undefined) {
    return [problem(name, `GET ${ROUTES.state} answered HTTP ${before.status} with no chain head, cannot compare; nothing written`)];
  }
  const list = await listCheckpoints(deps, opts.checkpointPrefix);
  if (list === undefined) return [problem(name, "could not list the checkpoint prefix; nothing written")];
  const last = list[list.length - 1];
  let prevSeq = 0;
  let prevHead = GENESIS_PREV;
  if (last) {
    const got = await deps.exec(["aws", "s3", "cp", `s3://${LEDGER_BUCKET}/${last.key}`, "-", "--region", REGION], { timeoutMs: 30_000 });
    try {
      const j = JSON.parse(got.stdout) as unknown;
      const h = pick(j, "head") ?? pick(j, "entry.hash") ?? pick(j, "hash");
      if (typeof h !== "string") throw new Error("no head");
      prevSeq = last.seq;
      prevHead = h;
    } catch {
      return [problem(name, `could not read ${last.key}; nothing written`)];
    }
  }
  const forged = forgedCheckpoint(prevSeq, prevHead, deps.now().getTime(), deps.randomBytes(64), deps.uuid());
  const key = `${opts.checkpointPrefix}${String(forged.seq).padStart(12, "0")}.json`;
  const put = await putIfAbsent(deps, key, JSON.stringify(forged.object));
  if (put.code !== 0) return [failed(name, `PutObject ${key} refused (${awsErrorCode(put.stderr)}), nothing forged`)];
  const etag = await headEtag(deps, key);
  const wrote = `wrote ${key} (seq ${forged.seq}, chains onto ${prevHead.slice(0, 12)}, random signature${etag ? ", head-object found it" : ""})`;

  if (!opts.withRestart) {
    const after = await getState(deps);
    const headAfter = stateHead(after.json);
    if (headAfter === forged.hash) return [problem(name, `${wrote}; running enclave now reports the forged head`)];
    if (headAfter === headBefore) return [failed(name, `${wrote}; running enclave still reports head ${headBefore.slice(0, 12)}`)];
    return [problem(name, `${wrote}; GET ${ROUTES.state} head changed or went missing, cannot show the forge was ignored`)];
  }

  const restart = await restartProduction(deps, opts);
  const restartLine = restart.ok ? failed("production-restart", restart.evidence) : problem("production-restart", restart.evidence);
  if (!restart.ok) return [problem(name, `${wrote}; enclave did not come back, cannot check`), restartLine];
  const after = await getState(deps);
  if (stateUnverified(after.json)) return [failed(name, `${wrote}; after restart GET ${ROUTES.state} reports STATE_UNVERIFIED`), restartLine];
  const probe = await postJson(deps, ROUTES.writs, { writ: forgedKeyWrit(deps) });
  if (pick(probe.json, "code") === "STATE_UNVERIFIED") return [failed(name, `${wrote}; after restart the next decision is STATE_UNVERIFIED`), restartLine];
  const headAfter = stateHead(after.json);
  if (headAfter === forged.hash) return [problem(name, `${wrote}; after restart the enclave accepted the forged head`), restartLine];
  return [problem(name, `${wrote}; after restart state is not unverified and the next decision was ${String(pick(probe.json, "code"))}`), restartLine];
}

/** 7. Delete, overwrite or shorten the lock on an existing checkpoint. */
export async function attackCheckpointTamper(deps: HostDeps, opts: Options): Promise<AttackResult> {
  const name = "checkpoint-delete-overwrite";
  const list = (await listCheckpoints(deps, opts.checkpointPrefix)) ?? [];
  const key = list[0]?.key ?? LEGACY_CHECKPOINT_KEY;
  const etag = await headEtag(deps, key);
  if (!etag) return problem(name, `no checkpoint to attack (${key} not found), cannot show the refusal`);
  const versions = await deps.exec(["aws", "s3api", "list-object-versions", "--region", REGION, "--bucket", LEDGER_BUCKET, "--prefix", key, "--output", "json"], { timeoutMs: 30_000 });
  let versionId = "";
  try {
    const v = JSON.parse(versions.stdout) as { Versions?: { Key?: string; VersionId?: string; IsLatest?: boolean }[] };
    versionId = v.Versions?.find((x) => x.Key === key && x.IsLatest)?.VersionId ?? "";
  } catch {
    versionId = "";
  }
  const base = ["aws", "s3api"];
  const tail = ["--region", REGION, "--bucket", LEDGER_BUCKET, "--key", key];
  const outcomes: string[] = [];
  let worked = false;
  const del = await deps.exec([...base, "delete-object", ...tail], { timeoutMs: 30_000 });
  outcomes.push(`delete ${del.code === 0 ? "accepted" : awsErrorCode(del.stderr)}`);
  if (del.code === 0) worked = true;
  if (versionId) {
    const delv = await deps.exec([...base, "delete-object", ...tail, "--version-id", versionId], { timeoutMs: 30_000 });
    outcomes.push(`delete version ${delv.code === 0 ? "accepted" : awsErrorCode(delv.stderr)}`);
    if (delv.code === 0) worked = true;
    const until = new Date(deps.now().getTime() + 60_000).toISOString();
    const ret = await deps.exec([...base, "put-object-retention", ...tail, "--version-id", versionId, "--retention", `Mode=GOVERNANCE,RetainUntilDate=${until}`], { timeoutMs: 30_000 });
    outcomes.push(`shorten lock ${ret.code === 0 ? "accepted" : awsErrorCode(ret.stderr)}`);
    if (ret.code === 0) worked = true;
  }
  const put = await putIfAbsent(deps, key, JSON.stringify({ attack: "overwrite", at: deps.now().toISOString() }));
  outcomes.push(`overwrite ${put.code === 0 ? "accepted" : awsErrorCode(put.stderr)}`);
  if (put.code === 0) worked = true;
  const after = await headEtag(deps, key);
  if (after !== etag) worked = true;
  const summary = `${key}: ${outcomes.join(", ")}; etag ${after === etag ? "unchanged" : "changed"}`;
  return worked ? problem(name, summary) : failed(name, summary);
}

function raBody(eventId: string): string {
  return JSON.stringify({
    card_transaction_event_id: eventId,
    transaction_type: "AUTHORIZATION",
    card_id: "00000000-0000-4000-8000-000000000000",
    transaction_amount: 1999,
    transaction_currency: "USD",
    merchant: { name: "Unknown Merchant", category_code: "5999" },
  });
}

function raHeaders(deps: HostDeps): Record<string, string> {
  return { "x-nonce": `${deps.now().getTime()}.${hex(deps.randomBytes(16))}`, "x-signature": b64(deps.randomBytes(32)) };
}

/** 8. Remote Authorization with a guessed signature and a fresh nonce. */
export async function attackRaGuess(deps: HostDeps): Promise<AttackResult> {
  const name = "ra-guessed-signature";
  const r = await deps.fetch(ROUTES.remoteAuth, { method: "POST", headers: { "content-type": "application/json", ...raHeaders(deps) }, body: raBody(`host-attack-${deps.uuid()}`) });
  let j: unknown;
  try {
    j = JSON.parse(r.body);
  } catch {
    j = undefined;
  }
  const status = pick(j, "response_status");
  const reason = pick(j, "status_reason");
  if (status === "AUTHORIZED") return problem(name, `HTTP ${r.status} AUTHORIZED`);
  if (r.status === 200 && status === "DECLINED" && reason === "bad signature") return failed(name, `HTTP 200 DECLINED "bad signature"`);
  return problem(name, `HTTP ${r.status} ${String(status)} "${String(reason)}", expected DECLINED "bad signature"`);
}

const PLAINTEXT_NEEDLES = ["POST /", "GET /", "HTTP/1.1", "card_transaction_event_id", "x-signature", "x-nonce"];

/** True when the bytes hold a TLS record header and none of the plaintext needles. */
export function captureIsCiphertext(bytes: Uint8Array, marker: string): { ok: boolean; tls: boolean; found: string[] } {
  const text = Buffer.from(bytes).toString("latin1");
  const found = [...PLAINTEXT_NEEDLES, marker].filter((n) => text.includes(n));
  const tls = text.includes("\u0016\u0003");
  return { ok: tls && found.length === 0, tls, found };
}

/** 9. What the host relay carries for one attestation GET and one RA POST. */
export async function attackRaCapture(deps: HostDeps): Promise<AttackResult> {
  const name = "ra-capture";
  const marker = `host-attack-${deps.uuid()}`;
  const statuses: string[] = [];
  const bytes = await deps.tee(async (port) => {
    const origin = `https://${PUBLIC_HOST}:${port}`;
    const common = ["curl", "-sS", "-k", "--max-time", "15", "--resolve", `${PUBLIC_HOST}:${port}:127.0.0.1`, "-o", "/dev/null", "-w", "%{http_code}"];
    const g = await deps.exec([...common, `${origin}${ROUTES.attestation}?nonce=${hex(deps.randomBytes(32))}`], { timeoutMs: 20_000 });
    statuses.push(g.stdout.trim() || "none");
    const h = raHeaders(deps);
    const p = await deps.exec(
      [...common, "-X", "POST", "-H", "content-type: application/json", "-H", `x-nonce: ${h["x-nonce"]}`, "-H", `x-signature: ${h["x-signature"]}`, "--data-binary", "@-", `${origin}${ROUTES.remoteAuth}`],
      { timeoutMs: 20_000, stdin: raBody(marker) },
    );
    statuses.push(p.stdout.trim() || "none");
  });
  const check = captureIsCiphertext(bytes, marker);
  const size = bytes.length;
  bytes.fill(0);
  const evidence = `${size} bytes relayed, GET attestation HTTP ${statuses[0] ?? "none"}, POST remote-auth HTTP ${statuses[1] ?? "none"}`;
  if (check.found.length > 0) return problem(name, `${evidence}; plaintext seen: ${check.found.join(", ")}`);
  if (!check.tls || statuses.some((s) => s !== "200")) return problem(name, `${evidence}; cannot show the capture is a full TLS exchange`);
  return failed(name, `${evidence}; TLS records only, no "POST /", "HTTP/1.1" or card_transaction_event_id; capture deleted`);
}

/** 10. Read enclave memory from the host. */
export async function attackEnclaveMemory(deps: HostDeps): Promise<AttackResult> {
  const name = "enclave-memory";
  const prod = (await describe(deps)).find((e) => e.state === "RUNNING");
  if (!prod) return problem(name, "no running enclave, cannot show the refusal");
  if (isDebug(prod.flags)) return problem(name, `the running enclave has Flags ${prod.flags}: its console is readable`);
  const con = await deps.exec(["nitro-cli", "console", "--enclave-id", prod.id, "--disconnect-timeout", "5"], { timeoutMs: 20_000 });
  const mem = deps.readDevMem(0x4000_0000, 4096);
  const parts = [`nitro-cli console ${con.code === 0 ? "connected" : `refused (exit ${con.code})`}`, `/dev/mem read ${mem.ok ? "allowed" : `refused (${mem.code})`}`];
  const evidence = `enclave Flags ${prod.flags || "NONE"}: ${parts.join(", ")}`;
  return con.code !== 0 && !mem.ok ? failed(name, evidence) : problem(name, evidence);
}

// ---------------------------------------------------------------------------
// Run

export interface RunOutput {
  results: AttackResult[];
  exitCode: number;
  save?: SaveRecord;
}

export interface SaveRecord {
  at: string;
  atIso: string;
  host: string;
  pcr0: string;
  flags: string;
  enclaveId: string;
  options: { withDebug: boolean; withRestart: boolean; allowLedgerWrite: boolean; signedWrit: boolean };
  lines: string[];
  exitCode: number;
}

async function guarded<T>(name: string, fn: () => Promise<T>): Promise<T | AttackResult> {
  try {
    return await fn();
  } catch (err) {
    return problem(name, `attack code threw (${err instanceof Error ? err.name : "error"}), cannot show the refusal`);
  }
}

export async function runAll(deps: HostDeps, opts: Options, print: (line: string) => void = (l) => console.log(l)): Promise<RunOutput> {
  const results: AttackResult[] = [];
  const add = (r: AttackResult | AttackResult[]) => {
    for (const x of Array.isArray(r) ? r : [r]) {
      results.push(x);
      print(formatLine(x));
    }
  };
  add(await guarded("read-key", () => attackReadKey(deps)));
  add(await guarded("kms-decrypt", () => attackKmsDecrypt(deps)));
  add(await guarded("enclave-memory", () => attackEnclaveMemory(deps)));
  add(await guarded("ra-guessed-signature", () => attackRaGuess(deps)));
  add(await guarded("ra-capture", () => attackRaCapture(deps)));
  add(await guarded("writ-forged-key", () => attackForgedKeyWrit(deps)));
  add(await guarded("writ-edited-amount", () => attackEditedWrit(deps, opts)));
  add(await guarded("checkpoint-delete-overwrite", () => attackCheckpointTamper(deps, opts)));
  add(await guarded("ledger-forge", () => attackLedgerForge(deps, opts)));
  add(await guarded("debug-unseal", () => attackDebugUnseal(deps, opts)));

  const exitCode = exitCodeFor(results);
  const out: RunOutput = { results, exitCode };
  if (opts.save) {
    const prod = (await describe(deps)).find((e) => e.state === "RUNNING");
    const now = deps.now();
    out.save = {
      at: istLabel(now),
      atIso: now.toISOString(),
      host: PUBLIC_HOST,
      pcr0: prod && /^[0-9a-f]{96}$/.test(prod.pcr0) ? prod.pcr0 : "unknown",
      flags: prod ? prod.flags || "NONE" : "no running enclave",
      enclaveId: prod?.id ?? "",
      options: { withDebug: opts.withDebug, withRestart: opts.withRestart, allowLedgerWrite: opts.allowLedgerWrite, signedWrit: opts.signedWrit !== undefined },
      lines: results.map(formatLine),
      exitCode,
    };
  }
  return out;
}

export function parseArgs(argv: readonly string[]): Options | string {
  const opts: Options = { withDebug: false, withRestart: false, allowLedgerWrite: false, bootScript: BOOT_SCRIPT, checkpointPrefix: CHECKPOINT_PREFIX };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    const value = () => {
      const v = argv[++i];
      if (v === undefined || v.startsWith("--")) throw new Error(`${a} needs a value`);
      return v;
    };
    try {
      if (a === "--with-debug") opts.withDebug = true;
      else if (a === "--with-restart") opts.withRestart = true;
      else if (a === "--allow-ledger-write") opts.allowLedgerWrite = true;
      else if (a === "--signed-writ") opts.signedWrit = value();
      else if (a === "--save") opts.save = value();
      else if (a === "--boot-script") opts.bootScript = value();
      else if (a === "--checkpoint-prefix") opts.checkpointPrefix = value().replace(/^\/+/, "").replace(/\/*$/, "/");
      else return `unknown argument ${a}`;
    } catch (err) {
      return err instanceof Error ? err.message : "bad argument";
    }
    if (a !== "--with-debug" && /debug/i.test(argv[i] ?? "")) return "refusing: debug may only be asked for with --with-debug";
  }
  if (opts.withRestart && !opts.allowLedgerWrite) return "--with-restart only applies to the ledger forge, which needs --allow-ledger-write";
  return opts;
}

// ---------------------------------------------------------------------------
// Real host dependencies

const realExec: Exec = async (argv, opts = {}) => {
  const proc = Bun.spawn([...argv], { stdin: opts.stdin !== undefined ? new TextEncoder().encode(opts.stdin) : "ignore", stdout: "pipe", stderr: "pipe", env: process.env });
  const timer = setTimeout(() => proc.kill(), opts.timeoutMs ?? 60_000);
  try {
    const [stdout, stderr, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);
    return { code, stdout, stderr };
  } finally {
    clearTimeout(timer);
  }
};

const STATUS_MARK = "\n__writ_http_status__";

/** HTTPS to the enclave through the host's own 443 relay, with the public name so SNI and the cert line up. */
export function curlFetch(exec: Exec): Fetch {
  return async (path, init = {}) => {
    const argv = ["curl", "-sS", "--max-time", "15", "--resolve", `${PUBLIC_HOST}:443:127.0.0.1`, "-X", init.method ?? "GET", "-w", `${STATUS_MARK}%{http_code}`];
    for (const [k, v] of Object.entries(init.headers ?? {})) argv.push("-H", `${k}: ${v}`);
    const execOpts: ExecOptions = { timeoutMs: 20_000 };
    if (init.body !== undefined) {
      argv.push("--data-binary", "@-");
      execOpts.stdin = init.body;
    }
    argv.push(`https://${PUBLIC_HOST}${path}`);
    const r = await exec(argv, execOpts);
    const at = r.stdout.lastIndexOf(STATUS_MARK);
    if (at === -1) return { status: 0, body: "" };
    return { status: Number(r.stdout.slice(at + STATUS_MARK.length).trim()) || 0, body: r.stdout.slice(0, at) };
  };
}

const SKIP_DIRS = new Set(["node_modules", ".git", "proc", "sys"]);

function walk(root: string, limit = 200_000): string[] {
  const out: string[] = [];
  const stack = [root];
  while (stack.length > 0 && out.length < limit) {
    const dir = stack.pop()!;
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch {
      continue;
    }
    for (const n of names) {
      const p = join(dir, n);
      let st;
      try {
        st = lstatSync(p);
      } catch {
        continue;
      }
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(n)) stack.push(p);
      } else if (st.isFile()) out.push(p);
    }
  }
  return out;
}

function realTee(fn: (port: number) => Promise<void>): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  const sockets: Socket[] = [];
  const server = createServer((client) => {
    const upstream = createConnection({ host: "127.0.0.1", port: 443 });
    sockets.push(client, upstream);
    client.on("data", (d: Buffer) => {
      chunks.push(Buffer.from(d));
      upstream.write(d);
    });
    upstream.on("data", (d: Buffer) => {
      chunks.push(Buffer.from(d));
      client.write(d);
    });
    client.on("close", () => upstream.destroy());
    upstream.on("close", () => client.destroy());
    client.on("error", () => upstream.destroy());
    upstream.on("error", () => client.destroy());
  });
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", async () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      try {
        await fn(port);
      } catch (err) {
        reject(err);
      } finally {
        for (const s of sockets) s.destroy();
        server.close();
        const all = new Uint8Array(Buffer.concat(chunks));
        for (const c of chunks) c.fill(0);
        resolve(all);
      }
    });
  });
}

export function realDeps(): HostDeps {
  const dir = mkdtempSync(join(tmpdir(), "writ-host-attack-"));
  chmodSync(dir, 0o700);
  return {
    exec: realExec,
    fetch: curlFetch(realExec),
    spawnBackground(argv) {
      const p = Bun.spawn([...argv], { stdin: "ignore", stdout: "ignore", stderr: "ignore" });
      return { stop: () => p.kill() };
    },
    processEnvs() {
      const out: { pid: number; vars: string[] }[] = [];
      let pids: string[] = [];
      try {
        pids = readdirSync("/proc").filter((n) => /^\d+$/.test(n));
      } catch {
        return out;
      }
      for (const pid of pids) {
        try {
          out.push({ pid: Number(pid), vars: readFileSync(`/proc/${pid}/environ`, "utf8").split("\u0000").filter(Boolean) });
        } catch {
          // process ended or kernel thread
        }
      }
      return out;
    },
    walkFiles: (root) => walk(root),
    readSmall(path, maxBytes) {
      try {
        if (statSync(path).size > maxBytes) return undefined;
        return readFileSync(path, "utf8");
      } catch {
        return undefined;
      }
    },
    writeTemp(data) {
      const p = join(dir, randomUUID());
      writeFileSync(p, data, { mode: 0o600 });
      return p;
    },
    wipe(path) {
      try {
        const n = statSync(path).size;
        writeFileSync(path, Buffer.alloc(n));
      } catch {
        // missing is fine
      }
      rmSync(path, { force: true });
    },
    readDevMem(offset, length) {
      let fd: number | undefined;
      try {
        fd = openSync("/dev/mem", "r");
        const buf = Buffer.alloc(length);
        readSync(fd, buf, 0, length, offset);
        buf.fill(0);
        return { ok: true };
      } catch (err) {
        return { ok: false, code: (err as { code?: string }).code ?? "error" };
      } finally {
        if (fd !== undefined) closeSync(fd);
      }
    },
    tee: realTee,
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    now: () => new Date(),
    randomBytes: (n) => new Uint8Array(nodeRandomBytes(n)),
    uuid: () => randomUUID(),
    ownPid: process.pid,
  };
}

/** Instance role only. A key carried in the environment is not the host-root attack. */
function useInstanceRole(): void {
  for (const k of [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_ROLE_ARN",
  ]) {
    delete process.env[k];
  }
  process.env.AWS_SHARED_CREDENTIALS_FILE = "/var/lib/writ/host-attack-no-credentials";
  process.env.AWS_CONFIG_FILE = "/var/lib/writ/host-attack-no-config";
  process.env.AWS_REGION = REGION;
  process.env.AWS_DEFAULT_REGION = REGION;
  process.env.AWS_PAGER = "";
  if (!process.env.NITRO_CLI_ARTIFACTS) process.env.NITRO_CLI_ARTIFACTS = "/usr/share/nitro_enclaves/blobs";
}

async function main(): Promise<number> {
  const opts = parseArgs(process.argv.slice(2));
  if (typeof opts === "string") {
    console.error(opts);
    return 2;
  }
  if (process.getuid?.() !== 0) {
    console.error("Refusing to run: run it as root on the enclave host.");
    return 2;
  }
  useInstanceRole();
  const out = await runAll(realDeps(), opts);
  if (opts.save && out.save) {
    writeFileSync(opts.save, `${JSON.stringify(out.save, null, 2)}\n`, { mode: 0o644 });
    console.log(`saved ${opts.save}`);
  }
  console.log(out.exitCode === 0 ? "every attack failed" : "at least one attack was not shown to fail");
  return out.exitCode;
}

if (import.meta.main) {
  process.exitCode = await main();
}
