// Verifies an AWS Nitro Enclaves attestation document against the PCRs we published.
//
//   bun run scripts/verify-attestation.ts <document.cbor> <nonce-hex> [--save <path>]
//   bun run scripts/verify-attestation.ts --url https://host --ledger-key <key> [--allow-untrusted-ca] [--save <path>]
//
// File mode: <document.cbor> is the raw COSE_Sign1 bytes the NSM returned for our nonce.
// <nonce-hex> is the nonce we sent, at least 32 bytes (64 hex characters).
//
// URL mode: the script makes a 32 byte nonce, fetches GET /attestation?nonce=<hex> over one TLS
// connection, and reads the server leaf certificate from that same connection. user_data must
// bind the ledger key and that certificate. The binding is either sha256(canonical JSON of
// {ledgerPublicKey, raUrl, rung, spkiSha256}) or that canonical JSON itself. raUrl is the URL
// origin. spkiSha256 is the sha256 of the certificate SubjectPublicKeyInfo. The rung is printed
// from the document, or from the preimage whose hash matches. The running image may still hash
// the label R1 while src/host/enclave-tls.ts says R2. This script reports whichever matched.
// --allow-untrusted-ca accepts a certificate outside the system CA store. The SPKI binding still holds.
//
// Expected PCR0, PCR1 and PCR2 come from enclave/PCR0.txt, PCR1.txt and PCR2.txt.
// Each is printed with MATCH or MISMATCH. A missing file, a mismatch, or 96 zero hex characters
// fails the run. The report also prints the document timestamp in IST, the nonce check, the
// certificate chain result against the pinned AWS Nitro root, and the user_data fields.
// AWS is in the trust root.
//
// Exit 0 only when every check matches. On failure the report goes to stderr and stdout stays
// empty, then a line `attestation refused: CODE: message`. The raw document is not printed.
// --save writes the same result as JSON, including the document as base64. That file is public.
// It must not contain a private key or an API secret.

import { createHash, randomBytes, timingSafeEqual, type X509Certificate } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { isIP } from "node:net";
import { join } from "node:path";
import { connect, type TLSSocket } from "node:tls";
import {
  AWS_NITRO_ROOT_G1_SHA256,
  MAX_DOCUMENT_BYTES,
  MIN_NONCE_BYTES,
  parseCoseSign1,
  parsePayload,
  verifyAttestation,
  verifyChain,
  verifyCoseSignature,
  type AttestationPayload,
  type CoseSign1,
} from "../src/attest/verify";
import { canonicalJson } from "../src/core/writ";
import { certSpkiSha256, RUNG } from "../src/host/enclave-tls";

const ENCLAVE_DIR = join(import.meta.dir, "..", "enclave");
const FETCH_TIMEOUT_MS = 10_000;
const FILE_USAGE = "usage: verify-attestation <document.cbor> <nonce-hex> [--save <path>]";
const URL_USAGE = "usage: verify-attestation --url https://host --ledger-key <key> [--allow-untrusted-ca] [--save <path>]";
const ZERO_PCR = "0".repeat(96);
const HEX96 = /^[0-9a-f]{96}$/;

export interface Failure {
  code: string;
  message: string;
}

export interface PcrJudgement {
  status: "MATCH" | "MISMATCH";
  document: string | null;
  expected: string | null;
  detail: "all zeros" | "missing" | "malformed" | "differs" | null;
}

export interface UserFields {
  ledgerPublicKey: string;
  raUrl: string;
  rung: string;
  spkiSha256: string;
}

type UserEncoding = "canonical-json" | "sha256" | "absent" | "unrecognized";

export interface BindingJudgement {
  encoding: UserEncoding;
  fields: UserFields | null;
  fieldsFrom: "document" | "preimage" | null;
  ledgerKey: "MATCH" | "MISMATCH" | "NOT_CHECKED";
  spki: "MATCH" | "MISMATCH" | "NOT_CHECKED";
  ok: boolean;
  code: string | null;
  message: string | null;
}

export interface SaveReport {
  ok: boolean;
  code: string | null;
  message: string | null;
  pcr0: PcrJudgement;
  pcr1: PcrJudgement;
  pcr2: PcrJudgement;
  timestamp: string | null;
  timestampMs: number | null;
  nonce: "MATCH" | "MISMATCH" | "MISSING" | "TOO_SHORT" | "NOT_CHECKED";
  certificateChain: "MATCH" | "MISMATCH" | "FAIL";
  certificateChainDetail: string;
  signature: "MATCH" | "MISMATCH" | "NOT_CHECKED";
  pinnedRootSha256: string;
  userData: {
    encoding: UserEncoding;
    fieldsFrom: "document" | "preimage" | null;
    ledgerPublicKey: string | null;
    raUrl: string | null;
    rung: string | null;
    spkiSha256: string | null;
  };
  ledgerKey: "MATCH" | "MISMATCH" | "NOT_CHECKED";
  spki: "MATCH" | "MISMATCH" | "NOT_CHECKED";
  observed: {
    ledgerPublicKey: string | null;
    raUrl: string | null;
    spkiSha256: string | null;
  };
  moduleId: string | null;
  nonceHex: string;
  documentBase64: string;
}

export interface RunOptions {
  enclaveDir?: string;
  now?: () => number;
  log?: (line: string) => void;
  error?: (line: string) => void;
}

interface ExpectedFile {
  hex: string | null;
  code: "PCR_MISSING" | "PCR_MALFORMED" | "PCR_ZERO" | null;
  message: string | null;
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

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Same bytes computeUserData returns, for any rung label. computeUserData itself only accepts RUNG. */
function userDataHash(fields: UserFields): Uint8Array {
  const json = canonicalJson({
    ledgerPublicKey: fields.ledgerPublicKey,
    raUrl: fields.raUrl,
    rung: fields.rung,
    spkiSha256: fields.spkiSha256,
  });
  return new Uint8Array(createHash("sha256").update(json).digest());
}

function sameText(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function normHex(hex: string | null): string | null {
  if (hex === null) return null;
  const trimmed = hex.trim().toLowerCase();
  return trimmed === "" ? null : trimmed;
}

/** Byte compare of one PCR. 96 zero hex characters is never a match. */
export function judgePcr(documentHex: string | null, expectedHex: string | null): PcrJudgement {
  const document = normHex(documentHex);
  const expected = normHex(expectedHex);
  if (document === null || expected === null) return { status: "MISMATCH", document, expected, detail: "missing" };
  if (document === ZERO_PCR || expected === ZERO_PCR) return { status: "MISMATCH", document, expected, detail: "all zeros" };
  if (!HEX96.test(document) || !HEX96.test(expected)) return { status: "MISMATCH", document, expected, detail: "malformed" };
  if (document !== expected) return { status: "MISMATCH", document, expected, detail: "differs" };
  return { status: "MATCH", document, expected, detail: null };
}

export function readExpectedPcr(dir: string, n: 0 | 1 | 2): ExpectedFile {
  let text: string;
  try {
    text = readFileSync(join(dir, `PCR${n}.txt`), "utf8");
  } catch {
    return { hex: null, code: "PCR_MISSING", message: `cannot read PCR${n}.txt` };
  }
  const hex = text.trim().toLowerCase();
  if (hex === "") return { hex: null, code: "PCR_MISSING", message: `cannot read PCR${n}.txt` };
  if (!HEX96.test(hex)) return { hex, code: "PCR_MALFORMED", message: `PCR${n} is not 96 lowercase hex characters` };
  if (hex === ZERO_PCR) return { hex, code: "PCR_ZERO", message: `PCR${n} is all zeros, which is debug mode or a missing measurement` };
  return { hex, code: null, message: null };
}

function firstFileError(files: readonly ExpectedFile[]): Failure | null {
  for (const file of files) {
    if (file.code !== null && file.message !== null) return { code: file.code, message: file.message };
  }
  return null;
}

/** user_data is either 32 byte sha256 or canonical JSON of the four binding fields. */
export function decodeUserData(bytes: Uint8Array | null): { encoding: UserEncoding; fields: UserFields | null } {
  if (!bytes || bytes.length === 0) return { encoding: "absent", fields: null };
  if (bytes.length === 32) return { encoding: "sha256", fields: null };
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return { encoding: "unrecognized", fields: null };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { encoding: "unrecognized", fields: null };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return { encoding: "unrecognized", fields: null };
  let canonical: string;
  try {
    canonical = canonicalJson(parsed);
  } catch {
    return { encoding: "unrecognized", fields: null };
  }
  if (canonical !== text) return { encoding: "unrecognized", fields: null };
  const obj = parsed as Record<string, unknown>;
  const keys = Object.keys(obj).sort().join(",");
  if (keys !== "ledgerPublicKey,raUrl,rung,spkiSha256") return { encoding: "unrecognized", fields: null };
  const ledgerPublicKey = obj.ledgerPublicKey;
  const raUrl = obj.raUrl;
  const rung = obj.rung;
  const spkiSha256 = obj.spkiSha256;
  if (typeof ledgerPublicKey !== "string" || ledgerPublicKey.length === 0) return { encoding: "unrecognized", fields: null };
  if (typeof raUrl !== "string" || raUrl.length === 0) return { encoding: "unrecognized", fields: null };
  if (typeof rung !== "string" || rung.length === 0) return { encoding: "unrecognized", fields: null };
  if (typeof spkiSha256 !== "string" || spkiSha256.length === 0) return { encoding: "unrecognized", fields: null };
  return { encoding: "canonical-json", fields: { ledgerPublicKey, raUrl, rung, spkiSha256 } };
}

export function judgeBinding(input: {
  userData: Uint8Array | null;
  ledgerPublicKey: string | null;
  spkiSha256: string | null;
  raUrl: string | null;
  check: boolean;
}): BindingJudgement {
  const decoded = decodeUserData(input.userData);
  const fieldsFrom: "document" | "preimage" | null = decoded.encoding === "canonical-json" ? "document" : null;
  if (!input.check) {
    return {
      encoding: decoded.encoding,
      fields: decoded.fields,
      fieldsFrom,
      ledgerKey: "NOT_CHECKED",
      spki: "NOT_CHECKED",
      ok: true,
      code: null,
      message: null,
    };
  }

  const base = {
    encoding: decoded.encoding,
    fields: decoded.fields,
    fieldsFrom,
  };

  if (!input.spkiSha256) {
    return { ...base, ledgerKey: "MISMATCH", spki: "MISMATCH", ok: false, code: "SPKI_MISMATCH", message: "peer certificate does not parse" };
  }
  if (!input.ledgerPublicKey) {
    return { ...base, ledgerKey: "MISMATCH", spki: "MISMATCH", ok: false, code: "LEDGER_KEY_MISMATCH", message: "ledger key was not given" };
  }
  if (!input.raUrl) {
    return { ...base, ledgerKey: "MISMATCH", spki: "MISMATCH", ok: false, code: "USER_DATA_MISMATCH", message: "RA URL was not given" };
  }

  if (decoded.encoding === "sha256" && input.userData) {
    // R1 is the label the image still hashes. RUNG is the source constant.
    const rungs: string[] = [RUNG, "R1"];
    for (const rung of rungs) {
      const fields: UserFields = { ledgerPublicKey: input.ledgerPublicKey, raUrl: input.raUrl, rung, spkiSha256: input.spkiSha256 };
      if (sameBytes(input.userData, userDataHash(fields))) {
        return {
          encoding: "sha256",
          fields,
          fieldsFrom: "preimage",
          ledgerKey: "MATCH",
          spki: "MATCH",
          ok: true,
          code: null,
          message: null,
        };
      }
    }
    return {
      encoding: "sha256",
      fields: null,
      fieldsFrom: null,
      ledgerKey: "MISMATCH",
      spki: "MISMATCH",
      ok: false,
      code: "SPKI_MISMATCH",
      message: "user_data does not bind the certificate SPKI and the ledger key",
    };
  }

  if (decoded.encoding === "canonical-json" && decoded.fields) {
    const fields = decoded.fields;
    const ledgerKey = sameText(fields.ledgerPublicKey, input.ledgerPublicKey) ? "MATCH" : "MISMATCH";
    const spki = sameText(fields.spkiSha256.toLowerCase(), input.spkiSha256.toLowerCase()) ? "MATCH" : "MISMATCH";
    const raOk = sameText(fields.raUrl, input.raUrl);
    let code: string | null = null;
    let message: string | null = null;
    if (spki !== "MATCH") {
      code = "SPKI_MISMATCH";
      message = "user_data spkiSha256 does not match the certificate SPKI";
    } else if (ledgerKey !== "MATCH") {
      code = "LEDGER_KEY_MISMATCH";
      message = "user_data does not bind the ledger key";
    } else if (!raOk) {
      code = "USER_DATA_MISMATCH";
      message = "user_data raUrl does not match the URL we fetched";
    }
    return { encoding: "canonical-json", fields, fieldsFrom: "document", ledgerKey, spki, ok: code === null, code, message };
  }

  return {
    ...base,
    fields: null,
    fieldsFrom: null,
    ledgerKey: "MISMATCH",
    spki: "MISMATCH",
    ok: false,
    code: "SPKI_MISMATCH",
    message: decoded.encoding === "absent" ? "document carries no user_data" : "user_data is not the sha256 binding or canonical JSON",
  };
}

/** First failure wins: published PCR file, then the verifier, then the user_data binding. Exit 0 only when this returns null. */
export function decideFailure(input: {
  file: Failure | null;
  verified: { ok: true } | { ok: false; code: string; message: string } | null;
  checkBinding: boolean;
  binding: Failure | null;
  pcrsMatch: boolean;
  nonceMatch: boolean;
  chainMatch: boolean;
  signatureMatch: boolean;
}): Failure | null {
  if (input.file) return input.file;
  if (!input.verified) return { code: "VERIFIER_ERROR", message: "document was not verified" };
  if (!input.verified.ok) return { code: input.verified.code, message: input.verified.message };
  if (input.checkBinding && input.binding) return input.binding;
  if (!input.pcrsMatch) return { code: "PCR_MISMATCH", message: "PCR0, PCR1 or PCR2 does not match" };
  if (!input.nonceMatch) return { code: "NONCE_MISMATCH", message: "document nonce does not echo the nonce we sent" };
  if (!input.chainMatch) return { code: "CHAIN_NOT_PINNED_ROOT", message: "certificate chain does not start at the pinned AWS Nitro root" };
  if (!input.signatureMatch) return { code: "BAD_SIGNATURE", message: "COSE_Sign1 signature does not verify under the leaf key" };
  return null;
}

interface Inspected {
  pcr0: string | null;
  pcr1: string | null;
  pcr2: string | null;
  nonce: SaveReport["nonce"];
  chain: SaveReport["certificateChain"];
  chainDetail: string;
  signature: SaveReport["signature"];
  timestampMs: number | null;
  moduleId: string | null;
  userData: Uint8Array | null;
}

function pcrHex(pcrs: Map<number, Uint8Array>, index: number): string | null {
  const bytes = pcrs.get(index);
  return bytes ? Buffer.from(bytes).toString("hex") : null;
}

function judgeNonce(sent: Uint8Array, got: Uint8Array | null, parsed: boolean): SaveReport["nonce"] {
  if (sent.length < MIN_NONCE_BYTES) return "TOO_SHORT";
  if (!parsed) return "NOT_CHECKED";
  if (!got) return "MISSING";
  return sameBytes(sent, got) ? "MATCH" : "MISMATCH";
}

function inspect(doc: Uint8Array, nonce: Uint8Array, now: number): Inspected {
  const empty = (parsed: boolean): Inspected => ({
    pcr0: null,
    pcr1: null,
    pcr2: null,
    nonce: judgeNonce(nonce, null, parsed),
    chain: "FAIL",
    chainDetail: "not checked",
    signature: "NOT_CHECKED",
    timestampMs: null,
    moduleId: null,
    userData: null,
  });
  const sign1 = parseCoseSign1(doc);
  if (!sign1.ok) return empty(false);
  const payload = parsePayload(sign1.value.payloadBytes);
  if (!payload.ok) return empty(false);
  return inspectPayload(sign1.value, payload.value, nonce, now);
}

function inspectPayload(sign1: CoseSign1, payload: AttestationPayload, nonce: Uint8Array, now: number): Inspected {
  const chainResult = verifyChain(payload.certificate, payload.cabundle, now);
  let chain: SaveReport["certificateChain"] = "FAIL";
  let chainDetail = "not checked";
  let leaf: X509Certificate | null = null;
  if (chainResult.ok) {
    chain = "MATCH";
    chainDetail = "pinned AWS Nitro root";
    leaf = chainResult.value;
  } else if (chainResult.error.code === "CHAIN_NOT_PINNED_ROOT") {
    chain = "MISMATCH";
    chainDetail = "not the pinned AWS Nitro root";
  } else {
    chain = "FAIL";
    chainDetail = chainResult.error.message;
  }
  const signature = leaf && verifyCoseSignature(sign1, leaf) ? "MATCH" : leaf ? "MISMATCH" : "NOT_CHECKED";
  return {
    pcr0: pcrHex(payload.pcrs, 0),
    pcr1: pcrHex(payload.pcrs, 1),
    pcr2: pcrHex(payload.pcrs, 2),
    nonce: judgeNonce(nonce, payload.nonce, true),
    chain,
    chainDetail,
    signature,
    timestampMs: payload.timestamp,
    moduleId: payload.moduleId,
    userData: payload.userData,
  };
}

function formatStamp(ms: number | null): string | null {
  if (ms === null || !Number.isSafeInteger(ms)) return null;
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) return null;
  return istLabel(date);
}

function evaluate(input: {
  doc: Uint8Array;
  nonce: Uint8Array;
  files: readonly [ExpectedFile, ExpectedFile, ExpectedFile];
  now: number;
  ledgerPublicKey: string | null;
  spkiSha256: string | null;
  raUrl: string | null;
  checkBinding: boolean;
}): { report: SaveReport; failure: Failure | null } {
  const [file0, file1, file2] = input.files;
  const seen = inspect(input.doc, input.nonce, input.now);
  const pcr0 = judgePcr(seen.pcr0, file0.hex);
  const pcr1 = judgePcr(seen.pcr1, file1.hex);
  const pcr2 = judgePcr(seen.pcr2, file2.hex);
  const binding = judgeBinding({
    userData: seen.userData,
    ledgerPublicKey: input.ledgerPublicKey,
    spkiSha256: input.spkiSha256,
    raUrl: input.raUrl,
    check: input.checkBinding,
  });
  const file = firstFileError(input.files);
  let verified: { ok: true } | { ok: false; code: string; message: string } | null = null;
  if (!file && file0.hex && file1.hex && file2.hex) {
    const result = verifyAttestation(input.doc, {
      nonce: input.nonce,
      expected: { pcr0: file0.hex, pcr1: file1.hex, pcr2: file2.hex },
      now: input.now,
    });
    verified = result.ok ? { ok: true } : { ok: false, code: result.error.code, message: result.error.message };
  }
  const bindingFailure = !binding.ok && binding.code && binding.message ? { code: binding.code, message: binding.message } : null;
  const failure = decideFailure({
    file,
    verified,
    checkBinding: input.checkBinding,
    binding: bindingFailure,
    pcrsMatch: pcr0.status === "MATCH" && pcr1.status === "MATCH" && pcr2.status === "MATCH",
    nonceMatch: seen.nonce === "MATCH",
    chainMatch: seen.chain === "MATCH",
    signatureMatch: seen.signature === "MATCH",
  });
  const fields = binding.fields;
  const report: SaveReport = {
    ok: failure === null,
    code: failure?.code ?? null,
    message: failure?.message ?? null,
    pcr0,
    pcr1,
    pcr2,
    timestamp: formatStamp(seen.timestampMs),
    timestampMs: seen.timestampMs,
    nonce: seen.nonce,
    certificateChain: seen.chain,
    certificateChainDetail: seen.chainDetail,
    signature: seen.signature,
    pinnedRootSha256: AWS_NITRO_ROOT_G1_SHA256,
    userData: {
      encoding: binding.encoding,
      fieldsFrom: binding.fieldsFrom,
      ledgerPublicKey: fields?.ledgerPublicKey ?? null,
      raUrl: fields?.raUrl ?? null,
      rung: fields?.rung ?? null,
      spkiSha256: fields?.spkiSha256 ?? null,
    },
    ledgerKey: binding.ledgerKey,
    spki: binding.spki,
    observed: {
      ledgerPublicKey: input.ledgerPublicKey,
      raUrl: input.raUrl,
      spkiSha256: input.spkiSha256,
    },
    moduleId: seen.moduleId,
    nonceHex: Buffer.from(input.nonce).toString("hex"),
    documentBase64: Buffer.from(input.doc).toString("base64"),
  };
  return { report, failure };
}

function formatPcr(name: string, line: PcrJudgement): string {
  if (line.status === "MATCH") return line.document ? `${name} MATCH ${line.document}` : `${name} MATCH`;
  if (line.detail === "all zeros") return `${name} MISMATCH all zeros`;
  if (line.detail === "missing") return `${name} MISMATCH missing`;
  if (line.detail === "malformed") return `${name} MISMATCH malformed`;
  return `${name} MISMATCH ${line.document ?? "missing"} ${line.expected ?? "missing"}`;
}

function formatChain(report: SaveReport): string {
  if (report.certificateChain === "MATCH") return "certificate chain: MATCH pinned AWS Nitro root";
  if (report.certificateChain === "MISMATCH") return "certificate chain: MISMATCH not the pinned AWS Nitro root";
  return `certificate chain: FAIL ${report.certificateChainDetail}`;
}

function formatBinding(report: SaveReport): string[] {
  const user = report.userData;
  const lines: string[] = [];
  if (user.encoding === "canonical-json") lines.push("user_data: canonical JSON");
  else if (user.encoding === "sha256" && user.fieldsFrom === "preimage") lines.push("user_data: sha256 of canonical JSON");
  else if (user.encoding === "sha256") lines.push("user_data: sha256 MISMATCH");
  else if (user.encoding === "absent") lines.push("user_data: absent");
  else lines.push("user_data: unrecognized");
  if (user.ledgerPublicKey) lines.push(`user_data.ledgerPublicKey: ${user.ledgerPublicKey}`);
  if (user.raUrl) lines.push(`user_data.raUrl: ${user.raUrl}`);
  if (user.rung) lines.push(`user_data.rung: ${user.rung}`);
  if (user.spkiSha256) lines.push(`user_data.spkiSha256: ${user.spkiSha256}`);
  lines.push(`ledger key: ${report.ledgerKey}`);
  lines.push(`spki: ${report.spki}`);
  if (report.spki === "MISMATCH" && report.observed.spkiSha256) lines.push(`observed.spkiSha256: ${report.observed.spkiSha256}`);
  if (report.ledgerKey === "MISMATCH" && report.observed.ledgerPublicKey) lines.push(`observed.ledgerPublicKey: ${report.observed.ledgerPublicKey}`);
  return lines;
}

export function formatReport(report: SaveReport): string {
  return [
    formatPcr("PCR0", report.pcr0),
    formatPcr("PCR1", report.pcr1),
    formatPcr("PCR2", report.pcr2),
    `timestamp: ${report.timestamp ?? "missing"}`,
    `nonce: ${report.nonce}`,
    formatChain(report),
    `signature: ${report.signature}`,
    ...formatBinding(report),
  ].join("\n");
}

function writeSave(path: string, report: SaveReport): void {
  writeFileSync(path, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o644 });
}

interface Io {
  log: (line: string) => void;
  error: (line: string) => void;
}

function emit(io: Io, report: SaveReport | null, failure: Failure | null, save: string | null): number {
  const text = report ? formatReport(report) : "";
  const print = () => {
    if (!text) return;
    if (failure) io.error(text);
    else io.log(text);
  };
  if (save && report) {
    try {
      writeSave(save, report);
    } catch (e) {
      print();
      io.error(`attestation refused: SAVE_FAILED: ${e instanceof Error ? e.message : "unknown"}`);
      if (failure) io.error(`attestation refused: ${failure.code}: ${failure.message}`);
      return 1;
    }
  }
  print();
  if (failure) {
    io.error(`attestation refused: ${failure.code}: ${failure.message}`);
    return 1;
  }
  return 0;
}

function refuse(io: Io, code: string, message: string): number {
  io.error(`attestation refused: ${code}: ${message}`);
  return 1;
}

type FileArgs = { mode: "file"; docPath: string; nonceHex: string; save: string | null };
type UrlArgs = { mode: "url"; url: string; ledgerKey: string; allowUntrustedCa: boolean; save: string | null };
type Parsed = { ok: true; args: FileArgs | UrlArgs } | { ok: false; failure: Failure };

function takeValue(argv: string[], index: { i: number }): string | null {
  const value = argv[index.i + 1];
  if (value === undefined || value.startsWith("--")) return null;
  index.i += 1;
  return value;
}

function parseArgs(argv: string[]): Parsed {
  if (argv.includes("--url")) return parseUrl(argv);
  return parseFile(argv);
}

function parseFile(argv: string[]): Parsed {
  let save: string | null = null;
  const positional: string[] = [];
  const index = { i: 0 };
  for (; index.i < argv.length; index.i++) {
    const arg = argv[index.i];
    if (arg === undefined) continue;
    if (arg === "--save") {
      const value = takeValue(argv, index);
      if (value === null) return { ok: false, failure: { code: "BAD_OPTIONS", message: FILE_USAGE } };
      save = value;
      continue;
    }
    if (arg.startsWith("--")) return { ok: false, failure: { code: "BAD_OPTIONS", message: `unknown argument ${arg}` } };
    positional.push(arg);
  }
  const docPath = positional[0];
  const nonceHex = positional[1];
  if (!docPath || !nonceHex || positional.length !== 2) return { ok: false, failure: { code: "BAD_OPTIONS", message: FILE_USAGE } };
  return { ok: true, args: { mode: "file", docPath, nonceHex, save } };
}

function parseUrl(argv: string[]): Parsed {
  let url: string | null = null;
  let ledgerKey: string | null = null;
  let save: string | null = null;
  let allowUntrustedCa = false;
  const index = { i: 0 };
  for (; index.i < argv.length; index.i++) {
    const arg = argv[index.i];
    if (arg === undefined) continue;
    if (arg === "--url") {
      const value = takeValue(argv, index);
      if (value === null) return { ok: false, failure: { code: "BAD_OPTIONS", message: URL_USAGE } };
      url = value;
    } else if (arg === "--ledger-key") {
      const value = takeValue(argv, index);
      if (value === null) return { ok: false, failure: { code: "BAD_OPTIONS", message: URL_USAGE } };
      ledgerKey = value;
    } else if (arg === "--save") {
      const value = takeValue(argv, index);
      if (value === null) return { ok: false, failure: { code: "BAD_OPTIONS", message: URL_USAGE } };
      save = value;
    } else if (arg === "--allow-untrusted-ca") {
      allowUntrustedCa = true;
    } else {
      return { ok: false, failure: { code: "BAD_OPTIONS", message: `unknown argument ${arg}` } };
    }
  }
  if (!url || !ledgerKey) return { ok: false, failure: { code: "BAD_OPTIONS", message: URL_USAGE } };
  return { ok: true, args: { mode: "url", url, ledgerKey, allowUntrustedCa, save } };
}

function loadFiles(dir: string): [ExpectedFile, ExpectedFile, ExpectedFile] {
  return [readExpectedPcr(dir, 0), readExpectedPcr(dir, 1), readExpectedPcr(dir, 2)];
}

function runChecked(io: Io, input: Parameters<typeof evaluate>[0], save: string | null): number {
  const { report, failure } = evaluate(input);
  return emit(io, report, failure, save);
}

async function runFile(args: FileArgs, io: Io, enclaveDir: string, now: number): Promise<number> {
  if (!/^(?:[0-9a-fA-F]{2})+$/.test(args.nonceHex)) return refuse(io, "BAD_OPTIONS", "nonce must be hex");
  let doc: Uint8Array;
  try {
    doc = new Uint8Array(readFileSync(args.docPath));
  } catch {
    return refuse(io, "BAD_OPTIONS", "cannot read the document file");
  }
  return runChecked(
    io,
    {
      doc,
      nonce: new Uint8Array(Buffer.from(args.nonceHex, "hex")),
      files: loadFiles(enclaveDir),
      now,
      ledgerPublicKey: null,
      spkiSha256: null,
      raUrl: null,
      checkBinding: false,
    },
    args.save,
  );
}

type Fetched = { status: number; body: Uint8Array; certDer: Uint8Array };

/** One TLS connection: the document and the certificate it was served under come from the same session. */
function fetchOverOneConnection(url: URL, path: string, allowUntrustedCa: boolean): Promise<Fetched> {
  return new Promise((resolve, reject) => {
    const port = url.port ? Number(url.port) : 443;
    const socket: TLSSocket = connect({
      host: url.hostname,
      port,
      ...(isIP(url.hostname) ? {} : { servername: url.hostname }),
      rejectUnauthorized: !allowUntrustedCa,
    });
    const chunks: Buffer[] = [];
    let total = 0;
    let certDer: Uint8Array | null = null;
    let settled = false;
    const finish = (err: Error | undefined, value?: Fetched) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (err) reject(err);
      else resolve(value!);
    };
    const takeResponse = (): boolean => {
      if (!certDer) return false;
      const all = Buffer.concat(chunks);
      const split = all.indexOf("\r\n\r\n");
      if (split < 0) return false;
      const headText = all.subarray(0, split).toString("latin1");
      let body: Buffer = all.subarray(split + 4);
      const chunked = /\r\ntransfer-encoding:\s*chunked/i.test(headText);
      const len = /\r\ncontent-length:\s*(\d+)/i.exec("\r\n" + headText)?.[1];
      if (chunked) {
        if (!body.includes(Buffer.from("0\r\n\r\n"))) return false;
        body = dechunk(body);
      } else if (len !== undefined) {
        if (body.length < Number(len)) return false;
        body = body.subarray(0, Number(len));
      } else {
        return false;
      }
      const status = Number(/^HTTP\/1\.[01] (\d{3})/.exec(headText)?.[1] ?? "0");
      finish(undefined, { status, body: new Uint8Array(body), certDer });
      return true;
    };
    const timer = setTimeout(() => finish(new Error("timed out")), FETCH_TIMEOUT_MS);
    socket.on("secureConnect", () => {
      const raw = socket.getPeerX509Certificate()?.raw ?? socket.getPeerCertificate(true)?.raw;
      if (!raw || raw.length === 0) {
        finish(new Error("no peer certificate"));
        return;
      }
      certDer = new Uint8Array(raw);
      socket.write(`GET ${path} HTTP/1.1\r\nHost: ${url.host}\r\nAccept: application/cbor\r\nConnection: close\r\n\r\n`);
    });
    socket.on("data", (d: Buffer) => {
      if (settled) return;
      total += d.length;
      if (total > MAX_DOCUMENT_BYTES + 16 * 1024) {
        finish(new Error("response too large"));
        return;
      }
      chunks.push(d);
      takeResponse();
    });
    socket.on("error", (e) => finish(e));
    socket.on("close", () => {
      if (settled) return;
      if (!certDer) return finish(new Error("connection closed before TLS finished"));
      if (!takeResponse()) finish(new Error("no HTTP response"));
    });
  });
}

function dechunk(buf: Buffer): Buffer {
  const out: Buffer[] = [];
  let at = 0;
  while (at < buf.length) {
    const eol = buf.indexOf("\r\n", at);
    if (eol < 0) break;
    const size = parseInt(buf.subarray(at, eol).toString("latin1"), 16);
    if (!Number.isFinite(size) || size === 0) break;
    out.push(buf.subarray(eol + 2, eol + 2 + size));
    at = eol + 2 + size + 2;
  }
  return Buffer.concat(out);
}

async function runUrl(args: UrlArgs, io: Io, enclaveDir: string, now: number): Promise<number> {
  let url: URL;
  try {
    url = new URL(args.url);
  } catch {
    return refuse(io, "BAD_OPTIONS", "url does not parse");
  }
  if (url.protocol !== "https:") return refuse(io, "BAD_OPTIONS", "url must be https");
  const nonce = new Uint8Array(randomBytes(32));
  const nonceHex = Buffer.from(nonce).toString("hex");
  let fetched: Fetched;
  try {
    fetched = await fetchOverOneConnection(url, `/attestation?nonce=${nonceHex}`, args.allowUntrustedCa);
  } catch (e) {
    return refuse(io, "FETCH_FAILED", e instanceof Error ? e.message : "fetch failed");
  }
  if (fetched.status !== 200) return refuse(io, "FETCH_FAILED", `GET /attestation answered ${fetched.status}`);
  let spkiSha256: string | null = null;
  try {
    spkiSha256 = certSpkiSha256(fetched.certDer);
  } catch {
    spkiSha256 = null;
  }
  return runChecked(
    io,
    {
      doc: fetched.body,
      nonce,
      files: loadFiles(enclaveDir),
      now,
      ledgerPublicKey: args.ledgerKey,
      spkiSha256,
      raUrl: url.origin,
      checkBinding: true,
    },
    args.save,
  );
}

export async function run(argv: string[], opts: RunOptions = {}): Promise<number> {
  const io: Io = {
    log: opts.log ?? ((line) => console.log(line)),
    error: opts.error ?? ((line) => console.error(line)),
  };
  const enclaveDir = opts.enclaveDir ?? ENCLAVE_DIR;
  const now = (opts.now ?? Date.now)();
  const parsed = parseArgs(argv);
  if (!parsed.ok) return refuse(io, parsed.failure.code, parsed.failure.message);
  try {
    if (parsed.args.mode === "file") return await runFile(parsed.args, io, enclaveDir, now);
    return await runUrl(parsed.args, io, enclaveDir, now);
  } catch (e) {
    return refuse(io, "VERIFIER_ERROR", e instanceof Error ? e.message : "unknown");
  }
}

if (import.meta.main) {
  void run(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (e: unknown) => {
      console.error(`attestation refused: VERIFIER_ERROR: ${e instanceof Error ? e.message : "unknown"}`);
      process.exitCode = 1;
    },
  );
}
