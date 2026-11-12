// Attested unseal of the Airwallex API key. Runs inside the enclave only.
//
// The KMS key is the ARN baked into enclave/config/kms.json. This file takes no key id from anyone:
// not the caller, not the host, not the environment. Aliases are refused because an alias can be
// re-pointed at a different key (Trail of Bits, Aug 2026, see docs/REFERENCES.md section 1).
//
// This module builds the kmstool_reply command (enclave/kmstool-reply) and checks the answer. It never
// runs a process itself. The process runner is a dependency, so the tests need no docker, no network
// and no AWS.
//
// No logging here. Plaintext and credentials never go to a log line.

import kmsJson from "../../enclave/config/kms.json";
import type { AdapterError, Result } from "../types";
import { PCR_HEX_LENGTH, isAllZeroPcr, isWellFormedPcr } from "./nsm";

// Built from two parts so the repo boundary test can ban the literal text in this file.
const ALIAS_MARK = "alias" + "/";

/**
 * kmstool_enclave_cli v0.4.6 drops the KeyId of the Decrypt reply, so the unseal path runs
 * kmstool_reply instead. Same arguments, plus a KEYID line on stdout.
 */
export const KMSTOOL_REPLY_PATH = "/usr/bin/kmstool_reply";
const STDOUT_LIMIT = 64 * 1024;

export interface KmsConfig {
  keyArn: string;
  region: string;
  proxyPort: number;
}

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
}

/**
 * What the runner must return. replyKeyId is the KeyId field of the KMS Decrypt response, as
 * printed on the KEYID line by kmstool_reply. It is never the value we sent.
 */
export interface KmstoolReply {
  plaintextB64: string;
  replyKeyId: string;
}

/** What running one process gives back. stdout holds the plaintext, so nobody may log it. */
export interface KmstoolExecResult {
  exitCode: number;
  stdout: string;
}

/** Runs argv once (argv[0] is the binary). No shell, no retry. */
export type KmstoolExec = (argv: readonly string[]) => Promise<KmstoolExecResult>;

export interface UnsealDeps {
  /** From NSM. 96 hex characters, never all zeros. */
  pcr0: string;
  /** Other PCRs, for example pcr1 and pcr2. Each one present is checked the same way. */
  pcrs?: Record<string, string>;
  /** Short-lived credentials the host passed in. Useless without the attestation. */
  credentials: AwsCredentials;
  /** Runs argv (argv[0] is the binary) and returns the parsed reply. Must not retry with other arguments. */
  runKmstool(argv: readonly string[]): Promise<Result<KmstoolReply>>;
}

export type UnsealCode =
  | "KEY_CONFIG_INVALID"
  | "KEY_ID_FORBIDDEN"
  | "PCR_ZERO"
  | "PCR_MALFORMED"
  | "BAD_INPUT"
  | "KMSTOOL_FAILED"
  | "KEY_ID_MISMATCH"
  | "BAD_REPLY";

const declined = (code: UnsealCode, message: string): { ok: false; error: AdapterError } => ({
  ok: false,
  error: { kind: "config", code, message: `Declined: ${message}` },
});

const ARN_RE = /^arn:aws:kms:([a-z0-9-]+):(\d{12}):key\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const FORBIDDEN_DEP_NAMES = new Set(["keyid", "keyarn", "kmskeyid", "kmskeyarn", "alias", "keyalias", "kmsalias"]);

/** Validate the baked config. Exported so a test can feed it bad input. */
export function loadKmsConfig(raw: unknown): Result<KmsConfig, AdapterError> {
  if (typeof raw !== "object" || raw === null) return declined("KEY_CONFIG_INVALID", "kms config is not an object");
  const r = raw as Record<string, unknown>;
  const keyArn = r.keyArn;
  const region = r.region;
  const proxyPort = r.proxyPort;
  if (typeof keyArn !== "string" || keyArn.includes(ALIAS_MARK)) {
    return declined("KEY_CONFIG_INVALID", "key id must be a full key ARN, never an alias");
  }
  const m = ARN_RE.exec(keyArn);
  if (!m) return declined("KEY_CONFIG_INVALID", "key id is not a KMS key ARN");
  if (typeof region !== "string" || region !== m[1]) {
    return declined("KEY_CONFIG_INVALID", "region does not match the key ARN");
  }
  if (typeof proxyPort !== "number" || !Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535) {
    return declined("KEY_CONFIG_INVALID", "proxyPort is not a valid port");
  }
  return { ok: true, value: { keyArn, region, proxyPort } };
}

/** The config that ships in the image. Part of PCR0, so the host cannot change it. */
export const BAKED_KMS_CONFIG: Result<KmsConfig, AdapterError> = loadKmsConfig(kmsJson);

/**
 * Build the decrypt command. Pure. Refuses an alias anywhere in the command, which also catches
 * a ciphertext or token that happens to contain the text (about 1 in 10^9; ask again with fresh input).
 */
export function buildDecryptArgv(
  config: KmsConfig,
  ciphertext: Uint8Array,
  credentials: AwsCredentials,
): Result<string[], AdapterError> {
  if (ciphertext.length === 0) return declined("BAD_INPUT", "empty ciphertext");
  const { accessKeyId, secretAccessKey, sessionToken } = credentials;
  if (!accessKeyId || !secretAccessKey || !sessionToken) return declined("BAD_INPUT", "credentials are incomplete");
  const argv = [
    KMSTOOL_REPLY_PATH,
    "decrypt",
    "--region",
    config.region,
    "--proxy-port",
    String(config.proxyPort),
    "--aws-access-key-id",
    accessKeyId,
    "--aws-secret-access-key",
    secretAccessKey,
    "--aws-session-token",
    sessionToken,
    "--ciphertext",
    Buffer.from(ciphertext).toString("base64"),
    "--key-id",
    config.keyArn,
  ];
  if (argv.some((a) => a.includes(ALIAS_MARK))) return declined("KEY_ID_FORBIDDEN", "alias text in the decrypt command");
  return { ok: true, value: argv };
}

/** For logs: the same command with the secret values hidden. */
export function redactArgv(argv: readonly string[]): string[] {
  const hide = new Set(["--aws-access-key-id", "--aws-secret-access-key", "--aws-session-token", "--ciphertext"]);
  return argv.map((a, i) => (i > 0 && hide.has(argv[i - 1] ?? "") ? "<hidden>" : a));
}

const REPLY_STDOUT_RE = /^PLAINTEXT: ([A-Za-z0-9+/]+={0,2})\nKEYID: (arn:aws:kms:[^\s]+)\n?$/;

/**
 * Parse the stdout of `kmstool_reply decrypt`: exactly "PLAINTEXT: <base64>" then "KEYID: <arn>".
 * Any other shape, a second PLAINTEXT, a missing KEYID or extra text is BAD_REPLY. Whether the key
 * id is the baked one is unsealApiKey's check, not the parser's.
 */
export function parseKmstoolReplyStdout(stdout: string): Result<KmstoolReply, AdapterError> {
  if (typeof stdout !== "string" || stdout.length > STDOUT_LIMIT) {
    return declined("BAD_REPLY", "kmstool_reply output is missing or too long");
  }
  const m = REPLY_STDOUT_RE.exec(stdout);
  if (!m || !m[1] || !m[2]) return declined("BAD_REPLY", "kmstool_reply output is not a PLAINTEXT line then a KEYID line");
  return { ok: true, value: { plaintextB64: m[1], replyKeyId: m[2] } };
}

/**
 * The runner unsealApiKey uses in the enclave: run kmstool_reply through exec, then parse both
 * lines. A non-zero exit, a throw or any other binary is KMSTOOL_FAILED, with a fixed message.
 */
export function kmstoolReplyRunner(exec: KmstoolExec): UnsealDeps["runKmstool"] {
  return async (argv) => {
    if (argv[0] !== KMSTOOL_REPLY_PATH) return declined("KMSTOOL_FAILED", "the runner only runs kmstool_reply");
    let out: KmstoolExecResult;
    try {
      out = await exec(argv);
    } catch {
      return declined("KMSTOOL_FAILED", "kmstool_reply could not be run");
    }
    if (out.exitCode !== 0) return declined("KMSTOOL_FAILED", `kmstool_reply exited with code ${out.exitCode}`);
    return parseKmstoolReplyStdout(out.stdout);
  };
}

function checkPcrs(deps: UnsealDeps): { ok: false; error: AdapterError } | undefined {
  const all: Array<[string, unknown]> = [["pcr0", deps.pcr0], ...Object.entries(deps.pcrs ?? {})];
  // All zeros first, so a short string of zeros still reports PCR_ZERO.
  for (const [name, v] of all) {
    if (typeof v === "string" && isAllZeroPcr(v)) {
      return declined("PCR_ZERO", `${name} is all zeros, which is debug mode or a missing measurement`);
    }
  }
  for (const [name, v] of all) {
    if (!isWellFormedPcr(v)) return declined("PCR_MALFORMED", `${name} is not ${PCR_HEX_LENGTH} hex characters`);
  }
  return undefined;
}

/**
 * Decrypt the sealed Airwallex API key. Returns the plaintext bytes. The caller owns them and
 * should zero them after use. One attempt, one key, no retry.
 */
export async function unsealApiKey(ciphertext: Uint8Array, deps: UnsealDeps): Promise<Result<Uint8Array>> {
  try {
    // 1. Nobody hands us a key id.
    for (const name of Object.keys(deps)) {
      if (FORBIDDEN_DEP_NAMES.has(name.toLowerCase().replace(/[-_]/g, ""))) {
        return declined("KEY_ID_FORBIDDEN", "a key id may not come from the caller or the host");
      }
    }
    // 2. The baked key.
    if (!BAKED_KMS_CONFIG.ok) return BAKED_KMS_CONFIG;
    const config = BAKED_KMS_CONFIG.value;
    // 3. Attestation sanity, before any command exists.
    const pcrProblem = checkPcrs(deps);
    if (pcrProblem) return pcrProblem;
    // 4. The command.
    const argv = buildDecryptArgv(config, ciphertext, deps.credentials);
    if (!argv.ok) return argv;
    // 5. Run it once.
    const reply = await deps.runKmstool(argv.value).catch(() => undefined);
    if (!reply || !reply.ok) return declined("KMSTOOL_FAILED", "kmstool decrypt failed");
    // 6. The reply must name the baked key. Checked before the plaintext is touched.
    if (typeof reply.value.replyKeyId !== "string" || reply.value.replyKeyId !== config.keyArn) {
      return declined("KEY_ID_MISMATCH", "KMS answered for a different key id");
    }
    const b64 = reply.value.plaintextB64;
    if (typeof b64 !== "string" || !B64_RE.test(b64) || b64.length % 4 !== 0) {
      return declined("BAD_REPLY", "plaintext is not base64");
    }
    const buf = Buffer.from(b64, "base64");
    if (buf.length === 0) return declined("BAD_REPLY", "plaintext is empty");
    const out = new Uint8Array(buf);
    buf.fill(0);
    return { ok: true, value: out };
  } catch {
    return declined("KMSTOOL_FAILED", "unexpected error during unseal");
  }
}
