// ACME http-01 for the RA certificate, run inside the enclave with the pinned lego binary.
//
// lego gets a CSR, never a private key. The CSR is made by csrPem from the TLS identity that
// createTlsIdentity generated in this process, so the issued certificate carries that key's SPKI,
// which is the SPKI in attestation user_data. lego v5 refuses --csr together with --domains, so the
// hostname comes from the CSR and --cert.name fixes the output file name.
//
// lego still makes its own ACME account key in the work dir. That key signs ACME requests only.
// It is not the TLS key and it is removed with the work dir.
//
// Staging is the default. Production only when the caller passes acme: "production".
// Nothing here runs on import. runAcme spawns /usr/bin/lego only when called.

import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { X509Certificate } from "node:crypto";
import { acmePlan, certSpkiSha256, csrPem, HTTP_PORT, RA_HOSTNAME, TLS_BIND_HOST, type AcmeMode, type TlsIdentity } from "./enclave-tls";

export const LEGO_BIN = "/usr/bin/lego";
/** Must match the legofetch stage in enclave/Dockerfile. */
export const LEGO_VERSION = "5.6.0";
export const LEGO_HTTP_ADDRESS = `${TLS_BIND_HOST}:${HTTP_PORT}`;
export const ACME_TIMEOUT_MS = 180_000;

/** Work dir made by prepareAcmeWorkDir. Holds the CSR and lego's account and certificate files. */
export interface AcmeWorkDir {
  readonly path: string;
  readonly csrPath: string;
  readonly certPath: string;
}

const ownWorkDirs = new WeakSet<AcmeWorkDir>();

/** Makes a fresh 0700 dir and writes the identity's CSR into it. The path is chosen here, not by a caller. */
export function prepareAcmeWorkDir(identity: TlsIdentity): AcmeWorkDir {
  const path = mkdtempSync(join(tmpdir(), "writ-acme-"));
  const csrPath = join(path, "tls.csr");
  writeFileSync(csrPath, csrPem(identity, [RA_HOSTNAME]), { mode: 0o600 });
  const dir: AcmeWorkDir = Object.freeze({ path, csrPath, certPath: join(path, "certificates", `${RA_HOSTNAME}.crt`) });
  ownWorkDirs.add(dir);
  return dir;
}

// Any of these on an options object means someone tried to hand in key material or a path.
const REFUSED_KEYS = [
  "key",
  "keyPath",
  "privateKey",
  "privateKeyPath",
  "tlsKey",
  "tlsKeyPath",
  "keyPem",
  "pem",
  "csr",
  "csrPath",
  "path",
  "hostname",
  "domains",
  "server",
  "directoryUrl",
  "debug",
  "debugMode",
];

function refuseHostInputs(opts: object): void {
  for (const k of REFUSED_KEYS) {
    if (Object.prototype.hasOwnProperty.call(opts, k)) {
      throw new Error(`option ${k} is refused: the TLS key, CSR, hostname and ACME server are fixed inside the enclave`);
    }
  }
}

export interface LegoArgvOptions {
  workDir: AcmeWorkDir;
  /** Default "staging". */
  acme?: AcmeMode;
}

export interface LegoPlan {
  readonly argv: readonly string[];
  readonly directoryUrl: string;
  readonly certPath: string;
}

/** The lego command line for http-01 on 127.0.0.1:8080. Pure apart from the work dir check. */
export function buildLegoArgv(opts: LegoArgvOptions): LegoPlan {
  refuseHostInputs(opts);
  if (!ownWorkDirs.has(opts.workDir)) throw new Error("workDir must come from prepareAcmeWorkDir");
  const { directoryUrl } = acmePlan(opts.acme ?? "staging");
  const argv = Object.freeze([
    LEGO_BIN,
    "run",
    "--accept-tos",
    "--server",
    directoryUrl,
    "--csr",
    opts.workDir.csrPath,
    "--cert.name",
    RA_HOSTNAME,
    "--path",
    opts.workDir.path,
    "--http",
    "--http.address",
    LEGO_HTTP_ADDRESS,
  ]);
  return Object.freeze({ argv, directoryUrl, certPath: opts.workDir.certPath });
}

/** lego reads LEGO_* variables from the environment. The child gets PATH only, so the host cannot add flags. */
export function legoEnv(): Record<string, string> {
  return { PATH: "/usr/bin:/bin" };
}

export interface SpawnResult {
  exitCode: number;
  stderr: string;
}
export type SpawnFn = (argv: readonly string[], opts: { env: Record<string, string>; timeoutMs: number }) => Promise<SpawnResult>;

export const defaultSpawn: SpawnFn = async (argv, opts) => {
  const proc = Bun.spawn([...argv], { env: opts.env, stdin: "ignore", stdout: "ignore", stderr: "pipe" });
  const timer = setTimeout(() => proc.kill(), opts.timeoutMs);
  try {
    const [exitCode, stderr] = await Promise.all([proc.exited, new Response(proc.stderr).text()]);
    return { exitCode, stderr };
  } finally {
    clearTimeout(timer);
  }
};

export interface RunAcmeOptions {
  /** The identity the TLS server uses (EnclaveTlsHandle.identity). */
  identity: TlsIdentity;
  /** Default "staging". */
  acme?: AcmeMode;
  /** Called with the PEM chain only after the leaf SPKI matches the identity. */
  install?: (certificatePem: string) => void | Promise<void>;
  /** Tests inject a fake. Default spawns /usr/bin/lego. */
  spawn?: SpawnFn;
  timeoutMs?: number;
}

export type AcmeResult =
  | { ok: true; certificatePem: string; spkiSha256: string; directoryUrl: string }
  | { ok: false; reason: string; directoryUrl?: string };

const PEM_CERT = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----\n?/g;

/**
 * Runs lego once for RA_HOSTNAME. Returns a failure, and never calls install, unless lego exits 0,
 * the leaf names RA_HOSTNAME, and the leaf SPKI equals identity.spkiSha256.
 */
export async function runAcme(opts: RunAcmeOptions): Promise<AcmeResult> {
  refuseHostInputs(opts);
  const workDir = prepareAcmeWorkDir(opts.identity);
  let directoryUrl: string | undefined;
  try {
    const plan = buildLegoArgv({ workDir, acme: opts.acme ?? "staging" });
    directoryUrl = plan.directoryUrl;
    const spawn = opts.spawn ?? defaultSpawn;
    let res: SpawnResult;
    try {
      res = await spawn(plan.argv, { env: legoEnv(), timeoutMs: opts.timeoutMs ?? ACME_TIMEOUT_MS });
    } catch {
      return { ok: false, reason: "lego did not start", directoryUrl };
    }
    if (res.exitCode !== 0) return { ok: false, reason: `lego exited ${res.exitCode}`, directoryUrl };
    if (!existsSync(plan.certPath)) return { ok: false, reason: "lego wrote no certificate", directoryUrl };
    const chain = readFileSync(plan.certPath, "utf8").match(PEM_CERT);
    if (!chain || chain.length === 0) return { ok: false, reason: "certificate file has no PEM certificate", directoryUrl };
    const leaf = chain[0]!;
    let spki: string;
    try {
      spki = certSpkiSha256(leaf);
      if (!new X509Certificate(leaf).checkHost(RA_HOSTNAME)) return { ok: false, reason: `certificate does not name ${RA_HOSTNAME}`, directoryUrl };
    } catch {
      return { ok: false, reason: "certificate does not parse", directoryUrl };
    }
    if (spki !== opts.identity.spkiSha256) return { ok: false, reason: "certificate SPKI does not match the TLS identity", directoryUrl };
    const certificatePem = chain.map((c) => (c.endsWith("\n") ? c : `${c}\n`)).join("");
    if (opts.install) {
      try {
        await opts.install(certificatePem);
      } catch {
        return { ok: false, reason: "install failed", directoryUrl };
      }
    }
    return { ok: true, certificatePem, spkiSha256: spki, directoryUrl };
  } finally {
    rmSync(workDir.path, { recursive: true, force: true });
  }
}
