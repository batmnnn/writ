// NSM (Nitro Secure Module) seam.
// The real PCR read needs /dev/nsm, which exists only inside an enclave, so it cannot run on a Mac.
// Inside the enclave, enclaveNsm runs /usr/bin/writ-nsm-pcrs (enclave/nsm-pcrs, linked against
// libnsm) and parses its three lines. Any other machine uses unavailableNsm and fails closed.

import type { AdapterError, Result } from "../types";

/** Nitro PCRs are SHA-384, so 48 bytes, so 96 hex characters. */
export const PCR_HEX_LENGTH = 96;

export const NSM_PCRS_PATH = "/usr/bin/writ-nsm-pcrs";

export interface NsmPcrs {
  pcr0: string;
  pcr1: string;
  pcr2: string;
}

export interface NsmPort {
  /** Read PCR0, PCR1 and PCR2 of the running enclave. Lowercase or uppercase hex, 96 characters each. */
  readPcrs(): Promise<Result<NsmPcrs>>;
}

export const ZERO_PCR = "0".repeat(PCR_HEX_LENGTH);

/** True for any string made only of zeros. Debug mode enclaves report PCRs of all zeros. */
export function isAllZeroPcr(value: string): boolean {
  return /^0+$/.test(value);
}

export function isWellFormedPcr(value: unknown): value is string {
  return typeof value === "string" && new RegExp(`^[0-9a-fA-F]{${PCR_HEX_LENGTH}}$`).test(value);
}

const unavailable = (): AdapterError => ({
  kind: "config",
  code: "NSM_UNAVAILABLE",
  message: "NSM is only present inside a Nitro enclave. No PCR read was attempted.",
});

const nsmFailed = (code: string, message: string): { ok: false; error: AdapterError } => ({
  ok: false,
  error: { kind: "config", code, message },
});

/** Default port on any machine that is not an enclave. Always fails. */
export const unavailableNsm: NsmPort = {
  async readPcrs() {
    return { ok: false, error: unavailable() };
  },
};

/** For tests and for a later in-enclave adapter that already holds the values. */
export function fixedNsm(pcrs: NsmPcrs): NsmPort {
  return {
    async readPcrs() {
      return { ok: true, value: { ...pcrs } };
    },
  };
}

const PCRS_STDOUT_RE = new RegExp(`^([0-9a-f]{${PCR_HEX_LENGTH}})\\n([0-9a-f]{${PCR_HEX_LENGTH}})\\n([0-9a-f]{${PCR_HEX_LENGTH}})\\n$`);

/**
 * Parse the stdout of writ-nsm-pcrs: exactly three lowercase hex lines of 96 characters, PCR0 then
 * PCR1 then PCR2, each ending in a newline. Anything else, or any PCR of all zeros, is refused.
 */
export function parseNsmPcrsStdout(stdout: string): Result<NsmPcrs> {
  if (typeof stdout !== "string") return nsmFailed("NSM_BAD_OUTPUT", "writ-nsm-pcrs output is missing");
  const m = PCRS_STDOUT_RE.exec(stdout);
  if (!m || !m[1] || !m[2] || !m[3]) return nsmFailed("NSM_BAD_OUTPUT", "writ-nsm-pcrs output is not three PCR lines");
  const pcrs = { pcr0: m[1], pcr1: m[2], pcr2: m[3] };
  if (isAllZeroPcr(pcrs.pcr0) || isAllZeroPcr(pcrs.pcr1) || isAllZeroPcr(pcrs.pcr2)) {
    return nsmFailed("PCR_ZERO", "a PCR is all zeros, which is debug mode or a missing measurement");
  }
  return { ok: true, value: pcrs };
}

export interface NsmExecResult {
  exitCode: number;
  stdout: string;
  /** Helper stderr. The zero-PCR refusal is printed here and the process exits 1. */
  stderr?: string;
}

/** Runs argv once (argv[0] is the binary). No shell, no retry. */
export type NsmExec = (argv: readonly string[]) => Promise<NsmExecResult>;

/** NSM port backed by one run of writ-nsm-pcrs through exec. A throw or non-zero exit fails closed. */
export function commandNsm(exec: NsmExec, path: string = NSM_PCRS_PATH): NsmPort {
  return {
    async readPcrs() {
      let out: NsmExecResult;
      try {
        out = await exec([path]);
      } catch {
        return nsmFailed("NSM_READ_FAILED", "writ-nsm-pcrs could not be run");
      }
      if (out.exitCode !== 0) {
        if ((out.stderr ?? "").includes("PCR is all zeros")) {
          return nsmFailed("PCR_ZERO", "a PCR is all zeros, which is debug mode or a missing measurement");
        }
        return nsmFailed("NSM_READ_FAILED", `writ-nsm-pcrs exited with code ${out.exitCode}`);
      }
      return parseNsmPcrsStdout(out.stdout);
    },
  };
}

const NSM_TIMEOUT_MS = 5_000;
const NSM_STDOUT_LIMIT = 1024;

/** Bun.spawn with no shell, an empty environment, stderr dropped, a time limit and a size limit. */
export const nsmSpawnExec: NsmExec = async (argv) => {
  const proc = Bun.spawn([...argv], { stdin: "ignore", stdout: "pipe", stderr: "pipe", env: {} });
  const timer = setTimeout(() => proc.kill(), NSM_TIMEOUT_MS);
  const collect = async (stream: ReadableStream<Uint8Array>): Promise<string> => {
    const chunks: Uint8Array[] = [];
    let size = 0;
    for await (const chunk of stream) {
      size += chunk.length;
      if (size > NSM_STDOUT_LIMIT) {
        proc.kill();
        throw new Error("writ-nsm-pcrs output too long");
      }
      chunks.push(chunk);
    }
    return Buffer.concat(chunks).toString("utf8");
  };
  try {
    const [stdout, stderr, exitCode] = await Promise.all([collect(proc.stdout), collect(proc.stderr), proc.exited]);
    return { exitCode, stdout, stderr };
  } finally {
    clearTimeout(timer);
  }
};

/** The port the enclave uses: /usr/bin/writ-nsm-pcrs, which reads /dev/nsm through libnsm. */
export const enclaveNsm: NsmPort = commandNsm(nsmSpawnExec);
