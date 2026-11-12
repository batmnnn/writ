import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AWS_NITRO_ROOT_G1_SHA256, encodeCbor, type Cbor } from "../src/attest/verify";
import { canonicalJson } from "../src/core/writ";
import { RUNG, computeUserData, startEnclaveTls, type EnclaveTlsHandle } from "../src/host/enclave-tls";
import {
  decideFailure,
  judgeBinding,
  judgePcr,
  run,
  type SaveReport,
} from "../scripts/verify-attestation";

const P0 = "11".repeat(48);
const P1 = "22".repeat(48);
const P2 = "33".repeat(48);
const P2_OTHER = "44".repeat(48);
const ZERO = "0".repeat(96);
const NONCE = new Uint8Array(32).fill(7);
const NONCE_HEX = Buffer.from(NONCE).toString("hex");
const STAMP = Date.parse("2026-11-12T10:10:00Z");
const IST = "Thu Nov 12, 15:40 IST";
const LEDGER = `ed25519:${"ab".repeat(32)}`;

function capture() {
  const out: string[] = [];
  const err: string[] = [];
  return {
    log: (line: string) => out.push(line),
    error: (line: string) => err.push(line),
    stdout: () => out.join("\n"),
    stderr: () => err.join("\n"),
  };
}

async function withDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "writ-verify-"));
  try {
    await fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function writePcrs(dir: string, pcrs: { pcr0?: string; pcr1?: string; pcr2?: string }): void {
  if (pcrs.pcr0 !== undefined) writeFileSync(join(dir, "PCR0.txt"), `${pcrs.pcr0}\n`);
  if (pcrs.pcr1 !== undefined) writeFileSync(join(dir, "PCR1.txt"), `${pcrs.pcr1}\n`);
  if (pcrs.pcr2 !== undefined) writeFileSync(join(dir, "PCR2.txt"), `${pcrs.pcr2}\n`);
}

function buildDoc(opts: {
  p0: string;
  p1: string;
  p2: string;
  nonce: Uint8Array;
  userData?: Uint8Array | null;
  timestamp?: number;
}): Uint8Array {
  const pcrs = new Map<Cbor, Cbor>([
    [0, new Uint8Array(Buffer.from(opts.p0, "hex"))],
    [1, new Uint8Array(Buffer.from(opts.p1, "hex"))],
    [2, new Uint8Array(Buffer.from(opts.p2, "hex"))],
  ]);
  const payload = new Map<Cbor, Cbor>([
    ["module_id", "i-test"],
    ["digest", "SHA384"],
    ["timestamp", opts.timestamp ?? STAMP],
    ["pcrs", pcrs],
    ["certificate", new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01])],
    ["cabundle", [new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01])]],
    ["public_key", null],
    ["user_data", opts.userData === undefined ? null : opts.userData],
    ["nonce", opts.nonce],
  ]);
  const protectedBytes = encodeCbor(new Map<Cbor, Cbor>([[1, -35]]));
  const payloadBytes = encodeCbor(payload);
  const unprotected = new Map<Cbor, Cbor>();
  return encodeCbor({ tag: 18, value: [protectedBytes, unprotected, payloadBytes, new Uint8Array(96)] });
}

describe("PCR compare", () => {
  test("96 zero hex characters are a mismatch on either side", () => {
    expect(judgePcr(ZERO, P1)).toMatchObject({ status: "MISMATCH", detail: "all zeros" });
    expect(judgePcr(P1, ZERO)).toMatchObject({ status: "MISMATCH", detail: "all zeros" });
    expect(judgePcr(ZERO, ZERO)).toMatchObject({ status: "MISMATCH", detail: "all zeros" });
    expect(judgePcr(P1, P1).status).toBe("MATCH");
  });

  test("all-zero PCR1 fails and is printed as a mismatch", async () => {
    await withDir(async (dir) => {
      writePcrs(dir, { pcr0: P0, pcr1: ZERO, pcr2: P2 });
      const doc = buildDoc({ p0: P0, p1: P1, p2: P2, nonce: NONCE });
      const path = join(dir, "doc.cbor");
      writeFileSync(path, doc);
      const cap = capture();
      const code = await run([path, NONCE_HEX], { enclaveDir: dir, log: cap.log, error: cap.error });
      expect(code).toBe(1);
      expect(cap.stdout()).toBe("");
      expect(cap.stderr()).toContain("PCR1 MISMATCH all zeros");
      expect(cap.stderr()).toContain("attestation refused: PCR_ZERO:");
      expect(cap.stderr()).toContain("PCR1 is all zeros");
    });
  });

  test("a document PCR1 of 96 zeros is a mismatch", async () => {
    await withDir(async (dir) => {
      writePcrs(dir, { pcr0: P0, pcr1: P1, pcr2: P2 });
      const path = join(dir, "doc.cbor");
      writeFileSync(path, buildDoc({ p0: P0, p1: ZERO, p2: P2, nonce: NONCE }));
      const cap = capture();
      const code = await run([path, NONCE_HEX], { enclaveDir: dir, log: cap.log, error: cap.error });
      expect(code).toBe(1);
      expect(cap.stdout()).toBe("");
      expect(cap.stderr()).toContain("PCR1 MISMATCH all zeros");
      expect(cap.stderr()).not.toContain("PCR1 MATCH");
    });
  });

  test("mismatched PCR2 is printed and the process exits 1", async () => {
    await withDir(async (dir) => {
      writePcrs(dir, { pcr0: P0, pcr1: P1, pcr2: P2 });
      const path = join(dir, "doc.cbor");
      writeFileSync(path, buildDoc({ p0: P0, p1: P1, p2: P2_OTHER, nonce: NONCE }));
      const cap = capture();
      const code = await run([path, NONCE_HEX], { enclaveDir: dir, log: cap.log, error: cap.error });
      expect(code).toBe(1);
      expect(cap.stdout()).toBe("");
      expect(cap.stderr()).toContain(`PCR0 MATCH ${P0}`);
      expect(cap.stderr()).toContain(`PCR2 MISMATCH ${P2_OTHER} ${P2}`);
      expect(cap.stderr()).not.toContain("PCR2 MATCH");
    });
  });

  test("a missing PCR file fails", async () => {
    await withDir(async (dir) => {
      writePcrs(dir, { pcr0: P0, pcr1: P1 });
      const path = join(dir, "doc.cbor");
      writeFileSync(path, buildDoc({ p0: P0, p1: P1, p2: P2, nonce: NONCE }));
      const cap = capture();
      const code = await run([path, NONCE_HEX], { enclaveDir: dir, log: cap.log, error: cap.error });
      expect(code).toBe(1);
      expect(cap.stdout()).toBe("");
      expect(cap.stderr()).toContain("PCR2 MISMATCH missing");
      expect(cap.stderr()).toContain("attestation refused: PCR_MISSING:");
      expect(cap.stderr()).toContain("cannot read PCR2.txt");
    });
  });
});

describe("user_data binding", () => {
  test("sha256 user_data that matches binds the ledger key and the SPKI", () => {
    const spki = "11".repeat(32);
    const raUrl = "https://35-95-168-131.sslip.io";
    const userData = computeUserData({ spkiSha256: spki, ledgerPublicKey: LEDGER, raUrl, rung: RUNG });
    const judged = judgeBinding({ userData, ledgerPublicKey: LEDGER, spkiSha256: spki, raUrl, check: true });
    expect(judged.ok).toBe(true);
    expect(judged.ledgerKey).toBe("MATCH");
    expect(judged.spki).toBe("MATCH");
    expect(judged.fieldsFrom).toBe("preimage");
    expect(judged.fields?.rung).toBe(RUNG);
    expect(judged.fields?.ledgerPublicKey).toBe(LEDGER);
    expect(judged.fields?.spkiSha256).toBe(spki);
  });

  test("a sha256 preimage with rung R1 is reported as R1", () => {
    const spki = "11".repeat(32);
    const raUrl = "https://35-95-168-131.sslip.io";
    const json = canonicalJson({ ledgerPublicKey: LEDGER, raUrl, rung: "R1", spkiSha256: spki });
    const userData = new Uint8Array(createHash("sha256").update(json).digest());
    const judged = judgeBinding({ userData, ledgerPublicKey: LEDGER, spkiSha256: spki, raUrl, check: true });
    expect(judged.ok).toBe(true);
    expect(judged.spki).toBe("MATCH");
    expect(judged.ledgerKey).toBe("MATCH");
    expect(judged.fields?.rung).toBe("R1");
  });

  test("SPKI mismatch when user_data.spkiSha256 is not the certificate", () => {
    const raUrl = "https://35-95-168-131.sslip.io";
    const fields = { ledgerPublicKey: LEDGER, raUrl, rung: "R1", spkiSha256: "ab".repeat(32) };
    const userData = new TextEncoder().encode(canonicalJson(fields));
    const judged = judgeBinding({
      userData,
      ledgerPublicKey: LEDGER,
      spkiSha256: "cd".repeat(32),
      raUrl,
      check: true,
    });
    expect(judged.ok).toBe(false);
    expect(judged.code).toBe("SPKI_MISMATCH");
    expect(judged.spki).toBe("MISMATCH");
    expect(judged.ledgerKey).toBe("MATCH");
    expect(judged.fields?.rung).toBe("R1");
    expect(judged.fields?.spkiSha256).toBe("ab".repeat(32));
  });

  test("SPKI mismatch against the certificate on the TLS connection", async () => {
    await withDir(async (dir) => {
      writePcrs(dir, { pcr0: P0, pcr1: P1, pcr2: P2 });
      let handle: EnclaveTlsHandle | undefined;
      let served: Uint8Array | null = null;
      const h = startEnclaveTls({
        ledgerPublicKey: LEDGER,
        handler: () => ({ status: 200, body: { card_transaction_event_id: "evt", response_status: "DECLINED", status_reason: "bad signature" } }),
        attest: (nonce) => {
          const origin = `https://127.0.0.1:${handle?.port ?? 0}`;
          const fields = { ledgerPublicKey: LEDGER, raUrl: origin, rung: "R1", spkiSha256: "ab".repeat(32) };
          served = buildDoc({
            p0: P0,
            p1: P1,
            p2: P2,
            nonce,
            userData: new TextEncoder().encode(canonicalJson(fields)),
            timestamp: STAMP,
          });
          return served;
        },
        port: 0,
      });
      handle = h;
      try {
        expect(h.identity.spkiSha256).not.toBe("ab".repeat(32));
        const save = join(dir, "out.json");
        const cap = capture();
        const code = await run(
          ["--url", `https://127.0.0.1:${h.port}`, "--ledger-key", LEDGER, "--allow-untrusted-ca", "--save", save],
          { enclaveDir: dir, log: cap.log, error: cap.error },
        );
        expect(code).toBe(1);
        expect(cap.stdout()).toBe("");
        expect(cap.stderr()).toContain("spki: MISMATCH");
        expect(cap.stderr()).toContain("ledger key: MATCH");
        expect(cap.stderr()).toContain("user_data: canonical JSON");
        expect(cap.stderr()).toContain("user_data.rung: R1");
        expect(cap.stderr()).toContain(`observed.spkiSha256: ${h.identity.spkiSha256}`);
        const saved = JSON.parse(readFileSync(save, "utf8")) as SaveReport;
        expect(saved.spki).toBe("MISMATCH");
        expect(saved.ledgerKey).toBe("MATCH");
        expect(saved.userData.rung).toBe("R1");
        expect(saved.userData.spkiSha256).toBe("ab".repeat(32));
        expect(saved.observed.spkiSha256).toBe(h.identity.spkiSha256);
        expect(saved.observed.ledgerPublicKey).toBe(LEDGER);
        expect(saved.documentBase64).toBe(Buffer.from(served ?? new Uint8Array()).toString("base64"));
        expect(readFileSync(save, "utf8")).not.toContain("BEGIN PRIVATE");
      } finally {
        await h.stop();
      }
    });
  }, 20_000);
});

describe("--save", () => {
  test("writes the full result as JSON with no secret", async () => {
    await withDir(async (dir) => {
      writePcrs(dir, { pcr0: P0, pcr1: P1, pcr2: P2 });
      const fields = { ledgerPublicKey: LEDGER, raUrl: "https://35-95-168-131.sslip.io", rung: "R1", spkiSha256: "12".repeat(32) };
      const doc = buildDoc({
        p0: P0,
        p1: P1,
        p2: P2_OTHER,
        nonce: NONCE,
        userData: new TextEncoder().encode(canonicalJson(fields)),
        timestamp: STAMP,
      });
      const path = join(dir, "doc.cbor");
      writeFileSync(path, doc);
      const save = join(dir, "out.json");
      const cap = capture();
      const code = await run([path, NONCE_HEX, "--save", save], { enclaveDir: dir, log: cap.log, error: cap.error });
      expect(code).toBe(1);
      expect(cap.stdout()).toBe("");
      const text = readFileSync(save, "utf8");
      expect(text.endsWith("\n")).toBe(true);
      expect(text).not.toContain("BEGIN PRIVATE");
      expect(text).not.toContain("x-api-key");
      expect(text).not.toContain("\u2014");
      const saved = JSON.parse(text) as SaveReport;
      expect(saved.ok).toBe(false);
      expect(saved.pcr0).toEqual({ status: "MATCH", document: P0, expected: P0, detail: null });
      expect(saved.pcr2.status).toBe("MISMATCH");
      expect(saved.pcr2.detail).toBe("differs");
      expect(saved.pcr2.document).toBe(P2_OTHER);
      expect(saved.pcr2.expected).toBe(P2);
      expect(saved.timestamp).toBe(IST);
      expect(saved.timestampMs).toBe(STAMP);
      expect(saved.nonce).toBe("MATCH");
      expect(saved.certificateChain).toBe("FAIL");
      expect(saved.pinnedRootSha256).toBe(AWS_NITRO_ROOT_G1_SHA256);
      expect(saved.userData.encoding).toBe("canonical-json");
      expect(saved.userData.fieldsFrom).toBe("document");
      expect(saved.userData.ledgerPublicKey).toBe(LEDGER);
      expect(saved.userData.raUrl).toBe("https://35-95-168-131.sslip.io");
      expect(saved.userData.rung).toBe("R1");
      expect(saved.userData.spkiSha256).toBe("12".repeat(32));
      expect(saved.ledgerKey).toBe("NOT_CHECKED");
      expect(saved.spki).toBe("NOT_CHECKED");
      expect(Buffer.from(saved.documentBase64, "base64").equals(Buffer.from(doc))).toBe(true);
      expect(cap.stderr()).not.toContain(saved.documentBase64);
      expect(cap.stderr()).toContain(`timestamp: ${IST}`);
      expect(cap.stderr()).toContain("nonce: MATCH");
      expect(cap.stderr()).toContain("user_data.rung: R1");
    });
  });
});

describe("exit 0 only when every check matches", () => {
  const ok = { file: null, verified: { ok: true as const }, checkBinding: true, binding: null, pcrsMatch: true, nonceMatch: true, chainMatch: true, signatureMatch: true };

  test("a published all-zero PCR wins over a later chain error", () => {
    expect(
      decideFailure({
        ...ok,
        file: { code: "PCR_ZERO", message: "PCR1 is all zeros, which is debug mode or a missing measurement" },
        verified: { ok: false, code: "CHAIN_INVALID", message: "no" },
        pcrsMatch: false,
        chainMatch: false,
      })?.code,
    ).toBe("PCR_ZERO");
  });

  test("a verifier PCR mismatch wins over an SPKI mismatch", () => {
    expect(
      decideFailure({
        ...ok,
        verified: { ok: false, code: "PCR_MISMATCH", message: "PCR2 does not match" },
        binding: { code: "SPKI_MISMATCH", message: "user_data spkiSha256 does not match the certificate SPKI" },
        pcrsMatch: false,
      })?.code,
    ).toBe("PCR_MISMATCH");
  });

  test("SPKI mismatch fails a document the verifier otherwise accepted", () => {
    expect(
      decideFailure({
        ...ok,
        binding: { code: "SPKI_MISMATCH", message: "user_data spkiSha256 does not match the certificate SPKI" },
      }),
    ).toEqual({ code: "SPKI_MISMATCH", message: "user_data spkiSha256 does not match the certificate SPKI" });
  });

  test("null only when the PCRs, nonce, chain, signature and binding match", () => {
    expect(decideFailure(ok)).toBeNull();
  });
});

describe("positional mode", () => {
  test("keeps the usage line", async () => {
    const cap = capture();
    const code = await run([], { log: cap.log, error: cap.error });
    expect(code).toBe(1);
    expect(cap.stdout()).toBe("");
    expect(cap.stderr()).toContain("usage: verify-attestation <document.cbor> <nonce-hex>");
  });
});
