import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { ATTEST_PATH, parseAttestOnly, runBoot, type AttestExec, type BootIo } from "../src/host/enclave";
import { fixedNsm } from "../src/host/nsm";
import type { KmstoolReply } from "../src/host/kms-unseal";
import type { Result } from "../src/types";

const P0 = "a1".repeat(48);
const P1 = "b2".repeat(48);
const P2 = "c3".repeat(48);
const NONCE = randomBytes(32).toString("hex");
const DOC_B64 = randomBytes(4500).toString("base64");
const FAKE = {
  accessKeyId: "ASIAFAKEFAKEFAKE",
  secretAccessKey: "fake-secret-not-a-real-key",
  sessionToken: "fake-session-token",
};
const PLAINTEXT_B64 = Buffer.from("fake-airwallex-key-for-tests").toString("base64");
const ARN = "arn:aws:kms:us-west-2:401046276943:key/04d013d8-fb9b-4261-bf67-4d87370a31bb";
const attestLine = (extra: Record<string, unknown> = {}) => JSON.stringify({ attestOnly: true, nonce: NONCE, ...extra });

function harness(line: string, attest?: AttestExec) {
  const out: string[] = [];
  const err: string[] = [];
  const replies: string[] = [];
  const execCalls: string[][] = [];
  let kmsCalls = 0;
  let armCalls = 0;
  const io: BootIo = {
    nsm: fixedNsm({ pcr0: P0, pcr1: P1, pcr2: P2 }),
    async readLine() {
      return { ok: true, value: Buffer.from(line) };
    },
    async runKmstool(): Promise<Result<KmstoolReply>> {
      kmsCalls += 1;
      return { ok: true, value: { plaintextB64: PLAINTEXT_B64, replyKeyId: ARN } };
    },
    stdout: (l) => out.push(l),
    stderr: (l) => err.push(l),
    reply: (l) => replies.push(l),
    arm: new Proxy({} as NonNullable<BootIo["arm"]>, {
      get() {
        armCalls += 1;
        throw new Error("arm must not be touched on the attest-only path");
      },
    }),
    ...(attest
      ? {
          attest: async (argv: readonly string[]) => {
            execCalls.push([...argv]);
            return attest(argv);
          },
        }
      : {}),
  };
  return { io, out, err, replies, execCalls, kmsCalls: () => kmsCalls, armCalls: () => armCalls };
}

const okExec: AttestExec = async () => ({ exitCode: 0, stdout: `${DOC_B64}\n` });

describe("attest-only boot line", () => {
  test("a fake stdout line is returned as the ATTEST reply, with no unseal and no arm", async () => {
    const h = harness(attestLine(), okExec);
    expect(await runBoot(h.io)).toBe(0);
    expect(h.out).toEqual([`ATTEST ${DOC_B64}`]);
    expect(h.replies).toEqual([`ATTEST ${DOC_B64}`]);
    expect(h.err).toEqual([]);
    expect(h.execCalls).toEqual([[ATTEST_PATH, NONCE]]);
    expect(ATTEST_PATH).toBe("/usr/bin/writ-attest");
    expect(h.kmsCalls()).toBe(0);
    expect(h.armCalls()).toBe(0);
  });

  test("a short nonce is refused before exec", async () => {
    for (const nonce of [NONCE.slice(0, 62), "", "ab"]) {
      const h = harness(attestLine({ nonce }), okExec);
      expect(await runBoot(h.io)).toBe(1);
      expect(h.err).toEqual(["DECLINED ATTEST_FAILED"]);
      expect(h.replies).toEqual(["DECLINED ATTEST_FAILED"]);
      expect(h.out).toEqual([]);
      expect(h.execCalls).toEqual([]);
    }
  });

  test("a bad nonce or extra keys are refused before exec", async () => {
    const bad = [
      attestLine({ nonce: `${NONCE}a` }),
      attestLine({ nonce: `zz${NONCE.slice(2)}` }),
      attestLine({ nonce: 42 }),
      attestLine({ nonce: "ab".repeat(513) }),
      attestLine({ attestOnly: "true" }),
      attestLine({ cardId: "x" }),
      JSON.stringify({ attestOnly: true }),
    ];
    for (const line of bad) {
      const h = harness(line, okExec);
      expect(await runBoot(h.io)).toBe(1);
      expect(h.err).toEqual(["DECLINED ATTEST_FAILED"]);
      expect(h.execCalls).toEqual([]);
      expect(h.kmsCalls()).toBe(0);
    }
  });

  test("a non-zero exit is ATTEST_FAILED, even with good stdout", async () => {
    const h = harness(attestLine(), async () => ({ exitCode: 1, stdout: `${DOC_B64}\n` }));
    expect(await runBoot(h.io)).toBe(1);
    expect(h.err).toEqual(["DECLINED ATTEST_FAILED"]);
    expect(h.replies).toEqual(["DECLINED ATTEST_FAILED"]);
    expect(h.out).toEqual([]);
    expect(h.kmsCalls()).toBe(0);
  });

  test("a throw, empty or malformed stdout, or no exec is ATTEST_FAILED", async () => {
    const execs: Array<AttestExec | undefined> = [
      async () => {
        throw new Error("no /dev/nsm");
      },
      async () => ({ exitCode: 0, stdout: "" }),
      async () => ({ exitCode: 0, stdout: "\n" }),
      async () => ({ exitCode: 0, stdout: DOC_B64 }),
      async () => ({ exitCode: 0, stdout: `${DOC_B64}\n${DOC_B64}\n` }),
      async () => ({ exitCode: 0, stdout: "not base64!\n" }),
      async () => ({ exitCode: 0, stdout: "QQ=\n" }),
      undefined,
    ];
    for (const exec of execs) {
      const h = harness(attestLine(), exec);
      expect(await runBoot(h.io)).toBe(1);
      expect(h.err).toEqual(["DECLINED ATTEST_FAILED"]);
      expect(h.out).toEqual([]);
    }
  });

  test("the boot line buffer is zeroed", async () => {
    const buf = Buffer.from(attestLine());
    const h = harness("", okExec);
    h.io.readLine = async () => ({ ok: true, value: buf });
    expect(await runBoot(h.io)).toBe(0);
    expect(buf.every((b) => b === 0)).toBe(true);
  });

  test("without attestOnly the unseal path runs as before and exec is never called", async () => {
    const line = JSON.stringify({ ciphertextB64: randomBytes(64).toString("base64"), ...FAKE });
    const h = harness(line, okExec);
    delete h.io.arm;
    expect(await runBoot(h.io)).toBe(0);
    expect(h.out[0]).toStartWith("UNSEALED ");
    expect(h.kmsCalls()).toBe(1);
    expect(h.execCalls).toEqual([]);
    expect(parseAttestOnly(Buffer.from(line))).toBeUndefined();
  });
});

describe("writ-attest image files", () => {
  const read = (p: string) => readFileSync(new URL(`../${p}`, import.meta.url), "utf8");

  test("main.c writes stdout once, after NSM is closed, with null user_data and public key", () => {
    const c = read("enclave/nsm-attest/main.c");
    const stdoutWrites = c.match(/\b(?:fputs|fprintf|fwrite|printf|puts)\([^;]*\bstdout\b[^;]*;/g) ?? [];
    expect(stdoutWrites.length).toBe(1);
    expect(stdoutWrites[0]).toStartWith("fputs(out, stdout)");
    expect(/\bprintf\(|\bputs\(|\bwrite\(1/.test(c)).toBe(false);
    expect(c).toContain("nsm_get_attestation_doc(fd, NULL, 0, nonce, nonce_len, NULL, 0, doc, &doc_len) != 0");
    expect(c).toContain("#define DOC_BUF (48 * 1024)");
    expect(c).toContain("doc_len == 0");
    expect(c.indexOf("fputs(out, stdout)")).toBeGreaterThan(c.lastIndexOf("nsm_lib_exit(fd);"));
  });

  test("CMakeLists links libnsm with no git dependency", () => {
    const cm = read("enclave/nsm-attest/CMakeLists.txt");
    expect(/FetchContent|ExternalProject|GIT_TAG|GIT_REPOSITORY/.test(cm)).toBe(false);
    expect(cm).toContain("4b851f3006c6fa98f23dcffb2cba03b39de9b8af");
    expect(cm).toMatch(/NAMES nsm\b/);
    expect(cm).toContain("install(TARGETS writ-attest RUNTIME DESTINATION bin)");
  });

  test("Dockerfile builds and copies writ-attest like writ-nsm-pcrs, and eif.ts stages it", () => {
    const d = read("enclave/Dockerfile");
    expect(d).toContain("COPY enclave/nsm-attest /tmp/crt-builder/nsm-attest");
    expect(d).toMatch(/cp -f [^\n]*\/usr\/bin\/writ-attest \/rootfs\/usr\/bin\//);
    expect(d).toMatch(/for bin in [^\n]*\/usr\/bin\/writ-attest/);
    const eif = read("scripts/eif.ts");
    expect(eif).toContain('"enclave/nsm-attest/CMakeLists.txt"');
    expect(eif).toContain('"enclave/nsm-attest/main.c"');
  });

  test("no debug flag and no em dash in any owned file", () => {
    const debugFlag = "--" + "debug-mode";
    for (const p of ["enclave/nsm-attest/main.c", "enclave/nsm-attest/CMakeLists.txt", "enclave/Dockerfile", "scripts/eif.ts", "src/host/enclave.ts", "test/enclave-attest.test.ts"]) {
      const t = read(p);
      expect(t.includes(debugFlag)).toBe(false);
      expect(t.includes("\u2014")).toBe(false);
    }
  });
});
