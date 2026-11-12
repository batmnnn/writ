import { afterEach, describe, expect, test } from "bun:test";
import { createServer, type Server, type Socket } from "node:net";
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import {
  NSM_PCRS_PATH,
  ZERO_PCR,
  commandNsm,
  fixedNsm,
  parseNsmPcrsStdout,
  unavailableNsm,
  type NsmExec,
} from "../src/host/nsm";
import { parseBootPayload, readBootLine, runBoot, type BootIo } from "../src/host/enclave";
import type { KmstoolReply } from "../src/host/kms-unseal";
import type { Result } from "../src/types";

const ARN = "arn:aws:kms:us-west-2:401046276943:key/04d013d8-fb9b-4261-bf67-4d87370a31bb";
const P0 = "a1".repeat(48);
const P1 = "b2".repeat(48);
const P2 = "c3".repeat(48);
const FAKE = {
  accessKeyId: "ASIAFAKEFAKEFAKE",
  secretAccessKey: "fake-secret-not-a-real-key",
  sessionToken: "fake-session-token",
};
const CIPHERTEXT = randomBytes(64);
const CIPHERTEXT_B64 = CIPHERTEXT.toString("base64");
const PLAINTEXT = new TextEncoder().encode("fake-airwallex-key-for-tests");
const PLAINTEXT_B64 = Buffer.from(PLAINTEXT).toString("base64");
const fakeLine = (extra: Record<string, unknown> = {}) => JSON.stringify({ ciphertextB64: CIPHERTEXT_B64, ...FAKE, ...extra });

describe("parseNsmPcrsStdout", () => {
  test("three lowercase lines in order", () => {
    const r = parseNsmPcrsStdout(`${P0}\n${P1}\n${P2}\n`);
    expect(r).toEqual({ ok: true, value: { pcr0: P0, pcr1: P1, pcr2: P2 } });
  });

  test("any other shape is NSM_BAD_OUTPUT", () => {
    const bad = [
      "",
      `${P0}\n${P1}\n`,
      `${P0}\n${P1}\n${P2}`,
      `${P0}\n${P1}\n${P2}\n${P2}\n`,
      `${P0.toUpperCase()}\n${P1}\n${P2}\n`,
      `${P0.slice(2)}\n${P1}\n${P2}\n`,
      `${P0}ab\n${P1}\n${P2}\n`,
      `${P0}\r\n${P1}\n${P2}\n`,
      ` ${P0}\n${P1}\n${P2}\n`,
    ];
    for (const s of bad) {
      const r = parseNsmPcrsStdout(s);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error.code).toBe("NSM_BAD_OUTPUT");
    }
  });

  test("a zero PCR in any slot is PCR_ZERO", () => {
    for (const s of [`${ZERO_PCR}\n${P1}\n${P2}\n`, `${P0}\n${ZERO_PCR}\n${P2}\n`, `${P0}\n${P1}\n${ZERO_PCR}\n`]) {
      const r = parseNsmPcrsStdout(s);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error.code).toBe("PCR_ZERO");
    }
  });
});

describe("commandNsm", () => {
  test("runs only the helper, with no arguments, and parses its stdout", async () => {
    const calls: string[][] = [];
    const exec: NsmExec = async (argv) => {
      calls.push([...argv]);
      return { exitCode: 0, stdout: `${P0}\n${P1}\n${P2}\n` };
    };
    const r = await commandNsm(exec).readPcrs();
    expect(r).toEqual({ ok: true, value: { pcr0: P0, pcr1: P1, pcr2: P2 } });
    expect(calls).toEqual([[NSM_PCRS_PATH]]);
    expect(NSM_PCRS_PATH).toBe("/usr/bin/writ-nsm-pcrs");
  });

  test("non-zero exit or a throw is NSM_READ_FAILED, even with good stdout", async () => {
    const cases: NsmExec[] = [
      async () => ({ exitCode: 1, stdout: `${P0}\n${P1}\n${P2}\n` }),
      async () => {
        throw new Error("no /dev/nsm");
      },
    ];
    for (const exec of cases) {
      const r = await commandNsm(exec).readPcrs();
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error.code).toBe("NSM_READ_FAILED");
    }
  });

  test("a helper that exits 1 because a PCR is all zeros is PCR_ZERO", async () => {
    const exec: NsmExec = async () => ({ exitCode: 1, stdout: "", stderr: "writ-nsm-pcrs: PCR is all zeros\n" });
    const r = await commandNsm(exec).readPcrs();
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("PCR_ZERO");
  });
});

describe("readBootLine", () => {
  let server: Server | undefined;
  afterEach(() => {
    server?.close();
    server = undefined;
  });
  const serve = async (handler: (s: Socket) => void): Promise<number> => {
    server = createServer(handler);
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", () => resolve()));
    const addr = server.address();
    if (typeof addr !== "object" || addr === null) throw new Error("no port");
    return addr.port;
  };

  test("reads one fake line, split across writes, and stops at the newline", async () => {
    const line = fakeLine();
    const port = await serve((s) => {
      s.write(line.slice(0, 10));
      setTimeout(() => s.write(`${line.slice(10)}\n{"ignored":true}\n`), 10);
    });
    const r = await readBootLine({ port });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value.toString("utf8")).toBe(line);
  });

  test("over the size limit is LINE_TOO_LONG", async () => {
    const port = await serve((s) => s.write(Buffer.alloc(2048, 0x61)));
    const r = await readBootLine({ port, maxBytes: 1024 });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("LINE_TOO_LONG");
  });

  test("the default limit is 64 KiB", async () => {
    const port = await serve((s) => s.end(Buffer.alloc(64 * 1024 + 1, 0x61)));
    const r = await readBootLine({ port });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("LINE_TOO_LONG");
  });

  test("close before a newline, refused connection and silence are RELAY_FAILED", async () => {
    const port = await serve((s) => s.end(fakeLine()));
    const closed = await readBootLine({ port });
    expect(closed.ok).toBe(false);
    if (!closed.ok) expect(closed.error.code).toBe("RELAY_FAILED");

    server!.close();
    server = undefined;
    const refused = await readBootLine({ port });
    expect(refused.ok).toBe(false);
    if (!refused.ok) expect(refused.error.code).toBe("RELAY_FAILED");

    const quiet = await serve(() => {});
    const silent = await readBootLine({ port: quiet, timeoutMs: 100 });
    expect(silent.ok).toBe(false);
    if (!silent.ok) expect(silent.error.code).toBe("RELAY_FAILED");
  });
});

describe("parseBootPayload", () => {
  const enc = (s: string) => new TextEncoder().encode(s);

  test("takes exactly the four fields", () => {
    const r = parseBootPayload(enc(fakeLine()));
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(Buffer.from(r.value.ciphertext).equals(CIPHERTEXT)).toBe(true);
      expect(r.value.credentials).toEqual(FAKE);
    }
  });

  test("anything else is BAD_INPUT and the message never echoes a value", () => {
    const { sessionToken: _drop, ...noToken } = FAKE;
    const bad = [
      "not json",
      "[]",
      "null",
      fakeLine({ keyId: ARN }),
      JSON.stringify({ ciphertextB64: CIPHERTEXT_B64, ...noToken }),
      fakeLine({ ciphertextB64: "not base64!" }),
      fakeLine({ ciphertextB64: "QQ=" }),
      fakeLine({ ciphertextB64: "" }),
      fakeLine({ secretAccessKey: 42 }),
    ];
    for (const s of bad) {
      const r = parseBootPayload(enc(s));
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.error.code).toBe("BAD_INPUT");
        for (const v of [...Object.values(FAKE), CIPHERTEXT_B64]) expect(r.error.message.includes(v)).toBe(false);
      }
    }
    const notUtf8 = parseBootPayload(new Uint8Array([0x7b, 0xff, 0x7d]));
    expect(notUtf8.ok).toBe(false);
  });
});

describe("runBoot", () => {
  const okKms = async (): Promise<Result<KmstoolReply>> => ({ ok: true, value: { plaintextB64: PLAINTEXT_B64, replyKeyId: ARN } });
  const goodNsm = fixedNsm({ pcr0: P0, pcr1: P1, pcr2: P2 });

  function harness(over: Partial<BootIo> = {}) {
    const out: string[] = [];
    const err: string[] = [];
    let lineReads = 0;
    const argvSeen: string[][] = [];
    const io: BootIo = {
      nsm: goodNsm,
      async readLine() {
        lineReads += 1;
        return { ok: true, value: Buffer.from(fakeLine()) };
      },
      async runKmstool(argv) {
        argvSeen.push([...argv]);
        return okKms();
      },
      stdout: (l) => out.push(l),
      stderr: (l) => err.push(l),
      ...over,
    };
    return { io, out, err, argvSeen, lineReads: () => lineReads };
  }

  const noSecretIn = (lines: string[]) => {
    const all = lines.join("\n");
    for (const v of [...Object.values(FAKE), CIPHERTEXT_B64, PLAINTEXT_B64, "fake-airwallex-key"]) expect(all.includes(v)).toBe(false);
  };

  test("success prints only UNSEALED with the byte length and exits 0", async () => {
    const h = harness();
    expect(await runBoot(h.io)).toBe(0);
    expect(h.out).toEqual([`UNSEALED ${PLAINTEXT.length}`]);
    expect(h.err).toEqual([]);
    expect(h.argvSeen.length).toBe(1);
    expect(h.argvSeen[0]).toContain("--key-id");
    noSecretIn([...h.out, ...h.err]);
  });

  test("no NSM declines before the boot line is read", async () => {
    const h = harness({ nsm: unavailableNsm });
    expect(await runBoot(h.io)).toBe(1);
    expect(h.err).toEqual(["DECLINED NSM_UNAVAILABLE"]);
    expect(h.out).toEqual([]);
    expect(h.lineReads()).toBe(0);
  });

  test("zero PCRs from NSM decline PCR_ZERO and never reach kmstool", async () => {
    const h = harness({ nsm: fixedNsm({ pcr0: ZERO_PCR, pcr1: P1, pcr2: P2 }) });
    expect(await runBoot(h.io)).toBe(1);
    expect(h.err).toEqual(["DECLINED PCR_ZERO"]);
    expect(h.argvSeen.length).toBe(0);
  });

  test("relay, payload and kmstool failures each print one DECLINED line and no secret", async () => {
    const cases: Array<[Partial<BootIo>, string]> = [
      [{ readLine: async () => ({ ok: false, error: { kind: "config", code: "RELAY_FAILED", message: "x" } }) }, "RELAY_FAILED"],
      [{ readLine: async () => ({ ok: true, value: Buffer.from(fakeLine({ extra: 1 })) }) }, "BAD_INPUT"],
      [{ runKmstool: async () => ({ ok: false, error: { kind: "config", code: "KMSTOOL_FAILED", message: FAKE.secretAccessKey } }) }, "KMSTOOL_FAILED"],
      [{ runKmstool: async () => ({ ok: true, value: { plaintextB64: PLAINTEXT_B64, replyKeyId: ARN.replace("us-west-2", "us-east-1") } }) }, "KEY_ID_MISMATCH"],
      [{ readLine: async () => { throw new Error(FAKE.sessionToken); } }, "BOOT_FAILED"],
    ];
    for (const [over, code] of cases) {
      const h = harness(over);
      expect(await runBoot(h.io)).toBe(1);
      expect(h.err).toEqual([`DECLINED ${code}`]);
      expect(h.out).toEqual([]);
      noSecretIn(h.err);
    }
  });

  test("the boot line buffer is zeroed after parsing", async () => {
    const buf = Buffer.from(fakeLine());
    const h = harness({ readLine: async () => ({ ok: true, value: buf }) });
    expect(await runBoot(h.io)).toBe(0);
    expect(buf.every((b) => b === 0)).toBe(true);
  });
});

describe("entry point off the enclave", () => {
  test("bun run src/host/enclave.ts declines NSM_READ_FAILED on stderr, exits 1, prints nothing on stdout", async () => {
    const root = join(import.meta.dir, "..");
    const proc = Bun.spawn(["bun", "run", join(root, "src/host/enclave.ts")], { cwd: root, stdout: "pipe", stderr: "pipe", env: { PATH: process.env.PATH ?? "" } });
    const [stdout, stderr, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);
    expect(code).toBe(1);
    expect(stdout).toBe("");
    expect(stderr.trim()).toBe("DECLINED NSM_READ_FAILED");
  });
});

describe("image files", () => {
  const read = (p: string) => readFileSync(new URL(`../${p}`, import.meta.url), "utf8");

  test("writ-nsm-pcrs writes stdout once, after all checks, and links libnsm with no git dependency", () => {
    const c = read("enclave/nsm-pcrs/main.c");
    const stdoutWrites = c.match(/\b(?:fputs|fprintf|fwrite|printf|puts)\([^;]*\bstdout\b[^;]*;/g) ?? [];
    expect(stdoutWrites.length).toBe(1);
    expect(stdoutWrites[0]).toStartWith("fputs(out, stdout)");
    expect(/\bprintf\(|\bputs\(|\bwrite\(1/.test(c)).toBe(false);
    expect(c.indexOf("fputs(out, stdout)")).toBeGreaterThan(c.indexOf("nsm_lib_exit(fd);\n\n"));
    expect(c).toContain("nsm_describe_pcr(fd, i, &lock, data, &len) != 0");
    expect(c).toContain("len != PCR_BYTES");
    const cm = read("enclave/nsm-pcrs/CMakeLists.txt");
    expect(/FetchContent|ExternalProject|GIT_TAG|GIT_REPOSITORY/.test(cm)).toBe(false);
    expect(cm).toContain("4b851f3006c6fa98f23dcffb2cba03b39de9b8af");
    expect(cm).toMatch(/NAMES nsm\b/);
  });

  test("Dockerfile builds and copies the helper like kmstool_reply, and eif.ts stages it", () => {
    const d = read("enclave/Dockerfile");
    expect(d).toContain("COPY enclave/nsm-pcrs /tmp/crt-builder/nsm-pcrs");
    expect(d).toMatch(/cp -f [^\n]*\/usr\/bin\/writ-nsm-pcrs \/rootfs\/usr\/bin\//);
    expect(d).toMatch(/for bin in [^\n]*\/usr\/bin\/writ-nsm-pcrs/);
    const eif = read("scripts/eif.ts");
    expect(eif).toContain('"enclave/nsm-pcrs/CMakeLists.txt"');
    expect(eif).toContain('"enclave/nsm-pcrs/main.c"');
  });

  test("boot.sh starts the socat bridge after lo is up and before bun, in the background", () => {
    const b = read("enclave/boot.sh");
    const lo = b.indexOf("ip link set lo up");
    const socat = b.indexOf("socat TCP-LISTEN:5000,bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:3:5000 &");
    const bun = b.indexOf("exec /usr/local/bin/bun run /app/src/host/enclave.ts");
    expect(lo).toBeGreaterThan(-1);
    expect(socat).toBeGreaterThan(lo);
    expect(bun).toBeGreaterThan(socat);
  });

  test("no debug flag and no em dash in any owned file", () => {
    const debugFlag = "--" + "debug-mode";
    for (const p of ["enclave/nsm-pcrs/main.c", "enclave/nsm-pcrs/CMakeLists.txt", "enclave/boot.sh", "enclave/Dockerfile", "scripts/eif.ts", "src/host/nsm.ts", "src/host/enclave.ts", "test/enclave-boot.test.ts"]) {
      const t = read(p);
      expect(t.includes(debugFlag)).toBe(false);
      expect(t.includes("\u2014")).toBe(false);
    }
  });

  test("enclave.ts never logs argv, credentials or the plaintext", () => {
    const e = read("src/host/enclave.ts");
    for (const line of e.split("\n").filter((l) => /console\.|process\.(stdout|stderr)|io\.(stdout|stderr)\(/.test(l))) {
      expect(/argv|secretAccessKey|sessionToken|accessKeyId|ciphertextB64|plaintext/i.test(line.replace(/"[^"]*"|`[^`]*`/g, (m) => (m.includes("${") ? m : "")))).toBe(false);
    }
  });
});
