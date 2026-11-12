import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { randomBytes, randomUUID } from "node:crypto";
import {
  BAKED_KMS_CONFIG,
  KMSTOOL_REPLY_PATH,
  buildDecryptArgv,
  kmstoolReplyRunner,
  loadKmsConfig,
  parseKmstoolReplyStdout,
  redactArgv,
  unsealApiKey,
  type AwsCredentials,
  type KmstoolExec,
  type KmstoolReply,
  type UnsealDeps,
} from "../src/host/kms-unseal";
import { ZERO_PCR, fixedNsm, unavailableNsm } from "../src/host/nsm";
import { bunSpawnExec, unsealAtBoot } from "../src/host/enclave";
import type { Result } from "../src/types";

const ARN = "arn:aws:kms:us-west-2:401046276943:key/04d013d8-fb9b-4261-bf67-4d87370a31bb";
const PCR = "ab".repeat(48);
const creds: AwsCredentials = { accessKeyId: "ASIAFAKEFAKEFAKE", secretAccessKey: "fake-secret", sessionToken: "fake-token" };
const SECRET = new TextEncoder().encode("fake-airwallex-key");
const SECRET_B64 = Buffer.from(SECRET).toString("base64");

function deps(reply: (argv: readonly string[]) => Result<KmstoolReply>, calls: string[][] = []): UnsealDeps {
  return {
    pcr0: PCR,
    credentials: creds,
    async runKmstool(argv) {
      calls.push([...argv]);
      return reply(argv);
    },
  };
}
const okReply = (keyId: string) => (): Result<KmstoolReply> => ({
  ok: true,
  value: { plaintextB64: SECRET_B64, replyKeyId: keyId },
});

describe("baked config", () => {
  test("kms.json holds the dev key ARN and no alias", () => {
    const raw = readFileSync(new URL("../enclave/config/kms.json", import.meta.url), "utf8");
    expect(raw.includes("alias/")).toBe(false);
    expect(BAKED_KMS_CONFIG.ok).toBe(true);
    if (BAKED_KMS_CONFIG.ok) expect(BAKED_KMS_CONFIG.value.keyArn).toBe(ARN);
  });

  test("an alias or a malformed key id is refused by the loader", () => {
    for (const keyArn of ["alias/writ-dev", `arn:aws:kms:us-west-2:401046276943:alias/writ-dev`, "04d013d8-fb9b-4261-bf67-4d87370a31bb", ""]) {
      const r = loadKmsConfig({ keyArn, region: "us-west-2", proxyPort: 8000 });
      expect(r.ok).toBe(false);
    }
    expect(loadKmsConfig({ keyArn: ARN, region: "us-east-1", proxyPort: 8000 }).ok).toBe(false);
  });
});

describe("decrypt command", () => {
  test("argv has --key-id and the ARN, and never alias/", () => {
    if (!BAKED_KMS_CONFIG.ok) throw new Error("config");
    const r = buildDecryptArgv(BAKED_KMS_CONFIG.value, randomBytes(64), creds);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const i = r.value.indexOf("--key-id");
    expect(i).toBeGreaterThan(0);
    expect(r.value[i + 1]).toBe(ARN);
    expect(r.value.join(" ").includes("alias/")).toBe(false);
    expect(r.value.includes("--debug-mode")).toBe(false);
  });

  test("text that looks like an alias anywhere in the command is refused", () => {
    if (!BAKED_KMS_CONFIG.ok) throw new Error("config");
    const r = buildDecryptArgv(BAKED_KMS_CONFIG.value, randomBytes(64), { ...creds, sessionToken: "xxalias/yy" });
    expect(r.ok).toBe(false);
  });

  test("redactArgv hides credentials and ciphertext but keeps the key id", () => {
    if (!BAKED_KMS_CONFIG.ok) throw new Error("config");
    const r = buildDecryptArgv(BAKED_KMS_CONFIG.value, randomBytes(64), creds);
    if (!r.ok) throw new Error("argv");
    const shown = redactArgv(r.value).join(" ");
    expect(shown.includes(creds.secretAccessKey)).toBe(false);
    expect(shown.includes(creds.sessionToken)).toBe(false);
    expect(shown.includes(ARN)).toBe(true);
  });

  test("the real runner argv is what unsealApiKey passes", async () => {
    const calls: string[][] = [];
    const r = await unsealApiKey(randomBytes(64), deps(okReply(ARN), calls));
    expect(r.ok).toBe(true);
    expect(calls.length).toBe(1);
    expect(calls[0]).toContain("--key-id");
    expect(calls[0]).toContain(ARN);
    expect(calls[0]!.join(" ").includes("alias/")).toBe(false);
  });
});

describe("pcr gate", () => {
  test("all-zero pcr0 builds no decrypt command and calls no runner", async () => {
    const calls: string[][] = [];
    const d = { ...deps(okReply(ARN), calls), pcr0: ZERO_PCR };
    const r = await unsealApiKey(randomBytes(64), d);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("PCR_ZERO");
    expect(calls.length).toBe(0);
  });

  test("any other all-zero pcr declines before the runner", async () => {
    const calls: string[][] = [];
    const d = { ...deps(okReply(ARN), calls), pcrs: { pcr1: PCR, pcr2: ZERO_PCR } };
    const r = await unsealApiKey(randomBytes(64), d);
    expect(r.ok).toBe(false);
    expect(calls.length).toBe(0);
  });

  test("a malformed pcr0 declines", async () => {
    const calls: string[][] = [];
    const r = await unsealApiKey(randomBytes(64), { ...deps(okReply(ARN), calls), pcr0: "abcd" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("PCR_MALFORMED");
    expect(calls.length).toBe(0);
  });
});

describe("reply key id", () => {
  test("random key ids other than the ARN are refused and no plaintext comes back", async () => {
    for (let i = 0; i < 25; i++) {
      const other = `arn:aws:kms:us-west-2:401046276943:key/${randomUUID()}`;
      const calls: string[][] = [];
      const r = await unsealApiKey(randomBytes(64), deps(okReply(other), calls));
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error.code).toBe("KEY_ID_MISMATCH");
      expect(calls.length).toBe(1); // one attempt, no retry with another key
    }
    for (const other of ["", "alias/writ-dev", ARN.toUpperCase(), `${ARN} `, "writ-dev"]) {
      const r = await unsealApiKey(randomBytes(64), deps(okReply(other)));
      expect(r.ok).toBe(false);
    }
  });

  test("a runner that gives no key id is refused", async () => {
    const r = await unsealApiKey(randomBytes(64), deps(() => ({ ok: true, value: { plaintextB64: SECRET_B64 } as unknown as KmstoolReply })));
    expect(r.ok).toBe(false);
  });

  test("a matching key id returns the plaintext bytes", async () => {
    const r = await unsealApiKey(randomBytes(64), deps(okReply(ARN)));
    expect(r.ok).toBe(true);
    if (r.ok) expect(Array.from(r.value)).toEqual(Array.from(SECRET));
  });

  test("a runner failure or throw declines with a generic message", async () => {
    const failing = await unsealApiKey(randomBytes(64), deps(() => ({ ok: false, error: { kind: "network", message: "has fake-secret in it" } })));
    expect(failing.ok).toBe(false);
    if (!failing.ok) expect(failing.error.message.includes("fake-secret")).toBe(false);
    const throwing = await unsealApiKey(randomBytes(64), {
      ...deps(okReply(ARN)),
      runKmstool: async () => {
        throw new Error("boom fake-secret");
      },
    });
    expect(throwing.ok).toBe(false);
    if (!throwing.ok) expect(throwing.error.message.includes("fake-secret")).toBe(false);
  });
});

describe("no key id from the host", () => {
  test("a key id or alias property on deps is refused before the runner", async () => {
    for (const name of ["keyId", "kmsKeyId", "key_id", "keyArn", "alias", "KeyId"]) {
      const calls: string[][] = [];
      const d = { ...deps(okReply(ARN), calls), [name]: "arn:aws:kms:us-west-2:401046276943:key/" + randomUUID() } as UnsealDeps;
      const r = await unsealApiKey(randomBytes(64), d);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error.code).toBe("KEY_ID_FORBIDDEN");
      expect(calls.length).toBe(0);
    }
  });

  test("unsealApiKey takes two arguments and no key id", () => {
    expect(unsealApiKey.length).toBe(2);
  });
});

const twoLines = (keyId: string, b64 = SECRET_B64) => `PLAINTEXT: ${b64}\nKEYID: ${keyId}\n`;

/** A fake process: records argv, prints what it is told. No docker, no network, no AWS. */
function fakeExec(stdout: string, exitCode = 0, calls: string[][] = []): KmstoolExec {
  return async (argv) => {
    calls.push([...argv]);
    return { exitCode, stdout };
  };
}

function viaHelper(exec: KmstoolExec): UnsealDeps {
  return { pcr0: PCR, pcrs: { pcr1: PCR, pcr2: PCR }, credentials: creds, runKmstool: kmstoolReplyRunner(exec) };
}

describe("kmstool_reply stdout parser", () => {
  test("two lines give the plaintext and the reply key id", () => {
    for (const out of [twoLines(ARN), twoLines(ARN).trimEnd()]) {
      const r = parseKmstoolReplyStdout(out);
      expect(r.ok).toBe(true);
      if (r.ok) expect(r.value).toEqual({ plaintextB64: SECRET_B64, replyKeyId: ARN });
    }
  });

  test("the old kmstool_enclave_cli output, with no KEYID line, is refused", () => {
    const r = parseKmstoolReplyStdout(`PLAINTEXT: ${SECRET_B64}\n`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("BAD_REPLY");
  });

  test("any other shape is refused", () => {
    const bad = [
      "",
      "nothing here",
      `KEYID: ${ARN}\nPLAINTEXT: ${SECRET_B64}\n`,
      `PLAINTEXT: ${SECRET_B64}\nPLAINTEXT: ${SECRET_B64}\nKEYID: ${ARN}\n`,
      `PLAINTEXT: ${SECRET_B64}\nKEYID: ${ARN}\nKEYID: ${ARN}\n`,
      `PLAINTEXT: ${SECRET_B64}\r\nKEYID: ${ARN}\r\n`,
      `noise\n${twoLines(ARN)}`,
      `${twoLines(ARN)}noise\n`,
      `PLAINTEXT: ${SECRET_B64}\nKEYID: alias/writ-dev\n`,
      `PLAINTEXT: ${SECRET_B64}\nKEYID: \n`,
      `PLAINTEXT: not*base64\nKEYID: ${ARN}\n`,
      `PLAINTEXT:  ${SECRET_B64}\nKEYID: ${ARN}\n`,
      `PLAINTEXT: ${SECRET_B64}\nKEYID: ${ARN} extra\n`,
      `PLAINTEXT: ${"A".repeat(70_000)}\nKEYID: ${ARN}\n`,
    ];
    for (const out of bad) expect(parseKmstoolReplyStdout(out).ok).toBe(false);
  });
});

describe("unseal through kmstool_reply", () => {
  test("argv[0] is kmstool_reply and the matching KEYID returns the plaintext", async () => {
    const calls: string[][] = [];
    const r = await unsealApiKey(randomBytes(64), viaHelper(fakeExec(twoLines(ARN), 0, calls)));
    expect(r.ok).toBe(true);
    if (r.ok) expect(Array.from(r.value)).toEqual(Array.from(SECRET));
    expect(calls.length).toBe(1);
    expect(calls[0]![0]).toBe(KMSTOOL_REPLY_PATH);
    expect(calls[0]![calls[0]!.indexOf("--key-id") + 1]).toBe(ARN);
    expect(calls[0]!.includes("--debug-mode")).toBe(false);
  });

  test("a KEYID for another key is KEY_ID_MISMATCH, once, with no plaintext", async () => {
    for (let i = 0; i < 25; i++) {
      const other = `arn:aws:kms:us-west-2:401046276943:key/${randomUUID()}`;
      const calls: string[][] = [];
      const r = await unsealApiKey(randomBytes(64), viaHelper(fakeExec(twoLines(other), 0, calls)));
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error.code).toBe("KEY_ID_MISMATCH");
      expect(calls.length).toBe(1);
    }
    for (const other of [ARN.replace(/key\/.*/, (m) => m.toUpperCase()), ARN.replace("us-west-2", "us-east-1"), ARN.replace("401046276943", "111111111111")]) {
      const r = await unsealApiKey(randomBytes(64), viaHelper(fakeExec(twoLines(other))));
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error.code).toBe("KEY_ID_MISMATCH");
    }
  });

  test("no KEYID line, a non-zero exit or a throwing exec declines without plaintext", async () => {
    const cases: KmstoolExec[] = [
      fakeExec(`PLAINTEXT: ${SECRET_B64}\n`),
      fakeExec(twoLines(ARN), 1),
      async () => {
        throw new Error(`boom ${creds.secretAccessKey}`);
      },
    ];
    for (const exec of cases) {
      const r = await unsealApiKey(randomBytes(64), viaHelper(exec));
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.error.code).toBe("KMSTOOL_FAILED");
        expect(r.error.message.includes(creds.secretAccessKey)).toBe(false);
        expect(r.error.message.includes(SECRET_B64)).toBe(false);
      }
    }
  });

  test("the runner refuses any binary other than kmstool_reply and never calls exec", async () => {
    const calls: string[][] = [];
    const run = kmstoolReplyRunner(fakeExec(twoLines(ARN), 0, calls));
    for (const bin of ["/usr/bin/kmstool_enclave_cli", "/bin/sh", ""]) {
      const r = await run([bin, "decrypt"]);
      expect(r.ok).toBe(false);
    }
    expect(calls.length).toBe(0);
  });

  test("zero PCRs decline before exec runs", async () => {
    const calls: string[][] = [];
    const d = { ...viaHelper(fakeExec(twoLines(ARN), 0, calls)), pcrs: { pcr1: ZERO_PCR, pcr2: PCR } };
    expect((await unsealApiKey(randomBytes(64), d)).ok).toBe(false);
    expect((await unsealApiKey(randomBytes(64), { ...d, pcr0: ZERO_PCR, pcrs: {} })).ok).toBe(false);
    expect(calls.length).toBe(0);
  });

  test("a key id handed to deps is refused before exec runs", async () => {
    const calls: string[][] = [];
    const d = { ...viaHelper(fakeExec(twoLines(ARN), 0, calls)), keyId: ARN } as UnsealDeps;
    const r = await unsealApiKey(randomBytes(64), d);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe("KEY_ID_FORBIDDEN");
    expect(calls.length).toBe(0);
  });
});

describe("bunSpawnExec", () => {
  test("returns stdout and the exit code of a local process, with an empty environment", async () => {
    const ok = await bunSpawnExec(["/bin/sh", "-c", 'printf "PLAINTEXT: QQ==\\nKEYID: x\\n"; printf "ignored" >&2']);
    expect(ok).toEqual({ exitCode: 0, stdout: "PLAINTEXT: QQ==\nKEYID: x\n" });
    const fail = await bunSpawnExec(["/bin/sh", "-c", "exit 3"]);
    expect(fail.exitCode).toBe(3);
    const env = await bunSpawnExec(["/usr/bin/env"]);
    expect(env.stdout).toBe("");
  });

  test("output over the limit throws instead of returning", async () => {
    await expect(bunSpawnExec(["/bin/sh", "-c", "head -c 70000 /dev/zero"])).rejects.toThrow();
  });
});

describe("boot wiring", () => {
  test("unsealAtBoot fails closed without NSM and with zero PCRs, and passes with real-looking ones", async () => {
    const runKmstool = async () => okReply(ARN)();
    const base = { ciphertext: randomBytes(64), credentials: creds, runKmstool };
    expect((await unsealAtBoot({ ...base, nsm: unavailableNsm })).ok).toBe(false);
    expect((await unsealAtBoot({ ...base, nsm: fixedNsm({ pcr0: ZERO_PCR, pcr1: ZERO_PCR, pcr2: ZERO_PCR }) })).ok).toBe(false);
    expect((await unsealAtBoot({ ...base, nsm: fixedNsm({ pcr0: PCR, pcr1: PCR, pcr2: PCR }) })).ok).toBe(true);
  });
});

describe("image files", () => {
  const read = (p: string) => readFileSync(new URL(`../${p}`, import.meta.url), "utf8");
  const owned = [
    "enclave/Dockerfile",
    "enclave/boot.sh",
    "enclave/config/README.md",
    "enclave/config/kms.json",
    "enclave/kmstool-reply/main.c",
    "enclave/kmstool-reply/CMakeLists.txt",
    "enclave/kmstool-reply/README.md",
    "src/host/kms-unseal.ts",
    "src/host/nsm.ts",
    "src/host/enclave.ts",
    "scripts/eif.ts",
  ];

  test("kmstool_reply prints the two lines on stdout only, and stderr never carries a secret", () => {
    const c = read("enclave/kmstool-reply/main.c");
    const stdoutWrites = c.match(/fprintf\(stdout,[^;]*;/gs) ?? [];
    expect(stdoutWrites.length).toBe(1);
    expect(stdoutWrites[0]).toContain('"PLAINTEXT: %s\\nKEYID: %s\\n"');
    expect(stdoutWrites[0]).toContain("resp->key_id");
    expect(/\bprintf\(|puts\(|\bwrite\(1/.test(c)).toBe(false);
    for (const line of c.split("\n").filter((l) => l.includes("stderr"))) {
      expect(/plaintext|secret|session_token|ciphertext_b64|access_key/.test(line.replace(/"[^"]*"/g, ""))).toBe(false);
    }
    expect(c).toContain("aws_string_eq(resp->key_id, req->key_id)");
  });

  test("kmstool_reply pulls in no git dependency", () => {
    const cm = read("enclave/kmstool-reply/CMakeLists.txt");
    expect(/FetchContent|ExternalProject|GIT_TAG|GIT_REPOSITORY/.test(cm)).toBe(false);
    expect(cm).toContain("f2dbc3fb1ab9b4496ff8ebc077d24e5f24265923");
  });

  test("no debug flag and no em dash in any owned file", () => {
    for (const p of owned) {
      const t = read(p);
      expect(t.includes("--debug-mode")).toBe(false);
      expect(t.includes("\u2014")).toBe(false);
    }
  });

  test("every FROM is pinned by digest and nothing copies the whole context", () => {
    const d = read("enclave/Dockerfile");
    for (const line of d.split("\n").filter((l) => l.startsWith("FROM "))) expect(line).toMatch(/@sha256:[0-9a-f]{64}/);
    expect(/^COPY\s+\.\s/m.test(d)).toBe(false);
    expect(/\.env/.test(d.replace(/#.*$/gm, ""))).toBe(false);
  });
});
