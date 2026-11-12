import { describe, expect, test } from "bun:test";
import { randomBytes } from "node:crypto";
import {
  CHECKPOINT_PREFIX,
  ROUTES,
  assertNoDebug,
  attackCheckpointTamper,
  attackDebugUnseal,
  attackEditedWrit,
  attackEnclaveMemory,
  attackForgedKeyWrit,
  attackKmsDecrypt,
  attackLedgerForge,
  attackRaCapture,
  attackRaGuess,
  attackReadKey,
  captureIsCiphertext,
  debugRunArgv,
  exitCodeFor,
  formatLine,
  istLabel,
  keyHitsInText,
  parseArgs,
  restartArgv,
  runAll,
  scrub,
  type AttackResult,
  type ExecOptions,
  type ExecResult,
  type FetchInit,
  type HostDeps,
  type HttpReply,
  type Options,
} from "../scripts/host-attack";
import { generateApproverKeys, signWrit } from "../src/core/writ";

const PCR0 = "ab".repeat(48);
const ZERO = "0".repeat(96);
const BOOT = "/opt/writ/scripts/boot-serve-host.sh";
// Built at run time so no file in the repo holds a credential-shaped literal.
const FAKE_KEY_ID = ["AS", "IA", "Q".repeat(16)].join("");
const FAKE_SECRET = ["fakeSecret", "Value", "x9Y8z7W6v5U4t3S2r1Q0p9O8n7M6"].join("");
const FAKE_TOKEN = ["Fake", "Session", "Token", "Zz09".repeat(30)].join("");
const CIPHER = randomBytes(220);
const RA_CIPHER = randomBytes(180);
const KEY_VAR = ["AIRWALLEX", "API", "KEY"].join("_");
const TEST_PAN = "4111" + "1111".repeat(3);

const ok = (stdout = ""): ExecResult => ({ code: 0, stdout, stderr: "" });
const err = (code: string): ExecResult => ({ code: 254, stdout: "", stderr: `An error occurred (${code}) when calling the operation: refused` });

interface Fake {
  deps: HostDeps;
  calls: string[][];
  stdins: (string | undefined)[];
  posts: { path: string; body: unknown }[];
  wiped: string[];
  temps: Map<string, string>;
}

type Handler = (argv: readonly string[], opts?: ExecOptions) => ExecResult | undefined;
type Route = (init?: FetchInit) => HttpReply;

function enclaveList(flags = "NONE", pcr0 = PCR0, id = "i-0abc-enc1") {
  return JSON.stringify([{ EnclaveID: id, State: "RUNNING", Flags: flags, Measurements: { PCR0: pcr0 } }]);
}

function fake(opts: { exec?: Handler; routes?: Record<string, Route>; files?: Record<string, string>; envs?: { pid: number; vars: string[] }[]; tee?: Uint8Array; devMem?: boolean } = {}): Fake {
  const calls: string[][] = [];
  const stdins: (string | undefined)[] = [];
  const posts: { path: string; body: unknown }[] = [];
  const wiped: string[] = [];
  const temps = new Map<string, string>();
  let debugRunning = false;
  let tempN = 0;
  const files: Record<string, string> = { [BOOT]: "#!/bin/bash\nnitro-cli run-enclave --eif-path /opt/writ/writ.eif --cpu-count 2 --memory 3072 --enclave-cid 16\n", ...opts.files };
  const routes: Record<string, Route> = {
    [ROUTES.state]: () => ({ status: 200, body: JSON.stringify({ head: "h0".repeat(32), verified: true }) }),
    [ROUTES.writs]: () => ({ status: 200, body: JSON.stringify({ status: "DECLINED", code: "WRIT_BAD_SIGNATURE", reason: "bad signature" }) }),
    [ROUTES.remoteAuth]: () => ({ status: 200, body: JSON.stringify({ card_transaction_event_id: "x", response_status: "DECLINED", status_reason: "bad signature" }) }),
    [ROUTES.attestation]: () => ({ status: 200, body: "cbor" }),
    ...opts.routes,
  };
  const base: Handler = (argv) => {
    const a = argv.join(" ");
    if (a.startsWith("nitro-cli describe-enclaves")) return ok(debugRunning ? enclaveList("DEBUG_MODE", ZERO, "i-0abc-dbg") : enclaveList());
    if (a.startsWith("nitro-cli run-enclave")) {
      debugRunning = argv.includes("--" + "debug-mode");
      return ok('{"EnclaveID": "i-0abc-dbg"}\nDECLINED PCR_ZERO\n');
    }
    if (a.startsWith("nitro-cli terminate-enclave")) {
      debugRunning = false;
      return ok("{}");
    }
    if (a.startsWith("nitro-cli console")) return { code: 1, stdout: "", stderr: "Enclave was not started in debug mode" };
    if (a.startsWith("aws secretsmanager")) return ok(JSON.stringify({ ciphertext: CIPHER.toString("base64"), raCiphertext: RA_CIPHER.toString("base64") }));
    if (a.startsWith("aws kms decrypt")) return err("AccessDeniedException");
    if (a.startsWith("aws s3api list-objects-v2")) return ok(JSON.stringify([`${CHECKPOINT_PREFIX}000000000003.json`]));
    if (a.startsWith("aws s3 cp")) return ok(JSON.stringify({ seq: 3, head: "c3".repeat(32) }));
    if (a.startsWith("aws s3api head-object")) return ok('"etag-1"');
    if (a.startsWith("aws s3api list-object-versions")) return ok(JSON.stringify({ Versions: [{ Key: argv[argv.indexOf("--prefix") + 1], VersionId: "v1", IsLatest: true }] }));
    if (a.startsWith("aws s3api delete-object")) return err("AccessDenied");
    if (a.startsWith("aws s3api put-object-retention")) return err("AccessDenied");
    if (a.startsWith("aws s3api put-object")) return a.includes("000000000003.json") ? err("PreconditionFailed") : ok('{"ETag":"new"}');
    if (a.includes("169.254.169.254/latest/api/token")) return ok("imds-token");
    if (a.endsWith("/security-credentials/")) return ok("writ-host-role");
    if (a.includes("/security-credentials/writ-host-role")) return ok(JSON.stringify({ AccessKeyId: FAKE_KEY_ID, SecretAccessKey: FAKE_SECRET, Token: FAKE_TOKEN }));
    if (argv[0] === "curl") return ok("200");
    if (argv[0] === "bash") {
      debugRunning = false;
      return ok("REPLY UNSEALED 64\nISSUER CN=YE2\n");
    }
    return undefined;
  };
  const deps: HostDeps = {
    async exec(argv, o) {
      calls.push([...argv]);
      stdins.push(o?.stdin);
      return opts.exec?.(argv, o) ?? base(argv, o) ?? { code: 127, stdout: "", stderr: "not found" };
    },
    async fetch(path, init) {
      const route = path.split("?")[0] ?? path;
      if (init?.method === "POST") posts.push({ path: route, body: init.body ? JSON.parse(init.body) : undefined });
      const r = routes[route];
      return r ? r(init) : { status: 404, body: "not found" };
    },
    spawnBackground: (argv) => {
      calls.push(["spawn", ...argv]);
      return { stop: () => calls.push(["stop"]) };
    },
    processEnvs: () => opts.envs ?? [{ pid: 10, vars: ["PATH=/usr/bin", "HOME=/root"] }],
    walkFiles: (root) => Object.keys(files).filter((f) => f.startsWith(root)),
    readSmall: (path) => temps.get(path) ?? files[path],
    writeTemp(data) {
      const p = `/tmp/fake-${++tempN}`;
      temps.set(p, typeof data === "string" ? data : Buffer.from(data).toString("base64"));
      return p;
    },
    wipe(path) {
      wiped.push(path);
      temps.delete(path);
    },
    readDevMem: () => (opts.devMem ? { ok: true } : { ok: false, code: "EPERM" }),
    async tee(fn) {
      await fn(40123);
      return opts.tee ?? new Uint8Array([0x16, 0x03, 0x01, 0x02, 0x00, ...randomBytes(600)]);
    },
    sleep: async () => undefined,
    now: (() => {
      let t = Date.parse("2026-11-12T10:10:00Z");
      return () => new Date((t += 1_000));
    })(),
    randomBytes: (n) => new Uint8Array(randomBytes(n)),
    uuid: () => crypto.randomUUID(),
    ownPid: 1,
  };
  return { deps, calls, stdins, posts, wiped, temps };
}

const options = (over: Partial<Options> = {}): Options => ({
  withDebug: false,
  withRestart: false,
  allowLedgerWrite: false,
  bootScript: BOOT,
  checkpointPrefix: CHECKPOINT_PREFIX,
  ...over,
});

const one = (r: AttackResult | AttackResult[], name: string): AttackResult => {
  const list = Array.isArray(r) ? r : [r];
  const found = list.find((x) => x.name === name);
  if (!found) throw new Error(`no result ${name}`);
  return found;
};

describe("read-key", () => {
  test("FAILED when nothing holds a key and the secret is ciphertext", async () => {
    const f = fake({ files: { "/opt/writ/.env.example": `${KEY_VAR}=\n`, "/etc/hosts": "127.0.0.1 localhost\n" } });
    const r = await attackReadKey(f.deps);
    expect(r.status).toBe("FAILED");
    expect(r.evidence).toContain("KMS ciphertext only");
    expect(r.evidence).toContain(`ciphertext ${CIPHER.length} bytes`);
    expect(r.evidence).not.toContain(CIPHER.toString("base64").slice(0, 20));
  });

  test("PROBLEM when a process env holds a key", async () => {
    const f = fake({ envs: [{ pid: 77, vars: [`${KEY_VAR}=${FAKE_SECRET}`] }] });
    const r = await attackReadKey(f.deps);
    expect(r.status).toBe("PROBLEM");
    expect(r.evidence).toContain(`pid 77 ${KEY_VAR}`);
    expect(r.evidence).not.toContain(FAKE_SECRET);
  });

  test("PROBLEM when a file on disk holds a key", async () => {
    const f = fake({ files: { "/root/.env": `export ${KEY_VAR}="${FAKE_SECRET}"\n` } });
    const r = await attackReadKey(f.deps);
    expect(r.status).toBe("PROBLEM");
    expect(r.evidence).toContain("/root/.env");
    expect(r.evidence).not.toContain(FAKE_SECRET);
  });

  test("PROBLEM when Secrets Manager holds plaintext", async () => {
    const f = fake({ exec: (a) => (a[1] === "secretsmanager" ? ok(JSON.stringify({ apiKey: "plain words for a key value here" })) : undefined) });
    expect((await attackReadKey(f.deps)).status).toBe("PROBLEM");
  });

  test("placeholders and empty slots are not keys", () => {
    expect(keyHitsInText(`${KEY_VAR}=\nexport AWX_API_KEY="<sandbox-api-key>"\n`)).toEqual([]);
    expect(keyHitsInText(`${KEY_VAR}: process.env.${KEY_VAR},\n`)).toEqual([]);
    expect(keyHitsInText(`${KEY_VAR}=${FAKE_SECRET}\n`)).toEqual([KEY_VAR]);
  });
});

describe("kms-decrypt", () => {
  test("FAILED on AccessDeniedException for both blobs, temp files wiped", async () => {
    const f = fake();
    const r = await attackKmsDecrypt(f.deps);
    expect(r.status).toBe("FAILED");
    expect(r.evidence).toBe("ciphertext: AccessDeniedException, raCiphertext: AccessDeniedException");
    expect(f.temps.size).toBe(0);
    const decrypts = f.calls.filter((c) => c[1] === "kms");
    expect(decrypts).toHaveLength(2);
    for (const c of decrypts) expect(c).toContain("KeyId");
  });

  test("PROBLEM when decrypt succeeds", async () => {
    const f = fake({ exec: (a) => (a[1] === "kms" ? ok("arn:aws:kms:key") : undefined) });
    const r = await attackKmsDecrypt(f.deps);
    expect(r.status).toBe("PROBLEM");
    expect(r.evidence).toContain("decrypt succeeded");
  });
});

describe("debug-unseal", () => {
  test("SKIPPED without --with-debug and nothing is terminated", async () => {
    const f = fake();
    const r = await attackDebugUnseal(f.deps, options());
    expect(one(r, "debug-unseal").status).toBe("SKIPPED");
    expect(f.calls.some((c) => c.includes("terminate-enclave"))).toBe(false);
  });

  test("FAILED when the debug enclave has zero PCRs and declines, then production restarts without debug", async () => {
    const f = fake();
    const r = await attackDebugUnseal(f.deps, options({ withDebug: true }));
    const d = one(r, "debug-unseal");
    expect(d.status).toBe("FAILED");
    expect(d.evidence).toContain("debug Flags DEBUG_MODE");
    expect(d.evidence).toContain("debug PCR0 all zeros");
    expect(d.evidence).toContain("production Flags NONE");
    expect(d.evidence).toContain("DECLINED PCR_ZERO");
    expect(one(r, "production-restart").status).toBe("FAILED");

    const runIdx = f.calls.findIndex((c) => c.includes("run-enclave"));
    const restartIdx = f.calls.findIndex((c) => c[0] === "bash");
    expect(runIdx).toBeGreaterThan(-1);
    expect(restartIdx).toBeGreaterThan(runIdx);
    expect(f.calls[restartIdx]!.some((a) => /debug/i.test(a))).toBe(false);
    expect(f.calls.slice(restartIdx).flat().some((a) => /debug/i.test(a))).toBe(false);
    expect(f.temps.size).toBe(0);
    for (const line of r.map(formatLine)) {
      expect(line).not.toContain(FAKE_SECRET);
      expect(line).not.toContain(FAKE_KEY_ID);
    }
  });

  test("FAILED when the console shows an all-zero PCR and the enclave exits before describe sees it", async () => {
    const f = fake({
      exec: (a) => {
        if (a[0] === "nitro-cli" && a[1] === "run-enclave") {
          return ok('{"EnclaveID": "i-0abc-dbg"}\nwrit-nsm-pcrs: PCR is all zeros\nDECLINED NSM_READ_FAILED\n');
        }
        if (a[0] === "nitro-cli" && a[1] === "describe-enclaves") return ok(enclaveList());
        return undefined;
      },
    });
    const r = await attackDebugUnseal(f.deps, options({ withDebug: true }));
    const d = one(r, "debug-unseal");
    expect(d.status).toBe("FAILED");
    expect(d.evidence).toContain("PCR is all zeros");
    expect(d.evidence).toContain("DECLINED NSM_READ_FAILED");
    expect(d.evidence).toContain("never asked KMS");
    expect(d.evidence).not.toContain("UNSEALED");
    expect(one(r, "production-restart").status).toBe("FAILED");
  });

  test("PROBLEM when the debug enclave unseals", async () => {
    const f = fake({ files: { "/var/log/writ-unseal-reply.log": "UNSEALED 64 LEDGER_PUB ed25519:aa\n" } });
    const r = await attackDebugUnseal(f.deps, options({ withDebug: true }));
    expect(one(r, "debug-unseal").status).toBe("PROBLEM");
    expect(f.calls.some((c) => c[0] === "bash")).toBe(true);
  });

  test("PROBLEM and production untouched when the boot script mentions debug", async () => {
    const f = fake({ files: { [BOOT]: `nitro-cli run-enclave --eif-path x ${"--" + "debug-mode"}\n` } });
    const r = await attackDebugUnseal(f.deps, options({ withDebug: true }));
    expect(one(r, "debug-unseal").status).toBe("PROBLEM");
    expect(f.calls.some((c) => c.includes("terminate-enclave"))).toBe(false);
  });

  test("PROBLEM on restart when the restarted enclave comes back in debug mode", async () => {
    const f = fake({ exec: (a) => (a[0] === "bash" ? ok("") : a.join(" ").startsWith("nitro-cli describe") && f.calls.some((c) => c[0] === "bash") ? ok(enclaveList("DEBUG_MODE")) : undefined) });
    const r = await attackDebugUnseal(f.deps, options({ withDebug: true }));
    expect(one(r, "production-restart").status).toBe("PROBLEM");
  });
});

describe("restart command", () => {
  test("has no debug flag", () => {
    const argv = restartArgv(BOOT);
    expect(argv).toEqual(["bash", BOOT]);
    expect(argv.join(" ")).not.toMatch(/debug/i);
  });

  test("refuses anything that mentions debug", () => {
    expect(() => restartArgv("/opt/writ/scripts/boot-debug.sh")).toThrow();
    expect(() => assertNoDebug(["nitro-cli", "run-enclave", "--" + "debug-mode"])).toThrow();
  });

  test("only the debug attack argv carries the debug flag", () => {
    expect(debugRunArgv()).toContain("--" + "debug-mode");
    expect(debugRunArgv()).toContain("--attach-console");
  });
});

describe("writ attacks", () => {
  test("forged key: FAILED on WRIT_BAD_SIGNATURE", async () => {
    const f = fake();
    const r = await attackForgedKeyWrit(f.deps);
    expect(r.status).toBe("FAILED");
    expect(r.evidence).toContain("WRIT_BAD_SIGNATURE");
    expect(f.posts[0]?.path).toBe(ROUTES.writs);
    expect((f.posts[0]?.body as { writ: { signature: string } }).writ.signature.length).toBeGreaterThan(0);
  });

  test("forged key: PROBLEM when the enclave arms", async () => {
    const f = fake({ routes: { [ROUTES.writs]: () => ({ status: 200, body: JSON.stringify({ status: "AUTHORIZED", armed: true }) }) } });
    expect((await attackForgedKeyWrit(f.deps)).status).toBe("PROBLEM");
  });

  test("forged key: PROBLEM when the route is not live", async () => {
    const f = fake({ routes: { [ROUTES.writs]: () => ({ status: 404, body: "not found" }) } });
    const r = await attackForgedKeyWrit(f.deps);
    expect(r.status).toBe("PROBLEM");
    expect(r.evidence).toContain("not live");
  });

  test("forged key: PROBLEM when a different check stopped it", async () => {
    const f = fake({ routes: { [ROUTES.writs]: () => ({ status: 200, body: JSON.stringify({ status: "DECLINED", code: "NO_WRIT_FOR_CARD" }) }) } });
    expect((await attackForgedKeyWrit(f.deps)).status).toBe("PROBLEM");
  });

  const realWrit = () => {
    const keys = generateApproverKeys();
    return signWrit(
      { id: "w-1", team: "research", agent: "a", runId: "r", purpose: "p", merchantName: "DataCo", mcc: "5734", amountMinor: 5000, currency: "USD", expiresAt: "2026-11-12T12:00:00Z", nonce: "n" },
      "2026-11-12T10:00:00Z",
      keys.privateKeyPem,
    );
  };

  test("edited amount: SKIPPED without --signed-writ", async () => {
    expect((await attackEditedWrit(fake().deps, options())).status).toBe("SKIPPED");
  });

  test("edited amount: FAILED on WRIT_HASH_MISMATCH and the amount really changed", async () => {
    const f = fake({
      files: { "/tmp/w.json": JSON.stringify({ writ: realWrit() }) },
      routes: { [ROUTES.writs]: () => ({ status: 200, body: JSON.stringify({ status: "DECLINED", code: "WRIT_HASH_MISMATCH" }) }) },
    });
    const r = await attackEditedWrit(f.deps, options({ signedWrit: "/tmp/w.json" }));
    expect(r.status).toBe("FAILED");
    expect(r.evidence).toContain("5000 to 15000 cents");
    expect((f.posts[0]?.body as { writ: { amountMinor: number } }).writ.amountMinor).toBe(15000);
  });

  test("edited amount: PROBLEM when it arms", async () => {
    const f = fake({
      files: { "/tmp/w.json": JSON.stringify(realWrit()) },
      routes: { [ROUTES.writs]: () => ({ status: 200, body: JSON.stringify({ status: "AUTHORIZED", armed: true }) }) },
    });
    expect((await attackEditedWrit(f.deps, options({ signedWrit: "/tmp/w.json" }))).status).toBe("PROBLEM");
  });
});

describe("ledger-forge", () => {
  test("SKIPPED without --allow-ledger-write and nothing is written", async () => {
    const f = fake();
    const r = await attackLedgerForge(f.deps, options());
    expect(one(r, "ledger-forge").status).toBe("SKIPPED");
    expect(f.calls.some((c) => c.includes("put-object"))).toBe(false);
  });

  test("FAILED without restart when the running head is unchanged", async () => {
    const f = fake();
    const r = await attackLedgerForge(f.deps, options({ allowLedgerWrite: true }));
    const l = one(r, "ledger-forge");
    expect(l.status).toBe("FAILED");
    expect(l.evidence).toContain(`${CHECKPOINT_PREFIX}000000000004.json`);
    const put = f.calls.find((c) => c.includes("put-object"))!;
    expect(put).toContain("--if-none-match");
    expect(put).toContain("--content-md5");
  });

  test("PROBLEM without restart when the enclave adopts the forged head", async () => {
    let forgedHead = "";
    const f = fake({ routes: { [ROUTES.state]: () => ({ status: 200, body: JSON.stringify({ head: forgedHead || "h0".repeat(32) }) }) } });
    const write = f.deps.writeTemp;
    f.deps.writeTemp = (data) => {
      const head = (JSON.parse(String(data)) as { head?: string }).head;
      if (head) forgedHead = head;
      return write(data);
    };
    const r = await attackLedgerForge(f.deps, options({ allowLedgerWrite: true }));
    expect(one(r, "ledger-forge").status).toBe("PROBLEM");
    expect(one(r, "ledger-forge").evidence).toContain("forged head");
  });

  test("FAILED with restart when state is STATE_UNVERIFIED", async () => {
    let restarted = false;
    const f = fake({
      exec: (a) => {
        if (a[0] === "bash") restarted = true;
        return undefined;
      },
      routes: { [ROUTES.state]: () => ({ status: 200, body: JSON.stringify(restarted ? { head: "h0".repeat(32), verified: false, code: "STATE_UNVERIFIED" } : { head: "h0".repeat(32) }) }) },
    });
    const r = await attackLedgerForge(f.deps, options({ allowLedgerWrite: true, withRestart: true }));
    expect(one(r, "ledger-forge").status).toBe("FAILED");
    expect(one(r, "production-restart").status).toBe("FAILED");
    expect(f.calls.find((c) => c[0] === "bash")!.join(" ")).not.toMatch(/debug/i);
  });

  test("PROBLEM with restart when the enclave still decides normally", async () => {
    const f = fake();
    const r = await attackLedgerForge(f.deps, options({ allowLedgerWrite: true, withRestart: true }));
    expect(one(r, "ledger-forge").status).toBe("PROBLEM");
  });

  test("FAILED when S3 refuses the put", async () => {
    const f = fake({ exec: (a) => (a.includes("put-object") ? err("AccessDenied") : undefined) });
    expect(one(await attackLedgerForge(f.deps, options({ allowLedgerWrite: true })), "ledger-forge").status).toBe("FAILED");
  });
});

describe("checkpoint-delete-overwrite", () => {
  test("FAILED when delete, version delete, retention and overwrite are all refused", async () => {
    const f = fake();
    const r = await attackCheckpointTamper(f.deps, options());
    expect(r.status).toBe("FAILED");
    expect(r.evidence).toContain("delete AccessDenied");
    expect(r.evidence).toContain("delete version AccessDenied");
    expect(r.evidence).toContain("shorten lock AccessDenied");
    expect(r.evidence).toContain("overwrite PreconditionFailed");
    expect(r.evidence).toContain("etag unchanged");
  });

  test("PROBLEM when a delete goes through", async () => {
    const f = fake({ exec: (a) => (a.includes("delete-object") ? ok("{}") : undefined) });
    expect((await attackCheckpointTamper(f.deps, options())).status).toBe("PROBLEM");
  });

  test("PROBLEM when the etag changes", async () => {
    let n = 0;
    const f = fake({ exec: (a) => (a.includes("head-object") ? ok(`"etag-${++n}"`) : undefined) });
    expect((await attackCheckpointTamper(f.deps, options())).status).toBe("PROBLEM");
  });
});

describe("remote auth", () => {
  test("guessed signature: FAILED on DECLINED bad signature with a fresh nonce", async () => {
    let headers: Record<string, string> = {};
    const f = fake({
      routes: {
        [ROUTES.remoteAuth]: (init) => {
          headers = init?.headers ?? {};
          return { status: 200, body: JSON.stringify({ response_status: "DECLINED", status_reason: "bad signature" }) };
        },
      },
    });
    const r = await attackRaGuess(f.deps);
    expect(r.status).toBe("FAILED");
    expect(headers["x-nonce"]).toMatch(/^\d{13}\.[0-9a-f]{32}$/);
    expect(headers["x-signature"]?.length).toBeGreaterThan(0);
  });

  test("guessed signature: PROBLEM when another reason means the signature passed", async () => {
    const f = fake({ routes: { [ROUTES.remoteAuth]: () => ({ status: 200, body: JSON.stringify({ response_status: "DECLINED", status_reason: "stale nonce" }) }) } });
    expect((await attackRaGuess(f.deps)).status).toBe("PROBLEM");
  });

  test("guessed signature: PROBLEM on AUTHORIZED", async () => {
    const f = fake({ routes: { [ROUTES.remoteAuth]: () => ({ status: 200, body: JSON.stringify({ response_status: "AUTHORIZED", status_reason: "ok" }) }) } });
    expect((await attackRaGuess(f.deps)).status).toBe("PROBLEM");
  });

  test("capture: FAILED when the relay carried TLS records only", async () => {
    const f = fake();
    const r = await attackRaCapture(f.deps);
    expect(r.status).toBe("FAILED");
    const posted = f.calls.findIndex((c) => c[0] === "curl" && c.includes("POST"));
    expect(f.calls[posted]!.join(" ")).toContain("--resolve 35-95-168-131.sslip.io:40123:127.0.0.1");
    expect(f.stdins[posted]).toContain("card_transaction_event_id");
  });

  test("capture: PROBLEM when plaintext HTTP shows up", async () => {
    const f = fake({ tee: new Uint8Array(Buffer.from("\u0016\u0003POST /remote-auth HTTP/1.1\r\n{\"card_transaction_event_id\":1}", "latin1")) });
    const r = await attackRaCapture(f.deps);
    expect(r.status).toBe("PROBLEM");
    expect(r.evidence).toContain("plaintext seen");
  });

  test("capture: PROBLEM when nothing was relayed", async () => {
    const f = fake({ tee: new Uint8Array(0) });
    expect((await attackRaCapture(f.deps)).status).toBe("PROBLEM");
  });

  test("capture check needs a TLS header", () => {
    expect(captureIsCiphertext(new Uint8Array([1, 2, 3]), "m").ok).toBe(false);
    expect(captureIsCiphertext(new Uint8Array([0x16, 0x03, 0x01, 9]), "m").ok).toBe(true);
  });
});

describe("enclave-memory", () => {
  test("FAILED when console and /dev/mem are refused", async () => {
    const r = await attackEnclaveMemory(fake().deps);
    expect(r.status).toBe("FAILED");
    expect(r.evidence).toContain("console refused");
    expect(r.evidence).toContain("/dev/mem read refused (EPERM)");
  });

  test("PROBLEM when the console connects", async () => {
    const f = fake({ exec: (a) => (a.includes("console") ? ok("boot log") : undefined) });
    expect((await attackEnclaveMemory(f.deps)).status).toBe("PROBLEM");
  });

  test("PROBLEM when /dev/mem is readable", async () => {
    expect((await attackEnclaveMemory(fake({ devMem: true }).deps)).status).toBe("PROBLEM");
  });

  test("PROBLEM when the running enclave is in debug mode", async () => {
    const f = fake({ exec: (a) => (a.join(" ").startsWith("nitro-cli describe") ? ok(enclaveList("DEBUG_MODE", ZERO)) : undefined) });
    expect((await attackEnclaveMemory(f.deps)).status).toBe("PROBLEM");
  });
});

describe("exit code and output", () => {
  const r = (status: AttackResult["status"]): AttackResult => ({ name: "x", status, evidence: "e" });

  test("0 only when no line is PROBLEM", () => {
    expect(exitCodeFor([r("FAILED"), r("SKIPPED")])).toBe(0);
    expect(exitCodeFor([r("FAILED"), r("PROBLEM")])).toBe(1);
    expect(exitCodeFor([])).toBe(1);
  });

  test("line format", () => {
    expect(formatLine({ name: "kms-decrypt", status: "FAILED", evidence: "AccessDeniedException" })).toBe("FAILED kms-decrypt: AccessDeniedException");
  });

  test("IST label", () => {
    expect(istLabel(new Date("2026-11-12T10:10:00Z"))).toBe("Thu Nov 12, 15:40 IST");
  });

  test("scrub removes credentials, base64 and card numbers, keeps hex and paths", () => {
    const s = scrub(`${FAKE_KEY_ID} ${FAKE_TOKEN} ${CIPHER.toString("base64")} ${TEST_PAN} ${PCR0} /opt/writ/scripts/boot-serve-host.sh`);
    expect(s).not.toContain(FAKE_KEY_ID);
    expect(s).not.toContain(FAKE_TOKEN);
    expect(s).not.toContain(TEST_PAN);
    expect(s).toContain(PCR0);
    expect(s).toContain("/opt/writ/scripts/boot-serve-host.sh");
  });

  test("full run with --save: exit 0, every attack printed, no secret shaped strings", async () => {
    const f = fake({ files: { "/tmp/w.json": "{}" } });
    const lines: string[] = [];
    const out = await runAll(f.deps, options({ withDebug: true, allowLedgerWrite: true, save: "/tmp/out.json" }), (l) => lines.push(l));
    expect(out.exitCode).toBe(0);
    for (const n of ["read-key", "kms-decrypt", "debug-unseal", "writ-forged-key", "writ-edited-amount", "ledger-forge", "checkpoint-delete-overwrite", "ra-guessed-signature", "ra-capture", "enclave-memory"]) {
      expect(lines.some((l) => l.includes(` ${n}: `))).toBe(true);
    }
    expect(lines.find((l) => l.includes("writ-edited-amount"))).toMatch(/^SKIPPED/);
    const saved = JSON.stringify(out.save);
    expect(out.save?.pcr0).toBe(PCR0);
    expect(out.save?.flags).toBe("NONE");
    expect(out.save?.at).toMatch(/IST$/);
    for (const bad of [FAKE_KEY_ID, FAKE_SECRET, FAKE_TOKEN, CIPHER.toString("base64").slice(0, 24), RA_CIPHER.toString("base64").slice(0, 24), "imds-token"]) {
      expect(saved).not.toContain(bad);
      expect(lines.join("\n")).not.toContain(bad);
    }
    expect(saved).not.toMatch(/(?:AKIA|ASIA)[A-Za-z0-9]{16}/);
    expect(saved).not.toMatch(/(?<!\d)\d{16}(?!\d)/);
    expect(saved).not.toMatch(/PRIVATE KEY/);
    for (const t of saved.match(/[A-Za-z0-9+/]{40,}={0,2}/g) ?? []) expect(t).toMatch(/^[0-9a-f]+$/);
  });

  test("a PROBLEM anywhere makes the run exit 1", async () => {
    const f = fake({ exec: (a) => (a[1] === "kms" ? ok("arn") : undefined) });
    const out = await runAll(f.deps, options(), () => undefined);
    expect(out.exitCode).toBe(1);
  });
});

describe("arguments", () => {
  test("defaults and flags", () => {
    const o = parseArgs(["--with-debug", "--allow-ledger-write", "--with-restart", "--signed-writ", "/tmp/w.json", "--save", "fixtures/host_attack.json", "--checkpoint-prefix", "checkpoints/v3"]);
    expect(typeof o).toBe("object");
    if (typeof o === "string") return;
    expect(o.withDebug && o.allowLedgerWrite && o.withRestart).toBe(true);
    expect(o.checkpointPrefix).toBe("checkpoints/v3/");
    expect(o.signedWrit).toBe("/tmp/w.json");
  });

  test("refuses unknown args, debug values and restart without the ledger write", () => {
    expect(typeof parseArgs(["--" + "debug-mode"])).toBe("string");
    expect(typeof parseArgs(["--save", "debug.json"])).toBe("string");
    expect(typeof parseArgs(["--boot-script", "/opt/writ/boot-debug.sh"])).toBe("string");
    expect(typeof parseArgs(["--with-restart"])).toBe("string");
  });
});
