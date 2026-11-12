import { afterEach, describe, expect, test } from "bun:test";
import { X509Certificate, createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { spawnSync, spawn } from "node:child_process";
import { canonicalJson } from "../src/core/writ";
import { EGRESS_ALLOWLIST } from "../src/host/enclave-parent";
import {
  ACME_PLAN,
  INBOUND_PLAN,
  RA_HOSTNAME,
  RaRegisterGuard,
  acmePlan,
  certSpkiSha256,
  computeUserData,
  createTlsIdentity,
  selfSignedCertPem,
  startEnclaveTls,
  type EnclaveTlsHandle,
  type EnclaveTlsOptions,
  type RaReply,
} from "../src/host/enclave-tls";

const root = join(import.meta.dir, "..");
const read = (p: string) => readFileSync(join(root, p), "utf8");
const LEDGER_KEY = "ed25519:" + "ab".repeat(32);
const STAGING = "acme-staging-v02.api.letsencrypt.org";
const PRODUCTION = "acme-v02.api.letsencrypt.org";

const reply = (response_status: "AUTHORIZED" | "DECLINED", status_reason: string): RaReply => ({
  status: 200,
  body: { card_transaction_event_id: "evt_1", response_status, status_reason },
});

const handles: EnclaveTlsHandle[] = [];
afterEach(async () => {
  while (handles.length > 0) await handles.pop()!.stop();
});

function start(o: Partial<EnclaveTlsOptions> = {}) {
  const seen: { nonce: Uint8Array; userData: Uint8Array }[] = [];
  const h = startEnclaveTls({
    ledgerPublicKey: LEDGER_KEY,
    handler: () => reply("DECLINED", "bad signature"),
    attest: (nonce, userData) => {
      seen.push({ nonce, userData });
      return new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    },
    port: 0,
    ...o,
  });
  handles.push(h);
  return { h, seen };
}

// keepalive false: a pooled socket to a stopped server on a recycled port would make tests flaky.
const insecure = { tls: { rejectUnauthorized: false }, keepalive: false } as RequestInit;
type Body = { card_transaction_event_id: string; response_status: string; status_reason: string };
const json = async (r: Response) => (await r.json()) as Body;
const post = (h: EnclaveTlsHandle, body = "{}") =>
  fetch(`https://127.0.0.1:${h.port}/remote-auth`, { ...insecure, method: "POST", body, headers: { "content-type": "application/json" } });

describe("TLS key", () => {
  test("is generated inside: options that carry a key or a bind address are refused", () => {
    const base = { ledgerPublicKey: LEDGER_KEY, handler: () => reply("DECLINED", "x"), attest: () => new Uint8Array(1), port: 0 };
    for (const k of ["key", "privateKey", "keyPem", "pem", "tlsKey", "hostname", "host", "debugMode"]) {
      expect(() => startEnclaveTls({ ...base, [k]: "-----BEGIN PRIVATE KEY-----" } as never)).toThrow(/refused/);
    }
  });

  test("the identity exposes only public fields and every call makes a new key", () => {
    const a = createTlsIdentity();
    const b = createTlsIdentity();
    expect(Object.keys(a).sort()).toEqual(["spkiDer", "spkiSha256"]);
    expect(a.spkiSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(a.spkiSha256).not.toBe(b.spkiSha256);
    expect(a.spkiSha256).toBe(createHash("sha256").update(a.spkiDer).digest("hex"));
  });

  test("an identity that was not created here is refused", () => {
    const forged = { spkiDer: new Uint8Array(91), spkiSha256: "ab".repeat(32) };
    expect(() => start({ identity: forged })).toThrow(/not created/);
  });

  test("a certificate for some other key is refused", () => {
    const other = createTlsIdentity();
    const pem = selfSignedCertPem(other, [RA_HOSTNAME], Date.now());
    expect(() => start({ certificatePem: () => pem })).toThrow(/generated TLS key/);
  });

  test("bootstrap certificates always parse and carry the key (300 serials)", () => {
    const id = createTlsIdentity();
    for (let i = 0; i < 300; i++) {
      const pem = selfSignedCertPem(id, [RA_HOSTNAME, "127.0.0.1"], Date.now());
      const x = new X509Certificate(pem);
      expect(x.serialNumber.length).toBe(32);
      expect(certSpkiSha256(pem)).toBe(id.spkiSha256);
    }
  });

  test("selfSignedCertPem only works for identities made here", () => {
    const forged = { spkiDer: new Uint8Array(91), spkiSha256: "00".repeat(32) };
    expect(() => selfSignedCertPem(forged, [RA_HOSTNAME], Date.now())).toThrow();
  });

  test("the served certificate carries the generated key, and the server listens on loopback only", async () => {
    const { h } = start();
    expect(certSpkiSha256(h.certificatePem)).toBe(h.identity.spkiSha256);
    const src = read("src/host/enclave-tls.ts");
    expect(src).toContain('export const TLS_BIND_HOST = "127.0.0.1"');
    expect(src).toMatch(/hostname: TLS_BIND_HOST/);
    const r = await fetch(`https://127.0.0.1:${h.port}/nope`, insecure);
    expect(r.status).toBe(404);
  });
});

describe("user_data", () => {
  const fields = { spkiSha256: "11".repeat(32), ledgerPublicKey: LEDGER_KEY, raUrl: "https://35-95-168-131.sslip.io", rung: "R2" as const };

  test("is sha256 of the canonical JSON of the four fields", () => {
    const want = createHash("sha256").update(canonicalJson(fields)).digest();
    expect(Buffer.from(computeUserData(fields)).equals(want)).toBe(true);
    expect(canonicalJson(fields)).toBe(
      `{"ledgerPublicKey":"${LEDGER_KEY}","raUrl":"https://35-95-168-131.sslip.io","rung":"R2","spkiSha256":"${"11".repeat(32)}"}`,
    );
  });

  test("changes when the SPKI changes", () => {
    const a = computeUserData(fields);
    const b = computeUserData({ ...fields, spkiSha256: "12".repeat(32) });
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  test("two servers get different keys and so different user_data", () => {
    const { h: a } = start();
    const { h: b } = start();
    expect(a.identity.spkiSha256).not.toBe(b.identity.spkiSha256);
    expect(Buffer.from(a.userData).equals(Buffer.from(b.userData))).toBe(false);
    expect(a.userDataFields).toEqual({ spkiSha256: a.identity.spkiSha256, ledgerPublicKey: LEDGER_KEY, raUrl: `https://${RA_HOSTNAME}`, rung: "R2" });
  });

  test("refuses an empty field or another rung", () => {
    expect(() => computeUserData({ ...fields, ledgerPublicKey: "" })).toThrow();
    expect(() => computeUserData({ ...fields, rung: "R1" as never })).toThrow();
  });
});

describe("GET /attestation", () => {
  test("passes the nonce and the server's user_data to attest, fresh per request", async () => {
    const { h, seen } = start();
    const nonce = "a1".repeat(32);
    const r = await fetch(`https://127.0.0.1:${h.port}/attestation?nonce=${nonce}`, insecure);
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toBe("application/cbor");
    expect(new Uint8Array(await r.arrayBuffer())).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
    await fetch(`https://127.0.0.1:${h.port}/attestation?nonce=${"b2".repeat(32)}`, insecure);
    expect(seen.length).toBe(2);
    expect(Buffer.from(seen[0]!.nonce).toString("hex")).toBe(nonce);
    expect(Buffer.from(seen[0]!.userData).equals(Buffer.from(h.userData))).toBe(true);
  });

  test("refuses a short, odd or missing nonce without calling attest", async () => {
    const { h, seen } = start();
    for (const q of ["", "?nonce=abcd", `?nonce=${"a".repeat(65)}`, `?nonce=${"zz".repeat(32)}`]) {
      const r = await fetch(`https://127.0.0.1:${h.port}/attestation${q}`, insecure);
      expect(r.status).toBe(400);
    }
    expect(seen.length).toBe(0);
  });

  test("an attest failure is 503", async () => {
    const { h } = start({ attest: () => { throw new Error("nsm down"); } });
    const r = await fetch(`https://127.0.0.1:${h.port}/attestation?nonce=${"a1".repeat(32)}`, insecure);
    expect(r.status).toBe(503);
  });
});

describe("register guard", () => {
  test("RaRegisterGuard counts only DECLINED with status_reason bad signature", () => {
    const g = new RaRegisterGuard();
    expect(g.registerRaGuard().ok).toBe(false);
    g.noteBadSignatureDecline(reply("DECLINED", "replayed nonce").body);
    g.noteBadSignatureDecline(reply("AUTHORIZED", "bad signature").body);
    g.noteBadSignatureDecline(reply("DECLINED", "Bad signature").body);
    expect(g.registerRaAllowed()).toBe(false);
    g.noteBadSignatureDecline(reply("DECLINED", "bad signature").body);
    expect(g.count).toBe(1);
    expect(g.registerRaGuard()).toEqual({ ok: true });
  });

  test("stays shut until the handler declines a request for a bad signature", async () => {
    const answers = [reply("DECLINED", "stale timestamp"), reply("AUTHORIZED", "ok"), reply("DECLINED", "bad signature")];
    const bodies: string[] = [];
    const { h } = start({
      handler: ({ rawBody }) => {
        bodies.push(new TextDecoder().decode(rawBody));
        return answers.shift()!;
      },
    });
    const shut = h.registerRaGuard();
    expect(shut.ok).toBe(false);
    if (!shut.ok) expect(shut.reason).toContain("bad signature");

    expect((await json(await post(h, '{"a":1}'))).status_reason).toBe("stale timestamp");
    expect(h.registerRaAllowed()).toBe(false);
    expect((await json(await post(h))).response_status).toBe("AUTHORIZED");
    expect(h.registerRaAllowed()).toBe(false);
    const third = await json(await post(h));
    expect(third).toEqual({ card_transaction_event_id: "evt_1", response_status: "DECLINED", status_reason: "bad signature" });
    expect(h.registerRaGuard()).toEqual({ ok: true });
    expect(bodies[0]).toBe('{"a":1}');
  });

  test("a handler that throws is answered DECLINED and does not open the guard", async () => {
    const { h } = start({ handler: () => { throw new Error("boom"); } });
    const r = await post(h);
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ card_transaction_event_id: "", response_status: "DECLINED", status_reason: "internal error" });
    expect(h.registerRaAllowed()).toBe(false);
  });

  test("GET /remote-auth is not handled", async () => {
    const { h } = start();
    expect((await fetch(`https://127.0.0.1:${h.port}/remote-auth`, insecure)).status).toBe(405);
    expect(h.registerRaAllowed()).toBe(false);
  });

  test("the module never calls Airwallex config/update", () => {
    const src = read("src/host/enclave-tls.ts");
    expect(src).not.toMatch(/config\/update|airwallex\.com/);
    expect(src).not.toMatch(/await fetch\(|globalThis\.fetch/);
  });
});

describe("ACME plan", () => {
  test("staging is the default, production maps to acme-v02", () => {
    expect(acmePlan().host).toBe(STAGING);
    expect(acmePlan("production").directoryUrl).toBe(`https://${PRODUCTION}/directory`);
    expect(ACME_PLAN.production).toMatchObject({ loopback: "127.0.0.4", port: 443, vsockPort: 8445 });
    expect(ACME_PLAN.staging).toMatchObject({ loopback: "127.0.0.5", port: 443, vsockPort: 8446 });
    expect(() => acmePlan("live" as never)).toThrow();
    const { h } = start();
    expect(h.acme.mode).toBe("staging");
  });

  test("inbound plan forwards vsock 443 and 80 to the loopback listeners", () => {
    expect(INBOUND_PLAN.map((p) => [p.vsockPort, p.target])).toEqual([
      [443, "127.0.0.1:8443"],
      [80, "127.0.0.1:8080"],
    ]);
  });

  test("boot.sh maps both ACME hosts to their loopback bridges before bun, and starts no TLS server", () => {
    const b = read("enclave/boot.sh");
    const bun = b.indexOf("exec /usr/local/bin/bun run /app/src/host/enclave.ts");
    for (const line of [
      "ip addr add 127.0.0.4/8 dev lo",
      "ip addr add 127.0.0.5/8 dev lo",
      `127.0.0.4 ${PRODUCTION}`,
      `127.0.0.5 ${STAGING}`,
      "socat TCP-LISTEN:443,bind=127.0.0.4,reuseaddr,fork VSOCK-CONNECT:3:8445 &",
      "socat TCP-LISTEN:443,bind=127.0.0.5,reuseaddr,fork VSOCK-CONNECT:3:8446 &",
    ]) {
      const i = b.indexOf(line);
      expect(i).toBeGreaterThan(-1);
      expect(i).toBeLessThan(bun);
    }
    const live = b.split("\n").filter((l) => !l.trim().startsWith("#"));
    expect(live.some((l) => /openssl|lego|certbot|https|OPENSSL-LISTEN|SSL-LISTEN|bun .*serve/i.test(l))).toBe(false);
    expect(b).toContain("127.0.0.1:8443");
    expect(b).toContain("127.0.0.1:8080");
  });

  test("boot.sh starts the inbound VSOCK-LISTEN byte relays before bun, and nothing else listens on vsock", () => {
    const b = read("enclave/boot.sh");
    const bun = b.indexOf("exec /usr/local/bin/bun run /app/src/host/enclave.ts");
    const live = b.split("\n").filter((l) => !l.trim().startsWith("#"));
    const want = [
      "socat VSOCK-LISTEN:443,reuseaddr,fork TCP:127.0.0.1:8443 &",
      "socat VSOCK-LISTEN:80,reuseaddr,fork TCP:127.0.0.1:8080 &",
      "socat VSOCK-LISTEN:5001,reuseaddr,fork TCP:127.0.0.1:5001 &",
    ];
    for (const line of want) {
      expect(live).toContain(line);
      expect(b.indexOf(line)).toBeLessThan(bun);
    }
    expect(live.filter((l) => l.includes("VSOCK-LISTEN"))).toEqual(want);
    // The credential relay is plain TCP to its own port, never the TLS listener, and no public port feeds it.
    expect(live.filter((l) => l.includes("VSOCK-LISTEN:5001"))).toEqual(["socat VSOCK-LISTEN:5001,reuseaddr,fork TCP:127.0.0.1:5001 &"]);
    expect(INBOUND_PLAN.some((p) => (p.vsockPort as number) === 5001)).toBe(false);
    expect(read("scripts/run-serve-host.sh")).not.toMatch(/VSOCK-CONNECT:16:5001/);
    expect(b.includes("--" + "debug-mode")).toBe(false);
    expect(/debug/i.test(live.join("\n"))).toBe(false);
  });
});

describe("allowlists", () => {
  test("the relay lists staging, and instance user data does not", () => {
    const yaml = read("enclave/parent/vsock-proxy.yaml");
    expect(yaml).toContain(`- {address: ${STAGING}, port: 443}`);
    expect(yaml).toContain(`- {address: ${PRODUCTION}, port: 443}`);
    expect(EGRESS_ALLOWLIST).toContainEqual({ host: STAGING, port: 443 });
    expect(EGRESS_ALLOWLIST).toContainEqual({ host: PRODUCTION, port: 443 });
    const stack = read("infra/lib/core-stack.ts");
    const list = /export const VSOCK_ALLOWLIST = \[([^\]]*)\]/.exec(stack)?.[1] ?? "";
    expect(list).toContain(`"${PRODUCTION}"`);
    expect(list).not.toContain(`"${STAGING}"`);
    expect(stack).toContain("replaces the EC2 instance");
  });
});

describe("scripts/run-serve-host.sh", () => {
  const path = join(root, "scripts/run-serve-host.sh");
  const debugFlag = "--" + "debug-mode";

  test("documents the raw TCP forwards and has no debug flag", () => {
    const s = read("scripts/run-serve-host.sh");
    expect(s.includes(debugFlag)).toBe(false);
    expect(s).toContain("socat TCP-LISTEN:443,fork,reuseaddr VSOCK-CONNECT:16:443");
    expect(s).toContain("socat TCP-LISTEN:80,fork,reuseaddr VSOCK-CONNECT:16:80");
    const live = s.split("\n").filter((l) => !l.trim().startsWith("#")).join("\n");
    expect(live).not.toMatch(/nginx|certbot|lego |openssl/);
    expect(readFileSync(path).length).toBeGreaterThan(0);
  });

  test("is executable", () => {
    expect(statSync(path).mode & 0o777).toBe(0o755);
  });

  test("exits 2 when nitro-cli is absent", () => {
    const r = spawnSync("/bin/bash", [path], { encoding: "utf8", env: { PATH: "/usr/bin:/bin" } });
    expect(r.status).toBe(2);
    expect(r.stdout).toContain("VSOCK-CONNECT:16:443");
  });

  test("refuses a debug flag", () => {
    const r = spawnSync("/bin/bash", [path, debugFlag], { encoding: "utf8", env: { PATH: "/usr/bin:/bin" } });
    expect(r.status).toBe(1);
    expect(r.stdout).toBe("");
  });
});

describe("scripts/verify-attestation.ts --url", () => {
  test("fetches over one TLS connection and refuses a document that is not genuine, printing nothing", async () => {
    const { h, seen } = start();
    const child = spawn(
      "bun",
      ["run", join(root, "scripts/verify-attestation.ts"), "--url", `https://127.0.0.1:${h.port}`, "--ledger-key", LEDGER_KEY, "--allow-untrusted-ca"],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    const status = await new Promise<number | null>((resolve) => child.on("close", resolve));
    expect(status).toBe(1);
    expect(out).toBe("");
    expect(err).toContain("NOT_COSE_SIGN1");
    expect(seen.length).toBe(1);
    expect(seen[0]!.nonce.length).toBe(32);
  });

  test("keeps the positional usage", () => {
    const r = spawnSync("bun", ["run", join(root, "scripts/verify-attestation.ts")], { encoding: "utf8" });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("usage: verify-attestation <document.cbor> <nonce-hex>");
  });
});
