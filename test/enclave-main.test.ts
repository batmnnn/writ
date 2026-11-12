import { afterEach, describe, expect, test } from "bun:test";
import { createHmac, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  AirwallexSession,
  BALANCE_URL,
  BalancePoller,
  LOGIN_URL,
  dateHeaderIso,
  usdAvailableMinor,
  type HttpFetch,
  type HttpInit,
} from "../src/host/enclave-balance";
import { runServe, type ServeHandle, type ServeIo } from "../src/host/enclave";
import { connect } from "node:net";
import { RA_HOSTNAME, certSpkiSha256, createTlsIdentity, sealTlsIdentity, selfSignedCertPem, startEnclaveTls } from "../src/host/enclave-tls";
import { startCredsListener } from "../src/host/enclave-creds";
import { deriveTlsSealKey } from "../src/host/enclave-keys";
import type { ArmOrder, BakedConfig } from "../src/host/enclave-serve";
import type { S3PutRequest } from "../src/host/s3-committer";
import { fixedNsm } from "../src/host/nsm";
import { FakeS3Store } from "./fake-s3";
import { signWrit } from "../src/core/writ";
import { APPROVED_AT, KEYS, OTHER_KEYS, proposal, signed } from "./helpers";

const ARN = "arn:aws:kms:us-west-2:401046276943:key/04d013d8-fb9b-4261-bf67-4d87370a31bb";
const PCRS = { pcr0: "a1".repeat(48), pcr1: "b2".repeat(48), pcr2: "c3".repeat(48) };
const CARD = "3f2b8c1e-7a4d-4e9b-9c11-2d5e6f708192";
const CLIENT = "fake-client-id";
const FAKE = { accessKeyId: "ASIAFAKEFAKEFAKE", secretAccessKey: "fake-secret-not-a-real-key", sessionToken: "fake-session-token" };
const API_KEY = "fake-airwallex-key-for-tests";
const TOKEN = "fake-bearer-token";
const DATE = "Thu, 12 Nov 2026 08:35:00 GMT";
const DATE_ISO = "2026-11-12T08:35:00.000Z";
const USD_ROWS = [
  { currency: "AED", available_amount: 0 },
  { currency: "USD", available_amount: 99999.57, account_type: "cash" },
];

type Call = { url: string; init: HttpInit };

function fakeAirwallex(o: { balanceStatus?: number; date?: string | null; rows?: unknown; loginStatus?: number } = {}) {
  const calls: Call[] = [];
  const state = { ...o };
  const fetch: HttpFetch = async (url, init) => {
    calls.push({ url, init });
    const headers = new Headers();
    if (url === LOGIN_URL) {
      const s = state.loginStatus ?? 201;
      return { status: s, headers, text: async () => (s < 300 ? JSON.stringify({ token: TOKEN }) : "{}") };
    }
    if (url === BALANCE_URL) {
      const date = "date" in state ? state.date : DATE;
      if (date) headers.set("date", date);
      return { status: state.balanceStatus ?? 200, headers, text: async () => JSON.stringify(state.rows ?? USD_ROWS) };
    }
    return { status: 599, headers, text: async () => "" };
  };
  return { fetch, calls, state };
}

function poller(f: HttpFetch, mono = () => 0) {
  const session = new AirwallexSession(Buffer.from(API_KEY), CLIENT, f, mono);
  return { session, p: new BalancePoller({ session, fetch: f, mono, setTimer: () => ({ stop() {} }) }) };
}

describe("balance and clock from Airwallex", () => {
  test("a USD balance and a Date header become the observation, in integer cents", async () => {
    const aw = fakeAirwallex();
    const { p } = poller(aw.fetch);
    expect(await p.pollOnce()).toBe(true);
    expect(p.latest()).toEqual({ amountMinor: 9_999_957, at: DATE_ISO });
    expect(Number.isSafeInteger(p.latest()!.amountMinor)).toBe(true);
    expect(p.now()).toBe(DATE_ISO);
    expect(aw.calls[0]).toEqual({ url: LOGIN_URL, init: { method: "POST", headers: { "x-client-id": CLIENT, "x-api-key": API_KEY } } });
    expect(aw.calls[1]!.init).toEqual({ method: "GET", headers: { authorization: `Bearer ${TOKEN}` } });
  });

  test("missing or malformed Date header gives no observation and no clock", async () => {
    for (const date of [null, "", "2026-11-12T08:35:00Z", "yesterday", "Thu, 12 Nov 2026 08:35:00"]) {
      const { p } = poller(fakeAirwallex({ date }).fetch);
      expect(await p.pollOnce()).toBe(false);
      expect(p.latest()).toBeUndefined();
      expect(p.now()).toBeUndefined();
    }
  });

  test("a failed poll keeps the last good observation, and the clock keeps running so it goes stale", async () => {
    let t = 0;
    const aw = fakeAirwallex();
    const { p } = poller(aw.fetch, () => t);
    await p.pollOnce();
    aw.state.balanceStatus = 500;
    t = 90_000;
    expect(await p.pollOnce()).toBe(false);
    expect(p.latest()).toEqual({ amountMinor: 9_999_957, at: DATE_ISO });
    expect(p.now()).toBe("2026-11-12T08:36:30.000Z");
  });

  test("no USD row, two USD rows, a float with 3 decimals or a 401 is not an observation", async () => {
    for (const rows of [[], [{ currency: "USD", available_amount: 1 }, { currency: "USD", available_amount: 2 }], [{ currency: "USD", available_amount: 1.005 }], {}]) {
      const { p } = poller(fakeAirwallex({ rows }).fetch);
      expect(await p.pollOnce()).toBe(false);
    }
    const aw = fakeAirwallex({ balanceStatus: 401 });
    const { p } = poller(aw.fetch);
    expect(await p.pollOnce()).toBe(false);
    await p.pollOnce();
    expect(aw.calls.filter((c) => c.url === LOGIN_URL).length).toBe(2);
  });

  test("dateHeaderIso and usdAvailableMinor", () => {
    expect(dateHeaderIso(DATE)).toBe(DATE_ISO);
    expect(dateHeaderIso(undefined)).toBeUndefined();
    expect(usdAvailableMinor(USD_ROWS)).toBe(9_999_957);
    expect(usdAvailableMinor([{ currency: "USD", available_amount: -1 }])).toBeUndefined();
  });

  test("a zeroed session wipes the key and logs in no more", async () => {
    const aw = fakeAirwallex();
    const key = Buffer.from(API_KEY);
    const s = new AirwallexSession(key, CLIENT, aw.fetch);
    s.zero();
    expect(key.every((b) => b === 0)).toBe(true);
    expect(await s.token()).toBeUndefined();
    expect(aw.calls.length).toBe(0);
  });

  test("the module reads no host wall clock and logs nothing", () => {
    const src = readFileSync(new URL("../src/host/enclave-balance.ts", import.meta.url), "utf8");
    expect(/Date\.now|new Date\(\)|console\.|process\.(stdout|stderr)/.test(src)).toBe(false);
    expect(src.includes("\u2014")).toBe(false);
  });
});

// ---------------------------------------------------------------------------

function baked(): BakedConfig {
  return {
    approvers: { version: 1, approvers: [{ name: "test", publicKeyPem: KEYS.publicKeyPem }] },
    ringFenceMinor: 2_500_000,
    reserveFloorMinor: 2_000_000,
    maxBalanceAgeMs: 60_000,
    teams: [{ team: "research", poolLimitMinor: 50_000 }],
    cards: [{ cardId: CARD, team: "research", agent: "research-1" }],
  };
}

const handles: ServeHandle[] = [];
afterEach(async () => {
  while (handles.length > 0) await handles.pop()!.stop();
});

function harness(bootLine: Record<string, unknown>, aw = fakeAirwallex(), opts: { s3?: number; kmsFails?: boolean; store?: FakeS3Store } = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const replies: string[] = [];
  const orders: ArmOrder[] = [];
  const disarms: string[] = [];
  const attestArgv: string[][] = [];
  const store = opts.store ?? new FakeS3Store();
  if (opts.s3 !== undefined) store.putStatus = opts.s3;
  const puts: S3PutRequest[] = store.puts;
  const io: ServeIo = {
    nsm: fixedNsm(PCRS),
    readLine: async () => ({ ok: true, value: Buffer.from(JSON.stringify(bootLine)) }),
    runKmstool: async () =>
      opts.kmsFails
        ? { ok: false, error: { kind: "config", code: "KMS_FAILED", message: "Declined: kms" } }
        : { ok: true, value: { plaintextB64: Buffer.from(API_KEY).toString("base64"), replyKeyId: ARN } },
    stdout: (l) => out.push(l),
    stderr: (l) => err.push(l),
    reply: (l) => replies.push(l),
    attest: async (argv) => {
      attestArgv.push([...argv]);
      return { exitCode: 0, stdout: `${Buffer.from([0xde, 0xad]).toString("base64")}\n` };
    },
    baked: baked(),
    fetch: aw.fetch,
    s3: (_creds, clock) => {
      store.clock = clock;
      return store;
    },
    bucket: "writ-ledger-test",
    armCard: async (order) => (orders.push(order), true),
    disarmCard: async (cardId) => (disarms.push(cardId), true),
    listTransactions: async () => [],
    startTls: (o) => startEnclaveTls({ ...o, port: 0 }),
    setTimer: () => ({ stop() {} }),
    watchTimer: () => ({ stop() {} }),
    retryTimer: () => ({ stop() {} }),
    sleep: async () => {},
    mono: () => 0,
  };
  return { io, out, err, replies, orders, disarms, puts, store, attestArgv, aw };
}

const base = () => ({ ciphertextB64: randomBytes(64).toString("base64"), ...FAKE });
const armLine = (extra: Record<string, unknown> = {}) => ({ ...base(), cardId: CARD, clientId: CLIENT, writ: signed(), ...extra });

async function serve(h: ReturnType<typeof harness>) {
  const r = await runServe(h.io);
  if (r.handle) handles.push(r.handle);
  return r;
}

const insecure = { tls: { rejectUnauthorized: false }, keepalive: false } as RequestInit;

describe("runServe", () => {
  test("replies UNSEALED, stays up, and arms only through EnclaveServe after the checkpoint", async () => {
    const h = harness(armLine());
    const r = await serve(h);
    expect(r.code).toBe(0);
    expect(r.handle).toBeDefined();
    expect(h.replies[0]).toMatch(new RegExp(`^UNSEALED ${API_KEY.length} LEDGER_PUB ed25519:[0-9a-f]{64}$`));
    expect(h.out[0]).toBe(`UNSEALED ${API_KEY.length}`);
    expect(h.out[1]).toMatch(/^LEDGER_PUB ed25519:[0-9a-f]{64}$/);
    expect(h.out[2]).toBe("CLOCK_OK");
    expect(h.out[3]).toBe("LEDGER_VERIFIED 0");
    expect(h.out).toContain("ARMED");
    expect(h.store.checkpoints().map((c) => c.entry.kind)).toEqual(["consume", "arm"]);
    expect(h.puts.every((p) => p.ifNoneMatch === "*")).toBe(true);
    expect(h.orders).toEqual([
      expect.objectContaining({ cardId: CARD, writId: "writ-1", amountMinor: 18_000, currency: "USD", mcc: "5734", merchantName: "DataCo" }),
    ]);
    expect(r.handle!.armResult).toMatchObject({ status: "AUTHORIZED", armed: true });
    const all = [...h.out, ...h.err, ...h.replies].join("\n");
    for (const v of [...Object.values(FAKE), API_KEY, TOKEN]) expect(all.includes(v)).toBe(false);
  });

  test("an issued certificate is the one the TLS server presents", async () => {
    const h = harness({ ...base(), clientId: CLIENT });
    h.io.issueCertificate = async (identity) => ({
      ok: true,
      certificatePem: selfSignedCertPem(identity, ["35-95-168-131.sslip.io"], Date.parse(DATE)),
      spkiSha256: identity.spkiSha256,
      directoryUrl: "https://acme-staging-v02.api.letsencrypt.org/directory",
    });
    const r = await serve(h);
    expect(h.out).toContain("ACME_OK");
    expect(certSpkiSha256(r.handle!.tls.certificatePem)).toBe(r.handle!.tls.identity.spkiSha256);
  });

  test("a failed certificate request still serves the bootstrap certificate", async () => {
    const h = harness({ ...base(), clientId: CLIENT });
    h.io.issueCertificate = async () => ({ ok: false, reason: "lego exited 1" });
    const r = await serve(h);
    expect(r.handle).toBeDefined();
    expect(h.err).toContain("ACME_FAILED lego exited 1");
    expect(certSpkiSha256(r.handle!.tls.certificatePem)).toBe(r.handle!.tls.identity.spkiSha256);
    const all = [...h.out, ...h.err, ...h.replies].join("\n");
    for (const v of [...Object.values(FAKE), API_KEY, TOKEN]) expect(all.includes(v)).toBe(false);
  });

  test("a boot line balance and now are ignored: with no Airwallex clock the ledger cannot be read, so the arm declines STATE_UNVERIFIED", async () => {
    const h = harness(armLine({ balance: { amountMinor: 1_000_000_000, at: DATE_ISO }, now: DATE_ISO }), fakeAirwallex({ balanceStatus: 503 }));
    const r = await serve(h);
    expect(r.code).toBe(0);
    expect(h.out).toContain("LEDGER_UNVERIFIED transient");
    expect(r.handle!.armResult).toMatchObject({ status: "DECLINED", code: "STATE_UNVERIFIED" });
    expect(h.orders.length).toBe(0);
    expect(h.puts.length).toBe(0);
    expect(h.err).toEqual(["DECLINED STATE_UNVERIFIED"]);
  });

  test("a boot line balance cannot lift a low Airwallex balance over the reserve floor", async () => {
    const h = harness(armLine({ balance: { amountMinor: 1_000_000_000, at: DATE_ISO } }), fakeAirwallex({ rows: [{ currency: "USD", available_amount: 20100 }] }));
    const r = await serve(h);
    expect(r.handle!.armResult).toMatchObject({ status: "DECLINED", code: "RESERVE_FLOOR" });
    expect(h.orders.length).toBe(0);
  });

  test("a public key on the boot line is ignored", async () => {
    const other = signWrit(proposal(), APPROVED_AT, OTHER_KEYS.privateKeyPem);
    const h = harness(armLine({ writ: other, publicKeyPem: OTHER_KEYS.publicKeyPem }));
    const r = await serve(h);
    expect(r.handle!.armResult).toMatchObject({ status: "DECLINED", code: "WRIT_BAD_SIGNATURE" });
    expect(h.orders.length).toBe(0);
  });

  test("S3 412 is COMMIT_FAILED and nothing is armed", async () => {
    const h = harness(armLine(), fakeAirwallex(), { s3: 412 });
    const r = await serve(h);
    expect(r.handle!.armResult).toMatchObject({ status: "DECLINED", code: "COMMIT_FAILED" });
    expect(h.orders.length).toBe(0);
  });

  test("no arm fields: no arm, TLS still serves; a bad signature reaches the guard, never Gate", async () => {
    const h = harness({ ...base(), clientId: CLIENT });
    const r = await serve(h);
    expect(r.code).toBe(0);
    expect(r.handle!.armResult).toBeUndefined();
    expect(h.orders.length).toBe(0);
    const tls = r.handle!.tls;
    expect(tls.registerRaAllowed()).toBe(false);
    const eventsBefore = r.handle!.serve.events.length;
    const body = JSON.stringify({ version: 2, card_transaction_event_id: "evt-1", transaction_type: "AUTHORIZATION", card_id: CARD, transaction_amount: 180, transaction_currency: "USD", merchant: { category_code: "5734", name: "DataCo" } });
    const res = await fetch(`https://127.0.0.1:${tls.port}/remote-auth`, { ...insecure, method: "POST", body, headers: { "x-nonce": `${Date.now()}.abc`, "x-signature": "AAAA" } });
    expect(await res.json()).toEqual({ card_transaction_event_id: "evt-1", response_status: "DECLINED", status_reason: "bad signature" });
    expect(tls.registerRaAllowed()).toBe(true);
    expect(r.handle!.serve.events.length).toBe(eventsBefore);
    expect(h.aw.calls.every((c) => !c.url.includes("config/update"))).toBe(true);
  });

  test("a sealed RA secret verifies the nonce signature and is not printed", async () => {
    const ra = "test-ra-secret-value";
    const raCipher = randomBytes(48);
    const raB64 = Buffer.from(raCipher).toString("base64");
    const h = harness({ ...base(), clientId: CLIENT, raCiphertextB64: raB64 });
    h.io.runKmstool = async (argv) => {
      const at = argv.indexOf("--ciphertext");
      const blob = argv[at + 1];
      const text = blob === raB64 ? ra : API_KEY;
      return { ok: true, value: { plaintextB64: Buffer.from(text).toString("base64"), replyKeyId: ARN } };
    };
    const r = await serve(h);
    expect(r.code).toBe(0);
    const nonce = `${Date.now()}.abc`;
    const body = JSON.stringify({ version: 2, card_transaction_event_id: "evt-ra", transaction_type: "AUTHORIZATION", card_id: CARD, transaction_amount: 1, transaction_currency: "USD", merchant: { category_code: "5734", name: "DataCo" } });
    const signature = createHmac("sha256", ra).update(nonce).digest("base64");
    const res = await fetch(`https://127.0.0.1:${r.handle!.tls.port}/remote-auth`, {
      ...insecure,
      method: "POST",
      body,
      headers: { "content-type": "application/json", "x-nonce": nonce, "x-signature": signature },
    });
    const json = (await res.json()) as { response_status: string; status_reason: string };
    expect(json.response_status).toBe("DECLINED");
    expect(json.status_reason).not.toBe("bad signature");
    const all = [...h.out, ...h.err, ...h.replies, json.status_reason].join("\n");
    expect(all.includes(ra)).toBe(false);
  });

  test("GET /attestation runs writ-attest with the nonce hex and the TLS user_data hex", async () => {
    const h = harness({ ...base(), clientId: CLIENT });
    const r = await serve(h);
    const tls = r.handle!.tls;
    const nonce = "a1".repeat(32);
    const res = await fetch(`https://127.0.0.1:${tls.port}/attestation?nonce=${nonce}`, insecure);
    expect(res.status).toBe(200);
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(new Uint8Array([0xde, 0xad]));
    expect(h.attestArgv).toEqual([["/usr/bin/writ-attest", nonce, Buffer.from(tls.userData).toString("hex")]]);
  });

  test("attest-only line answers ATTEST once and starts no server", async () => {
    const h = harness({ attestOnly: true, nonce: "b2".repeat(32) });
    const r = await serve(h);
    expect(r).toEqual({ code: 0 });
    expect(h.replies.length).toBe(1);
    expect(h.replies[0]).toStartWith("ATTEST ");
    expect(h.aw.calls.length).toBe(0);
  });

  test("a failed unseal declines, exits 1, and starts nothing", async () => {
    const h = harness(armLine(), fakeAirwallex(), { kmsFails: true });
    const r = await serve(h);
    expect(r).toEqual({ code: 1 });
    expect(h.replies.length).toBe(1);
    expect(h.replies[0]).toStartWith("DECLINED ");
    expect(h.aw.calls.length).toBe(0);
  });
});

describe("runServe front door, resume, sealed TLS and credential refresh", () => {
  const send = (port: number, line: string) =>
    new Promise<string>((resolve, reject) => {
      let got = "";
      const sock = connect({ host: "127.0.0.1", port }, () => sock.write(line));
      sock.on("data", (d) => (got += d.toString()));
      sock.on("end", () => resolve(got));
      sock.on("error", reject);
    });
  const freshCreds = (expiration: string) => ({ accessKeyId: "ASIAREFRESHEDKEY0001", secretAccessKey: "refreshed-secret-value-0001", sessionToken: "refreshed-session-token-0001", expiration });

  test("the new routes answer over the enclave TLS server, and unknown paths are a JSON 404", async () => {
    const h = harness({ ...base(), clientId: CLIENT });
    const r = await serve(h);
    const port = r.handle!.tls.port;
    const p = await fetch(`https://127.0.0.1:${port}/proposals`, { ...insecure, method: "POST", body: JSON.stringify({ ...proposal(), id: "writ-tls" }) });
    expect(p.status).toBe(201);
    const s = await fetch(`https://127.0.0.1:${port}/state`, insecure);
    const state = (await s.json()) as { ledgerPublicKey: string; verified: boolean; cards: unknown[] };
    expect(state.verified).toBe(true);
    expect(state.ledgerPublicKey).toBe(r.handle!.ledgerPublicKey);
    expect(JSON.stringify(state)).not.toContain(CARD);
    const w = await fetch(`https://127.0.0.1:${port}/writs`, { ...insecure, method: "POST", body: JSON.stringify({ writ: signed() }) });
    expect(await w.json()).toMatchObject({ writId: "writ-1", status: "AUTHORIZED", seq: 1 });
    const nf = await fetch(`https://127.0.0.1:${port}/nope`, insecure);
    expect(nf.status).toBe(404);
    expect(await nf.json()).toEqual({ ok: false, reason: "not found" });
    const big = await fetch(`https://127.0.0.1:${port}/proposals`, { ...insecure, method: "POST", body: "x".repeat(40_000) });
    expect(big.status).toBe(413);
    expect(((await big.json()) as { ok: boolean }).ok).toBe(false);
  });

  test("the ledger key is the same on every boot, and a second boot resumes the signed chain", async () => {
    const store = new FakeS3Store();
    const h1 = harness(armLine(), fakeAirwallex(), { store });
    const r1 = await serve(h1);
    expect(r1.handle!.armResult).toMatchObject({ status: "AUTHORIZED" });
    await r1.handle!.stop();
    handles.length = 0;
    const h2 = harness(armLine(), fakeAirwallex(), { store });
    const r2 = await serve(h2);
    expect(h2.out).toContain("LEDGER_VERIFIED 2");
    expect(r2.handle!.ledgerPublicKey).toBe(r1.handle!.ledgerPublicKey);
    expect(r2.handle!.armResult).toMatchObject({ status: "DECLINED", code: "WRIT_REPLAY" });
    expect(h2.orders.length).toBe(0);
  });

  test("an edited checkpoint means the next boot is STATE_UNVERIFIED and arms nothing", async () => {
    const store = new FakeS3Store();
    await serve(harness(armLine(), fakeAirwallex(), { store }));
    const k = "checkpoints/v2/000000000001.json";
    const b = JSON.parse(store.objects.get(k)!);
    b.entry.payload.amountMinor = 100;
    store.objects.set(k, JSON.stringify(b));
    const h = harness(armLine({ writ: signed({ id: "writ-2", nonce: "n-2" }) }), fakeAirwallex(), { store });
    const r = await serve(h);
    expect(h.out).toContain("LEDGER_UNVERIFIED tampered");
    expect(r.handle!.armResult).toMatchObject({ code: "STATE_UNVERIFIED" });
    expect(h.orders.length).toBe(0);
  });

  test("a sealed certificate with more than 72 hours left is reused and ACME is not called", async () => {
    const store = new FakeS3Store();
    const sealKey = deriveTlsSealKey(Buffer.from(API_KEY));
    const id = createTlsIdentity();
    const pem = selfSignedCertPem(id, [RA_HOSTNAME], Date.parse(DATE));
    store.objects.set("tls/1762900000.json", sealTlsIdentity(id, pem, sealKey));
    store.objects.set("tls/1762999999.json", "junk from the host");
    const h = harness({ ...base(), clientId: CLIENT }, fakeAirwallex(), { store });
    let acme = 0;
    h.io.issueCertificate = async () => (acme++, { ok: false, reason: "should not run" });
    const r = await serve(h);
    expect(h.out).toContain("TLS_REUSED");
    expect(acme).toBe(0);
    expect(r.handle!.tls.certificatePem).toBe(pem);
    expect(r.handle!.tls.identity.spkiSha256).toBe(id.spkiSha256);
  });

  test("a sealed certificate near expiry is skipped: ACME runs and the new one is sealed to tls/<unix seconds>.json", async () => {
    const store = new FakeS3Store();
    const sealKey = deriveTlsSealKey(Buffer.from(API_KEY));
    const old = createTlsIdentity();
    store.objects.set("tls/1762000000.json", sealTlsIdentity(old, selfSignedCertPem(old, [RA_HOSTNAME], Date.parse(DATE) - 5 * 86_400_000), sealKey));
    const h = harness({ ...base(), clientId: CLIENT }, fakeAirwallex(), { store });
    h.io.issueCertificate = async (identity) => ({ ok: true, certificatePem: selfSignedCertPem(identity, [RA_HOSTNAME], Date.parse(DATE)), spkiSha256: identity.spkiSha256, directoryUrl: "x" });
    const r = await serve(h);
    expect(h.out).toContain("ACME_OK");
    expect(h.out).toContain("TLS_SEALED");
    const key = `tls/${Math.floor(Date.parse(DATE) / 1000)}.json`;
    expect(store.objects.has(key)).toBe(true);
    expect(store.objects.get(key)).not.toContain("PRIVATE");
    expect(r.handle!.tls.identity.spkiSha256).not.toBe(old.spkiSha256);
  });

  test("the credential listener swaps the S3 credentials, refuses junk and expired ones, and prints nothing", async () => {
    const h = harness({ ...base(), clientId: CLIENT });
    let current: (() => { accessKeyId: string } | undefined) | undefined;
    const s3 = h.io.s3;
    h.io.s3 = (creds, clock) => ((current = creds), s3(creds, clock));
    h.io.startCreds = (box, nowMs) => startCredsListener({ box, nowMs, port: 0 });
    const r = await serve(h);
    const port = r.handle!.creds!.port;
    expect(port).not.toBe(r.handle!.tls.port);
    expect(current!()!.accessKeyId).toBe(FAKE.accessKeyId);
    expect(await send(port, "not json\n")).toBe("DECLINED BAD_INPUT\n");
    expect(await send(port, `${JSON.stringify(freshCreds("2026-11-12T08:00:00Z"))}\n`)).toBe("DECLINED EXPIRED\n");
    expect(await send(port, `${JSON.stringify({ ...freshCreds("2026-11-12T20:00:00Z"), extra: 1 })}\n`)).toBe("DECLINED BAD_INPUT\n");
    expect(current!()!.accessKeyId).toBe(FAKE.accessKeyId);
    expect(await send(port, `${JSON.stringify(freshCreds("2026-11-12T20:00:00Z"))}\n`)).toBe("OK 2026-11-12T20:00:00.000Z\n");
    expect(current!()!.accessKeyId).toBe("ASIAREFRESHEDKEY0001");
    const all = [...h.out, ...h.err, ...h.replies].join("\n");
    for (const v of ["refreshed-secret-value-0001", "refreshed-session-token-0001", "ASIAREFRESHEDKEY0001"]) expect(all.includes(v)).toBe(false);
  });

  test("the credential refresh is not reachable through the public TLS server", async () => {
    const h = harness({ ...base(), clientId: CLIENT });
    let current: (() => { accessKeyId: string } | undefined) | undefined;
    const s3 = h.io.s3;
    h.io.s3 = (creds, clock) => ((current = creds), s3(creds, clock));
    h.io.startCreds = (box, nowMs) => startCredsListener({ box, nowMs, port: 0 });
    const r = await serve(h);
    const port = r.handle!.tls.port;
    const line = JSON.stringify(freshCreds("2026-11-12T20:00:00Z"));
    for (const path of ["/creds", "/refresh-creds", "/credentials", "/", "/taint", "/writs"]) {
      const res = await fetch(`https://127.0.0.1:${port}${path}`, { ...insecure, method: "POST", body: line });
      expect(res.status).toBeGreaterThanOrEqual(400);
    }
    expect(current!()!.accessKeyId).toBe(FAKE.accessKeyId);
    const src = readFileSync(new URL("../src/host/enclave-app.ts", import.meta.url), "utf8");
    expect(src).not.toMatch(/accessKeyId|sessionToken|CredentialBox/);
  });

  test("credentials that expire on the enclave clock make the next commit fail closed", async () => {
    const h = harness({ ...base(), clientId: CLIENT });
    let t = 0;
    h.io.mono = () => t;
    h.io.startCreds = (box, nowMs) => startCredsListener({ box, nowMs, port: 0 });
    h.io.s3 = (creds, clock) => {
      h.store.clock = clock;
      const real = h.store;
      return { ...real, putObject: async (req) => (creds() === undefined ? Promise.reject(new Error("no AWS credentials")) : real.putObject(req)), listKeys: real.listKeys.bind(real), getObject: real.getObject.bind(real) };
    };
    const r = await serve(h);
    expect(await send(r.handle!.creds!.port, `${JSON.stringify(freshCreds("2026-11-12T08:35:01Z"))}\n`)).toStartWith("OK ");
    t = 5_000;
    r.handle!.serve.setObservation({ amountMinor: 9_999_957, at: "2026-11-12T08:35:05.000Z" });
    const res = await fetch(`https://127.0.0.1:${r.handle!.tls.port}/writs`, { ...insecure, method: "POST", body: JSON.stringify({ writ: signed() }) });
    expect(await res.json()).toMatchObject({ status: "DECLINED", code: "COMMIT_FAILED" });
    expect(h.orders.length).toBe(0);
  });
});

describe("boot order, clock wait and retries", () => {
  type State = { ledger: string; verified: boolean; unverifiedReason?: string; cards: { agent: string; armed: unknown; lastDisarm: { ok: boolean; reason: string; attempts: number } | null }[]; boot: Record<string, any> };
  const state = async (r: { handle?: ServeHandle }) => (await (await fetch(`https://127.0.0.1:${r.handle!.tls.port}/state`, insecure)).json()) as State;

  test("the poller runs first and S3 is read only after the first Airwallex Date header", async () => {
    const aw = fakeAirwallex({ balanceStatus: 503 });
    const h = harness({ ...base(), clientId: CLIENT }, aw);
    const sleeps: number[] = [];
    let balanceCalls = 0;
    const inner = aw.fetch;
    h.io.fetch = async (url, init) => {
      if (url === BALANCE_URL && ++balanceCalls === 4) aw.state.balanceStatus = 200;
      return inner(url, init);
    };
    const listAt: number[] = [];
    const list = h.store.listKeys.bind(h.store);
    h.store.listKeys = async (b, p) => (listAt.push(balanceCalls), list(b, p));
    h.io.sleep = async (ms) => void sleeps.push(ms);
    const r = await serve(h);
    expect(sleeps).toEqual([2_000, 2_000, 2_000]);
    expect(h.out).toContain("CLOCK_OK");
    expect(h.out).toContain("LEDGER_VERIFIED 0");
    expect(Math.min(...listAt)).toBe(4);
    expect((await state(r)).ledger).toBe("verified");
  });

  test("no clock within the wait: retrying, ACME skipped, the poller keeps running, and a later retry resumes", async () => {
    const aw = fakeAirwallex({ balanceStatus: 503 });
    const h = harness({ ...base(), clientId: CLIENT }, aw);
    const sleeps: number[] = [];
    h.io.sleep = async (ms) => void sleeps.push(ms);
    let pollTick: (() => void) | undefined;
    h.io.setTimer = (fn) => ((pollTick = fn), { stop() {} });
    let acme = 0;
    h.io.issueCertificate = async () => (acme++, { ok: false, reason: "should not run" });
    const r = await serve(h);
    expect(sleeps.length).toBe(30);
    expect(h.out).toContain("CLOCK_MISSING BALANCE_HTTP_503");
    expect(h.out).toContain("LEDGER_UNVERIFIED transient");
    expect(h.err).toContain("ACME_SKIPPED TLS_BLOBS_UNREADABLE");
    expect(acme).toBe(0);
    const before = await state(r);
    expect(before.ledger).toBe("retrying");
    expect(before.unverifiedReason).toContain("transient, retrying");
    expect(before.boot.balancePoll.lastError).toBe("BALANCE_HTTP_503");

    await r.handle!.retryNow();
    expect((await state(r)).ledger).toBe("retrying");
    expect((await state(r)).boot.resumeAttempts).toBe(1);

    aw.state.balanceStatus = 200;
    pollTick!();
    await r.handle!.poller.pollOnce();
    expect(r.handle!.poller.latest()).toBeDefined();
    await r.handle!.retryNow();
    const after = await state(r);
    expect(after.ledger).toBe("verified");
    expect(after.verified).toBe(true);
    expect(h.out).toContain("LEDGER_VERIFIED 0");
    const w = await fetch(`https://127.0.0.1:${r.handle!.tls.port}/writs`, { ...insecure, method: "POST", body: JSON.stringify({ writ: signed() }) });
    expect(await w.json()).toMatchObject({ status: "AUTHORIZED" });
  });

  test("a transient S3 failure is retried until it works", async () => {
    const store = new FakeS3Store();
    store.listFails = true;
    const h = harness({ ...base(), clientId: CLIENT }, fakeAirwallex(), { store });
    const r = await serve(h);
    expect(h.out).toContain("LEDGER_UNVERIFIED transient");
    await r.handle!.retryNow();
    await r.handle!.retryNow();
    const mid = await state(r);
    expect(mid.ledger).toBe("retrying");
    expect(mid.unverifiedReason).toContain("list refused");
    store.listFails = false;
    await r.handle!.retryNow();
    expect((await state(r)).ledger).toBe("verified");
  });

  test("tampering stays unverified: no retry changes it, and a retry that finds tampering stops retrying", async () => {
    const store = new FakeS3Store();
    store.objects.set("checkpoints/v2/000000000007.json", "{}");
    const h = harness({ ...base(), clientId: CLIENT }, fakeAirwallex(), { store });
    const r = await serve(h);
    expect(h.out).toContain("LEDGER_UNVERIFIED tampered");
    await r.handle!.retryNow();
    const s1 = await state(r);
    expect(s1.ledger).toBe("tampered");
    expect(s1.unverifiedReason).toContain("tampered, needs a fix");
    expect(s1.boot.resumeAttempts).toBe(0);

    const store2 = new FakeS3Store();
    store2.listFails = true;
    const h2 = harness({ ...base(), clientId: CLIENT }, fakeAirwallex(), { store: store2 });
    const r2 = await serve(h2);
    expect((await state(r2)).ledger).toBe("retrying");
    store2.listFails = false;
    store2.objects.set("checkpoints/v2/000000000002.json", "{}");
    await r2.handle!.retryNow();
    expect(h2.out).toContain("LEDGER_TAMPERED");
    expect((await state(r2)).ledger).toBe("tampered");
    store2.objects.delete("checkpoints/v2/000000000002.json");
    await r2.handle!.retryNow();
    expect((await state(r2)).ledger).toBe("tampered");
    const w = await fetch(`https://127.0.0.1:${r2.handle!.tls.port}/writs`, { ...insecure, method: "POST", body: JSON.stringify({ writ: signed() }) });
    expect(await w.json()).toMatchObject({ code: "STATE_UNVERIFIED" });
  });

  test("armed is true only for a card this boot armed; an unverified boot reports unknown until the sweep confirms INACTIVE", async () => {
    const store = new FakeS3Store();
    store.listFails = true;
    const h = harness({ ...base(), clientId: CLIENT }, fakeAirwallex(), { store });
    h.io.disarmCard = async () => false;
    const r = await serve(h);
    await r.handle!.serve.armWatcher!.idle();
    const s = await state(r);
    expect(s.cards[0]!.armed).toBe("unknown");
    expect(s.cards[0]!.lastDisarm).toMatchObject({ ok: false, reason: "ledger unverified at boot", attempts: 1 });

    const store2 = new FakeS3Store();
    store2.listFails = true;
    const h2 = harness({ ...base(), clientId: CLIENT }, fakeAirwallex(), { store: store2 });
    const r2 = await serve(h2);
    await r2.handle!.serve.armWatcher!.idle();
    const s2 = await state(r2);
    expect(h2.disarms).toEqual([CARD]);
    expect(s2.cards[0]!.armed).toBe(false);
    expect(s2.cards[0]!.lastDisarm).toMatchObject({ ok: true, reason: "ledger unverified at boot" });

    const h3 = harness(armLine());
    const r3 = await serve(h3);
    expect((await state(r3)).cards[0]!.armed).toBe(true);
  });

  test("a new certificate whose seal PUT failed is written by the retry once S3 works, and the next boot reuses it", async () => {
    const store = new FakeS3Store();
    const h = harness({ ...base(), clientId: CLIENT }, fakeAirwallex(), { store });
    let acme = 0;
    h.io.issueCertificate = async (identity) => (acme++, { ok: true, certificatePem: selfSignedCertPem(identity, [RA_HOSTNAME], Date.parse(DATE)), spkiSha256: identity.spkiSha256, directoryUrl: "x" });
    const put = store.putObject.bind(store);
    let tlsPutFails = true;
    store.putObject = async (req) => (req.key.startsWith("tls/") && tlsPutFails ? { status: 503 } : put(req));
    const r = await serve(h);
    expect(h.err).toContain("TLS_SEAL_PENDING");
    expect((await state(r)).boot.tlsSealed).toBe("pending");
    expect([...store.objects.keys()].some((k) => k.startsWith("tls/"))).toBe(false);
    tlsPutFails = false;
    await r.handle!.retryNow();
    expect(h.out).toContain("TLS_SEALED");
    expect((await state(r)).boot.tlsSealed).toBe(true);
    expect([...store.objects.keys()].filter((k) => k.startsWith("tls/"))).toEqual([`tls/${Math.floor(Date.parse(DATE) / 1000)}.json`]);
    const servedPem = r.handle!.tls.certificatePem;
    await r.handle!.stop();
    handles.length = 0;

    const h2 = harness({ ...base(), clientId: CLIENT }, fakeAirwallex(), { store });
    h2.io.issueCertificate = async () => (acme++, { ok: false, reason: "should not run" });
    const r2 = await serve(h2);
    expect(h2.out).toContain("TLS_REUSED");
    expect(acme).toBe(1);
    expect(r2.handle!.tls.certificatePem).toBe(servedPem);
  });

  test("no client id anywhere: the reply says NO_CLIENT_ID, no clock wait, /state shows why", async () => {
    const h = harness(base());
    const sleeps: number[] = [];
    h.io.sleep = async (ms) => void sleeps.push(ms);
    const r = await serve(h);
    expect(h.replies[0]).toMatch(/ NO_CLIENT_ID$/);
    expect(sleeps.length).toBe(0);
    const s = await state(r);
    expect(s.boot.clientId).toBe(false);
    expect(s.boot.balancePoll.lastError).toBe("NO_CLIENT_ID");
    expect(s.ledger).toBe("retrying");
  });

  test("a baked client id wins over the boot line and needs no boot line field", async () => {
    const h = harness(base());
    h.io.baked = { ...h.io.baked, airwallexClientId: "baked-client-id" };
    const r = await serve(h);
    expect(h.replies[0]).not.toContain("NO_CLIENT_ID");
    expect(h.aw.calls[0]!.init.headers["x-client-id"]).toBe("baked-client-id");
    expect((await state(r)).ledger).toBe("verified");
  });
});

describe("serve entry source", () => {
  const read = (p: string) => readFileSync(new URL(`../${p}`, import.meta.url), "utf8");
  const body = (src: string, start: string) => {
    const i = src.indexOf(start);
    expect(i).toBeGreaterThan(-1);
    const next = src.indexOf("\nasync function ", i + 1);
    const nextExport = src.indexOf("\nexport ", i + 1);
    const ends = [next, nextExport, src.indexOf("\nif (import.meta.main)", i + 1)].filter((n) => n > i);
    return src.slice(i, Math.min(...ends));
  };

  test("main() and runServe never call armAfterUnseal or runBoot, and main() calls runServe", () => {
    const src = read("src/host/enclave.ts");
    const main = body(src, "async function main()");
    const serve = body(src, "export async function runServe(");
    for (const b of [main, serve]) {
      expect(b.includes("armAfterUnseal")).toBe(false);
      expect(b.includes("runBoot(")).toBe(false);
    }
    expect(main).toContain("runServe(");
    expect(serve).toContain(".authorize(");
  });

  test("every file in the enclave.ts import graph is copied in the Dockerfile and staged by eif.ts", () => {
    const d = read("enclave/Dockerfile");
    const eif = read("scripts/eif.ts");
    const seen = new Set<string>();
    const walk = (file: string) => {
      if (seen.has(file)) return;
      seen.add(file);
      if (!file.endsWith(".ts")) return;
      const dir = file.split("/").slice(0, -1);
      for (const m of read(file).matchAll(/^import\s[^;]*?from\s+"(\.{1,2}\/[^"]+)"/gm)) {
        const parts = [...dir];
        for (const seg of m[1]!.split("/")) {
          if (seg === "..") parts.pop();
          else if (seg !== ".") parts.push(seg);
        }
        const target = parts.join("/");
        walk(target.endsWith(".json") ? target : `${target}.ts`);
      }
    };
    walk("src/host/enclave.ts");
    for (const f of ["src/airwallex/ra-server.ts", "src/airwallex/redact.ts", "src/host/enclave-balance.ts", "src/host/enclave-serve.ts"]) expect(seen.has(f)).toBe(true);
    for (const f of [...seen, "enclave/config/approvers.json", "enclave/config/serve.json"]) {
      expect(d).toContain(`COPY ${f} /app/${f}`);
      expect(eif).toContain(`"${f}"`);
    }
    expect(/^COPY\s+\.\s/m.test(d)).toBe(false);
    expect(/^COPY\s+\S*\.env/m.test(d)).toBe(false);
  });

  test("serve.json is whole cents and has no key material", () => {
    const text = read("enclave/config/serve.json");
    expect(text).not.toMatch(/PRIVATE|publicKey|"balance"|"now"/i);
    const c = JSON.parse(text);
    for (const n of [c.ringFenceMinor, c.reserveFloorMinor, c.maxBalanceAgeMs, ...c.teams.map((t: { poolLimitMinor: number }) => t.poolLimitMinor)]) {
      expect(Number.isSafeInteger(n)).toBe(true);
    }
  });

  test("no debug flag and no em dash in the new files", () => {
    const debugFlag = "--" + "debug-mode";
    for (const p of ["src/host/enclave.ts", "src/host/enclave-balance.ts", "enclave/config/serve.json", "test/enclave-main.test.ts"]) {
      const t = read(p);
      expect(t.includes(debugFlag)).toBe(false);
      expect(t.includes("\u2014")).toBe(false);
    }
  });
});
