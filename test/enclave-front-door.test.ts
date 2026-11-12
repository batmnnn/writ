import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { entryHash, entrySigningMessage } from "../src/core/chain";
import { parseIso } from "../src/core/time";
import { canonicalJson, signWrit } from "../src/core/writ";
import { EnclaveApp } from "../src/host/enclave-app";
import { deriveLedgerSigner, verifyEd25519 } from "../src/host/enclave-keys";
import { EnclaveServe, type ArmOrder, type BakedConfig } from "../src/host/enclave-serve";
import { taintVerifier, derToP1363 } from "../src/host/enclave-taint";
import { listCardTransactions, type CardTx } from "../src/host/enclave-watch";
import { S3CheckpointCommitter, SIGNED_CHECKPOINT_PREFIX, loadSignedChain } from "../src/host/s3-committer";
import type { ApprovedTask, WritProposal } from "../src/types";
import { FakeS3Store } from "./fake-s3";
import { APPROVED_AT, KEYS, OTHER_KEYS, proposal } from "./helpers";

const API_KEY = new TextEncoder().encode("fake-airwallex-key-for-tests");
const SIGNER = deriveLedgerSigner(API_KEY);
const NOW = "2026-11-12T08:35:00.000Z";
const BUCKET = "writ-ledger-test";
const CARDS = {
  research1: "11111111-1111-4111-8111-111111111111",
  researchAgent: "22222222-2222-4222-8222-222222222222",
  ops1: "33333333-3333-4333-8333-333333333333",
};
const KMS = generateKeyPairSync("ec", { namedCurve: "P-256" });
const KMS_PEM = KMS.publicKey.export({ type: "spki", format: "pem" }).toString();
const OTHER_KMS = generateKeyPairSync("ec", { namedCurve: "P-256" });

function baked(): BakedConfig {
  return {
    approvers: { version: 1, approvers: [{ name: "test", publicKeyPem: KEYS.publicKeyPem }] },
    ringFenceMinor: 2_500_000,
    reserveFloorMinor: 2_000_000,
    maxBalanceAgeMs: 60_000,
    teams: [
      { team: "research", poolLimitMinor: 50_000 },
      { team: "ops", poolLimitMinor: 1_000_000 },
    ],
    cards: [
      { cardId: CARDS.research1, team: "research", agent: "research-1", last4: "9263" },
      { cardId: CARDS.researchAgent, team: "research", agent: "research-agent", last4: "4605" },
      { cardId: CARDS.ops1, team: "ops", agent: "ops-1", last4: "6760" },
    ],
    taintSignerPem: KMS_PEM,
  };
}

const writFor = (over: Partial<WritProposal> = {}, approvedAt = APPROVED_AT, key = KEYS.privateKeyPem): ApprovedTask =>
  signWrit(proposal({ agent: "research-agent", ...over }), approvedAt, key);

const kmsSign = (event: unknown, key = KMS.privateKey) => sign("sha256", Buffer.from(canonicalJson(event), "utf8"), { key, dsaEncoding: "der" }).toString("base64");
const taintEvent = (over: Record<string, unknown> = {}) => ({ agent: "research-agent", runId: "run-1", urlSha256: "ab".repeat(32), at: NOW, seq: 1, ...over });

interface WorldOpts {
  store?: FakeS3Store;
  disarmResults?: boolean[];
  armOk?: boolean;
  balanceMinor?: number;
  maxProposals?: number;
}

async function world(o: WorldOpts = {}) {
  const clock = { iso: NOW as string };
  const store = o.store ?? new FakeS3Store();
  store.clock = () => new Date(parseIso(clock.iso));
  const orders: ArmOrder[] = [];
  const disarms: string[] = [];
  const txs = new Map<string, CardTx[]>();
  const disarmResults = [...(o.disarmResults ?? [])];
  const loaded = await loadSignedChain(store, BUCKET, SIGNED_CHECKPOINT_PREFIX, SIGNER.publicKeyRaw);
  const serve = new EnclaveServe({
    baked: baked(),
    bootAt: NOW,
    checkpoint: { s3: { client: store, bucket: BUCKET, prefix: SIGNED_CHECKPOINT_PREFIX } },
    signer: SIGNER,
    ...(loaded.ok ? { resume: loaded.entries } : { resumeError: loaded.reason }),
    armCard: async (order) => (orders.push(order), o.armOk ?? true),
    watch: {
      listTransactions: async (cardId) => txs.get(cardId) ?? [],
      disarmCard: async (cardId) => (disarms.push(cardId), disarmResults.length > 0 ? disarmResults.shift()! : true),
      setTimer: () => ({ stop() {} }),
      bankEvery: 1,
    },
    clock: () => clock.iso,
  });
  const fresh = () => serve.setObservation({ amountMinor: o.balanceMinor ?? 10_000_000, at: clock.iso });
  fresh();
  const app = new EnclaveApp({ serve, signer: SIGNER, verifyTaint: taintVerifier(KMS_PEM), clock: () => clock.iso, ...(o.maxProposals ? { maxProposals: o.maxProposals } : {}) });
  const call = async (method: string, path: string, body?: unknown, raw?: string) => {
    const url = new URL(`https://127.0.0.1${path}`);
    const init: RequestInit = { method };
    if (raw !== undefined) init.body = raw;
    else if (body !== undefined) init.body = JSON.stringify(body);
    const res = await app.route(new Request(url.toString(), init), url);
    if (!res) return { status: 404, json: undefined as never };
    return { status: res.status, json: (await res.json()) as Record<string, any> };
  };
  const tick = async (iso?: string) => {
    if (iso) clock.iso = iso;
    await serve.armWatcher!.tick();
    await serve.armWatcher!.idle();
  };
  return { clock, store, orders, disarms, txs, serve, app, call, tick, fresh, loaded };
}

describe("POST /proposals and GET /proposals/:id", () => {
  test("stores the canonical proposal, moves no money, and the approver can sign exactly what it returns", async () => {
    const w = await world();
    const body = { team: "research", agent: "research-agent", runId: "run-1", purpose: "Dataset licence", merchantName: "DataCo", mcc: "5734", amountMinor: 18_000, currency: "USD", expiresAt: "2026-11-12T09:00:00.000Z" };
    const r = await w.call("POST", "/proposals", body);
    expect(r.status).toBe(201);
    expect(r.json.proposalId).toMatch(/^p-/);
    const p = r.json.proposal as WritProposal;
    expect(Object.keys(p)).toEqual([...Object.keys(p)].sort());
    expect(p).toMatchObject(body);
    expect(typeof p.id).toBe("string");
    expect(typeof p.nonce).toBe("string");
    expect("approvedAt" in p).toBe(false);
    expect((await w.call("GET", `/proposals/${r.json.proposalId}`)).json.proposal).toEqual(p);
    expect(w.store.puts.length).toBe(0);
    expect(w.serve.state().teams.find((t) => t.team === "research")).toMatchObject({ reservedMinor: 0, pendingMinor: 0, settledMinor: 0 });

    const writ = signWrit(p, APPROVED_AT, KEYS.privateKeyPem);
    const a = await w.call("POST", "/writs", { writ });
    expect(a.json).toMatchObject({ writId: p.id, status: "AUTHORIZED", cardLast4: "4605", seq: 1 });
    expect(w.orders[0]).toMatchObject({ cardId: CARDS.researchAgent, amountMinor: 18_000 });
  });

  test("keeps at most the cap, oldest dropped", async () => {
    const w = await world({ maxProposals: 3 });
    const ids: string[] = [];
    for (let i = 0; i < 5; i++) {
      const r = await w.call("POST", "/proposals", { ...proposal({ id: `w-${i}`, nonce: `n-${i}`, agent: "research-agent" }) });
      expect(r.status).toBe(201);
      ids.push(r.json.proposalId);
    }
    expect(w.app.proposalCount).toBe(3);
    expect((await w.call("GET", `/proposals/${ids[0]}`)).status).toBe(404);
    expect((await w.call("GET", `/proposals/${ids[1]}`)).status).toBe(404);
    expect((await w.call("GET", `/proposals/${ids[4]}`)).status).toBe(200);
  });

  test("the default cap is 500", async () => {
    const w = await world();
    for (let i = 0; i < 503; i++) await w.call("POST", "/proposals", proposal({ id: `w-${i}`, nonce: `n-${i}`, agent: "research-agent" }));
    expect(w.app.proposalCount).toBe(500);
  });

  test("refuses unknown fields, an agent with no card, a past expiry, bad JSON and a body over 32 KiB, always as JSON", async () => {
    const w = await world();
    const cases: [unknown, string | undefined, number][] = [
      [{ ...proposal(), approvedAt: NOW }, undefined, 400],
      [{ ...proposal(), signature: "x" }, undefined, 400],
      [proposal({ agent: "nobody" }), undefined, 400],
      [proposal({ agent: "research-agent", expiresAt: "2026-11-12T08:00:00.000Z" }), undefined, 400],
      [proposal({ agent: "research-agent", amountMinor: 1.5 }), undefined, 400],
      [undefined, "{not json", 400],
      [undefined, JSON.stringify({ ...proposal(), purpose: "x".repeat(40_000) }), 413],
      [[1, 2], undefined, 400],
    ];
    for (const [body, raw, status] of cases) {
      const r = await w.call("POST", "/proposals", body, raw);
      expect(r.status).toBe(status);
      expect(r.json.ok).toBe(false);
      expect(typeof r.json.reason).toBe("string");
      expect(JSON.stringify(r.json)).not.toMatch(/at .*\.ts:\d+/);
    }
    expect((await w.call("GET", "/proposals")).status).toBe(405);
    expect((await w.call("GET", "/proposals/nope")).status).toBe(404);
  });
});

describe("POST /writs and GET /decisions/:writId", () => {
  test("a writ with a bad signature never arms and writes no checkpoint", async () => {
    const w = await world();
    const forged = writFor({}, APPROVED_AT, OTHER_KEYS.privateKeyPem);
    const r = await w.call("POST", "/writs", { writ: forged });
    expect(r.json).toMatchObject({ writId: "writ-1", status: "DECLINED", code: "WRIT_BAD_SIGNATURE" });
    expect(w.orders.length).toBe(0);
    expect(w.store.puts.length).toBe(0);
    expect((await w.call("GET", "/decisions/writ-1")).json).toMatchObject({ status: "DECLINED", code: "WRIT_BAD_SIGNATURE" });
  });

  test("a writ for an agent with no baked card declines NO_WRIT_FOR_CARD and arms nothing", async () => {
    const w = await world();
    const r = await w.call("POST", "/writs", { writ: writFor({ agent: "research-9" }) });
    expect(r.json).toMatchObject({ status: "DECLINED", code: "NO_WRIT_FOR_CARD" });
    expect(w.orders.length + w.store.puts.length).toBe(0);
  });

  test("the caller never picks the card: a cardId in the body is ignored", async () => {
    const w = await world();
    const r = await w.call("POST", "/writs", { writ: writFor(), cardId: CARDS.ops1 });
    expect(r.json.status).toBe("AUTHORIZED");
    expect(w.orders.map((o) => o.cardId)).toEqual([CARDS.researchAgent]);
  });

  test("S3 412 on the checkpoint is COMMIT_FAILED and the card is not armed", async () => {
    const w = await world();
    w.store.putStatus = 412;
    const r = await w.call("POST", "/writs", { writ: writFor() });
    expect(r.json).toMatchObject({ status: "DECLINED", code: "COMMIT_FAILED" });
    expect(w.orders.length).toBe(0);
    expect(w.serve.state().cards.every((c) => !c.armed)).toBe(true);
  });

  test("a key already taken by someone else (412 on our seq) is COMMIT_FAILED, keys are zero padded", async () => {
    const w = await world();
    expect((await w.call("POST", "/writs", { writ: writFor() })).json.status).toBe("AUTHORIZED");
    expect([...w.store.objects.keys()]).toEqual(["checkpoints/v2/000000000001.json", "checkpoints/v2/000000000002.json"]);
    w.store.objects.set("checkpoints/v2/000000000003.json", "{}");
    const r = await w.call("POST", "/writs", { writ: writFor({ id: "writ-2", nonce: "n-2", agent: "research-1" }) });
    expect(r.json).toMatchObject({ status: "DECLINED", code: "COMMIT_FAILED" });
    expect(w.orders.length).toBe(1);
  });

  test("an ops writ for $6,000 hits the cash reserve: RESERVE_FLOOR, no arm", async () => {
    const w = await world();
    const r = await w.call("POST", "/writs", { writ: writFor({ id: "ops-big", team: "ops", agent: "ops-1", amountMinor: 600_000, nonce: "n-ops" }) });
    expect(r.json).toMatchObject({ status: "DECLINED", code: "RESERVE_FLOOR", cardLast4: "6760" });
    expect(w.orders.length).toBe(0);
  });

  test("a replay keeps the first AUTHORIZED answer, and unknown writs are 404", async () => {
    const w = await world();
    await w.call("POST", "/writs", { writ: writFor() });
    expect((await w.call("POST", "/writs", { writ: writFor() })).json).toMatchObject({ status: "DECLINED", code: "WRIT_REPLAY" });
    expect((await w.call("GET", "/decisions/writ-1")).json).toMatchObject({ status: "AUTHORIZED", seq: 1 });
    expect((await w.call("GET", "/decisions/nope")).status).toBe(404);
    expect(w.orders.length).toBe(1);
  });

  test("malformed bodies are JSON declines", async () => {
    const w = await world();
    for (const body of [{}, { writ: "x" }, { writ: { ...writFor(), id: "" } }, { writ: { ...writFor(), amountMinor: 18_000.5 } }]) {
      const r = await w.call("POST", "/writs", body);
      expect(r.status).toBe(400);
      expect(r.json.ok).toBe(false);
    }
    expect(w.orders.length).toBe(0);
  });
});

describe("POST /taint", () => {
  test("a good signature gets a signed ack, disarms the run's armed card, and the next spend is TAINTED_RUN", async () => {
    const w = await world();
    expect((await w.call("POST", "/writs", { writ: writFor() })).json.status).toBe("AUTHORIZED");
    expect(w.serve.state().cards.find((c) => c.agent === "research-agent")!.armed).toBe(true);

    const event = taintEvent();
    const r = await w.call("POST", "/taint", { event, signature: kmsSign(event) });
    expect(r.status).toBe(200);
    expect(r.json.ack).toEqual({ agent: "research-agent", runId: "run-1", seq: 1, taintedAt: NOW, ok: true });
    expect(verifyEd25519(SIGNER.publicKeyRaw, Buffer.from(canonicalJson(r.json.ack)), Buffer.from(r.json.signature, "base64"))).toBe(true);
    await w.serve.armWatcher!.idle();
    expect(w.disarms).toEqual([CARDS.researchAgent]);
    expect(w.serve.state().cards.find((c) => c.agent === "research-agent")!.armed).toBe(false);
    expect(w.store.checkpoints().map((c) => c.entry.kind)).toEqual(["consume", "arm", "taint", "disarm", "release"]);

    const second = await w.call("POST", "/writs", { writ: writFor({ id: "writ-2", nonce: "n-2" }) });
    expect(second.json).toMatchObject({ status: "DECLINED", code: "TAINTED_RUN" });
    expect(w.orders.length).toBe(1);
  });

  test("a bad signature is 400 with no ack, records nothing, and taints nothing", async () => {
    const w = await world();
    const event = taintEvent();
    for (const signature of [kmsSign(event, OTHER_KMS.privateKey), "", "AAAA", 7, kmsSign({ ...event, seq: 2 })]) {
      const r = await w.call("POST", "/taint", { event, signature });
      expect(r.status).toBe(400);
      expect(r.json).toEqual({ ok: false, reason: "bad signature" });
    }
    expect(w.store.puts.length).toBe(0);
    expect((await w.call("POST", "/writs", { writ: writFor() })).json.status).toBe("AUTHORIZED");
  });

  test("a replayed or older seq is refused, a newer one is accepted", async () => {
    const w = await world();
    const e1 = taintEvent({ seq: 5 });
    expect((await w.call("POST", "/taint", { event: e1, signature: kmsSign(e1) })).status).toBe(200);
    const again = await w.call("POST", "/taint", { event: e1, signature: kmsSign(e1) });
    expect(again.status).toBe(400);
    expect(again.json.ok).toBe(false);
    expect(again.json.ack).toBeUndefined();
    const older = taintEvent({ seq: 4 });
    expect((await w.call("POST", "/taint", { event: older, signature: kmsSign(older) })).status).toBe(400);
    const newer = taintEvent({ seq: 6 });
    expect((await w.call("POST", "/taint", { event: newer, signature: kmsSign(newer) })).status).toBe(200);
  });

  test("a backdated at still marks the run at the enclave clock, so a writ approved before now cannot spend", async () => {
    const w = await world();
    const event = taintEvent({ at: "2026-11-12T07:00:00.000Z" });
    const r = await w.call("POST", "/taint", { event, signature: kmsSign(event) });
    expect(r.json.ack.taintedAt).toBe(NOW);
    expect((await w.call("POST", "/writs", { writ: writFor() })).json).toMatchObject({ status: "DECLINED", code: "TAINTED_RUN" });
  });

  test("a failed taint checkpoint is 503 with no ack, and the run is still tainted in memory", async () => {
    const w = await world();
    w.store.putStatus = 500;
    const event = taintEvent();
    const r = await w.call("POST", "/taint", { event, signature: kmsSign(event) });
    expect(r.status).toBe(503);
    expect(r.json.ack).toBeUndefined();
    w.store.putStatus = undefined;
    expect((await w.call("POST", "/writs", { writ: writFor() })).json).toMatchObject({ code: "TAINTED_RUN" });
  });

  test("malformed events and unknown agents are refused", async () => {
    const w = await world();
    for (const event of [{ ...taintEvent(), extra: 1 }, taintEvent({ seq: 0 }), taintEvent({ urlSha256: "xyz" }), taintEvent({ at: "yesterday" })]) {
      expect((await w.call("POST", "/taint", { event, signature: kmsSign(event) })).status).toBe(400);
    }
    const stranger = taintEvent({ agent: "nobody" });
    expect((await w.call("POST", "/taint", { event: stranger, signature: kmsSign(stranger) })).status).toBe(400);
    expect((await w.call("POST", "/taint", { event: taintEvent() })).status).toBe(400);
  });

  test("derToP1363 takes strict DER only", () => {
    const der = sign("sha256", Buffer.from("m"), { key: KMS.privateKey, dsaEncoding: "der" });
    expect(derToP1363(new Uint8Array(der))!.length).toBe(64);
    expect(derToP1363(new Uint8Array(der.subarray(0, der.length - 1)))).toBeUndefined();
    expect(derToP1363(new Uint8Array([0x30, 0x02, 0x02, 0x00]))).toBeUndefined();
  });
});

describe("GET /state", () => {
  test("pools, reserve, cards, chain head, ledger key and decisions, with no card id or secret", async () => {
    const w = await world();
    await w.call("POST", "/writs", { writ: writFor() });
    await w.call("POST", "/writs", { writ: writFor({ id: "ops-big", team: "ops", agent: "ops-1", amountMinor: 600_000, nonce: "n-ops" }) });
    const r = await w.call("GET", "/state");
    expect(r.status).toBe(200);
    const s = r.json;
    expect(s.ledgerPublicKey).toBe(SIGNER.publicKey);
    expect(s.verified).toBe(true);
    expect(s.teams).toContainEqual({ team: "research", poolLimitMinor: 50_000, reservedMinor: 18_000, pendingMinor: 0, settledMinor: 0, releasedMinor: 0, teamFrozen: null });
    expect(s.teams).toContainEqual({ team: "ops", poolLimitMinor: 1_000_000, reservedMinor: 0, pendingMinor: 0, settledMinor: 0, releasedMinor: 0, teamFrozen: null });
    expect(s.reserve).toEqual({ liveBalanceMinor: 10_000_000, ringFenceMinor: 2_500_000, reserveFloorMinor: 2_000_000, openReservationsMinor: 18_000, asOf: NOW });
    expect(s.cards).toContainEqual({ agent: "research-agent", team: "research", last4: "4605", armed: true, lastDisarm: null });
    expect(s.cards).toContainEqual({ agent: "ops-1", team: "ops", last4: "6760", armed: false, lastDisarm: null });
    expect(s.ledger).toBe("verified");
    expect(s.chain.seq).toBe(3);
    expect(s.chain.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(s.decisions.length).toBe(2);
    expect(s.decisions[0]).toMatchObject({ status: "DECLINED", code: "RESERVE_FLOOR", agent: "ops-1", cardLast4: "6760" });
    expect(s.decisions[1]).toMatchObject({ status: "AUTHORIZED", writId: "writ-1", cardLast4: "4605" });
    const text = JSON.stringify(s);
    for (const id of Object.values(CARDS)) expect(text.includes(id)).toBe(false);
    expect(text).not.toMatch(/\d{13,19}/);
    expect(text).not.toContain("fake-airwallex-key");
  });

  test("only the last 50 decisions", async () => {
    const w = await world();
    for (let i = 0; i < 55; i++) await w.call("POST", "/writs", { writ: writFor({ id: `f-${i}`, nonce: `n-${i}` }, APPROVED_AT, OTHER_KEYS.privateKeyPem) });
    expect((await w.call("GET", "/state")).json.decisions.length).toBe(50);
  });
});

describe("resume from the signed S3 chain", () => {
  async function used() {
    const w = await world();
    await w.call("POST", "/writs", { writ: writFor() });
    const e = taintEvent({ runId: "run-2", seq: 3 });
    await w.call("POST", "/taint", { event: e, signature: kmsSign(e) });
    return w.store;
  }

  test("a good chain verifies: used writs, held money, taint and the taint seq guard all survive, armed cards stay watched", async () => {
    const store = await used();
    const w = await world({ store });
    expect(w.loaded.ok).toBe(true);
    expect(w.serve.verified).toBe(true);
    expect((await w.call("POST", "/writs", { writ: writFor() })).json).toMatchObject({ code: "WRIT_REPLAY" });
    expect((await w.call("POST", "/writs", { writ: writFor({ id: "writ-3", nonce: "n-3", runId: "run-2", agent: "research-1" }) })).json).toMatchObject({ code: "TAINTED_RUN" });
    const replay = taintEvent({ runId: "run-2", seq: 3 });
    expect((await w.call("POST", "/taint", { event: replay, signature: kmsSign(replay) })).status).toBe(400);
    const s = w.serve.state();
    expect(s.teams.find((t) => t.team === "research")!.reservedMinor).toBe(18_000);
    // A previous boot armed it and never disarmed it: this boot cannot know, so it does not say true.
    expect(s.cards.find((c) => c.agent === "research-agent")!.armed).toBe("unknown");
    expect(w.serve.armWatcher!.watched(CARDS.researchAgent)?.origin).toBe("resume");
    expect(s.chain.seq).toBe(4);
    expect(w.orders.length).toBe(0);
  });

  test("objects under the old unsigned prefix do not matter", async () => {
    const store = await used();
    store.objects.set("checkpoints/serve/000000000001.json", JSON.stringify({ seq: 1, head: "x", entry: {} }));
    expect((await world({ store })).serve.verified).toBe(true);
  });

  const broken: [string, (s: FakeS3Store) => void][] = [
    ["an edited entry", (s) => {
      const k = "checkpoints/v2/000000000001.json";
      const b = JSON.parse(s.objects.get(k)!);
      b.entry.payload.amountMinor = 1;
      s.objects.set(k, JSON.stringify(b));
    }],
    ["a truncated chain with a gap", (s) => s.objects.delete("checkpoints/v2/000000000002.json")],
    ["an unsigned entry", (s) => {
      const k = "checkpoints/v2/000000000002.json";
      const b = JSON.parse(s.objects.get(k)!);
      delete b.signature;
      s.objects.set(k, JSON.stringify(b));
    }],
    ["an entry signed by another key", (s) => {
      const k = "checkpoints/v2/000000000002.json";
      const b = JSON.parse(s.objects.get(k)!);
      b.signature = Buffer.from(deriveLedgerSigner(new TextEncoder().encode("other")).sign(entrySigningMessage(b.entry.hash))).toString("base64");
      s.objects.set(k, JSON.stringify(b));
    }],
    ["a forked entry, correctly signed, whose prev is not the entry before it", (s) => {
      const k = "checkpoints/v2/000000000002.json";
      const b = JSON.parse(s.objects.get(k)!);
      const body = { seq: 2, prev: "1".repeat(64), at: b.entry.at, kind: b.entry.kind, payload: b.entry.payload };
      const hash = entryHash(body.prev, body);
      s.objects.set(k, JSON.stringify({ seq: 2, head: hash, entry: { ...body, hash }, signature: Buffer.from(SIGNER.sign(entrySigningMessage(hash))).toString("base64") }));
    }],
    ["a body that names another seq", (s) => {
      s.objects.set("checkpoints/v2/000000000004.json", s.objects.get("checkpoints/v2/000000000003.json")!);
    }],
    ["a stray object under the prefix", (s) => s.objects.set("checkpoints/v2/notes.txt", "hi")],
    ["a list that fails", (s) => (s.listFails = true)],
  ];
  for (const [name, damage] of broken) {
    test(`${name}: STATE_UNVERIFIED for every decision, nothing arms`, async () => {
      const store = await used();
      damage(store);
      const putsBefore = store.puts.length;
      const w = await world({ store });
      expect(w.loaded.ok).toBe(false);
      expect(w.serve.verified).toBe(false);
      const r = await w.call("POST", "/writs", { writ: writFor({ id: "writ-9", nonce: "n-9", agent: "research-1", runId: "run-9" }) });
      expect(r.json).toMatchObject({ status: "DECLINED", code: "STATE_UNVERIFIED" });
      const ra = await w.serve.authorizeRa({ mode: "ra", cardId: CARDS.research1, amountMinor: 1, currency: "USD", mcc: "5734", merchantName: "DataCo", now: NOW, ra: { signatureValid: true, nonceFresh: true, nonceSeen: false } }, "evt-1");
      expect(ra).toMatchObject({ status: "DECLINED", code: "STATE_UNVERIFIED" });
      expect(w.orders.length).toBe(0);
      expect((await w.call("GET", "/state")).json.verified).toBe(false);
      await w.tick();
      expect(w.disarms.sort()).toEqual(Object.values(CARDS).sort());
      expect(w.store.puts.length).toBe(putsBefore);
    });
  }

  test("a consume with no arm record is disarmed at boot, to be sure", async () => {
    const w1 = await world({ armOk: false });
    expect((await w1.call("POST", "/writs", { writ: writFor() })).json).toMatchObject({ code: "ARM_FAILED" });
    const w2 = await world({ store: w1.store });
    expect(w2.serve.verified).toBe(true);
    await w2.tick();
    expect(w2.disarms).toEqual([CARDS.researchAgent]);
    expect(w2.store.checkpoints().map((c) => c.entry.kind)).toEqual(["consume", "disarm"]);
  });
});

describe("disarm after one swipe", () => {
  const tx = (over: Partial<CardTx> = {}): CardTx => ({ transactionId: "tx-1", type: "AUTHORIZATION", status: "APPROVED", amountMinor: 18_000, at: "2026-11-12T08:35:03.000Z", ...over });

  test("the first transaction after the arm disarms the card, swipe and disarm are recorded", async () => {
    const w = await world();
    await w.call("POST", "/writs", { writ: writFor() });
    await w.tick("2026-11-12T08:35:05.000Z");
    expect(w.disarms).toEqual([]);
    w.txs.set(CARDS.researchAgent, [tx({ at: "2026-11-12T08:20:00.000Z", transactionId: "old", status: "FAILED", failureReason: "CARD_INACTIVE" }), tx()]);
    await w.tick("2026-11-12T08:35:10.000Z");
    expect(w.disarms).toEqual([CARDS.researchAgent]);
    expect(w.serve.armWatcher!.isArmed(CARDS.researchAgent)).toBe(false);
    expect(w.store.checkpoints().map((c) => c.entry.kind)).toEqual(["consume", "arm", "bank", "swipe", "disarm"]);
    const kinds = w.serve.events.map((e) => e.kind);
    expect(kinds).toContain("ARM");
    expect(kinds).toContain("SWIPE");
    expect(kinds).toContain("DISARM");
    await w.tick("2026-11-12T08:35:15.000Z");
    expect(w.disarms.length).toBe(1);
  });

  test("a declined swipe also ends the arm", async () => {
    const w = await world();
    await w.call("POST", "/writs", { writ: writFor() });
    w.txs.set(CARDS.researchAgent, [tx({ status: "FAILED", failureReason: "MERCHANT_CATEGORY_NOT_ALLOWED" })]);
    await w.tick("2026-11-12T08:35:10.000Z");
    expect(w.disarms).toEqual([CARDS.researchAgent]);
  });

  test("the writ expiry disarms the card with no swipe", async () => {
    const w = await world();
    await w.call("POST", "/writs", { writ: writFor() });
    await w.tick("2026-11-12T08:59:59.000Z");
    expect(w.disarms).toEqual([]);
    await w.tick("2026-11-12T09:00:00.000Z");
    expect(w.disarms).toEqual([CARDS.researchAgent]);
    const disarm = w.store.checkpoints().find((c) => c.entry.kind === "disarm")!;
    expect(disarm.entry.payload.reason).toBe("writ expired");
  });

  test("a failed disarm retries on each tick and records an alert each time, then the disarm", async () => {
    const w = await world({ disarmResults: [false, false, true] });
    await w.call("POST", "/writs", { writ: writFor() });
    w.txs.set(CARDS.researchAgent, [tx()]);
    await w.tick("2026-11-12T08:35:10.000Z");
    expect(w.serve.armWatcher!.isArmed(CARDS.researchAgent)).toBe(true);
    await w.tick("2026-11-12T08:35:15.000Z");
    await w.tick("2026-11-12T08:35:20.000Z");
    expect(w.disarms.length).toBe(3);
    expect(w.serve.armWatcher!.isArmed(CARDS.researchAgent)).toBe(false);
    expect(w.store.checkpoints().map((c) => c.entry.kind)).toEqual(["consume", "arm", "bank", "swipe", "alert", "alert", "disarm"]);
    expect(w.serve.events.filter((e) => e.kind === "ALERT").length).toBe(2);
  });

  test("listCardTransactions turns the Airwallex list into positive cents and refuses junk", async () => {
    const items = [
      { card_id: "c-1", transaction_id: "t-1", transaction_type: "AUTHORIZATION", status: "FAILED", failure_reason: "LIMIT_EXCEEDED", transaction_amount: -60, transaction_date: "2026-11-09T10:42:25.472+0000" },
      { card_id: "c-1", transaction_id: "t-2", transaction_type: "CLEARING", status: "APPROVED", transaction_amount: -40.5, transaction_date: "2026-11-09T10:42:17.769+0000" },
    ];
    const urls: string[] = [];
    const fetch = async (url: string) => (urls.push(url), { status: 200, headers: new Headers(), text: async () => JSON.stringify({ items }) });
    const out = await listCardTransactions(fetch, "tok", "c-1", "2026-11-09T10:00:00.000Z");
    expect(out).toEqual([
      { transactionId: "t-1", type: "AUTHORIZATION", status: "FAILED", amountMinor: 6_000, at: "2026-11-09T10:42:25.472Z", failureReason: "LIMIT_EXCEEDED" },
      { transactionId: "t-2", type: "CLEARING", status: "APPROVED", amountMinor: 4_050, at: "2026-11-09T10:42:17.769Z" },
    ]);
    expect(urls[0]).toContain("card_id=c-1");
    expect(urls[0]).toContain("from_created_at=2026-11-09T10%3A00%3A00%2B0000");
    expect(await listCardTransactions(fetch, undefined, "c-1", NOW)).toBeUndefined();
    const bad = async () => ({ status: 200, headers: new Headers(), text: async () => JSON.stringify({ items: [{ transaction_id: "x", transaction_amount: 1.234, transaction_date: NOW }] }) });
    expect(await listCardTransactions(bad, "tok", "c-1", NOW)).toBeUndefined();
    const down = async () => ({ status: 500, headers: new Headers(), text: async () => "" });
    expect(await listCardTransactions(down, "tok", "c-1", NOW)).toBeUndefined();
  });
});

describe("bank events feed the enclave ledger", () => {
  const bank = (over: Partial<CardTx> = {}): CardTx => ({ transactionId: "tx-a", type: "AUTHORIZATION", status: "APPROVED", amountMinor: 18_000, at: "2026-11-12T08:35:03.000Z", ...over });
  const team = (w: Awaited<ReturnType<typeof world>>, name: string) => w.serve.state().teams.find((t) => t.team === name)!;
  const RESEARCH_CARDS = [CARDS.research1, CARDS.researchAgent].sort();

  test("a matched authorization moves reserved to pending, and its clearing moves pending to settled", async () => {
    const w = await world();
    await w.call("POST", "/writs", { writ: writFor() });
    expect(team(w, "research")).toMatchObject({ reservedMinor: 18_000, pendingMinor: 0, settledMinor: 0 });
    w.txs.set(CARDS.researchAgent, [bank()]);
    await w.tick("2026-11-12T08:35:10.000Z");
    expect(team(w, "research")).toMatchObject({ reservedMinor: 0, pendingMinor: 18_000, settledMinor: 0, teamFrozen: null });
    w.txs.set(CARDS.researchAgent, [bank(), bank({ transactionId: "tx-c", type: "CLEARING", matchedAuthorizations: 1, at: "2026-11-12T08:40:00.000Z" })]);
    await w.tick("2026-11-12T08:40:10.000Z");
    expect(team(w, "research")).toMatchObject({ reservedMinor: 0, pendingMinor: 0, settledMinor: 18_000, teamFrozen: null });
    const banks = w.store.checkpoints().filter((c) => c.entry.kind === "bank").map((c) => c.entry.payload);
    expect(banks).toEqual([
      expect.objectContaining({ eventId: "bank:tx-a", kind: "AUTHORIZATION", writId: "writ-1", amountMinor: 18_000 }),
      expect.objectContaining({ eventId: "bank:tx-c", kind: "CLEARING", writId: "writ-1", amountMinor: 18_000 }),
    ]);
    expect(w.serve.events.filter((e) => e.kind === "FREEZE").length).toBe(0);
  });

  test("an unmatched clearing counts against the pool, freezes the team, disarms all its cards, and the next writ declines", async () => {
    const w = await world();
    w.txs.set(CARDS.research1, [bank({ transactionId: "tx-x", type: "CLEARING", amountMinor: 5_000, matchedAuthorizations: 1 })]);
    await w.tick("2026-11-12T08:35:10.000Z");
    const r = team(w, "research");
    expect(r.settledMinor).toBe(5_000);
    expect(r.teamFrozen).toMatchObject({ at: "2026-11-12T08:35:03.000Z" });
    expect(r.teamFrozen!.reason).toContain("no matching approval");
    expect(team(w, "ops").teamFrozen).toBeNull();
    expect([...w.disarms].sort()).toEqual(RESEARCH_CARDS);
    const kinds = w.serve.events.map((e) => e.kind);
    expect(kinds).toContain("ALERT");
    expect(kinds).toContain("FREEZE");
    expect(w.store.checkpoints().map((c) => c.entry.kind)).toEqual(["bank", "freeze", "disarm", "disarm"]);
    const freeze = w.store.checkpoints().find((c) => c.entry.kind === "freeze")!;
    expect(freeze.entry.payload).toMatchObject({ eventId: "freeze:awx:tx-x", team: "research", txId: "tx-x" });

    expect((await w.call("POST", "/writs", { writ: writFor() })).json).toMatchObject({ status: "DECLINED", code: "TEAM_POOL_EXHAUSTED" });
    const ops = await w.call("POST", "/writs", { writ: writFor({ id: "ops-1w", team: "ops", agent: "ops-1", nonce: "n-ops" }) });
    expect(ops.json.status).toBe("AUTHORIZED");
    expect(w.orders.map((o) => o.cardId)).toEqual([CARDS.ops1]);
  });

  test("a clearing with no matched authorization is a forced capture and freezes the team even with a used writ", async () => {
    const w = await world();
    await w.call("POST", "/writs", { writ: writFor() });
    w.txs.set(CARDS.researchAgent, [bank({ transactionId: "tx-f", type: "CLEARING", matchedAuthorizations: 0, amountMinor: 18_000 })]);
    await w.tick("2026-11-12T08:35:10.000Z");
    expect(w.store.checkpoints().find((c) => c.entry.kind === "bank")!.entry.payload).toMatchObject({ kind: "FORCED_CAPTURE" });
    expect(team(w, "research").teamFrozen).not.toBeNull();
    expect(w.serve.armWatcher!.isArmed(CARDS.researchAgent)).toBe(false);
  });

  test("a second authorization on a writ that already had one is unmatched and freezes the team", async () => {
    const w = await world();
    await w.call("POST", "/writs", { writ: writFor() });
    w.txs.set(CARDS.researchAgent, [bank(), bank({ transactionId: "tx-a2", at: "2026-11-12T08:35:04.000Z" })]);
    await w.tick("2026-11-12T08:35:10.000Z");
    const banks = w.store.checkpoints().filter((c) => c.entry.kind === "bank").map((c) => c.entry.payload);
    expect(banks[0]).toMatchObject({ writId: "writ-1" });
    expect(banks[1]!.writId).toBeUndefined();
    expect(team(w, "research").teamFrozen).not.toBeNull();
  });

  test("declined swipes move no money and freeze nothing", async () => {
    const w = await world();
    w.txs.set(CARDS.research1, [bank({ status: "FAILED", failureReason: "CARD_INACTIVE" })]);
    await w.tick("2026-11-12T08:35:10.000Z");
    expect(team(w, "research")).toMatchObject({ reservedMinor: 0, pendingMinor: 0, settledMinor: 0, teamFrozen: null });
    expect(w.store.puts.length).toBe(0);
    expect(w.disarms.length).toBe(0);
  });

  test("a re-poll of the same transactions does nothing", async () => {
    const w = await world();
    w.txs.set(CARDS.research1, [bank({ transactionId: "tx-x", type: "CLEARING", amountMinor: 5_000, matchedAuthorizations: 1 })]);
    await w.tick("2026-11-12T08:35:10.000Z");
    const puts = w.store.puts.length;
    const events = w.serve.events.length;
    const disarms = w.disarms.length;
    for (const t of ["08:35:25", "08:35:40", "08:35:55"]) await w.tick(`2026-11-12T${t}.000Z`);
    expect(w.store.puts.length).toBe(puts);
    expect(w.serve.events.length).toBe(events);
    expect(w.disarms.length).toBe(disarms);
    expect(team(w, "research").settledMinor).toBe(5_000);
    expect(w.serve.events.filter((e) => e.eventId === "awx:tx-x").length).toBe(1);
  });

  test("replay restores the freeze and the money, disarms the team again, and a re-poll after restart adds nothing", async () => {
    const w1 = await world();
    await w1.call("POST", "/writs", { writ: writFor({ id: "ops-1w", team: "ops", agent: "ops-1", nonce: "n-ops" }) });
    w1.txs.set(CARDS.research1, [bank({ transactionId: "tx-x", type: "CLEARING", amountMinor: 5_000, matchedAuthorizations: 1 })]);
    await w1.tick("2026-11-12T08:35:10.000Z");
    const w2 = await world({ store: w1.store });
    expect(w2.serve.verified).toBe(true);
    const r = team(w2, "research");
    expect(r.settledMinor).toBe(5_000);
    expect(r.teamFrozen).toMatchObject({ at: "2026-11-12T08:35:03.000Z" });
    expect(team(w2, "ops").teamFrozen).toBeNull();
    expect((await w2.call("POST", "/writs", { writ: writFor({ id: "writ-9", nonce: "n-9" }) })).json).toMatchObject({ code: "TEAM_POOL_EXHAUSTED" });
    const puts = w2.store.puts.length;
    w2.txs.set(CARDS.research1, [bank({ transactionId: "tx-x", type: "CLEARING", amountMinor: 5_000, matchedAuthorizations: 1 })]);
    await w2.tick("2026-11-12T08:36:00.000Z");
    expect(w2.disarms.filter((c) => RESEARCH_CARDS.includes(c)).sort()).toEqual(RESEARCH_CARDS);
    expect(w2.store.checkpoints().filter((c) => c.entry.kind === "bank").length).toBe(1);
    expect(w2.store.puts.length - puts).toBe(2);
    expect(w2.store.checkpoints().slice(-2).map((c) => c.entry.kind)).toEqual(["disarm", "disarm"]);
  });

  test("an edited bank checkpoint is tampering", async () => {
    const w1 = await world();
    w1.txs.set(CARDS.research1, [bank({ transactionId: "tx-x", type: "CLEARING", amountMinor: 5_000, matchedAuthorizations: 1 })]);
    await w1.tick("2026-11-12T08:35:10.000Z");
    const k = "checkpoints/v2/000000000001.json";
    const b = JSON.parse(w1.store.objects.get(k)!);
    b.entry.payload.amountMinor = 1;
    w1.store.objects.set(k, JSON.stringify(b));
    const w2 = await world({ store: w1.store });
    expect(w2.loaded.ok).toBe(false);
    expect(w2.serve.verified).toBe(false);
  });
});

describe("release of an unswiped reservation", () => {
  const auth = (over: Partial<CardTx> = {}): CardTx => ({ transactionId: "tx-a", type: "AUTHORIZATION", status: "APPROVED", amountMinor: 18_000, at: "2026-11-12T08:35:03.000Z", ...over });
  const team = (w: Awaited<ReturnType<typeof world>>, name: string) => w.serve.state().teams.find((t) => t.team === name)!;
  const kinds = (w: Awaited<ReturnType<typeof world>>) => w.store.checkpoints().map((c) => c.entry.kind);

  test("expiry with no authorization disarms, then releases the hold so the pool can be used again", async () => {
    const w = await world();
    await w.call("POST", "/writs", { writ: writFor() });
    const big = writFor({ id: "writ-big", nonce: "n-big", agent: "research-1", runId: "run-b", amountMinor: 40_000, expiresAt: "2026-11-12T10:00:00.000Z" });
    w.fresh();
    expect((await w.call("POST", "/writs", { writ: big })).json).toMatchObject({ code: "TEAM_POOL_EXHAUSTED" });
    await w.tick("2026-11-12T09:00:00.000Z");
    expect(w.disarms).toEqual([CARDS.researchAgent]);
    expect(team(w, "research")).toMatchObject({ reservedMinor: 0, pendingMinor: 0, settledMinor: 0, releasedMinor: 18_000 });
    expect(kinds(w)).toEqual(["consume", "arm", "revoke", "disarm", "release"]);
    const rel = w.store.checkpoints().find((c) => c.entry.kind === "release")!;
    expect(rel.entry.payload).toMatchObject({ eventId: "release:writ-1", writId: "writ-1", amountMinor: 18_000, reason: "writ expired" });
    expect((await w.call("GET", "/state")).json.reserve.openReservationsMinor).toBe(0);

    w.fresh();
    expect((await w.call("POST", "/writs", { writ: big })).json).toMatchObject({ code: "WRIT_REVOKED" });
    const big2 = writFor({ id: "writ-big2", nonce: "n-big2", agent: "research-1", runId: "run-b", amountMinor: 40_000, expiresAt: "2026-11-12T10:00:00.000Z" });
    expect((await w.call("POST", "/writs", { writ: big2 })).json.status).toBe("AUTHORIZED");
  });

  test("expiry after a matched authorization keeps the money pending, no release", async () => {
    const w = await world();
    await w.call("POST", "/writs", { writ: writFor() });
    w.txs.set(CARDS.researchAgent, [auth()]);
    await w.tick("2026-11-12T08:35:10.000Z");
    await w.tick("2026-11-12T09:00:00.000Z");
    expect(team(w, "research")).toMatchObject({ reservedMinor: 0, pendingMinor: 18_000, releasedMinor: 0 });
    expect(kinds(w)).not.toContain("release");
  });

  test("a failed disarm at expiry keeps the hold until the card is confirmed INACTIVE", async () => {
    const w = await world({ disarmResults: [false, true] });
    await w.call("POST", "/writs", { writ: writFor() });
    await w.tick("2026-11-12T09:00:00.000Z");
    expect(team(w, "research")).toMatchObject({ reservedMinor: 18_000, releasedMinor: 0 });
    await w.tick("2026-11-12T09:00:05.000Z");
    expect(team(w, "research")).toMatchObject({ reservedMinor: 0, releasedMinor: 18_000 });
  });

  test("an authorization that arrives after the release is unmatched: it counts, alerts and freezes the team", async () => {
    const w = await world();
    await w.call("POST", "/writs", { writ: writFor() });
    await w.tick("2026-11-12T09:00:00.000Z");
    w.txs.set(CARDS.researchAgent, [auth({ transactionId: "tx-late", at: "2026-11-12T09:00:30.000Z" })]);
    await w.tick("2026-11-12T09:00:40.000Z");
    const late = w.store.checkpoints().find((c) => c.entry.kind === "bank")!;
    expect(late.entry.payload.writId).toBeUndefined();
    const t = team(w, "research");
    expect(t.pendingMinor).toBe(18_000);
    expect(t.teamFrozen).not.toBeNull();
    expect(w.serve.events.some((e) => e.kind === "ALERT" && e.eventId === "alert:awx:tx-late")).toBe(true);
  });

  test("a taint disarm releases an unswiped writ", async () => {
    const w = await world();
    await w.call("POST", "/writs", { writ: writFor() });
    const event = taintEvent();
    await w.call("POST", "/taint", { event, signature: kmsSign(event) });
    await w.serve.armWatcher!.idle();
    await new Promise((r) => setTimeout(r, 0));
    expect(team(w, "research")).toMatchObject({ reservedMinor: 0, releasedMinor: 18_000 });
    expect(w.store.checkpoints().find((c) => c.entry.kind === "release")!.entry.payload.reason).toBe("run tainted");
  });

  test("a team freeze releases the unswiped writs of that team", async () => {
    const w = await world();
    await w.call("POST", "/writs", { writ: writFor() });
    w.txs.set(CARDS.research1, [auth({ transactionId: "tx-x", type: "CLEARING", amountMinor: 5_000, matchedAuthorizations: 1 })]);
    await w.tick("2026-11-12T08:35:10.000Z");
    const t = team(w, "research");
    expect(t.teamFrozen).not.toBeNull();
    expect(t).toMatchObject({ reservedMinor: 0, settledMinor: 5_000, releasedMinor: 18_000 });
    expect(w.store.checkpoints().find((c) => c.entry.kind === "release")!.entry.payload.reason).toBe("team frozen");
  });

  test("replay restores the release once, and a later expiry pass does not release twice", async () => {
    const w1 = await world();
    await w1.call("POST", "/writs", { writ: writFor() });
    await w1.tick("2026-11-12T09:00:00.000Z");
    const w2 = await world({ store: w1.store });
    expect(w2.serve.verified).toBe(true);
    expect(team(w2, "research")).toMatchObject({ reservedMinor: 0, releasedMinor: 18_000 });
    expect(w2.serve.state().cards.find((c) => c.agent === "research-agent")!.armed).toBe(false);
    const puts = w2.store.puts.length;
    await w2.tick("2026-11-12T09:01:00.000Z");
    expect(w2.store.puts.length).toBe(puts);
    expect(w2.serve.events.filter((e) => e.eventId === "release:writ-1").length).toBe(1);
  });
});

describe("an authorization row that changes status in place", () => {
  const auth = (status: string, over: Partial<CardTx> = {}): CardTx => ({ transactionId: "tx-a", type: "AUTHORIZATION", status, amountMinor: 18_000, at: "2026-11-12T08:35:03.000Z", ...over });
  const team = (w: Awaited<ReturnType<typeof world>>, name: string) => w.serve.state().teams.find((t) => t.team === name)!;
  const banks = (w: Awaited<ReturnType<typeof world>>) => w.store.checkpoints().filter((c) => c.entry.kind === "bank").map((c) => c.entry.payload);

  test("PENDING then REVERSED on the same id releases the pending hold, once", async () => {
    const w = await world();
    await w.call("POST", "/writs", { writ: writFor() });
    w.txs.set(CARDS.researchAgent, [auth("PENDING")]);
    await w.tick("2026-11-12T08:35:10.000Z");
    expect(team(w, "research")).toMatchObject({ reservedMinor: 0, pendingMinor: 18_000 });
    w.txs.set(CARDS.researchAgent, [auth("REVERSED")]);
    await w.tick("2026-11-12T08:36:00.000Z");
    expect(team(w, "research")).toMatchObject({ reservedMinor: 0, pendingMinor: 0, settledMinor: 0, releasedMinor: 18_000, teamFrozen: null });
    expect(banks(w)).toEqual([
      expect.objectContaining({ eventId: "bank:tx-a", kind: "AUTHORIZATION", writId: "writ-1" }),
      expect.objectContaining({ eventId: "bank:tx-a:reversed", kind: "REVERSAL", stage: "reversed", writId: "writ-1", amountMinor: 18_000 }),
    ]);
    const puts = w.store.puts.length;
    for (const t of ["08:36:15", "08:36:30"]) await w.tick(`2026-11-12T${t}.000Z`);
    w.txs.set(CARDS.researchAgent, [auth("PENDING"), auth("REVERSED")]);
    await w.tick("2026-11-12T08:36:45.000Z");
    expect(w.store.puts.length).toBe(puts);
    expect(team(w, "research").releasedMinor).toBe(18_000);
  });

  test("PENDING then a cleared status settles the matched writ", async () => {
    const w = await world();
    await w.call("POST", "/writs", { writ: writFor() });
    w.txs.set(CARDS.researchAgent, [auth("PENDING")]);
    await w.tick("2026-11-12T08:35:10.000Z");
    w.txs.set(CARDS.researchAgent, [auth("CLEARED")]);
    await w.tick("2026-11-12T08:40:00.000Z");
    expect(team(w, "research")).toMatchObject({ reservedMinor: 0, pendingMinor: 0, settledMinor: 18_000, teamFrozen: null });
    expect(banks(w)[1]).toMatchObject({ eventId: "bank:tx-a:cleared", kind: "CLEARING", stage: "cleared", writId: "writ-1" });
  });

  test("PENDING to APPROVED is the same hold, not a second one", async () => {
    const w = await world();
    await w.call("POST", "/writs", { writ: writFor() });
    w.txs.set(CARDS.researchAgent, [auth("PENDING")]);
    await w.tick("2026-11-12T08:35:10.000Z");
    w.txs.set(CARDS.researchAgent, [auth("APPROVED")]);
    await w.tick("2026-11-12T08:36:00.000Z");
    expect(banks(w).length).toBe(1);
    expect(team(w, "research")).toMatchObject({ pendingMinor: 18_000, teamFrozen: null });
  });

  test("a REVERSED row with no hold recorded moves nothing", async () => {
    const w = await world();
    w.txs.set(CARDS.research1, [auth("REVERSED")]);
    await w.tick("2026-11-12T08:35:10.000Z");
    expect(w.store.puts.length).toBe(0);
    expect(team(w, "research").teamFrozen).toBeNull();
  });

  test("replay reproduces the reversal and a re-poll after restart adds nothing", async () => {
    const w1 = await world();
    await w1.call("POST", "/writs", { writ: writFor() });
    w1.txs.set(CARDS.researchAgent, [auth("PENDING")]);
    await w1.tick("2026-11-12T08:35:10.000Z");
    w1.txs.set(CARDS.researchAgent, [auth("REVERSED")]);
    await w1.tick("2026-11-12T08:36:00.000Z");
    const w2 = await world({ store: w1.store });
    expect(w2.serve.verified).toBe(true);
    expect(team(w2, "research")).toMatchObject({ pendingMinor: 0, releasedMinor: 18_000 });
    const puts = w2.store.puts.length;
    w2.txs.set(CARDS.researchAgent, [auth("REVERSED")]);
    await w2.tick("2026-11-12T08:37:00.000Z");
    expect(w2.store.checkpoints().filter((c) => c.entry.kind === "bank").length).toBe(2);
    expect(w2.store.puts.length).toBe(puts);
  });

  test("a hold recorded by the older image (key awx:<id>, no stage) is reversed by the new one", async () => {
    const w1 = await world();
    await w1.call("POST", "/writs", { writ: writFor() });
    w1.txs.set(CARDS.researchAgent, [auth("PENDING")]);
    await w1.tick("2026-11-12T08:35:10.000Z");
    expect(banks(w1)[0]!.stage).toBeUndefined();
    const w2 = await world({ store: w1.store });
    expect(team(w2, "research").pendingMinor).toBe(18_000);
    w2.txs.set(CARDS.researchAgent, [auth("REVERSED")]);
    await w2.tick("2026-11-12T08:36:00.000Z");
    expect(team(w2, "research")).toMatchObject({ pendingMinor: 0, releasedMinor: 18_000 });
  });
});

describe("a declined writ does not hold the card", () => {
  test("a declined writ frees the card, is closed with a checkpointed revoke, and the next writ is evaluated normally", async () => {
    const w = await world();
    const over = writFor({ id: "writ-over", nonce: "n-over", amountMinor: 60_000 });
    expect((await w.call("POST", "/writs", { writ: over })).json).toMatchObject({ code: "TEAM_POOL_EXHAUSTED" });
    expect(w.store.checkpoints().map((c) => c.entry.kind)).toEqual(["revoke"]);
    expect(w.store.checkpoints()[0]!.entry.payload).toMatchObject({ eventId: "revoke:writ-over", writId: "writ-over", code: "TEAM_POOL_EXHAUSTED" });
    expect((await w.call("POST", "/writs", { writ: over })).json).toMatchObject({ code: "WRIT_REVOKED" });
    const next = await w.call("POST", "/writs", { writ: writFor({ id: "writ-ok", nonce: "n-ok" }) });
    expect(next.json).toMatchObject({ writId: "writ-ok", status: "AUTHORIZED" });
  });

  test("a forged or edited writ never binds to the card, and the card still takes a real one", async () => {
    const w = await world();
    const forged = writFor({ id: "writ-f", nonce: "n-f" }, APPROVED_AT, OTHER_KEYS.privateKeyPem);
    expect((await w.call("POST", "/writs", { writ: forged })).json).toMatchObject({ code: "WRIT_BAD_SIGNATURE" });
    const edited = { ...writFor({ id: "writ-e", nonce: "n-e" }), amountMinor: 1_000 };
    expect((await w.call("POST", "/writs", { writ: edited })).json).toMatchObject({ code: "WRIT_HASH_MISMATCH" });
    expect(w.serve.events.some((e) => e.kind === "WRIT_REGISTERED")).toBe(false);
    expect(w.store.puts.length).toBe(0);
    const decisions = (await w.call("GET", "/state")).json.decisions as { code?: string }[];
    expect(decisions.map((d) => d.code)).toEqual(["WRIT_HASH_MISMATCH", "WRIT_BAD_SIGNATURE"]);
    expect((await w.call("POST", "/writs", { writ: writFor() })).json.status).toBe("AUTHORIZED");
  });

  test("a forged writ that reuses a real writ id cannot close or replace the real one", async () => {
    const w = await world();
    const forged = writFor({}, APPROVED_AT, OTHER_KEYS.privateKeyPem);
    expect((await w.call("POST", "/writs", { writ: forged })).json).toMatchObject({ code: "WRIT_BAD_SIGNATURE" });
    expect((await w.call("POST", "/writs", { writ: writFor() })).json.status).toBe("AUTHORIZED");
  });

  test("an authorized writ stays bound: the same writ again is WRIT_REPLAY, never a revoke", async () => {
    const w = await world();
    await w.call("POST", "/writs", { writ: writFor() });
    expect((await w.call("POST", "/writs", { writ: writFor() })).json).toMatchObject({ code: "WRIT_REPLAY" });
    expect(w.store.checkpoints().map((c) => c.entry.kind)).not.toContain("revoke");
    expect(w.serve.state().cards.find((c) => c.agent === "research-agent")!.armed).toBe(true);
  });

  test("a writ declined before a restart stays closed after it", async () => {
    const w1 = await world();
    const over = writFor({ id: "writ-over", nonce: "n-over", amountMinor: 60_000 });
    await w1.call("POST", "/writs", { writ: over });
    const w2 = await world({ store: w1.store });
    expect(w2.serve.verified).toBe(true);
    expect((await w2.call("POST", "/writs", { writ: over })).json).toMatchObject({ code: "WRIT_REVOKED" });
    expect((await w2.call("POST", "/writs", { writ: writFor() })).json.status).toBe("AUTHORIZED");
  });
});

describe("expired holds written by an older image", () => {
  /** consume, arm, then a disarm 'writ expired' with no release, as the image before the release fix wrote it. */
  async function legacyStore(withAuth = false) {
    const w = await world();
    await w.call("POST", "/writs", { writ: writFor() });
    const store = new FakeS3Store();
    for (const k of ["checkpoints/v2/000000000001.json", "checkpoints/v2/000000000002.json"]) store.objects.set(k, w.store.objects.get(k)!);
    const loaded = await loadSignedChain(store, BUCKET, SIGNED_CHECKPOINT_PREFIX, SIGNER.publicKeyRaw);
    if (!loaded.ok) throw new Error(loaded.reason);
    store.clock = () => new Date("2026-11-12T09:00:05.000Z");
    const c = new S3CheckpointCommitter({ client: store, bucket: BUCKET, prefix: SIGNED_CHECKPOINT_PREFIX, resume: loaded.entries, signer: SIGNER });
    if (withAuth) {
      await c.append("bank", { eventId: "bank:tx-a", txId: "tx-a", cardId: CARDS.researchAgent, kind: "AUTHORIZATION", amountMinor: 18_000, at: "2026-11-12T08:35:03.000Z", writId: "writ-1" }, "2026-11-12T08:35:10.000Z");
    }
    await c.append("disarm", { eventId: "disarm:writ-1", cardId: CARDS.researchAgent, writId: "writ-1", reason: "writ expired" }, "2026-11-12T09:00:05.000Z");
    return store;
  }
  const research = (w: Awaited<ReturnType<typeof world>>) => w.serve.state().teams.find((t) => t.team === "research")!;

  test("replay plus the first tick releases the hold with one release entry, and a second boot adds nothing", async () => {
    const store = await legacyStore();
    const w = await world({ store });
    w.clock.iso = "2026-11-12T09:30:00.000Z";
    expect(w.serve.verified).toBe(true);
    expect(research(w).reservedMinor).toBe(18_000);
    await w.tick();
    expect(research(w)).toMatchObject({ reservedMinor: 0, releasedMinor: 18_000 });
    expect(w.disarms).toEqual([]);
    const releases = store.checkpoints().filter((c) => c.entry.kind === "release");
    expect(releases.map((r) => r.entry.payload)).toEqual([expect.objectContaining({ eventId: "release:writ-1", writId: "writ-1", amountMinor: 18_000, reason: "writ expired" })]);
    const puts = store.puts.length;

    const again = await world({ store });
    again.clock.iso = "2026-11-12T09:31:00.000Z";
    await again.tick();
    await again.tick();
    expect(research(again)).toMatchObject({ reservedMinor: 0, releasedMinor: 18_000 });
    expect(store.puts.length).toBe(puts);
  });

  test("a hold that is not past its expiry yet stays reserved", async () => {
    const store = await legacyStore();
    const w = await world({ store });
    w.clock.iso = "2026-11-12T08:59:00.000Z";
    await w.tick();
    expect(research(w).reservedMinor).toBe(18_000);
  });

  test("a writ with a matched authorization keeps its pending hold after expiry", async () => {
    const store = await legacyStore(true);
    const w = await world({ store });
    w.clock.iso = "2026-11-12T09:30:00.000Z";
    await w.tick();
    expect(research(w)).toMatchObject({ reservedMinor: 0, pendingMinor: 18_000, releasedMinor: 0 });
    expect(store.checkpoints().some((c) => c.entry.kind === "release")).toBe(false);
  });

  test("a newer writ armed on the same card does not block the release of an older expired one", async () => {
    const w1 = await world();
    await w1.call("POST", "/writs", { writ: writFor() });
    await w1.tick("2026-11-12T09:00:00.000Z");
    const later = writFor({ id: "writ-2", nonce: "n-2", expiresAt: "2026-11-12T11:00:00.000Z" }, "2026-11-12T09:00:30.000Z");
    w1.fresh();
    expect((await w1.call("POST", "/writs", { writ: later })).json.status).toBe("AUTHORIZED");
    expect(research(w1)).toMatchObject({ reservedMinor: 18_000, releasedMinor: 18_000 });
    expect(w1.serve.armWatcher!.isArmed(CARDS.researchAgent)).toBe(true);
  });
});

describe("source rules", () => {
  test("no host clock, no logging and no em dash in the new enclave files", () => {
    for (const f of ["enclave-app.ts", "enclave-watch.ts", "enclave-taint.ts", "enclave-serve.ts", "enclave-creds.ts", "enclave-keys.ts"]) {
      const t = readFileSync(new URL(`../src/host/${f}`, import.meta.url), "utf8");
      expect(/Date\.now|new Date\(\)|console\.|process\.(stdout|stderr)/.test(t)).toBe(false);
      expect(t.includes("\u2014")).toBe(false);
    }
  });
});
