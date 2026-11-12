// Hash chain: honest logs verify; any edit, drop, swap, truncation, fork or bad signature is STATE_UNVERIFIED.

import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import {
  checkpointSigningMessage,
  entryHash,
  entrySigningMessage,
  GENESIS_PREV,
  verifyChain,
  type ChainCheckpoint,
  type ChainEntry,
} from "../src/core/chain";
import { canonicalJson } from "../src/core/writ";
import { rng } from "./helpers";

type Rng = ReturnType<typeof rng>;

function keypair(): { priv: KeyObject; raw: Uint8Array } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const der = publicKey.export({ type: "spki", format: "der" });
  return { priv: privateKey, raw: new Uint8Array(der.subarray(der.length - 32)) };
}

const KEY = keypair();
const OTHER = keypair();

const KINDS = ["RESERVE", "AUTHORIZATION", "CLEARING", "REVERSAL", "REFUND", "TAINT"] as const;

function payloadFor(r: Rng, i: number): unknown {
  return {
    team: r.pick(["research", "ops", "growth"]),
    cardId: `card-${r.int(1, 9)}`,
    amountMinor: r.int(1, 500_000),
    reason: `event ${i} note ${r.int(0, 1_000_000)}`,
    tags: [r.pick(["a", "b", "c"]), r.int(0, 99)],
  };
}

function build(n: number, seed: number, signer?: KeyObject): ChainEntry[] {
  const r = rng(seed);
  const out: ChainEntry[] = [];
  let prev = GENESIS_PREV;
  for (let i = 1; i <= n; i++) {
    const body = { seq: i, prev, at: 1_700_000_000_000 + i * 1000, kind: r.pick(KINDS), payload: payloadFor(r, i) };
    const hash = entryHash(prev, body);
    const entry: ChainEntry = { ...body, hash };
    if (signer) entry.signature = new Uint8Array(sign(null, entrySigningMessage(hash), signer));
    out.push(entry);
    prev = hash;
  }
  return out;
}

function headOf(entries: ChainEntry[]): string {
  return entries.length === 0 ? GENESIS_PREV : entries[entries.length - 1]!.hash;
}

function checkpointAt(entries: ChainEntry[], seq: number, signer?: KeyObject): ChainCheckpoint {
  const head = seq === 0 ? GENESIS_PREV : entries[seq - 1]!.hash;
  const cp: ChainCheckpoint = { seq, head };
  if (signer) cp.signature = new Uint8Array(sign(null, checkpointSigningMessage(seq, head), signer));
  return cp;
}

function expectUnverified(res: ReturnType<typeof verifyChain>) {
  expect(res.ok).toBe(false);
  if (!res.ok) expect(res.code).toBe("STATE_UNVERIFIED");
}

/** Change one byte of the canonical payload so it still parses and means something different. */
function editOneByte(r: Rng, payload: unknown): unknown {
  const text = canonicalJson(payload);
  for (let attempt = 0; attempt < 1000; attempt++) {
    const pos = r.int(0, text.length - 1);
    const code = text.charCodeAt(pos);
    const replacement = String.fromCharCode(((code - 32 + r.int(1, 94)) % 95) + 32);
    const edited = text.slice(0, pos) + replacement + text.slice(pos + 1);
    try {
      const parsed = JSON.parse(edited);
      if (canonicalJson(parsed) !== text) return parsed;
    } catch {
      // not JSON any more, try another byte
    }
  }
  throw new Error("could not find a parseable one byte edit");
}

describe("honest chains", () => {
  for (const n of [0, 1, 2, 3, 7, 50, 200]) {
    test(`length ${n} verifies and reports the head`, () => {
      const log = build(n, 100 + n);
      expect(verifyChain(log, {})).toEqual({ ok: true, head: headOf(log) });
    });
  }

  test("a log that grew past the checkpoint verifies", () => {
    const log = build(20, 7);
    for (const seq of [0, 1, 10, 20]) {
      expect(verifyChain(log, { checkpoint: checkpointAt(log, seq) })).toEqual({ ok: true, head: headOf(log) });
    }
  });

  test("genesis prev is 64 hex zeros", () => {
    expect(GENESIS_PREV).toBe("0".repeat(64));
    expect(build(1, 1)[0]!.prev).toBe(GENESIS_PREV);
  });

  test("entryHash ignores key order and hash or signature fields", () => {
    const a = entryHash(GENESIS_PREV, { seq: 1, prev: GENESIS_PREV, at: 5, kind: "K", payload: { b: 1, a: [2, 3] } });
    const b = entryHash(GENESIS_PREV, { payload: { a: [2, 3], b: 1 }, kind: "K", at: 5, prev: GENESIS_PREV, seq: 1 });
    expect(a).toBe(b);
    expect(entryHash(GENESIS_PREV, { seq: 1, prev: GENESIS_PREV, at: 5, kind: "K", payload: { b: 1, a: [3, 2] } })).not.toBe(a);
  });
});

describe("property: random tampering of chains of length 1 to 200", () => {
  const TRIALS = 300;

  test("one byte edit to a canonical payload fails", () => {
    const r = rng(0xc0ffee);
    for (let t = 0; t < TRIALS; t++) {
      const n = r.int(1, 200);
      const log = build(n, r.int(1, 1e9));
      const i = r.int(0, n - 1);
      const tampered = log.map((e) => ({ ...e }));
      tampered[i]!.payload = editOneByte(r, tampered[i]!.payload);
      expectUnverified(verifyChain(tampered, {}));
    }
  });

  test("an edited entry whose own hash is recomputed still fails, at the next prev or at the checkpoint", () => {
    const r = rng(0xbeef);
    for (let t = 0; t < TRIALS; t++) {
      const n = r.int(1, 200);
      const log = build(n, r.int(1, 1e9));
      const cp = checkpointAt(log, n);
      const i = r.int(0, n - 1);
      const tampered = log.map((e) => ({ ...e }));
      const e = tampered[i]!;
      e.payload = editOneByte(r, e.payload);
      e.hash = entryHash(e.prev, e);
      expectUnverified(verifyChain(tampered, { checkpoint: cp }));
    }
  });

  test("a rewritten tail with every hash recomputed is caught by the checkpoint (fork)", () => {
    const r = rng(0xf02c);
    for (let t = 0; t < TRIALS; t++) {
      const n = r.int(1, 200);
      const log = build(n, r.int(1, 1e9));
      const cpSeq = r.int(1, n);
      const cp = checkpointAt(log, cpSeq);
      const forkAt = r.int(0, cpSeq - 1);
      const forked = log.slice(0, forkAt);
      let prev = headOf(forked);
      for (let i = forkAt; i < n; i++) {
        const body = { ...log[i]!, prev };
        if (i === forkAt) body.payload = editOneByte(r, body.payload);
        const hash = entryHash(prev, body);
        forked.push({ ...body, hash });
        prev = hash;
      }
      expect(verifyChain(forked, {}).ok).toBe(true);
      expectUnverified(verifyChain(forked, { checkpoint: cp }));
    }
  });

  test("a dropped entry fails", () => {
    const r = rng(0xd20b);
    for (let t = 0; t < TRIALS; t++) {
      const n = r.int(1, 200);
      const log = build(n, r.int(1, 1e9));
      const i = r.int(0, n - 1);
      const dropped = [...log.slice(0, i), ...log.slice(i + 1)];
      expectUnverified(verifyChain(dropped, { checkpoint: checkpointAt(log, n) }));
      if (i < n - 1) expectUnverified(verifyChain(dropped, {}));
    }
  });

  test("a dropped entry with seq renumbered fails", () => {
    const r = rng(0x5e9);
    for (let t = 0; t < TRIALS; t++) {
      const n = r.int(2, 200);
      const log = build(n, r.int(1, 1e9));
      const i = r.int(0, n - 2);
      const dropped = [...log.slice(0, i), ...log.slice(i + 1)].map((e, k) => ({ ...e, seq: k + 1 }));
      expectUnverified(verifyChain(dropped, {}));
    }
  });

  test("a swap of two entries fails, with or without seq rewritten", () => {
    const r = rng(0x5a9);
    for (let t = 0; t < TRIALS; t++) {
      const n = r.int(2, 200);
      const log = build(n, r.int(1, 1e9));
      const i = r.int(0, n - 1);
      let j = r.int(0, n - 2);
      if (j >= i) j++;
      const swapped = [...log];
      [swapped[i], swapped[j]] = [swapped[j]!, swapped[i]!];
      expectUnverified(verifyChain(swapped, {}));
      expectUnverified(verifyChain(swapped.map((e, k) => ({ ...e, seq: k + 1 })), {}));
    }
  });

  test("any truncation below the checkpoint fails", () => {
    const r = rng(0x7a0c);
    for (let t = 0; t < TRIALS; t++) {
      const n = r.int(1, 200);
      const log = build(n, r.int(1, 1e9));
      const keep = r.int(0, n - 1);
      expectUnverified(verifyChain(log.slice(0, keep), { checkpoint: checkpointAt(log, n) }));
    }
  });
});

describe("checkpoints", () => {
  test("a log shorter than checkpoint seq N is STATE_UNVERIFIED", () => {
    const log = build(10, 3);
    const res = verifyChain(log.slice(0, 9), { checkpoint: checkpointAt(log, 10) });
    expectUnverified(res);
    if (!res.ok) expect(res.reason).toContain("shorter");
    expectUnverified(verifyChain([], { checkpoint: checkpointAt(log, 1) }));
  });

  test("a checkpoint head that does not match the entry at that seq is STATE_UNVERIFIED", () => {
    const log = build(10, 4);
    const other = build(10, 5);
    expectUnverified(verifyChain(log, { checkpoint: { seq: 6, head: other[5]!.hash } }));
    expectUnverified(verifyChain(log, { checkpoint: { seq: 6, head: log[4]!.hash } }));
  });

  test("a malformed checkpoint is STATE_UNVERIFIED", () => {
    const log = build(3, 6);
    expectUnverified(verifyChain(log, { checkpoint: { seq: 1.5, head: log[0]!.hash } }));
    expectUnverified(verifyChain(log, { checkpoint: { seq: -1, head: GENESIS_PREV } }));
    expectUnverified(verifyChain(log, { checkpoint: { seq: 0, head: log[0]!.hash } }));
    expectUnverified(verifyChain(log, { checkpoint: { seq: 1, head: log[0]!.hash.toUpperCase() } }));
  });
});

describe("signatures", () => {
  test("good entry and checkpoint signatures pass", () => {
    const log = build(25, 8, KEY.priv);
    const cp = checkpointAt(log, 25, KEY.priv);
    expect(verifyChain(log, { pubKey: KEY.raw, checkpoint: cp, requireSignature: true })).toEqual({ ok: true, head: headOf(log) });
  });

  test("a signature from another key fails", () => {
    const log = build(5, 9, KEY.priv);
    const bad = log.map((e) => ({ ...e }));
    bad[2]!.signature = new Uint8Array(sign(null, entrySigningMessage(bad[2]!.hash), OTHER.priv));
    expectUnverified(verifyChain(bad, { pubKey: KEY.raw }));
  });

  test("a flipped signature byte fails", () => {
    const log = build(5, 10, KEY.priv);
    const bad = log.map((e) => ({ ...e }));
    const sig = new Uint8Array(bad[4]!.signature!);
    sig[0] = sig[0]! ^ 0x01;
    bad[4]!.signature = sig;
    expectUnverified(verifyChain(bad, { pubKey: KEY.raw }));
  });

  test("a signature over a different entry fails", () => {
    const log = build(5, 11, KEY.priv);
    const bad = log.map((e) => ({ ...e }));
    bad[1]!.signature = bad[0]!.signature!;
    expectUnverified(verifyChain(bad, { pubKey: KEY.raw }));
  });

  test("a bad checkpoint signature fails", () => {
    const log = build(5, 12, KEY.priv);
    expectUnverified(verifyChain(log, { pubKey: KEY.raw, checkpoint: checkpointAt(log, 5, OTHER.priv) }));
    const sig = sign(null, checkpointSigningMessage(4, log[4]!.hash), KEY.priv);
    expectUnverified(verifyChain(log, { pubKey: KEY.raw, checkpoint: { seq: 5, head: log[4]!.hash, signature: new Uint8Array(sig) } }));
  });

  test("requireSignature fails on a missing signature", () => {
    const log = build(5, 13, KEY.priv);
    const missing = log.map((e) => ({ ...e }));
    delete missing[3]!.signature;
    expectUnverified(verifyChain(missing, { pubKey: KEY.raw, requireSignature: true }));
    expect(verifyChain(missing, { pubKey: KEY.raw }).ok).toBe(true);
    expectUnverified(verifyChain(log, { pubKey: KEY.raw, checkpoint: checkpointAt(log, 5), requireSignature: true }));
  });

  test("requireSignature with no public key fails closed", () => {
    const log = build(3, 14, KEY.priv);
    expectUnverified(verifyChain(log, { requireSignature: true }));
  });

  test("a public key that is not 32 bytes fails closed", () => {
    const log = build(3, 15, KEY.priv);
    expectUnverified(verifyChain(log, { pubKey: new Uint8Array(31) }));
  });

  test("a recomputed tail cannot carry valid signatures without the private key", () => {
    const log = build(10, 16, KEY.priv);
    const forked = log.map((e) => ({ ...e }));
    forked[9]!.payload = { forged: true };
    forked[9]!.hash = entryHash(forked[9]!.prev, forked[9]!);
    expectUnverified(verifyChain(forked, { pubKey: KEY.raw }));
  });
});

describe("fail closed on garbage", () => {
  test("bad shapes are STATE_UNVERIFIED, never a throw", () => {
    const log = build(3, 17);
    expectUnverified(verifyChain(null as unknown as ChainEntry[], {}));
    expectUnverified(verifyChain([null as unknown as ChainEntry], {}));
    expectUnverified(verifyChain([{ ...log[0]!, seq: 0 }], {}));
    expectUnverified(verifyChain([{ ...log[0]!, at: Number.NaN }], {}));
    expectUnverified(verifyChain([{ ...log[0]!, payload: { n: Number.POSITIVE_INFINITY } }], {}));
    expectUnverified(verifyChain([{ ...log[0]!, payload: { f: () => 1 } }], {}));
    expectUnverified(verifyChain([{ ...log[0]!, prev: "1".repeat(64) }], {}));
  });

  test("first failure wins", () => {
    const log = build(5, 18);
    const bad = log.map((e) => ({ ...e }));
    bad[1]!.payload = { x: 1 };
    bad[3]!.seq = 99;
    const res = verifyChain(bad, {});
    expectUnverified(res);
    if (!res.ok) expect(res.reason).toContain("entry 2");
  });
});
