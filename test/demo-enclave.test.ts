import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { describe, expect, test } from "bun:test";
import type { Feed, FeedEvent } from "../console/feed";
import { formatMinor } from "../src/core/money";
import { canonicalJson, generateApproverKeys, writHash } from "../src/core/writ";
import {
  ENCLAVE_DEMO,
  kmsSignArgv,
  kmsSignMessage,
  normalizeEnclaveBase,
  parseEnclaveState,
  parseWritResult,
  poolAskMinor,
  poolExhaustedLine,
  readCardMap,
  runEnclaveDemo,
  type EnclaveDemoOptions,
  type EnclaveDemoRow,
} from "../scripts/demo-enclave";
import type { ApprovedTask, Result, SwipeOutcome, SwipeSpec } from "../src/types";

const LAST4 = {
  "research-1": "4242",
  "research-2": "1111",
  "research-3": "2222",
  "research-agent": "3333",
  "ops-1": "9999",
} as const;

interface World {
  seq: number;
  reserved: number;
  pending: number;
  settled: number;
  armed: Record<string, boolean>;
  used: Set<string>;
  results: Map<string, Record<string, unknown>>;
  taints: Map<string, string>;
  editedCode: "WRIT_HASH_MISMATCH" | "WRIT_BAD_SIGNATURE";
  forceFirstCode?: string;
  urls: string[];
  posts: { path: string; body: unknown }[];
  swipes: SwipeSpec[];
}

function newWorld(
  editedCode: World["editedCode"] = "WRIT_HASH_MISMATCH",
  held: { reserved?: number; pending?: number; settled?: number } = {},
): World {
  return {
    seq: 0,
    reserved: held.reserved ?? 0,
    pending: held.pending ?? 0,
    settled: held.settled ?? 0,
    armed: {
      "research-1": false,
      "research-2": false,
      "research-3": false,
      "research-agent": false,
      "ops-1": false,
    },
    used: new Set(),
    results: new Map(),
    taints: new Map(),
    editedCode,
    urls: [],
    posts: [],
    swipes: [],
  };
}

function budget(minor: number) {
  return { poolLimitMinor: minor, reservedMinor: 0, pendingMinor: 0, settledMinor: 0 };
}

function stateOf(world: World): Record<string, unknown> {
  return {
    note: "extra",
    verified: true,
    teams: [
      {
        team: "research",
        poolLimitMinor: 50_000,
        reservedMinor: world.reserved,
        pendingMinor: world.pending,
        settledMinor: world.settled,
      },
      { team: "ops", poolLimitMinor: 1_000_000, reservedMinor: 0, pendingMinor: 0, settledMinor: 0 },
    ],
    reserve: {
      liveBalanceMinor: 1_000_000_000,
      ringFenceMinor: 2_500_000,
      reserveFloorMinor: 2_000_000,
      openReservationsMinor: world.reserved + world.pending,
      asOf: "2026-11-12T10:00:00.000Z",
    },
    cards: (Object.keys(LAST4) as (keyof typeof LAST4)[]).map((agent) => ({
      agent,
      team: agent.startsWith("ops") ? "ops" : "research",
      last4: LAST4[agent],
      armed: world.armed[agent] === true,
    })),
    chain: { seq: world.seq, hash: "ab".repeat(32) },
    ledgerPublicKey: "ledger-pub",
    decisions: [...world.results.values()],
  };
}

function decline(world: World, writ: ApprovedTask, code: string, reason: string): Record<string, unknown> {
  world.seq += 1;
  const body = {
    writId: writ.id,
    status: "DECLINED",
    code,
    reason,
    seq: world.seq,
    serverTime: "ignored",
  };
  world.results.set(writ.id, body);
  return body;
}

function authorize(world: World, writ: ApprovedTask): Record<string, unknown> {
  world.seq += 1;
  world.used.add(writ.id);
  world.reserved += writ.amountMinor;
  world.armed[writ.agent] = true;
  const last4 = LAST4[writ.agent as keyof typeof LAST4] ?? "0000";
  const body = {
    writId: writ.id,
    status: "AUTHORIZED",
    reason: `${formatMinor(writ.amountMinor)} at ${writ.merchantName}.`,
    cardLast4: last4,
    seq: world.seq,
    serverTime: "ignored",
  };
  world.results.set(writ.id, body);
  return body;
}

function decideWrit(world: World, writ: ApprovedTask): Record<string, unknown> {
  if (world.forceFirstCode && world.posts.filter((p) => p.path === "/writs").length === 1) {
    return decline(world, writ, world.forceFirstCode, "Forced decline for the test.");
  }
  let hashOk = false;
  try {
    hashOk = writHash(writ) === writ.hash;
  } catch {
    hashOk = false;
  }
  if (!hashOk) return decline(world, writ, world.editedCode, "Writ was changed after it was approved.");
  const taintedAt = world.taints.get(writ.runId);
  if (taintedAt !== undefined && taintedAt >= writ.approvedAt) {
    return decline(world, writ, "TAINTED_RUN", "Agent read untrusted content after this writ was approved.");
  }
  if (world.used.has(writ.id)) return decline(world, writ, "WRIT_REPLAY", "Writ was already used once.");
    if (writ.team === "research") {
    const used = world.reserved + world.pending + world.settled;
    if (used + writ.amountMinor > 50_000) {
      return decline(world, writ, "TEAM_POOL_EXHAUSTED", poolExhaustedLine(used, 50_000, writ.amountMinor));
    }
  }
  if (writ.team === "ops") {
    const after = Math.min(1_000_000_000, 2_500_000) - (world.reserved + world.pending) - writ.amountMinor;
    if (after < 2_000_000) {
      return decline(world, writ, "RESERVE_FLOOR", `Cash reserve would fall to ${formatMinor(after)}, floor is $20,000.`);
    }
  }
  return authorize(world, writ);
}

function requestUrl(input: Parameters<typeof fetch>[0]): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

function mockFetch(world: World): typeof fetch {
  return (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const url = new URL(requestUrl(input));
    const method = init?.method ?? "GET";
    world.urls.push(`${method} ${url.href}`);
    const raw = typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
    if (url.hostname === "interceptor.test") {
      const event = raw && typeof raw === "object" && "event" in raw ? (raw as { event: { runId: string; at: string } }).event : undefined;
      if (event) world.taints.set(event.runId, event.at);
      world.posts.push({ path: "interceptor", body: raw });
      return Response.json({ ok: true, extra: true });
    }
    if (url.pathname === "/writs" && method === "POST") {
      const writ = (raw as { writ: ApprovedTask }).writ;
      world.posts.push({ path: "/writs", body: raw });
      return Response.json(decideWrit(world, writ));
    }
    if (url.pathname === "/taint" && method === "POST") {
      const event = (raw as { event: { runId: string; at: string } }).event;
      world.taints.set(event.runId, event.at);
      world.posts.push({ path: "/taint", body: raw });
      return Response.json({ ok: true, extra: true });
    }
    if (url.pathname === "/state") return Response.json(stateOf(world));
    if (url.pathname.startsWith("/decisions/")) {
      const id = decodeURIComponent(url.pathname.slice("/decisions/".length));
      const found = world.results.get(id);
      if (!found) return Response.json({ error: "missing" }, { status: 404 });
      return Response.json({ decision: found, extra: true });
    }
    return Response.json({ error: "unexpected" }, { status: 500 });
  }) as typeof fetch;
}

function mockSwipe(world: World): (spec: SwipeSpec) => Promise<Result<SwipeOutcome>> {
  return async (spec) => {
    world.swipes.push(spec);
    if (spec.amountMinor === ENCLAVE_DEMO.passMinor) {
      world.armed["research-1"] = false;
      world.reserved -= ENCLAVE_DEMO.passMinor;
      world.pending += ENCLAVE_DEMO.passMinor;
      const outcome: SwipeOutcome = {
        transactionId: "tx-pass",
        accepted: false,
        raw: { type: "AUTHORIZATION", status: "APPROVED" },
      };
      return { ok: true, value: outcome };
    }
    if (spec.amountMinor === ENCLAVE_DEMO.offWritMinor) {
      const outcome: SwipeOutcome = {
        transactionId: "tx-off",
        accepted: false,
        failureReason: "CARD_INACTIVE",
        raw: { type: "AUTHORIZATION", status: "FAILED" },
      };
      return { ok: true, value: outcome };
    }
    return { ok: false, error: { kind: "config", message: `unexpected swipe ${spec.amountMinor}` } };
  };
}

function recording(events: FeedEvent[]): Feed {
  return {
    url: "http://127.0.0.1:3000",
    up: () => true,
    ping: async () => true,
    emit: async (event) => {
      events.push(event);
    },
  };
}

function ids(): () => string {
  let n = 0;
  return () => `00000000-0000-4000-8000-${String(++n).padStart(12, "0")}`;
}

interface RunOpts {
  editedCode?: World["editedCode"];
  env?: Record<string, string | undefined>;
  kmsSign?: (message: string) => Promise<string>;
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  world?: World;
  held?: { reserved?: number; pending?: number; settled?: number };
  cleanup?: boolean;
  cardIds?: Record<string, string>;
  listTransactions?: EnclaveDemoOptions["listTransactions"];
  reverseSwipe?: EnclaveDemoOptions["reverseSwipe"];
  swipe?: EnclaveDemoOptions["swipe"];
}

const SCENE_LIFE = "11111111-2222-4333-8444-555555555555";

function setup(over: RunOpts = {}) {
  const world = over.world ?? newWorld(over.editedCode ?? "WRIT_HASH_MISMATCH", over.held);
  const events: FeedEvent[] = [];
  const logs: string[] = [];
  const keys = generateApproverKeys();
  const reverses: { lifecycleId: string; amountMinor: number }[] = [];
  let fixture: unknown;
  const sceneAuth = {
    lifecycleId: SCENE_LIFE,
    amountMinor: ENCLAVE_DEMO.passMinor,
    at: "2026-11-12T10:00:00.000Z",
    type: "AUTHORIZATION",
    status: "PENDING",
  };
  const run = () =>
    runEnclaveDemo({
      fetchImpl: over.fetchImpl ?? mockFetch(world),
      feed: recording(events),
      swipe: over.swipe ?? mockSwipe(world),
      listTransactions:
        over.listTransactions ??
        (async () => ({
          ok: true as const,
          value: [sceneAuth],
        })),
      reverseSwipe:
        over.reverseSwipe ??
        (async (lifecycleId, amountMinor) => {
          reverses.push({ lifecycleId, amountMinor });
          world.pending -= amountMinor;
          return {
            ok: true as const,
            value: {
              transactionId: "rev-1",
              accepted: false,
              raw: {
                type: "REVERSAL",
                process_result: "APPROVED",
                card_transaction_lifecycle_id: lifecycleId,
                card_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
              },
            },
          };
        }),
      writeReverseFixture: (body) => {
        fixture = body;
      },
      ...(over.cleanup ? { cleanup: true } : {}),
      nowMs: () => Date.parse("2026-11-12T10:00:00.000Z"),
      privateKeyPem: keys.privateKeyPem,
      cardIds: over.cardIds ?? { "research-1": "card-research-1" },
      cardMapSource: "test-map",
      env: over.env ?? {},
      baseUrl: over.baseUrl ?? "https://enclave.test",
      sceneDelayMs: 0,
      pollIntervalMs: 0,
      disarmTimeoutMs: 300,
      retryGapMs: 0,
      now: () => "2026-11-12T10:00:00.000Z",
      randomUUID: ids(),
      sleep: async () => {},
      log: (line) => logs.push(line),
      error: (line) => logs.push(line),
      ...(over.kmsSign ? { kmsSign: over.kmsSign } : {}),
    });
  return { world, events, logs, keys, run, reverses, fixture: () => fixture };
}

function rowShape(rows: EnclaveDemoRow[]) {
  return rows.map((r) => [r.scene, r.agent, r.amount, r.result, r.code]);
}

describe("enclave demo", () => {
  test("maps every scene and skips taint when the signer is unset", async () => {
    const { world, events, logs, keys, run, reverses, fixture } = setup();
    const rows = await run();
    expect(rowShape(rows)).toEqual([
      ["Approved", "research-1", formatMinor(ENCLAVE_DEMO.passMinor), "AUTHORIZED", "AUTHORIZED"],
      ["Off-writ swipe", "research-1", formatMinor(ENCLAVE_DEMO.offWritMinor), "DECLINED", "CARD_INACTIVE"],
      ["Team pool", "research-2", formatMinor(ENCLAVE_DEMO.poolOkMinor), "AUTHORIZED", "AUTHORIZED"],
      ["Team pool", "research-3", formatMinor(ENCLAVE_DEMO.poolNoMinor), "DECLINED", "TEAM_POOL_EXHAUSTED"],
      ["Edited writ", "research-agent", formatMinor(ENCLAVE_DEMO.editedSentMinor), "DECLINED", "WRIT_HASH_MISMATCH"],
      ["Replay", "research-1", formatMinor(ENCLAVE_DEMO.passMinor), "DECLINED", "WRIT_REPLAY"],
      ["Reversal", "research-1", formatMinor(ENCLAVE_DEMO.passMinor), "REVERSED", "REVERSED"],
      ["Taint", "research-agent", formatMinor(ENCLAVE_DEMO.taintMinor), "SKIPPED", "SKIPPED"],
      ["Reserve", "ops-1", formatMinor(ENCLAVE_DEMO.reserveMinor), "DECLINED", "RESERVE_FLOOR"],
    ]);
    for (const row of rows) expect(row.reason.length).toBeGreaterThan(0);
    expect(rows.find((r) => r.scene === "Taint")?.reason).toContain("WRIT_TAINT_SIGNER is not set");
    expect(world.urls.some((u) => u.includes("/taint"))).toBe(false);
    expect(world.swipes.map((s) => s.cardId)).toEqual(["card-research-1", "card-research-1"]);
    expect(world.swipes.map((s) => s.amountMinor)).toEqual([ENCLAVE_DEMO.passMinor, ENCLAVE_DEMO.offWritMinor]);

    const writs = world.posts.filter((p) => p.path === "/writs").map((p) => (p.body as { writ: ApprovedTask }).writ);
    expect(writs).toHaveLength(6);
    const first = writs[0];
    expect(first?.agent).toBe("research-1");
    expect(first?.amountMinor).toBe(ENCLAVE_DEMO.passMinor);
    expect(first?.expiresAt).toBe("2026-11-12T10:03:00.000Z");
    expect(first && Date.parse(first.expiresAt) - Date.parse(first.approvedAt)).toBe(ENCLAVE_DEMO.writExpiryMs);
    expect(poolAskMinor(50_000 - ENCLAVE_DEMO.passMinor)).toBe(ENCLAVE_DEMO.poolOkMinor);
    expect(rows.find((r) => r.agent === "research-3")?.reason).toBe("Team budget used up: $480 of $500 spent or held, this needs $250.");
    expect(rows.find((r) => r.scene === "Reversal")?.reason).toBe(
      "Reversal: Airwallex reversed the $180. The team pool released it: $300 of $500 now held.",
    );
    expect(reverses).toEqual([{ lifecycleId: SCENE_LIFE, amountMinor: ENCLAVE_DEMO.passMinor }]);
    const saved = JSON.stringify(fixture());
    expect(saved).not.toContain(SCENE_LIFE);
    expect(saved).toContain("…5555");
    expect(saved).not.toContain("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
    expect(logs.join("\n")).toContain("Earlier runs hold $0 of the $500 research pool.");
    expect(logs.join("\n")).toContain("Pending from swiped writs stays until the bank clears or reverses it in the sandbox.");
    expect(first && writHash(first)).toBe(first?.hash);
    expect((first?.signature.length ?? 0) > 20).toBe(true);
    const edited = writs[3];
    expect(edited?.amountMinor).toBe(ENCLAVE_DEMO.editedSentMinor);
    expect(edited && writHash(edited)).not.toBe(edited?.hash);
    expect(writs[4]?.id).toBe(first?.id);

    const pools = events.filter((e) => e.kind === "pool" && e.team === "research");
    const lastPool = pools[pools.length - 1];
    expect(lastPool && lastPool.kind === "pool" ? lastPool.poolLimitMinor : 0).toBe(50_000);
    expect(lastPool && lastPool.kind === "pool" ? lastPool.pendingMinor : -1).toBe(0);
    expect(lastPool && lastPool.kind === "pool" ? lastPool.reservedMinor : 0).toBe(ENCLAVE_DEMO.poolOkMinor);
    expect(lastPool && lastPool.kind === "pool" ? lastPool.releasedMinor : -1).toBe(0);
    const reserves = events.filter((e) => e.kind === "reserve");
    const lastReserve = reserves[reserves.length - 1];
    expect(lastReserve && lastReserve.kind === "reserve" ? lastReserve.ringFenceMinor : 0).toBe(2_500_000);
    expect(lastReserve && lastReserve.kind === "reserve" ? lastReserve.reserveFloorMinor : 0).toBe(2_000_000);
    const approvals = events.filter((e) => e.kind === "approval");
    expect(approvals.some((e) => e.kind === "approval" && e.approval.amountMinor === ENCLAVE_DEMO.passMinor && e.approval.signatureValid)).toBe(true);
    expect(approvals.some((e) => e.kind === "approval" && e.approval.amountMinor === ENCLAVE_DEMO.editedSentMinor && !e.approval.signatureValid)).toBe(true);
    const swipes = events.filter((e) => e.kind === "swipe");
    expect(swipes.map((e) => (e.kind === "swipe" ? e.accepted : false))).toEqual([true, false]);
    expect(events.some((e) => e.kind === "taint")).toBe(false);
    expect(events.some((e) => e.kind === "final" && e.ok)).toBe(true);
    expect(events.some((e) => e.kind === "done" && e.ok)).toBe(true);
    expect(events.some((e) => e.kind === "reset")).toBe(true);

    const dumped = JSON.stringify(events) + logs.join("\n");
    expect(dumped).not.toContain(keys.privateKeyPem);
    expect(dumped).not.toContain("BEGIN PRIVATE");
    expect(dumped).not.toContain("card-research-1");
    expect(dumped).not.toContain(first?.signature ?? "missing-signature");
  });

  test("a half used pool sizes research-2 from the room left", async () => {
    const { logs, run } = setup({ held: { pending: ENCLAVE_DEMO.passMinor } });
    const rows = await run();
    const room = 50_000 - ENCLAVE_DEMO.passMinor - ENCLAVE_DEMO.passMinor;
    const ask = poolAskMinor(room);
    expect(ask).toBe(12_000);
    expect(rows.find((r) => r.agent === "research-2")).toMatchObject({
      amount: formatMinor(ask),
      result: "AUTHORIZED",
      code: "AUTHORIZED",
    });
    expect(rows.find((r) => r.agent === "research-3")?.reason).toBe(poolExhaustedLine(50_000 - ENCLAVE_DEMO.poolCushionMinor, 50_000, ENCLAVE_DEMO.poolNoMinor));
    expect(logs.join("\n")).toContain("Earlier runs hold $180 of the $500 research pool.");
    expect(logs.join("\n")).toContain(`research-2 asks for ${formatMinor(ask)}.`);
  });

  test("a full pool stops before any writ", async () => {
    const { world, logs, run } = setup({ held: { pending: ENCLAVE_DEMO.passMinor, reserved: ENCLAVE_DEMO.poolOkMinor } });
    await expect(run()).rejects.toThrow(/Research pool is full from earlier runs\. It holds \$480 of \$500\. \$180 does not fit\. Wait 3 minutes/);
    expect(world.posts.filter((p) => p.path === "/writs")).toHaveLength(0);
    expect(world.swipes).toHaveLength(0);
    expect(logs.join("\n")).toContain("Earlier runs hold $480 of the $500 research pool.");
    expect(logs.join("\n")).toContain("Pending from swiped writs stays until the bank clears or reverses it in the sandbox.");
  });

  test("a reverse timeout is success when the authorization is REVERSED", async () => {
    const bank = { reversed: false, drop: (_amount: number) => {} };
    const { world, run } = setup({
      listTransactions: async () => ({
        ok: true,
        value: [
          {
            lifecycleId: "life-180",
            amountMinor: ENCLAVE_DEMO.passMinor,
            at: "2026-11-12T10:00:00.000Z",
            type: "AUTHORIZATION",
            status: bank.reversed ? "REVERSED" : "PENDING",
          },
        ],
      }),
      reverseSwipe: async (_lifecycleId, amountMinor) => {
        bank.reversed = true;
        bank.drop(amountMinor);
        return { ok: false, error: { kind: "timeout", message: "no answer within 20000 ms" } };
      },
    });
    bank.drop = (amount) => {
      world.pending -= amount;
    };
    const rows = await run();
    expect(rows.find((r) => r.scene === "Reversal")?.code).toBe("REVERSED");
    expect(rows.find((r) => r.scene === "Reversal")?.reason).toContain("The team pool released it:");
    expect(rows.find((r) => r.scene === "Reserve")?.code).toBe("RESERVE_FLOOR");
  });

  test("a swipe timeout is success when the authorization is already on the card", async () => {
    const { world, run } = setup({
      swipe: async (spec) => {
        if (spec.amountMinor === ENCLAVE_DEMO.passMinor) {
          world.armed["research-1"] = false;
          world.reserved -= ENCLAVE_DEMO.passMinor;
          world.pending += ENCLAVE_DEMO.passMinor;
          return { ok: false, error: { kind: "timeout", message: "no answer within 20000 ms" } };
        }
        if (spec.amountMinor === ENCLAVE_DEMO.offWritMinor) {
          return {
            ok: true,
            value: { transactionId: "tx-off", accepted: false, failureReason: "CARD_INACTIVE", raw: { type: "AUTHORIZATION", status: "FAILED" } },
          };
        }
        return { ok: false, error: { kind: "config", message: `unexpected swipe ${spec.amountMinor}` } };
      },
    });
    const rows = await run();
    expect(rows.find((r) => r.scene === "Approved")?.code).toBe("AUTHORIZED");
    expect(rows.find((r) => r.scene === "Reversal")?.code).toBe("REVERSED");
  });

  test("a failed reverse is FAILED and the demo continues", async () => {
    const { logs, run } = setup({
      reverseSwipe: async () => ({ ok: false, error: { kind: "http", status: 400, message: "cannot reverse" } }),
    });
    const rows = await run();
    expect(rows.find((r) => r.scene === "Reversal")).toMatchObject({ result: "FAILED", code: "FAILED" });
    expect(rows.find((r) => r.scene === "Reversal")?.reason).toContain("HTTP 400");
    expect(rows.find((r) => r.scene === "Reversal")?.reason).toContain("cannot reverse");
    expect(rows.find((r) => r.scene === "Reserve")?.code).toBe("RESERVE_FLOOR");
    expect(logs.join("\n")).toContain("HTTP 400: cannot reverse");
  });

  test("cleanup reverses only a pending research authorization older than 3 minutes", async () => {
    const reversed: string[] = [];
    const cards: string[] = [];
    const { logs, run } = setup({
      cleanup: true,
      held: { pending: ENCLAVE_DEMO.passMinor },
      cardIds: { "research-1": "card-research-1", "ops-1": "card-ops" },
      listTransactions: async (cardId) => {
        cards.push(cardId);
        if (cardId !== "card-research-1") return { ok: true, value: [] };
        return {
          ok: true,
          value: [
            { lifecycleId: "old-auth", amountMinor: 18_000, at: "2026-11-12T09:50:00.000Z", type: "AUTHORIZATION", status: "PENDING" },
            { lifecycleId: "fresh-auth", amountMinor: 18_000, at: "2026-11-12T10:00:00.000Z", type: "AUTHORIZATION", status: "APPROVED" },
            { lifecycleId: "dead-auth", amountMinor: 18_000, at: "2026-11-12T09:50:00.000Z", type: "AUTHORIZATION", status: "FAILED" },
            { lifecycleId: "already-reversed", amountMinor: 18_000, at: "2026-11-12T09:40:00.000Z", type: "AUTHORIZATION", status: "REVERSED" },
            { lifecycleId: "cleared", amountMinor: 18_000, at: "2026-11-12T09:50:00.000Z", type: "CLEARING", status: "APPROVED" },
          ],
        };
      },
      reverseSwipe: async (lifecycleId, amountMinor) => {
        reversed.push(`${lifecycleId}:${amountMinor}`);
        return { ok: true, value: { transactionId: "rev", accepted: false, raw: { type: "REVERSAL", process_result: "APPROVED" } } };
      },
    });
    const rows = await run();
    expect(reversed[0]).toBe("old-auth:18000");
    expect(reversed).toContain("fresh-auth:18000");
    expect(reversed.some((id) => id.startsWith("dead-auth") || id.startsWith("cleared") || id.startsWith("already-reversed"))).toBe(false);
    expect(cards.every((id) => id === "card-research-1")).toBe(true);
    expect(logs.join("\n")).toContain("Cleanup: reversed $180 on research-1.");
    expect(rows.find((r) => r.scene === "Reserve")?.code).toBe("RESERVE_FLOOR");
  });

  test("KMS AccessDenied skips taint and still runs the reserve scene", async () => {
    const { world, run } = setup({
      env: { WRIT_TAINT_SIGN: "kms" },
      kmsSign: async () => {
        throw new Error("aws kms sign failed (254): An error occurred (AccessDeniedException) when calling the Sign operation");
      },
    });
    const rows = await run();
    expect(rows.find((r) => r.scene === "Taint")).toMatchObject({
      result: "SKIPPED",
      code: "SKIPPED",
      reason: "KMS refused this Mac's credentials. Only the taint interceptor role may sign taint events.",
    });
    expect(rows.find((r) => r.scene === "Reserve")?.code).toBe("RESERVE_FLOOR");
    expect(world.posts.some((p) => p.path === "/taint")).toBe(false);
  });

  test("accepts WRIT_BAD_SIGNATURE for an edited writ", async () => {
    const { run } = setup({ editedCode: "WRIT_BAD_SIGNATURE" });
    const rows = await run();
    expect(rows.find((r) => r.scene === "Edited writ")?.code).toBe("WRIT_BAD_SIGNATURE");
  });

  test("a missing state field fails with a clear message", async () => {
    const { run } = setup({
      fetchImpl: (async () => Response.json({ teams: {}, extra: true })) as unknown as typeof fetch,
    });
    await expect(run()).rejects.toThrow(/missing reserve/);
  });

  test("a writ response missing reason fails with a clear message", async () => {
    const world = newWorld();
    let posts = 0;
    const fetchImpl = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
      const url = new URL(requestUrl(input));
      if (url.pathname === "/state") return Response.json(stateOf(world));
      if (url.pathname === "/writs") {
        posts += 1;
        void init;
        return Response.json({ writId: "writ-1", status: "AUTHORIZED", extra: true });
      }
      return Response.json({ error: "unexpected" }, { status: 500 });
    }) as typeof fetch;
    const { run } = setup({ world, fetchImpl: fetchImpl as unknown as typeof fetch });
    await expect(run()).rejects.toThrow(/POST \/writs response missing reason/);
    expect(posts).toBe(1);
  });

  test("the wrong code fails the scene", async () => {
    const world = newWorld();
    world.forceFirstCode = "CURRENCY_NOT_IN_WRIT";
    const { run } = setup({ world });
    await expect(run()).rejects.toThrow(/expected AUTHORIZED/);
  });

  test("KMS taint posts the canonical event and the spend is TAINTED_RUN", async () => {
    const messages: string[] = [];
    const { world, events, logs, keys, run } = setup({
      env: { WRIT_TAINT_SIGN: "kms", WRIT_TAINT_SIGNER: "https://interceptor.test/mark" },
      kmsSign: async (message) => {
        messages.push(message);
        return "sig-test";
      },
    });
    const rows = await run();
    expect(rows.find((r) => r.scene === "Taint")).toMatchObject({ result: "DECLINED", code: "TAINTED_RUN" });
    expect(messages).toHaveLength(1);
    const taint = world.posts.find((p) => p.path === "/taint");
    const body = taint?.body as { event: { agent: string; runId: string; urlSha256: string; at: string; seq: number }; signature: string };
    expect(body.signature).toBe("sig-test");
    expect(messages[0]).toBe(canonicalJson(body.event));
    expect(body.event.agent).toBe("research-agent");
    expect(body.event.urlSha256).toBe(createHash("sha256").update(ENCLAVE_DEMO.taintUrl).digest("hex"));
    expect(body.event.seq).toBeGreaterThan(0);
    expect(world.posts.some((p) => p.path === "interceptor")).toBe(false);
    expect(events.some((e) => e.kind === "taint" && e.source === ENCLAVE_DEMO.taintUrl)).toBe(true);
    const dumped = JSON.stringify(events) + logs.join("\n");
    expect(dumped).not.toContain("sig-test");
    expect(dumped).not.toContain(keys.privateKeyPem);
  });

  test("the AgentCore interceptor URL receives the taint when KMS signing is off", async () => {
    const { world, run } = setup({ env: { WRIT_TAINT_SIGNER: "https://interceptor.test/mark" } });
    const rows = await run();
    expect(rows.find((r) => r.scene === "Taint")?.code).toBe("TAINTED_RUN");
    expect(world.posts.some((p) => p.path === "interceptor")).toBe(true);
    expect(world.posts.some((p) => p.path === "/taint")).toBe(false);
    const sent = world.posts.find((p) => p.path === "interceptor")?.body as { event: { runId: string }; url: string };
    expect(sent.url).toBe(ENCLAVE_DEMO.taintUrl);
    const taintedWrit = world.posts
      .filter((p) => p.path === "/writs")
      .map((p) => (p.body as { writ: ApprovedTask }).writ)
      .find((w) => w.purpose === "Tainted run");
    expect(taintedWrit?.runId).toBe(sent.event.runId);
  });

  test("http enclave URL is refused before any fetch", async () => {
    let called = 0;
    const { run } = setup({
      baseUrl: "http://enclave.test",
      fetchImpl: (async () => {
        called += 1;
        return Response.json({});
      }) as unknown as typeof fetch,
    });
    await expect(run()).rejects.toThrow(/https/);
    expect(called).toBe(0);
  });
});

describe("enclave response parsers", () => {
  test("state accepts the enclave team list and a null balance", () => {
    const state = parseEnclaveState({
      verified: true,
      teams: [{ team: "research", poolLimitMinor: 50_000, reservedMinor: 0, pendingMinor: 0, settledMinor: 0 }],
      reserve: { liveBalanceMinor: null, ringFenceMinor: 2_500_000, reserveFloorMinor: 2_000_000, openReservationsMinor: 0, asOf: null },
      cards: [{ agent: "research-1", team: "research", last4: null, armed: false }],
      chain: { seq: 0, hash: "abc" },
      ledgerPublicKey: "pub",
      decisions: [],
    });
    expect(state.teams.research?.poolLimitMinor).toBe(50_000);
    expect(state.reserve.liveBalanceMinor).toBeNull();
    expect(state.reserve.asOf).toBeNull();
    expect(state.cards[0]?.last4).toBeNull();
    expect(state.cards[0]?.armed).toBe(false);
  });

  test("state keeps extra fields out and defaults releasedMinor", () => {
    const state = parseEnclaveState({
      note: "keep me",
      teams: { research: { ...budget(50_000), comment: "hi" } },
      reserve: {
        liveBalanceMinor: 1,
        ringFenceMinor: 2,
        reserveFloorMinor: 3,
        openReservationsMinor: 4,
        asOf: "2026-11-12T10:00:00.000Z",
        extra: true,
      },
      cards: [{ agent: "research-1", team: "research", last4: "4242", armed: false, pan: "nope" }],
      chain: { seq: 3, hash: "abc", extra: 1 },
      ledgerPublicKey: "pub",
      decisions: [],
    });
    expect(state.teams.research?.releasedMinor).toBe(0);
    expect(state.teams.research?.poolLimitMinor).toBe(50_000);
    expect(state.cards[0]?.armed).toBe(false);
    expect("note" in state).toBe(false);
  });

  test("missing card armed is an error", () => {
    expect(() =>
      parseEnclaveState({
        teams: {},
        reserve: { liveBalanceMinor: 1, ringFenceMinor: 2, reserveFloorMinor: 3, openReservationsMinor: 0, asOf: "2026-11-12T10:00:00.000Z" },
        cards: [{ agent: "research-1", team: "research", last4: "4242" }],
        chain: { seq: 0, hash: "abc" },
        ledgerPublicKey: "pub",
        decisions: [],
      }),
    ).toThrow(/missing cards\[0\]\.armed/);
  });

  test("writ result requires a code on a decline and ignores extras", () => {
    expect(parseWritResult({ writId: "w", status: "AUTHORIZED", reason: "ok", extra: 1 }, "POST /writs").status).toBe("AUTHORIZED");
    expect(() => parseWritResult({ writId: "w", status: "DECLINED", reason: "no" }, "POST /writs")).toThrow(/missing code/);
    expect(parseWritResult({ decision: { writId: "w", status: "DECLINED", code: "WRIT_REPLAY", reason: "used" } }, "GET /decisions").code).toBe("WRIT_REPLAY");
  });

  test("card map reads cards[] and a flat agent map", () => {
    expect(readCardMap({ version: 1, cards: [{ agent: "research-1", cardId: "card-1", team: "research" }] }, "serve.json")).toEqual({
      "research-1": "card-1",
    });
    expect(readCardMap({ "research-1": "card-1", version: 1 }, "map.json")).toEqual({ "research-1": "card-1" });
    expect(() => readCardMap({ cards: [{ agent: "research-1" }] }, "serve.json")).toThrow(/cardId/);
  });

  test("base URL drops userinfo and rejects http", () => {
    expect(normalizeEnclaveBase("https://user:secret@35-95-168-131.sslip.io/")).toBe("https://35-95-168-131.sslip.io");
    expect(normalizeEnclaveBase(ENCLAVE_DEMO.baseUrl)).toBe(ENCLAVE_DEMO.baseUrl);
    expect(() => normalizeEnclaveBase("http://example.com")).toThrow(/https/);
  });
});

describe("kms sign argv", () => {
  test("spawns aws kms sign with the pinned key and deletes the message file", async () => {
    let seen = "";
    let file = "";
    const signature = await kmsSignMessage(canonicalJson({ agent: "research-agent", at: "2026-11-12T10:00:00.000Z", runId: "run-1", seq: 2, urlSha256: "ab" }), async (argv) => {
      const message = argv[argv.length - 1] ?? "";
      expect(message.startsWith("fileb://")).toBe(true);
      file = message.slice("fileb://".length);
      expect(existsSync(file)).toBe(true);
      seen = await Bun.file(file).text();
      expect(argv).toEqual(kmsSignArgv(file));
      expect(argv).toContain(ENCLAVE_DEMO.taintKeyId);
      expect(argv).toContain("ECDSA_SHA_256");
      expect(argv).toContain("RAW");
      return { exitCode: 0, stdout: JSON.stringify({ Signature: "from-kms", KeyId: ENCLAVE_DEMO.taintKeyId }), stderr: "" };
    });
    expect(signature).toBe("from-kms");
    expect(seen).toContain("research-agent");
    expect(existsSync(file)).toBe(false);
  });
});
