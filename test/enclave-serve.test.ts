import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import type { ChainEntry } from "../src/core/chain";
import { bakedApproverKey, EnclaveServe, type ArmOrder, type ArmRequest, type BakedConfig, type ServeOptions } from "../src/host/enclave-serve";
import type { S3Client, S3PutRequest } from "../src/host/s3-committer";
import type { ApprovedTask } from "../src/types";
import { APPROVED_AT, KEYS, NOW, OTHER_KEYS, signed } from "./helpers";

const CARD = "card-1";

function baked(over: Partial<BakedConfig> = {}): BakedConfig {
  return {
    approvers: { version: 1, approvers: [{ name: "test", publicKeyPem: KEYS.publicKeyPem }] },
    ringFenceMinor: 2_500_000,
    reserveFloorMinor: 2_000_000,
    maxBalanceAgeMs: 60_000,
    teams: [{ team: "research", poolLimitMinor: 50_000 }],
    cards: [{ cardId: CARD, team: "research", agent: "research-1" }],
    ...over,
  };
}

type PutMode = number | "throw";

function fakeS3(mode: PutMode = 200) {
  const puts: S3PutRequest[] = [];
  const client: S3Client = {
    putObject: async (req) => {
      puts.push(req);
      if (mode === "throw") throw new Error("socket closed");
      return { status: mode };
    },
  };
  return { client, puts };
}

function fakeArm(behaviour: "ok" | "false" | "throw" = "ok") {
  const orders: ArmOrder[] = [];
  const armCard = async (o: ArmOrder) => {
    orders.push(o);
    if (behaviour === "throw") throw new Error("airwallex down");
    return behaviour === "ok";
  };
  return { armCard, orders };
}

const freshBalance = { amountMinor: 1_000_000_000, at: "2026-11-12T08:34:50.000Z" };

type Obs = { amountMinor: number; at: string } | undefined;

function serve(
  opts: { s3?: PutMode; arm?: "ok" | "false" | "throw"; baked?: Partial<BakedConfig>; resume?: ChainEntry[]; observation?: Obs; clock?: string | undefined } = {},
) {
  const s3 = fakeS3(opts.s3);
  const arm = fakeArm(opts.arm);
  let n = 0;
  const now = "clock" in opts ? opts.clock : NOW;
  const o: ServeOptions = {
    baked: baked(opts.baked),
    bootAt: "2026-11-12T08:00:00.000Z",
    checkpoint: { s3: { client: s3.client, bucket: "writ-ledger-test" } },
    armCard: arm.armCard,
    clock: () => now,
    newEventId: () => `ev-${++n}`,
  };
  if (opts.resume) o.resume = opts.resume;
  const s = new EnclaveServe(o);
  s.setObservation("observation" in opts ? opts.observation : freshBalance);
  return { s, s3, arm };
}

function req(writ: ApprovedTask | null = signed(), over: Partial<ArmRequest> = {}): ArmRequest {
  const r: ArmRequest = {
    cardId: CARD,
    amountMinor: 18_000,
    currency: "USD",
    mcc: "5734",
    merchantName: "DataCo",
    ...over,
  };
  if (writ) r.writ = writ;
  return r;
}

describe("EnclaveServe", () => {
  test("valid signed writ, fresh balance, under pool and reserve: AUTHORIZED and arm called once", async () => {
    const { s, s3, arm } = serve();
    const r = await s.authorize(req());
    expect(r).toMatchObject({ status: "AUTHORIZED", writId: "writ-1", armed: true });
    expect(arm.orders.length).toBe(1);
    expect(arm.orders[0]).toMatchObject({ cardId: CARD, writId: "writ-1", amountMinor: 18_000, currency: "USD", mcc: "5734", merchantName: "DataCo" });
    expect(Number.isSafeInteger(arm.orders[0]!.amountMinor)).toBe(true);
    expect(s3.puts.map((p) => (JSON.parse(p.body) as { entry: ChainEntry }).entry.kind)).toEqual(["consume", "arm"]);
    expect(Object.keys(s3.puts[0]!).sort()).toEqual(["body", "bucket", "contentType", "ifNoneMatch", "key"]);
    expect(s3.puts[0]!.ifNoneMatch).toBe("*");
    expect(JSON.stringify(s3.puts[0]).toLowerCase()).not.toContain("retention");
    expect(s.events.some((e) => e.kind === "WRIT_CONSUMED" && e.writId === "writ-1")).toBe(true);
  });

  test("no writ: DECLINED, arm not called", async () => {
    const { s, s3, arm } = serve();
    const r = await s.authorize(req(null));
    expect(r).toMatchObject({ status: "DECLINED", code: "NO_WRIT_FOR_CARD", armed: false });
    expect(arm.orders.length).toBe(0);
    expect(s3.puts.length).toBe(0);
  });

  test("bad signature: DECLINED, arm not called", async () => {
    const { s, s3, arm } = serve();
    const forged = { ...signed(), signature: signed({ nonce: "other" }).signature };
    expect(await s.authorize(req(forged))).toMatchObject({ status: "DECLINED", code: "WRIT_BAD_SIGNATURE" });
    expect(arm.orders.length).toBe(0);
    expect(s3.puts.length).toBe(0);
  });

  test("writ signed by a key that is not baked: DECLINED, arm not called", async () => {
    const { s, arm } = serve({ baked: { approvers: { approvers: [{ publicKeyPem: OTHER_KEYS.publicKeyPem }] } } });
    expect(await s.authorize(req())).toMatchObject({ status: "DECLINED", code: "WRIT_BAD_SIGNATURE" });
    expect(arm.orders.length).toBe(0);
  });

  test("amount over the team pool: DECLINED TEAM_POOL_EXHAUSTED, arm not called", async () => {
    const { s, s3, arm } = serve({ baked: { teams: [{ team: "research", poolLimitMinor: 10_000 }] } });
    expect(await s.authorize(req())).toMatchObject({ status: "DECLINED", code: "TEAM_POOL_EXHAUSTED" });
    expect(arm.orders.length).toBe(0);
    expect(s3.puts.map((p) => (JSON.parse(p.body) as { entry: ChainEntry }).entry.kind)).toEqual(["revoke"]);
  });

  test("S3 put returns 412: COMMIT_FAILED, arm not called", async () => {
    const { s, s3, arm } = serve({ s3: 412 });
    expect(await s.authorize(req())).toMatchObject({ status: "DECLINED", code: "COMMIT_FAILED" });
    expect(s3.puts.length).toBe(1);
    expect(arm.orders.length).toBe(0);
    expect(s.events.some((e) => e.kind === "WRIT_CONSUMED")).toBe(false);
  });

  test("S3 put throws: COMMIT_FAILED, arm not called, and the writ cannot be retried", async () => {
    const { s, arm } = serve({ s3: "throw" });
    expect(await s.authorize(req())).toMatchObject({ status: "DECLINED", code: "COMMIT_FAILED" });
    expect(arm.orders.length).toBe(0);
    expect((await s.authorize(req())).status).toBe("DECLINED");
    expect(arm.orders.length).toBe(0);
  });

  test("same writ again after a successful commit: no second arm", async () => {
    const { s, s3, arm } = serve();
    expect((await s.authorize(req())).status).toBe("AUTHORIZED");
    expect(await s.authorize(req())).toMatchObject({ status: "DECLINED", code: "WRIT_REPLAY" });
    expect(await s.authorize(req(null))).toMatchObject({ status: "DECLINED" });
    expect(arm.orders.length).toBe(1);
    expect(s3.puts.length).toBe(2);
  });

  test("arm throws after a successful commit: declined, and the writ never arms again", async () => {
    const { s, s3, arm } = serve({ arm: "throw" });
    expect(await s.authorize(req())).toMatchObject({ status: "DECLINED", code: "ARM_FAILED", writId: "writ-1" });
    expect(arm.orders.length).toBe(1);
    expect(await s.authorize(req())).toMatchObject({ status: "DECLINED", code: "WRIT_REPLAY" });
    expect(arm.orders.length).toBe(1);
    expect(s3.puts.length).toBe(1);
  });

  test("resume chain that already contains the writ: no arm", async () => {
    const first = serve();
    expect((await first.s.authorize(req())).status).toBe("AUTHORIZED");
    const resume = first.s3.puts.map((p) => (JSON.parse(p.body) as { entry: ChainEntry }).entry);
    expect(resume.map((e) => e.kind)).toEqual(["consume", "arm"]);

    const again = serve({ resume });
    expect(await again.s.authorize(req())).toMatchObject({ status: "DECLINED", code: "WRIT_REPLAY" });
    expect(again.arm.orders.length).toBe(0);
    expect(again.s3.puts.length).toBe(0);
  });

  test("resumed consumes still count against the team pool", async () => {
    const first = serve();
    await first.s.authorize(req());
    const resume = first.s3.puts.map((p) => (JSON.parse(p.body) as { entry: ChainEntry }).entry);
    const again = serve({ resume, baked: { teams: [{ team: "research", poolLimitMinor: 30_000 }] } });
    const w2 = signed({ id: "writ-2", nonce: "n-2" });
    expect(await again.s.authorize(req(w2))).toMatchObject({ status: "DECLINED", code: "TEAM_POOL_EXHAUSTED" });
    expect(again.arm.orders.length).toBe(0);
  });

  test("a resume chain that does not verify: every request is STATE_UNVERIFIED", async () => {
    const first = serve();
    await first.s.authorize(req());
    const entry = (JSON.parse(first.s3.puts[0]!.body) as { entry: ChainEntry }).entry;
    const tampered = { ...entry, payload: { ...(entry.payload as object), amountMinor: 1 } };
    const again = serve({ resume: [tampered] });
    expect(await again.s.authorize(req(signed({ id: "writ-2", nonce: "n-2" })))).toMatchObject({ status: "DECLINED", code: "STATE_UNVERIFIED" });
    expect(again.arm.orders.length).toBe(0);
  });

  test("taint marked at or after approval: TAINTED_RUN, arm not called, and a later call cannot clear it", async () => {
    const { s, s3, arm } = serve();
    s.markTaint("run-1", APPROVED_AT);
    expect(await s.authorize(req())).toMatchObject({ status: "DECLINED", code: "TAINTED_RUN", freezeCard: true });
    s.markTaint("run-1", "2026-11-12T07:00:00.000Z");
    s.markTaint("run-1", "not a time");
    expect(await s.authorize(req())).toMatchObject({ status: "DECLINED", code: "WRIT_REVOKED" });
    expect(await s.authorize(req(signed({ id: "writ-2", nonce: "n-2" })))).toMatchObject({ status: "DECLINED", code: "TAINTED_RUN" });
    expect(arm.orders.length).toBe(0);
    expect(s3.puts.map((p) => (JSON.parse(p.body) as { entry: ChainEntry }).entry.kind)).toEqual(["revoke", "revoke"]);
    expect("clearTaint" in s).toBe(false);
  });

  test("taint before approval does not block", async () => {
    const { s, arm } = serve();
    s.markTaint("run-1", "2026-11-12T08:00:00.000Z");
    expect((await s.authorize(req())).status).toBe("AUTHORIZED");
    expect(arm.orders.length).toBe(1);
  });

  test("missing baked approver key: decline, arm not called, even if the request carries a public key", async () => {
    for (const approvers of [undefined, {}, { approvers: [] }, { approvers: [{ publicKeyPem: "junk" }] }, { approvers: [{ publicKeyPem: KEYS.privateKeyPem }] }]) {
      const { s, s3, arm } = serve({ baked: { approvers } });
      const r = await s.authorize({ ...req(), publicKeyPem: KEYS.publicKeyPem } as ArmRequest);
      expect(r.status).toBe("DECLINED");
      if (r.status === "DECLINED") expect(["STATE_UNVERIFIED", "INTERNAL_ERROR"]).toContain(r.code);
      expect(arm.orders.length).toBe(0);
      expect(s3.puts.length).toBe(0);
    }
  });

  test("missing balance declines UPSTREAM_ERROR, stale balance declines BALANCE_STALE", async () => {
    const a = serve({ observation: undefined });
    expect(await a.s.authorize(req())).toMatchObject({ status: "DECLINED", code: "UPSTREAM_ERROR" });
    const b = serve({ observation: { amountMinor: 1_000_000_000, at: "2026-11-12T08:30:00.000Z" } });
    expect(await b.s.authorize(req())).toMatchObject({ status: "DECLINED", code: "BALANCE_STALE" });
    expect(a.arm.orders.length + b.arm.orders.length).toBe(0);
  });

  test("balance under the reserve floor declines RESERVE_FLOOR", async () => {
    const { s, arm } = serve({ observation: { amountMinor: 2_010_000, at: freshBalance.at } });
    expect(await s.authorize(req())).toMatchObject({ code: "RESERVE_FLOOR" });
    expect(arm.orders.length).toBe(0);
  });

  test("a balance and now on the request never win over the observation and the clock", async () => {
    const a = serve({ observation: undefined });
    const withBal = { ...req(), balance: freshBalance, now: NOW } as ArmRequest;
    expect(await a.s.authorize(withBal)).toMatchObject({ status: "DECLINED", code: "UPSTREAM_ERROR" });
    const b = serve({ observation: { amountMinor: 2_010_000, at: freshBalance.at } });
    expect(await b.s.authorize({ ...req(), balance: freshBalance } as ArmRequest)).toMatchObject({ code: "RESERVE_FLOOR" });
    const c = serve({ observation: { amountMinor: 1_000_000_000, at: "2026-11-12T08:30:00.000Z" } });
    expect(await c.s.authorize({ ...req(), now: "2026-11-12T08:30:05.000Z" } as ArmRequest)).toMatchObject({ code: "BALANCE_STALE" });
    expect(a.arm.orders.length + b.arm.orders.length + c.arm.orders.length).toBe(0);
  });

  test("no clock time declines UPSTREAM_ERROR and arms nothing", async () => {
    const { s, s3, arm } = serve({ clock: undefined });
    expect(await s.authorize({ ...req(), now: NOW } as ArmRequest)).toMatchObject({ status: "DECLINED", code: "UPSTREAM_ERROR" });
    expect(arm.orders.length + s3.puts.length).toBe(0);
  });

  test("setObservation refuses float cents or an unreadable time", async () => {
    for (const bad of [{ amountMinor: 1_000_000_000.5, at: freshBalance.at }, { amountMinor: 1_000_000_000, at: "yesterday" }]) {
      const { s, arm } = serve({ observation: bad });
      expect(await s.authorize(req())).toMatchObject({ status: "DECLINED", code: "UPSTREAM_ERROR" });
      expect(arm.orders.length).toBe(0);
    }
  });

  test("authorizeRa uses the same ledger: an RA swipe after the arm consumed the writ is WRIT_REPLAY", async () => {
    const { s } = serve();
    expect((await s.authorize(req())).status).toBe("AUTHORIZED");
    const ra = { mode: "ra" as const, cardId: CARD, amountMinor: 18_000, currency: "USD", mcc: "5734", merchantName: "DataCo", now: "1999-01-01T00:00:00.000Z", ra: { signatureValid: true, nonceFresh: true, nonceSeen: false } };
    const d = await s.authorizeRa(ra, "evt-ra-1");
    expect(d.status).toBe("DECLINED");
    expect(s.events.some((e) => e.kind === "WRIT_CONSUMED" && e.writId === "writ-1")).toBe(true);
    expect((await s.authorizeRa({ ...ra, mode: "frozen" }, "evt-ra-2")).status).toBe("DECLINED");
  });

  test("arm returning false is ARM_FAILED, not AUTHORIZED", async () => {
    const { s, arm } = serve({ arm: "false" });
    expect(await s.authorize(req())).toMatchObject({ status: "DECLINED", code: "ARM_FAILED" });
    expect(arm.orders.length).toBe(1);
  });
});

describe("baked approvers.json and image files", () => {
  const read = (p: string) => readFileSync(new URL(`../${p}`, import.meta.url), "utf8");

  test("approvers.json holds one Ed25519 public key and no private key", () => {
    const text = read("enclave/config/approvers.json");
    expect(text).not.toContain("PRIVATE");
    expect(bakedApproverKey(JSON.parse(text))).toBeDefined();
  });

  test("every file in the enclave-serve.ts import graph is copied in the Dockerfile and staged by eif.ts", () => {
    const d = read("enclave/Dockerfile");
    const eif = read("scripts/eif.ts");
    const seen = new Set<string>();
    const walk = (file: string) => {
      if (seen.has(file)) return;
      seen.add(file);
      const dir = file.split("/").slice(0, -1);
      for (const m of read(file).matchAll(/^import\s[^;]*?from\s+"(\.{1,2}\/[^"]+)"/gm)) {
        const parts = [...dir];
        for (const seg of m[1]!.split("/")) {
          if (seg === "..") parts.pop();
          else if (seg !== ".") parts.push(seg);
        }
        walk(`${parts.join("/")}.ts`);
      }
    };
    walk("src/host/enclave-serve.ts");
    for (const f of ["src/core/decide.ts", "src/core/gate.ts", "src/core/ledger.ts"]) expect(seen.has(f)).toBe(true);
    for (const f of [...seen, "enclave/config/approvers.json"]) {
      expect(d).toContain(`COPY ${f} /app/${f}`);
      expect(eif).toContain(`"${f}"`);
    }
    expect(/^COPY\s+\.\s/m.test(d)).toBe(false);
    expect(/^COPY\s+\S*\.env/m.test(d)).toBe(false);
  });

  test("no em dash, no clock, no logging in enclave-serve.ts", () => {
    const t = read("src/host/enclave-serve.ts");
    expect(t.includes("\u2014")).toBe(false);
    expect(read("test/enclave-serve.test.ts").includes("\u2014")).toBe(false);
    expect(/Date\.now|new Date\(\)|console\.|process\.(stdout|stderr)/.test(t)).toBe(false);
  });
});
