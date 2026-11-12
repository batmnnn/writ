import { describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { fixedNsm } from "../src/host/nsm";
import { runBoot, type BootIo } from "../src/host/enclave";
import {
  armAfterUnseal,
  armCheckpointBody,
  armCheckpointHash,
  sigV4Authorization,
  type ArmDeps,
  type FetchInit,
  type FetchLike,
} from "../src/host/enclave-arm";
import { GENESIS_PREV } from "../src/core/chain";

const ARN = "arn:aws:kms:us-west-2:401046276943:key/04d013d8-fb9b-4261-bf67-4d87370a31bb";
const PCRS = { pcr0: "a1".repeat(48), pcr1: "b2".repeat(48), pcr2: "c3".repeat(48) };
const CARD = "3f2b8c1e-7a4d-4e9b-9c11-2d5e6f708192";
const CLIENT = "fake-client-id";
const FAKE = { accessKeyId: "ASIAFAKEFAKEFAKE", secretAccessKey: "fake-secret-not-a-real-key", sessionToken: "fake-session-token" };
const CIPHERTEXT_B64 = randomBytes(64).toString("base64");
const API_KEY = "fake-airwallex-key-for-tests";
const API_KEY_B64 = Buffer.from(API_KEY).toString("base64");
const TOKEN = "fake-bearer-token";

type Call = { url: string; init: FetchInit };
type SwipeReply = { status: number; body: string };

const SIM_URL = "https://api.sandbox.airwallex.com/api/v1/simulation/issuing/create";
const swipeBody = (amount: number, processResult: string, failureReason?: string) =>
  JSON.stringify({
    card_transaction_event_id: "01a1bfe6-cffb-7000-af9c-1a62e6a3dc15",
    type: "AUTHORIZATION",
    subtype: "AUTHORIZATION",
    process_result: processResult,
    card_id: CARD,
    transaction_amount: amount,
    transaction_currency: "USD",
    masked_card_number: "************1803",
    ...(failureReason ? { failure_reason: failureReason } : {}),
  });
const APPROVED_1: SwipeReply = { status: 201, body: swipeBody(1, "APPROVED") };
const DECLINED_2: SwipeReply = { status: 201, body: swipeBody(2, "DECLINED", "LIMIT_EXCEEDED") };

function fakeFetch(
  statuses: { s3?: number; login?: number; active?: number; inactive?: number; swipe1?: SwipeReply; swipe2?: SwipeReply } = {},
) {
  const calls: Call[] = [];
  const fetch: FetchLike = async (url, init) => {
    calls.push({ url, init });
    const reply = (status: number, body = "") => ({ status, text: async () => body });
    if (url === SIM_URL) {
      const amount = (JSON.parse(init.body ?? "{}") as { transaction_amount?: number }).transaction_amount;
      const r = amount === 1 ? (statuses.swipe1 ?? APPROVED_1) : amount === 2 ? (statuses.swipe2 ?? DECLINED_2) : { status: 599, body: "" };
      return reply(r.status, r.body);
    }
    if (url.startsWith("https://s3.us-west-2.amazonaws.com/")) return reply(statuses.s3 ?? 200);
    if (url.endsWith("/api/v1/authentication/login")) {
      const s = statuses.login ?? 201;
      return reply(s, s < 300 ? JSON.stringify({ token: TOKEN, expires_at: "2026-11-11T05:00:00+0000" }) : '{"code":"unauthorized"}');
    }
    if (url.endsWith(`/api/v1/issuing/cards/${CARD}/update`)) {
      const status = (JSON.parse(init.body ?? "{}") as { card_status?: string }).card_status;
      return reply(status === "ACTIVE" ? (statuses.active ?? 200) : (statuses.inactive ?? 200), "{}");
    }
    return reply(599);
  };
  let n = 0;
  const deps: ArmDeps = { fetch, now: () => new Date("2026-11-11T03:43:00.000Z"), uuid: () => `00000000-0000-4000-8000-00000000000${++n}` };
  return { calls, deps };
}

const airwallexCalls = (calls: Call[]) => calls.filter((c) => c.url.startsWith("https://api.sandbox.airwallex.com"));

const stepsOf = (calls: Call[]) =>
  calls.map((c) => {
    if (c.url.includes("amazonaws.com")) return `S3 ${c.init.method}`;
    if (c.url.endsWith("/login")) return "LOGIN";
    if (c.url === SIM_URL) return `SWIPE ${(JSON.parse(c.init.body!) as { transaction_amount: number }).transaction_amount}`;
    return (JSON.parse(c.init.body!) as { card_status: string }).card_status;
  });

describe("sigV4Authorization", () => {
  test("matches the AWS S3 GET example from the SigV4 docs", () => {
    const auth = sigV4Authorization({
      method: "GET",
      path: "/test.txt",
      headers: {
        host: "examplebucket.s3.amazonaws.com",
        range: "bytes=0-9",
        "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "x-amz-date": "20130524T000000Z",
      },
      payloadSha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      region: "us-east-1",
      service: "s3",
      credentials: { accessKeyId: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" },
    });
    expect(auth).toBe(
      "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
    );
  });
});

describe("armAfterUnseal", () => {
  test("S3 412 is COMMIT_FAILED, Airwallex is never called, the key is zeroed", async () => {
    const { calls, deps } = fakeFetch({ s3: 412 });
    const key = Buffer.from(API_KEY);
    expect(await armAfterUnseal(key, { cardId: CARD, clientId: CLIENT }, FAKE, deps)).toEqual({ ok: false, code: "COMMIT_FAILED" });
    expect(calls.length).toBe(1);
    expect(airwallexCalls(calls)).toEqual([]);
    expect(key.every((b) => b === 0)).toBe(true);
  });

  test("S3 200 then login failure is ARM_FAILED, no card update, the key buffer is zeroed after", async () => {
    const { calls, deps } = fakeFetch({ login: 401 });
    const key = Buffer.from(API_KEY);
    expect(await armAfterUnseal(key, { cardId: CARD, clientId: CLIENT }, FAKE, deps)).toEqual({ ok: false, code: "ARM_FAILED" });
    expect(calls.map((c) => c.url.split("/").slice(-1)[0])).toEqual([`${CARD}.json`, "login"]);
    expect(calls[1]!.init.headers["x-api-key"]).toBe(API_KEY);
    expect(key.every((b) => b === 0)).toBe(true);
  });

  test("a failed ACTIVE still tries INACTIVE once, then ARM_FAILED", async () => {
    const { calls, deps } = fakeFetch({ active: 400 });
    const key = Buffer.from(API_KEY);
    expect(await armAfterUnseal(key, { cardId: CARD, clientId: CLIENT }, FAKE, deps)).toEqual({ ok: false, code: "ARM_FAILED" });
    expect(stepsOf(calls)).toEqual(["S3 PUT", "LOGIN", "ACTIVE", "INACTIVE"]);
  });

  test("both swipes go out in order with the bearer token, DataCo, MCC 5734, USD, 1 then 2 major units", async () => {
    const { calls, deps } = fakeFetch();
    expect(await armAfterUnseal(Buffer.from(API_KEY), { cardId: CARD, clientId: CLIENT }, FAKE, deps)).toEqual({ ok: true });
    const sims = calls.filter((c) => c.url === SIM_URL);
    expect(sims.length).toBe(2);
    for (const s of sims) {
      expect(s.init.method).toBe("POST");
      expect(s.init.headers.authorization).toBe(`Bearer ${TOKEN}`);
    }
    expect(JSON.parse(sims[0]!.init.body!)).toEqual({ card_id: CARD, transaction_amount: 1, transaction_currency: "USD", merchant_category_code: "5734", merchant_info: "DataCo" });
    expect(JSON.parse(sims[1]!.init.body!)).toEqual({ card_id: CARD, transaction_amount: 2, transaction_currency: "USD", merchant_category_code: "5734", merchant_info: "DataCo" });
  });

  test("the $2 swipe approved is ARM_FAILED and INACTIVE is still called last", async () => {
    const { calls, deps } = fakeFetch({ swipe2: { status: 201, body: swipeBody(2, "APPROVED") } });
    expect(await armAfterUnseal(Buffer.from(API_KEY), { cardId: CARD, clientId: CLIENT }, FAKE, deps)).toEqual({ ok: false, code: "ARM_FAILED" });
    expect(stepsOf(calls)).toEqual(["S3 PUT", "LOGIN", "ACTIVE", "SWIPE 1", "SWIPE 2", "INACTIVE"]);
  });

  test("the $1 swipe declined is ARM_FAILED and INACTIVE is still called last", async () => {
    const { calls, deps } = fakeFetch({ swipe1: { status: 201, body: swipeBody(1, "DECLINED", "LIMIT_EXCEEDED") } });
    expect(await armAfterUnseal(Buffer.from(API_KEY), { cardId: CARD, clientId: CLIENT }, FAKE, deps)).toEqual({ ok: false, code: "ARM_FAILED" });
    expect(stepsOf(calls)).toEqual(["S3 PUT", "LOGIN", "ACTIVE", "SWIPE 1", "SWIPE 2", "INACTIVE"]);
  });

  test("a held authorization, status PENDING, counts as the $1 swipe", async () => {
    const { calls, deps } = fakeFetch({ swipe1: { status: 201, body: JSON.stringify({ type: "AUTHORIZATION", status: "PENDING" }) } });
    expect(await armAfterUnseal(Buffer.from(API_KEY), { cardId: CARD, clientId: CLIENT }, FAKE, deps)).toEqual({ ok: true });
    expect(stepsOf(calls)).toEqual(["S3 PUT", "LOGIN", "ACTIVE", "SWIPE 1", "SWIPE 2", "INACTIVE"]);
  });

  test("a 201 that does not show an approval is not accepted", async () => {
    for (const swipe1 of [
      { status: 201, body: "{}" },
      { status: 201, body: "not json" },
      { status: 201, body: JSON.stringify({ type: "CLEARING", process_result: "PENDING" }) },
      { status: 400, body: swipeBody(1, "APPROVED") },
    ]) {
      const { calls, deps } = fakeFetch({ swipe1 });
      expect(await armAfterUnseal(Buffer.from(API_KEY), { cardId: CARD, clientId: CLIENT }, FAKE, deps)).toEqual({ ok: false, code: "ARM_FAILED" });
      expect(stepsOf(calls).at(-1)).toBe("INACTIVE");
    }
  });

  test("a $2 swipe that errors instead of declining is ARM_FAILED, not a pass", async () => {
    for (const swipe2 of [{ status: 500, body: "" }, { status: 201, body: "{}" }]) {
      const { calls, deps } = fakeFetch({ swipe2 });
      expect(await armAfterUnseal(Buffer.from(API_KEY), { cardId: CARD, clientId: CLIENT }, FAKE, deps)).toEqual({ ok: false, code: "ARM_FAILED" });
      expect(stepsOf(calls).at(-1)).toBe("INACTIVE");
    }
  });

  test("swipes pass but INACTIVE fails is ARM_FAILED", async () => {
    const { deps } = fakeFetch({ inactive: 500 });
    expect(await armAfterUnseal(Buffer.from(API_KEY), { cardId: CARD, clientId: CLIENT }, FAKE, deps)).toEqual({ ok: false, code: "ARM_FAILED" });
  });

  test("a throwing S3 fetch is COMMIT_FAILED", async () => {
    const deps: ArmDeps = { fetch: async () => { throw new Error(FAKE.secretAccessKey); }, now: () => new Date(), uuid: () => "x" };
    const key = Buffer.from(API_KEY);
    expect(await armAfterUnseal(key, { cardId: CARD, clientId: CLIENT }, FAKE, deps)).toEqual({ ok: false, code: "COMMIT_FAILED" });
    expect(key.every((b) => b === 0)).toBe(true);
  });

  test("the S3 PUT is conditional, path style, signed with the session token, body is the canonical checkpoint", async () => {
    const { calls, deps } = fakeFetch();
    await armAfterUnseal(Buffer.from(API_KEY), { cardId: CARD, clientId: CLIENT }, FAKE, deps);
    const put = calls[0]!;
    expect(put.url).toBe(`https://s3.us-west-2.amazonaws.com/writ-ledger-401046276943/checkpoints/arm/${CARD}.json`);
    expect(put.init.method).toBe("PUT");
    expect(put.init.headers["if-none-match"]).toBe("*");
    expect(put.init.headers["x-amz-security-token"]).toBe(FAKE.sessionToken);
    expect(put.init.headers["x-amz-date"]).toBe("20261111T034300Z");
    expect(put.init.headers.authorization).toStartWith(`AWS4-HMAC-SHA256 Credential=${FAKE.accessKeyId}/20261111/us-west-2/s3/aws4_request, SignedHeaders=`);
    expect(put.init.headers.authorization).toContain("if-none-match");
    expect(put.init.body).toBe(`{"amountMinor":100,"cardId":"${CARD}","kind":"arm","prev":"${GENESIS_PREV}","seq":1}`);
    expect(put.init.body).toBe(armCheckpointBody(CARD));
    expect(put.init.headers["x-amz-content-sha256"]).toBe(createHash("sha256").update(put.init.body!).digest("hex"));
    expect(put.init.headers["x-amz-meta-entry-hash"]).toBe(armCheckpointHash(CARD));
    expect(put.init.headers["x-amz-meta-entry-hash"]).toMatch(/^[0-9a-f]{64}$/);
  });

  test("the ACTIVE body uses integer 1 major unit for 100 cents, one MCC, USD only", async () => {
    const { calls, deps } = fakeFetch();
    await armAfterUnseal(Buffer.from(API_KEY), { cardId: CARD, clientId: CLIENT }, FAKE, deps);
    const [login, active, , , inactive] = airwallexCalls(calls);
    expect(login!.init.headers).toEqual({ "x-client-id": CLIENT, "x-api-key": API_KEY });
    expect(login!.init.body).toBeUndefined();
    expect(active!.init.headers.authorization).toBe(`Bearer ${TOKEN}`);
    const body = JSON.parse(active!.init.body!);
    expect(body).toEqual({
      request_id: "00000000-0000-4000-8000-000000000001",
      card_status: "ACTIVE",
      authorization_controls: {
        transaction_limits: { currency: "USD", limits: [{ amount: 1, interval: "PER_TRANSACTION" }, { amount: 1, interval: "ALL_TIME" }] },
        allowed_currencies: ["USD"],
        allowed_merchant_categories: ["5734"],
      },
    });
    expect(active!.init.body).toContain('"amount":1,');
    expect(JSON.parse(inactive!.init.body!)).toEqual({ request_id: "00000000-0000-4000-8000-000000000002", card_status: "INACTIVE" });
  });
});

describe("runBoot with arm", () => {
  const line = (extra: Record<string, unknown> = { cardId: CARD, clientId: CLIENT }) => JSON.stringify({ ciphertextB64: CIPHERTEXT_B64, ...FAKE, ...extra });

  function harness(arm: ArmDeps, bootLine = line()) {
    const out: string[] = [];
    const err: string[] = [];
    const replies: string[] = [];
    let kmsCalls = 0;
    const io: BootIo = {
      nsm: fixedNsm(PCRS),
      readLine: async () => ({ ok: true, value: Buffer.from(bootLine) }),
      runKmstool: async () => {
        kmsCalls += 1;
        return { ok: true, value: { plaintextB64: API_KEY_B64, replyKeyId: ARN } };
      },
      stdout: (l) => out.push(l),
      stderr: (l) => err.push(l),
      reply: (l) => replies.push(l),
      arm,
    };
    return { io, out, err, replies, kmsCalls: () => kmsCalls };
  }

  const noSecretIn = (lines: string[]) => {
    const all = lines.join("\n");
    for (const v of [...Object.values(FAKE), CIPHERTEXT_B64, API_KEY_B64, API_KEY, TOKEN]) expect(all.includes(v)).toBe(false);
  };

  test("happy path: S3, login, ACTIVE, $1 swipe, $2 swipe, INACTIVE, then one ARMED line on stdout and the reply", async () => {
    const { calls, deps } = fakeFetch();
    const h = harness(deps);
    expect(await runBoot(h.io)).toBe(0);
    expect(stepsOf(calls)).toEqual(["S3 PUT", "LOGIN", "ACTIVE", "SWIPE 1", "SWIPE 2", "INACTIVE"]);
    expect(h.out).toEqual(["ARMED"]);
    expect(h.replies).toEqual(["ARMED"]);
    expect(h.err).toEqual([]);
    noSecretIn([...h.out, ...h.err, ...h.replies]);
  });

  test("S3 412 replies DECLINED COMMIT_FAILED and never calls Airwallex", async () => {
    const { calls, deps } = fakeFetch({ s3: 412 });
    const h = harness(deps);
    expect(await runBoot(h.io)).toBe(1);
    expect(h.err).toEqual(["DECLINED COMMIT_FAILED"]);
    expect(h.replies).toEqual(["DECLINED COMMIT_FAILED"]);
    expect(h.out).toEqual([]);
    expect(airwallexCalls(calls)).toEqual([]);
  });

  test("login failure replies DECLINED ARM_FAILED", async () => {
    const { deps } = fakeFetch({ login: 401 });
    const h = harness(deps);
    expect(await runBoot(h.io)).toBe(1);
    expect(h.replies).toEqual(["DECLINED ARM_FAILED"]);
    noSecretIn([...h.out, ...h.err, ...h.replies]);
  });

  test("$2 swipe approved replies DECLINED ARM_FAILED after INACTIVE", async () => {
    const { calls, deps } = fakeFetch({ swipe2: { status: 201, body: swipeBody(2, "APPROVED") } });
    const h = harness(deps);
    expect(await runBoot(h.io)).toBe(1);
    expect(stepsOf(calls)).toEqual(["S3 PUT", "LOGIN", "ACTIVE", "SWIPE 1", "SWIPE 2", "INACTIVE"]);
    expect(h.replies).toEqual(["DECLINED ARM_FAILED"]);
    expect(h.out).toEqual([]);
    noSecretIn([...h.out, ...h.err, ...h.replies]);
  });

  test("missing or bad cardId or clientId is BAD_INPUT before KMS and with no network", async () => {
    const bad = [{}, { cardId: CARD }, { clientId: CLIENT }, { cardId: "not-a-uuid", clientId: CLIENT }, { cardId: CARD, clientId: "" }, { cardId: CARD, clientId: 7 }];
    for (const extra of bad) {
      const { calls, deps } = fakeFetch();
      const h = harness(deps, line(extra));
      expect(await runBoot(h.io)).toBe(1);
      expect(h.replies).toEqual(["DECLINED BAD_INPUT"]);
      expect(calls).toEqual([]);
      expect(h.kmsCalls()).toBe(0);
    }
  });
});

describe("image files", () => {
  const read = (p: string) => readFileSync(new URL(`../${p}`, import.meta.url), "utf8");

  test("boot.sh adds the loopback addresses, hosts lines and both bridges before bun", () => {
    const b = read("enclave/boot.sh");
    const at = (s: string) => {
      const i = b.indexOf(s);
      expect(i).toBeGreaterThan(-1);
      return i;
    };
    const lo = at("ip link set lo up");
    const boot = at("socat TCP-LISTEN:5000,bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:3:5000 &");
    const order = [
      "ip addr add 127.0.0.2/8 dev lo",
      "ip addr add 127.0.0.3/8 dev lo",
      "127.0.0.2 s3.us-west-2.amazonaws.com",
      "127.0.0.3 api.sandbox.airwallex.com",
      "socat TCP-LISTEN:443,bind=127.0.0.2,reuseaddr,fork VSOCK-CONNECT:3:8443 &",
      "socat TCP-LISTEN:443,bind=127.0.0.3,reuseaddr,fork VSOCK-CONNECT:3:8444 &",
    ].map(at);
    const bun = at("exec /usr/local/bin/bun run /app/src/host/enclave.ts");
    expect(boot).toBeGreaterThan(lo);
    for (const i of order) {
      expect(i).toBeGreaterThan(lo);
      expect(bun).toBeGreaterThan(i);
    }
  });

  test("every file enclave-arm.ts needs is copied in the Dockerfile and staged by eif.ts", () => {
    const d = read("enclave/Dockerfile");
    const eif = read("scripts/eif.ts");
    for (const f of ["src/host/enclave-arm.ts", "src/core/chain.ts", "src/core/writ.ts", "src/core/merchant.ts", "src/core/money.ts", "src/core/time.ts", "src/airwallex/units.ts"]) {
      expect(d).toContain(`COPY ${f} /app/${f}`);
      expect(eif).toContain(`"${f}"`);
    }
  });

  test("no debug flag, no em dash, no logging in enclave-arm.ts", () => {
    const debugFlag = "--" + "debug-mode";
    for (const p of ["src/host/enclave-arm.ts", "src/host/enclave.ts", "enclave/boot.sh", "enclave/Dockerfile", "scripts/eif.ts", "test/enclave-arm.test.ts"]) {
      const t = read(p);
      expect(t.includes(debugFlag)).toBe(false);
      expect(t.includes("\u2014")).toBe(false);
    }
    expect(/console\.|process\.(stdout|stderr)/.test(read("src/host/enclave-arm.ts"))).toBe(false);
  });
});
