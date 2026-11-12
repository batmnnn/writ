import { describe, expect, test } from "bun:test";
import { AirwallexClient } from "../src/airwallex/client";
import { FakeAdapter } from "../src/airwallex/fake-adapter";
import { redact } from "../src/airwallex/redact";
import { RestAdapter, toListedTransaction, toOutcome } from "../src/airwallex/rest-adapter";
import { majorToMinor, minorToMajor } from "../src/airwallex/units";
import { buildPlainAdapter } from "../src/host/plain";
import type { ArmSpec } from "../src/types";

const BASE = "https://api.sandbox.airwallex.com";
const quiet = () => {};

interface Call {
  url: string;
  method: string;
  body: any;
}

/** Mocked fetch. Login always works; other paths go to `handler`. */
function mockFetch(handler: (c: Call) => Response | Promise<Response>) {
  const calls: Call[] = [];
  const impl = (async (input: any, init?: RequestInit) => {
    const c: Call = { url: String(input), method: init?.method ?? "GET", body: init?.body ? JSON.parse(String(init.body)) : undefined };
    calls.push(c);
    if (c.url.endsWith("/api/v1/authentication/login")) {
      return Response.json({ token: "test-token", expires_at: new Date(Date.now() + 30 * 60_000).toISOString() });
    }
    return handler(c);
  }) as typeof fetch;
  return { impl, calls };
}

function client(fetchImpl: typeof fetch, timeoutMs = 5000) {
  return new AirwallexClient({ baseUrl: BASE, clientId: "id", apiKey: "key", fetchImpl, timeoutMs, minIntervalMs: 0, log: quiet });
}

const ARM: ArmSpec = { amountMinor: 5000, currency: "USD", mcc: "5734", activeTo: "2026-11-12T09:00:00.000Z", writHashPrefix: "abcd1234" };

describe("units", () => {
  test("minor to major is exact", () => {
    expect(minorToMajor(18000)).toBe(180);
    expect(minorToMajor(18050)).toBe(180.5);
    expect(minorToMajor(1)).toBe(0.01);
    expect(JSON.stringify({ amount: minorToMajor(18050) })).toBe('{"amount":180.5}');
    expect(JSON.stringify({ amount: minorToMajor(1) })).toBe('{"amount":0.01}');
    expect(minorToMajor(1.5)).toBeUndefined();
  });

  test("major to minor is exact and refuses sub cent values", () => {
    expect(majorToMinor(180)).toBe(18000);
    expect(majorToMinor(180.5)).toBe(18050);
    expect(majorToMinor(0.01)).toBe(1);
    expect(majorToMinor(0.29)).toBe(29);
    expect(majorToMinor(10000000)).toBe(1_000_000_000);
    expect(majorToMinor(1.005)).toBeUndefined();
    expect(majorToMinor("abc")).toBeUndefined();
  });
});

describe("client", () => {
  test("a per request timeout overrides the client default", async () => {
    const { impl } = mockFetch(() => new Promise<Response>(() => {}));
    const started = Date.now();
    const r = await client(impl, 5000).request("GET", "/api/v1/issuing/config", { timeoutMs: 40 });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.kind).toBe("timeout");
      expect(r.error.message).toContain("40 ms");
      expect(r.error.message).not.toContain("5000");
    }
    expect(Date.now() - started).toBeLessThan(2000);
  });

  test("a timeout returns a failure Result and does not throw", async () => {
    const { impl } = mockFetch(() => new Promise<Response>(() => {}));
    const r = await client(impl, 50).request("GET", "/api/v1/issuing/config");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.kind).toBe("timeout");
  });

  test("a thrown fetch returns a failure Result", async () => {
    const { impl } = mockFetch(() => {
      throw new Error("socket closed");
    });
    const r = await client(impl).request("GET", "/api/v1/issuing/config");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.kind).toBe("network");
  });

  test("a base URL without sandbox is refused before any fetch", async () => {
    let fetched = 0;
    const impl = (async () => {
      fetched += 1;
      return Response.json({});
    }) as unknown as typeof fetch;
    const c = new AirwallexClient({ baseUrl: "https://api.airwallex.com", clientId: "id", apiKey: "key", fetchImpl: impl, log: quiet });
    const r = await c.request("GET", "/api/v1/issuing/config");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.kind).toBe("config");
    expect(fetched).toBe(0);

    const host = buildPlainAdapter({ env: { AIRWALLEX_BASE_URL: "https://api.airwallex.com", AIRWALLEX_CLIENT_ID: "id", AIRWALLEX_API_KEY: "key" } });
    expect(host.ok).toBe(false);
  });

  test("error bodies keep code and message, and digit runs are stripped", async () => {
    const { impl } = mockFetch(() => Response.json({ code: "invalid_argument", message: "card 4242424242424242 bad" }, { status: 400 }));
    const r = await client(impl).request("POST", "/api/v1/issuing/cards/create", { body: {} });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe("invalid_argument");
      expect(r.error.message).not.toContain("4242424242424242");
    }
  });
});

describe("rest adapter", () => {
  test("request_id is unique per operation and reused on a disarm retry", async () => {
    let updates = 0;
    const { impl, calls } = mockFetch((c) => {
      if (c.url.includes("/update")) {
        updates += 1;
        // First disarm attempt fails, the retry succeeds.
        if (updates === 2) return Response.json({ code: "internal_error", message: "try again" }, { status: 500 });
        return Response.json({ card_status: c.body.card_status });
      }
      return Response.json({});
    });
    const a = new RestAdapter({ client: client(impl), mode: "frozen", sleep: async () => {}, disarmBackoffMs: [0, 0, 0] });
    expect((await a.arm("card-1", ARM)).ok).toBe(true);
    expect((await a.disarm("card-1")).ok).toBe(true);
    expect((await a.disarm("card-1")).ok).toBe(true);

    const ids = calls.filter((c) => c.url.includes("/update")).map((c) => c.body.request_id as string);
    expect(ids.length).toBe(4);
    const [armId, disarmTry1, disarmTry2, secondDisarm] = ids;
    expect(disarmTry1).toBe(disarmTry2!);
    expect(new Set([armId, disarmTry1, secondDisarm]).size).toBe(3);
  });

  test("getCard never returns a card number, only the last 4", async () => {
    const { impl } = mockFetch(() => Response.json({ card_id: "c1", card_status: "ACTIVE", card_number: "4242424242421234" }));
    const a = new RestAdapter({ client: client(impl), mode: "frozen" });
    const r = await a.getCard("c1");
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(JSON.stringify(r.value)).not.toContain("4242424242421234");
      expect(r.value.masked_card_number).toBe("************1234");
    }
  });

  test("disarm gives up after 3 retries and reports the failure", async () => {
    const { impl, calls } = mockFetch(() => Response.json({ code: "internal_error", message: "down" }, { status: 500 }));
    const a = new RestAdapter({ client: client(impl), mode: "frozen", sleep: async () => {}, disarmBackoffMs: [0, 0, 0] });
    const r = await a.disarm("card-1");
    expect(r.ok).toBe(false);
    expect(calls.filter((c) => c.url.includes("/update")).length).toBe(4);
  });

  test("arm sends major units, one MCC, one currency, PER_TRANSACTION and ALL_TIME", async () => {
    const { impl, calls } = mockFetch(() => Response.json({}));
    const a = new RestAdapter({ client: client(impl), mode: "frozen" });
    await a.arm("card-1", { ...ARM, amountMinor: 18050 });
    const body = calls.find((c) => c.url.includes("/update"))!.body;
    expect(body.card_status).toBe("ACTIVE");
    expect(body.authorization_controls.transaction_limits.limits).toEqual([
      { amount: 180.5, interval: "PER_TRANSACTION" },
      { amount: 180.5, interval: "ALL_TIME" },
    ]);
    expect(body.authorization_controls.allowed_merchant_categories).toEqual(["5734"]);
    expect(body.authorization_controls.allowed_currencies).toEqual(["USD"]);
  });

  test("re-arm: ALL_TIME is writ amount plus prior spend, PER_TRANSACTION is the writ amount", async () => {
    const { impl, calls } = mockFetch(() => Response.json({}));
    const a = new RestAdapter({ client: client(impl), mode: "frozen" });
    await a.arm("card-1", { ...ARM, amountMinor: 18050, priorSpendMinor: 4001 });
    const body = calls.find((c) => c.url.includes("/update"))!.body;
    expect(body.authorization_controls.transaction_limits.limits).toEqual([
      { amount: 180.5, interval: "PER_TRANSACTION" },
      { amount: 220.51, interval: "ALL_TIME" },
    ]);
  });

  test("a negative or fractional prior spend is refused before any update", async () => {
    const { impl, calls } = mockFetch(() => Response.json({}));
    const a = new RestAdapter({ client: client(impl), mode: "frozen" });
    expect((await a.arm("card-1", { ...ARM, priorSpendMinor: -1 })).ok).toBe(false);
    expect((await a.arm("card-1", { ...ARM, priorSpendMinor: 1.5 })).ok).toBe(false);
    expect(calls.filter((c) => c.url.includes("/update")).length).toBe(0);
  });

  test("a failed re-arm with prior spend still leaves the card INACTIVE", async () => {
    const { impl, calls } = mockFetch((c) =>
      c.body?.card_status === "ACTIVE" ? Response.json({ code: "invalid_argument", message: "no" }, { status: 400 }) : Response.json({}),
    );
    const a = new RestAdapter({ client: client(impl), mode: "frozen", sleep: async () => {} });
    const r = await a.arm("card-1", { ...ARM, priorSpendMinor: 4000 });
    expect(r.ok).toBe(false);
    expect(calls.filter((c) => c.url.includes("/update")).at(-1)!.body.card_status).toBe("INACTIVE");
  });

  test("a failed arm leaves the card INACTIVE", async () => {
    const { impl, calls } = mockFetch((c) =>
      c.body?.card_status === "ACTIVE" ? Response.json({ code: "invalid_argument", message: "no" }, { status: 400 }) : Response.json({}),
    );
    const a = new RestAdapter({ client: client(impl), mode: "frozen", sleep: async () => {} });
    const r = await a.arm("card-1", ARM);
    expect(r.ok).toBe(false);
    const last = calls.filter((c) => c.url.includes("/update")).at(-1)!;
    expect(last.body.card_status).toBe("INACTIVE");
  });

  test("simulation create, capture and reverse use a 20 s timeout, not the 5 s client default", async () => {
    const { impl } = mockFetch(() => new Promise<Response>(() => {}));
    const a = new RestAdapter({ client: client(impl, 5000), mode: "frozen", simulationTimeoutMs: 40 });
    const started = Date.now();
    const created = await a.simulateSwipe({ cardId: "card-1", amountMinor: 18000, currency: "USD", mcc: "5734", merchantName: "DataCo" });
    expect(created.ok).toBe(false);
    if (!created.ok) expect(created.error.message).toContain("40 ms");
    const captured = await a.simulateCapture(
      { transactionId: "t", accepted: false, raw: { card_transaction_lifecycle_id: "life-1" } },
      18000,
      "DataCo",
    );
    expect(captured.ok).toBe(false);
    if (!captured.ok) expect(captured.error.message).toContain("40 ms");
    const reversed = await a.reverseSwipe("life-1", 18000);
    expect(reversed.ok).toBe(false);
    if (!reversed.ok) {
      expect(reversed.error.kind).toBe("timeout");
      expect(reversed.error.message).toContain("40 ms");
      expect(reversed.error.message).not.toContain("5000");
    }
    expect(Date.now() - started).toBeLessThan(2000);
  });

  test("reverse sends major units, a fresh request_id, and the lifecycle path", async () => {
    const { impl, calls } = mockFetch(() =>
      Response.json({
        type: "REVERSAL",
        process_result: "APPROVED",
        card_transaction_lifecycle_id: "life-1",
        transaction_amount: 180,
      }),
    );
    let n = 0;
    const a = new RestAdapter({ client: client(impl), mode: "frozen", uuid: () => `req-${++n}` });
    const first = await a.reverseSwipe("life-1", 18000);
    const second = await a.reverseSwipe("life/2", 18050);
    expect(first.ok).toBe(true);
    expect((await a.reverseSwipe("", 18000)).ok).toBe(false);
    expect((await a.reverseSwipe("life-1", 0)).ok).toBe(false);
    expect((await a.reverseSwipe("life-1", 1.5)).ok).toBe(false);
    const reverses = calls.filter((c) => c.url.includes("/reverse"));
    expect(reverses).toHaveLength(2);
    expect(reverses[0]!.url).toContain("/api/v1/simulation/issuing/card_transaction_lifecycles/life-1/reverse");
    expect(reverses[0]!.body).toEqual({ request_id: "req-1", transaction_amount: 180 });
    expect(reverses[1]!.url).toContain("/card_transaction_lifecycles/life%2F2/reverse");
    expect(reverses[1]!.body.transaction_amount).toBe(180.5);
    expect(reverses[1]!.body.request_id).toBe("req-2");
    expect(reverses[0]!.body.request_id).not.toBe(reverses[1]!.body.request_id);
  });

  test("listTransactions reads the lifecycle id and converts a negative major amount", async () => {
    const { impl, calls } = mockFetch((c) => {
      if (c.url.includes("page_num=0")) {
        return Response.json({
          has_more: true,
          items: [
            {
              transaction_type: "AUTHORIZATION",
              status: "PENDING",
              transaction_amount: -180,
              transaction_date: "2026-11-12T10:00:00.000Z",
              card_transaction_data: { card_transaction_lifecycle_id: "life-180" },
            },
          ],
        });
      }
      return Response.json({
        has_more: false,
        items: [{ type: "AUTHORIZATION", process_result: "APPROVED", lifecycle_id: "life-top", billing_amount: "40.50" }],
      });
    });
    const a = new RestAdapter({ client: client(impl), mode: "frozen" });
    const r = await a.listTransactions("card-1", "2026-11-12T09:00:00.000Z");
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value[0]).toEqual({
        lifecycleId: "life-180",
        amountMinor: 18000,
        at: "2026-11-12T10:00:00.000Z",
        type: "AUTHORIZATION",
        status: "PENDING",
      });
      expect(r.value[1]?.lifecycleId).toBe("life-top");
      expect(r.value[1]?.amountMinor).toBe(4050);
    }
    expect(calls.some((c) => c.url.includes("from_created_at=") && c.url.includes("card_id=card-1"))).toBe(true);
    expect(toListedTransaction({ transaction_amount: -40, lifecycle_id: "only-top", transaction_type: "CLEARING", status: "APPROVED" }).amountMinor).toBe(4000);
  });

  test("an arm that times out still ends with a disarm attempt", async () => {
    const { impl, calls } = mockFetch((c) => (c.body?.card_status === "ACTIVE" ? new Promise<Response>(() => {}) : Response.json({})));
    const a = new RestAdapter({ client: client(impl, 30), mode: "frozen", sleep: async () => {} });
    const r = await a.arm("card-1", ARM);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.kind).toBe("timeout");
    expect(calls.filter((c) => c.url.includes("/update")).at(-1)!.body.card_status).toBe("INACTIVE");
  });

  test("transaction mapping: CLEARING plus APPROVED passes, CLEARING alone and AUTHORIZATION plus PENDING do not", () => {
    expect(toOutcome({ transaction_type: "CLEARING", status: "APPROVED" }).accepted).toBe(true);
    const failed = toOutcome({ transaction_type: "CLEARING", status: "FAILED", failure_reason: "LIMIT_EXCEEDED" });
    expect(failed.accepted).toBe(false);
    expect(failed.failureReason).toBe("LIMIT_EXCEEDED");
    expect(toOutcome({ transaction_type: "CLEARING" }).accepted).toBe(false);
    expect(toOutcome({ transaction_type: "AUTHORIZATION", status: "PENDING" }).accepted).toBe(false);
  });

  test("simulation response shape: approved authorization is held, declined carries failure_reason", () => {
    const held = toOutcome({ type: "AUTHORIZATION", process_result: "APPROVED", card_transaction_id: "ct-1" });
    expect(held.accepted).toBe(false);
    expect(held.failureReason).toBeUndefined();
    expect(held.transactionId).toBe("ct-1");
    const declined = toOutcome({ type: "AUTHORIZATION", process_result: "DECLINED", failure_reason: "CARD_INACTIVE" });
    expect(declined.failureReason).toBe("CARD_INACTIVE");
    expect(toOutcome({ type: "CLEARING", process_result: "APPROVED" }).accepted).toBe(true);
  });
});

describe("redact", () => {
  test("drops PAN like digit runs and secret keys", () => {
    const out = redact({ card_number: "4242424242424242", note: "pan 4111111111111111 here", token: "abc", masked_card_number: "************4242", ts: 1793856117809 }) as Record<string, unknown>;
    expect(JSON.stringify(out)).not.toMatch(/\d{13,19}/);
    expect(out.token).toBe("[removed]");
    expect(out.masked_card_number).toBe("************4242");
  });
});

describe("fake adapter", () => {
  async function armed(opts = {}) {
    const f = new FakeAdapter(opts);
    const card = await f.createAgentCard({ cardholderId: "h", team: "t", agent: "a" });
    if (!card.ok) throw new Error("create failed");
    return { f, cardId: card.value.cardId };
  }
  const swipe = (cardId: string, amountMinor: number, mcc = "5734", currency = "USD") => ({ cardId, amountMinor, mcc, currency, merchantName: "DataCo" });

  test("a new card in frozen mode is inactive", async () => {
    const { f, cardId } = await armed();
    const r = await f.simulateSwipe(swipe(cardId, 100));
    expect(r.ok && r.value.failureReason).toBe("CARD_INACTIVE");
  });

  test("bank side refusals", async () => {
    const { f, cardId } = await armed();
    await f.arm(cardId, ARM);
    const pass = await f.simulateSwipe(swipe(cardId, 4000));
    expect(pass.ok && pass.value.accepted).toBe(true);
    const over = await f.simulateSwipe(swipe(cardId, 6000));
    expect(over.ok && over.value.failureReason).toBe("LIMIT_EXCEEDED");
    const allTime = await f.simulateSwipe(swipe(cardId, 2000));
    expect(allTime.ok && allTime.value.failureReason).toBe("LIMIT_EXCEEDED");
    const mcc = await f.simulateSwipe(swipe(cardId, 500, "5999"));
    expect(mcc.ok && mcc.value.failureReason).toBe("MERCHANT_CATEGORY_NOT_ALLOWED");
    const cur = await f.simulateSwipe(swipe(cardId, 500, "5734", "EUR"));
    expect(cur.ok && cur.value.failureReason).toBe("CURRENCY_NOT_ALLOWED");
    await f.disarm(cardId);
    const off = await f.simulateSwipe(swipe(cardId, 500));
    expect(off.ok && off.value.failureReason).toBe("CARD_INACTIVE");
  });

  test("ALL_TIME behaviour on rearm follows the option", async () => {
    for (const counts of [true, false]) {
      const { f, cardId } = await armed({ allTimeCountsPriorSpend: counts });
      await f.arm(cardId, ARM);
      await f.simulateSwipe(swipe(cardId, 4000));
      await f.arm(cardId, ARM);
      const r = await f.simulateSwipe(swipe(cardId, 5000));
      expect(r.ok && r.value.accepted).toBe(!counts);
    }
  });

  test("re-arm with ALL_TIME of only the new writ declines LIMIT_EXCEEDED when prior spend counts", async () => {
    const { f, cardId } = await armed({ allTimeCountsPriorSpend: true });
    await f.arm(cardId, ARM);
    expect((await f.simulateSwipe(swipe(cardId, 4000))).ok).toBe(true);
    await f.arm(cardId, { ...ARM, amountMinor: 3000 });
    const r = await f.simulateSwipe(swipe(cardId, 3000));
    expect(r.ok && r.value.failureReason).toBe("LIMIT_EXCEEDED");
  });

  test("re-arm with priorSpendMinor equal to the old spend lets the new swipe through", async () => {
    const { f, cardId } = await armed({ allTimeCountsPriorSpend: true });
    await f.arm(cardId, ARM);
    const first = await f.simulateSwipe(swipe(cardId, 4000));
    expect(first.ok && first.value.accepted).toBe(true);
    await f.arm(cardId, { ...ARM, amountMinor: 3000, priorSpendMinor: 4000 });
    expect(f.cards.get(cardId)!.allTimeMinor).toBe(7000);
    const r = await f.simulateSwipe(swipe(cardId, 3000));
    expect(r.ok && r.value.accepted).toBe(true);
    const over = await f.simulateSwipe(swipe(cardId, 1));
    expect(over.ok && over.value.failureReason).toBe("LIMIT_EXCEEDED");
  });

  test("capture of an accepted authorization stays accepted and does not count twice", async () => {
    const { f, cardId } = await armed();
    await f.arm(cardId, ARM);
    const auth = await f.simulateSwipe(swipe(cardId, 4000));
    if (!auth.ok) throw new Error("swipe failed");
    const balance = f.balanceMinor;
    const cap = await f.simulateCapture(auth.value, 4000, "DataCo");
    expect(cap.ok && cap.value.accepted).toBe(true);
    expect(f.cards.get(cardId)!.allTimeSpentMinor).toBe(4000);
    expect(f.balanceMinor).toBe(balance);
  });

  test("capture of a declined authorization fails", async () => {
    const { f, cardId } = await armed();
    const auth = await f.simulateSwipe(swipe(cardId, 100));
    if (!auth.ok) throw new Error("swipe failed");
    expect(auth.value.accepted).toBe(false);
    const cap = await f.simulateCapture(auth.value, 100, "DataCo");
    expect(cap.ok).toBe(false);
  });

  test("injected failures surface as failure Results", async () => {
    const { f, cardId } = await armed();
    f.failNext.set("arm", { kind: "timeout", message: "slow" });
    const r = await f.arm(cardId, ARM);
    expect(r.ok).toBe(false);
    const s = await f.simulateSwipe(swipe(cardId, 100));
    expect(s.ok && s.value.failureReason).toBe("CARD_INACTIVE");
  });
});
