import { describe, expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { MAX_BODY_BYTES, NonceCache, type RaDecide, type RaRequest, handleRemoteAuth, readCapped, startRaServer } from "../src/airwallex/ra-server";
import type { Decision, DecisionInput } from "../src/types";

const SECRET = "test-shared-secret-not-real";
const NOW_MS = Date.parse("2026-11-12T08:35:00.000Z");
const EVENT_ID = "019dd72a-5bde-7000-8975-760d03a26bad";

const sign = (nonce: string, secret = SECRET) => createHmac("sha256", secret).update(nonce).digest("base64");

let counter = 0;
const freshNonce = (tsMs = NOW_MS) => `${tsMs}.r${++counter}abc`;

function v2Body(over: Record<string, unknown> = {}): string {
  return JSON.stringify({
    version: 2,
    card_id: "card-1",
    card_transaction_event_id: EVENT_ID,
    card_transaction_id: "019dd72a-5bde-7000-8975-760d03a26bac",
    transaction_type: "AUTHORIZATION",
    transaction_category: "PURCHASE",
    transaction_amount: 180,
    transaction_currency: "USD",
    merchant: { name: "DataCo", category_code: "5734", country: "US" },
    masked_card_number: "************5353",
    ...over,
  });
}

interface Spy {
  decide: RaDecide;
  calls: { input: DecisionInput; eventId: string }[];
}

function spy(result: Decision | (() => Decision | Promise<Decision>)): Spy {
  const calls: Spy["calls"] = [];
  return {
    calls,
    decide: (input, eventId) => {
      calls.push({ input, eventId });
      return typeof result === "function" ? result() : result;
    },
  };
}

const AUTHORIZED: Decision = { status: "AUTHORIZED", writId: "writ-1", reason: "$180.00 at DataCo. Team pool $180.00 of $500.00." };

function request(over: Partial<RaRequest> & { nonce?: string } = {}): RaRequest {
  const nonce = over.nonce ?? freshNonce();
  return {
    headers: { "x-nonce": nonce, "x-signature": sign(nonce) },
    rawBody: v2Body(),
    nowMs: NOW_MS,
    secret: SECRET,
    decide: spy(AUTHORIZED).decide,
    nonces: new NonceCache(),
    ...over,
  };
}

describe("handleRemoteAuth", () => {
  test("good signature and decide AUTHORIZED answers AUTHORIZED with the echoed id", async () => {
    const s = spy(AUTHORIZED);
    const res = await handleRemoteAuth(request({ decide: s.decide }));
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ card_transaction_event_id: EVENT_ID, response_status: "AUTHORIZED", status_reason: AUTHORIZED.reason });
    expect(Object.keys(res.body).sort()).toEqual(["card_transaction_event_id", "response_status", "status_reason"]);
    expect(s.calls).toHaveLength(1);
    expect(s.calls[0]?.eventId).toBe(EVENT_ID);
    expect(s.calls[0]?.input).toEqual({
      mode: "ra",
      cardId: "card-1",
      amountMinor: 18000,
      currency: "USD",
      mcc: "5734",
      merchantName: "DataCo",
      now: "2026-11-12T08:35:00.000Z",
      ra: { signatureValid: true, nonceFresh: true, nonceSeen: false },
    });
  });

  test("headers object from fetch works the same", async () => {
    const nonce = freshNonce();
    const headers = new Headers({ "X-Nonce": nonce, "X-Signature": sign(nonce) });
    const res = await handleRemoteAuth(request({ headers }));
    expect(res.body.response_status).toBe("AUTHORIZED");
  });

  test("bad signature declines, never calls decide, still echoes the id", async () => {
    const s = spy(AUTHORIZED);
    const nonce = freshNonce();
    const res = await handleRemoteAuth(request({ headers: { "x-nonce": nonce, "x-signature": sign(nonce, "wrong-secret") }, decide: s.decide }));
    expect(res.body).toEqual({ card_transaction_event_id: EVENT_ID, response_status: "DECLINED", status_reason: "bad signature" });
    expect(s.calls).toHaveLength(0);
  });

  test("missing signature or empty secret declines without calling decide", async () => {
    const s = spy(AUTHORIZED);
    const nonce = freshNonce();
    const missing = await handleRemoteAuth(request({ headers: { "x-nonce": nonce }, decide: s.decide }));
    expect(missing.body.response_status).toBe("DECLINED");
    const noSecret = await handleRemoteAuth(request({ headers: { "x-nonce": nonce, "x-signature": sign(nonce, "") }, secret: "", decide: s.decide }));
    expect(noSecret.body.response_status).toBe("DECLINED");
    expect(s.calls).toHaveLength(0);
  });

  test("signature over the body instead of the nonce is refused", async () => {
    const s = spy(AUTHORIZED);
    const nonce = freshNonce();
    const body = v2Body();
    const res = await handleRemoteAuth(request({ headers: { "x-nonce": nonce, "x-signature": sign(body) }, rawBody: body, decide: s.decide }));
    expect(res.body.response_status).toBe("DECLINED");
    expect(s.calls).toHaveLength(0);
  });

  test("stale nonce declines, in the past and in the future", async () => {
    const s = spy(AUTHORIZED);
    for (const ts of [NOW_MS - 30_001, NOW_MS + 30_001]) {
      const res = await handleRemoteAuth(request({ nonce: freshNonce(ts), decide: s.decide }));
      expect(res.body).toEqual({ card_transaction_event_id: EVENT_ID, response_status: "DECLINED", status_reason: "stale nonce" });
    }
    const edge = await handleRemoteAuth(request({ nonce: freshNonce(NOW_MS - 30_000), decide: s.decide }));
    expect(edge.body.response_status).toBe("AUTHORIZED");
    expect(s.calls).toHaveLength(1);
  });

  test("malformed nonce declines", async () => {
    const res = await handleRemoteAuth(request({ nonce: "not-a-nonce" }));
    expect(res.body.response_status).toBe("DECLINED");
  });

  test("replayed nonce declines the second time", async () => {
    const s = spy(AUTHORIZED);
    const nonces = new NonceCache();
    const nonce = freshNonce();
    const first = await handleRemoteAuth(request({ nonce, nonces, decide: s.decide }));
    expect(first.body.response_status).toBe("AUTHORIZED");
    const second = await handleRemoteAuth(request({ nonce, nonces, nowMs: NOW_MS + 5_000, decide: s.decide }));
    expect(second.body).toEqual({ card_transaction_event_id: EVENT_ID, response_status: "DECLINED", status_reason: "nonce replay" });
    expect(s.calls).toHaveLength(1);
  });

  test("an unsigned request does not burn a nonce", async () => {
    const nonces = new NonceCache();
    const nonce = freshNonce();
    await handleRemoteAuth(request({ headers: { "x-nonce": nonce, "x-signature": "AAAA" }, nonces }));
    expect(nonces.size).toBe(0);
    const res = await handleRemoteAuth(request({ nonce, nonces }));
    expect(res.body.response_status).toBe("AUTHORIZED");
  });

  test("body over 32 KiB declines without parsing and without calling decide", async () => {
    const s = spy(AUTHORIZED);
    const big = v2Body({ padding: "x".repeat(MAX_BODY_BYTES) });
    const res = await handleRemoteAuth(request({ rawBody: big, decide: s.decide }));
    expect(res.body).toEqual({ card_transaction_event_id: "", response_status: "DECLINED", status_reason: "body too large" });
    expect(s.calls).toHaveLength(0);

    const junk = await handleRemoteAuth(request({ rawBody: "{".repeat(MAX_BODY_BYTES + 1), decide: s.decide }));
    expect(junk.body).toEqual({ card_transaction_event_id: "", response_status: "DECLINED", status_reason: "body too large" });
    expect(s.calls).toHaveLength(0);
  });

  test("a single chunk past the cap is clipped to the cap plus one byte", async () => {
    const payload = new Uint8Array(MAX_BODY_BYTES * 4);
    payload.fill(0x7b);
    const req = new Request("http://127.0.0.1/remote-auth", { method: "POST", body: payload });
    const out = await readCapped(req, MAX_BODY_BYTES);
    expect(out.byteLength).toBe(MAX_BODY_BYTES + 1);
  });

  test("the listener declines an oversized body and does not call decide", async () => {
    let calls = 0;
    const server = startRaServer({
      port: 0,
      secret: SECRET,
      decide: () => {
        calls += 1;
        return AUTHORIZED;
      },
    });
    try {
      const payload = new Uint8Array(MAX_BODY_BYTES + 8);
      payload.fill(0x7b);
      const res = await fetch(`http://127.0.0.1:${server.port}/remote-auth`, { method: "POST", body: payload });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ card_transaction_event_id: "", response_status: "DECLINED", status_reason: "body too large" });
      expect(calls).toBe(0);
    } finally {
      await server.stop(true);
    }
  });

  test("decide throwing declines", async () => {
    const s = spy(() => {
      throw new Error("boom");
    });
    const res = await handleRemoteAuth(request({ decide: s.decide }));
    expect(res.body).toEqual({ card_transaction_event_id: EVENT_ID, response_status: "DECLINED", status_reason: "internal error" });
    const rejecting = await handleRemoteAuth(request({ decide: () => Promise.reject(new Error("boom")) }));
    expect(rejecting.body.response_status).toBe("DECLINED");
  });

  test("decide declining passes its reason through, truncated to 200 chars", async () => {
    const reason = `Team budget used up: $480.00 of $500.00 spent or held. ${"z".repeat(300)}`;
    const s = spy({ status: "DECLINED", code: "TEAM_POOL_EXHAUSTED", reason, writId: "writ-1" });
    const res = await handleRemoteAuth(request({ decide: s.decide }));
    expect(res.body.response_status).toBe("DECLINED");
    expect(res.body.card_transaction_event_id).toBe(EVENT_ID);
    expect(res.body.status_reason).toBe(reason.slice(0, 200));
  });

  test("decide that never answers declines on timeout", async () => {
    const res = await handleRemoteAuth(request({ decide: () => new Promise<Decision>(() => {}), decideTimeoutMs: 20 }));
    expect(res.body).toEqual({ card_transaction_event_id: EVENT_ID, response_status: "DECLINED", status_reason: "decision timed out" });
  });

  test("missing or bad fields decline without calling decide", async () => {
    const s = spy(AUTHORIZED);
    const cases: Record<string, unknown>[] = [
      { version: 1 },
      { transaction_type: "REFUND" },
      { transaction_type: undefined },
      { card_id: "" },
      { transaction_amount: undefined },
      { transaction_amount: 1.234 },
      { transaction_amount: -5 },
      { transaction_currency: undefined },
      { merchant: undefined },
      { merchant: { name: "DataCo" } },
      { merchant: { category_code: "5734" } },
    ];
    for (const over of cases) {
      const res = await handleRemoteAuth(request({ rawBody: v2Body(over), decide: s.decide }));
      expect(res.body.response_status).toBe("DECLINED");
      expect(res.body.card_transaction_event_id).toBe(EVENT_ID);
    }
    const noId = await handleRemoteAuth(request({ rawBody: v2Body({ card_transaction_event_id: undefined }), decide: s.decide }));
    expect(noId.body).toEqual({ card_transaction_event_id: "", response_status: "DECLINED", status_reason: "missing card_transaction_event_id" });
    const notJson = await handleRemoteAuth(request({ rawBody: "not json", decide: s.decide }));
    expect(notJson.body.response_status).toBe("DECLINED");
    expect(s.calls).toHaveLength(0);
  });

  test("a card number in a reason is removed from status_reason", async () => {
    const s = spy({ status: "DECLINED", code: "MERCHANT_NOT_IN_WRIT", reason: `Merchant "${"4".repeat(16)}" is not "DataCo".` });
    const res = await handleRemoteAuth(request({ decide: s.decide }));
    expect(res.body.status_reason).not.toMatch(/\d{13,19}/);
  });
});
