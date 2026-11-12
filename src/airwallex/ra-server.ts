// Remote Authorization endpoint. Airwallex POSTs each card authorization here and waits up to 2.5 s.
// Order: size cap, signature over x-nonce, nonce window, nonce replay, then parse the body and call decide.
// Every doubt answers DECLINED with HTTP 200, so Airwallex records our decline instead of falling back.
// No network, no .env: the caller injects the shared secret, the clock and decide.

import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import type { Decision, DecisionInput } from "../types";
import { redactString } from "./redact";
import { majorToMinor } from "./units";

export const RA_PATH = "/remote-auth";
export const MAX_BODY_BYTES = 32 * 1024;
export const NONCE_WINDOW_MS = 30_000;
export const DEFAULT_DECIDE_TIMEOUT_MS = 2_000;
const MAX_REASON_CHARS = 200;
const MAX_EVENT_ID_CHARS = 128;
const MAX_NONCE_CHARS = 512;
const NONCE_FORMAT = /^(\d{10,16})\.(\S{1,256})$/;
const SWIPE_TYPES = new Set(["AUTHORIZATION", "CLEARING"]);

export interface RaResponse {
  card_transaction_event_id: string;
  response_status: "AUTHORIZED" | "DECLINED";
  status_reason: string;
}

/** eventId is the Airwallex card_transaction_event_id, used by Gate for idempotency. */
export type RaDecide = (input: DecisionInput, eventId: string) => Decision | Promise<Decision>;

export type RaHeaders = Headers | Record<string, string | undefined>;

export interface RaRequest {
  headers: RaHeaders;
  rawBody: Uint8Array | string;
  nowMs: number;
  secret: string;
  decide: RaDecide;
  nonces: NonceCache;
  decideTimeoutMs?: number;
}

export interface RaResult {
  status: 200;
  body: RaResponse;
}

/** Seen nonces inside the window. Entries older than the window can be dropped: they fail the window check. */
export class NonceCache {
  private readonly seen = new Map<string, number>();
  private lastPruneMs = Number.NEGATIVE_INFINITY;

  constructor(
    private readonly windowMs = NONCE_WINDOW_MS,
    private readonly maxEntries = 100_000,
  ) {}

  /** Records the nonce. Returns "replay" if seen, "full" if the cache cannot take more. */
  remember(nonce: string, tsMs: number, nowMs: number): "fresh" | "replay" | "full" {
    this.prune(nowMs);
    if (this.seen.has(nonce)) return "replay";
    if (this.seen.size >= this.maxEntries) {
      this.prune(nowMs, true);
      if (this.seen.size >= this.maxEntries) return "full";
    }
    this.seen.set(nonce, tsMs);
    return "fresh";
  }

  get size(): number {
    return this.seen.size;
  }

  private prune(nowMs: number, force = false): void {
    if (!force && nowMs - this.lastPruneMs < 1_000) return;
    this.lastPruneMs = nowMs;
    for (const [nonce, ts] of this.seen) {
      if (ts < nowMs - this.windowMs) this.seen.delete(nonce);
    }
  }
}

/** Handles one Remote Authorization request. Never throws, never answers AUTHORIZED unless decide did. */
export async function handleRemoteAuth(req: RaRequest): Promise<RaResult> {
  let eventId = "";
  try {
    const raw = typeof req.rawBody === "string" ? new TextEncoder().encode(req.rawBody) : req.rawBody;

    // Do not parse an oversized body. It has not been authenticated, and a mismatched event id
    // makes Airwallex apply default_action, which we set to DECLINED.
    if (raw.byteLength > MAX_BODY_BYTES) return declined("", "body too large");

    const nonce = header(req.headers, "x-nonce");
    const signature = header(req.headers, "x-signature");
    if (!signatureValid(req.secret, nonce, signature)) {
      eventId = echoId(tryParse(raw));
      return declined(eventId, "bad signature");
    }

    // Signature is good, but it does not cover the body. The body is parsed only from here on.
    const body = tryParse(raw);
    eventId = echoId(body);

    const m = NONCE_FORMAT.exec(nonce as string);
    const tsMs = m ? Number(m[1]) : Number.NaN;
    if (!Number.isSafeInteger(tsMs) || !Number.isFinite(req.nowMs) || Math.abs(req.nowMs - tsMs) > NONCE_WINDOW_MS) {
      return declined(eventId, "stale nonce");
    }
    const seen = req.nonces.remember(nonce as string, tsMs, req.nowMs);
    if (seen === "replay") return declined(eventId, "nonce replay");
    if (seen === "full") return declined(eventId, "nonce cache full");

    if (eventId === "") return declined(eventId, "missing card_transaction_event_id");
    const mapped = toDecisionInput(body, req.nowMs);
    if (typeof mapped === "string") return declined(eventId, mapped);

    const decision = await withTimeout(
      Promise.resolve().then(() => req.decide(mapped, eventId)),
      req.decideTimeoutMs ?? DEFAULT_DECIDE_TIMEOUT_MS,
    );
    if (decision === undefined) return declined(eventId, "decision timed out");
    const reason = typeof decision.reason === "string" ? decision.reason : "";
    if (decision.status === "AUTHORIZED") return reply(eventId, "AUTHORIZED", reason);
    return declined(eventId, reason || "declined");
  } catch {
    return declined(eventId, "internal error");
  }
}

function reply(eventId: string, status: RaResponse["response_status"], reason: string): RaResult {
  return {
    status: 200,
    body: {
      card_transaction_event_id: eventId,
      response_status: status,
      status_reason: redactString(reason).slice(0, MAX_REASON_CHARS),
    },
  };
}

const declined = (eventId: string, reason: string): RaResult => reply(eventId, "DECLINED", reason);

function header(headers: RaHeaders, name: string): string | undefined {
  if (headers instanceof Headers) return headers.get(name) ?? undefined;
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === name && typeof v === "string") return v;
  }
  return undefined;
}

/** base64(HMAC_SHA256(secret, nonce)). The body is not signed. Compared in constant time. */
function signatureValid(secret: string, nonce: string | undefined, signature: string | undefined): boolean {
  if (typeof secret !== "string" || secret.length === 0) return false;
  if (!nonce || !signature || nonce.length > MAX_NONCE_CHARS || signature.length > MAX_NONCE_CHARS) return false;
  const expected = createHmac("sha256", secret).update(nonce, "utf8").digest("base64");
  // Hash both sides so the compare is equal length and leaks nothing about the signature length.
  const a = createHash("sha256").update(signature.trim(), "utf8").digest();
  const b = createHash("sha256").update(expected, "utf8").digest();
  return timingSafeEqual(a, b);
}

function tryParse(raw: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  } catch {
    return undefined;
  }
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

function echoId(body: unknown): string {
  if (!isRecord(body)) return "";
  const id = body.card_transaction_event_id;
  return typeof id === "string" && id.length > 0 && id.length <= MAX_EVENT_ID_CHARS ? id : "";
}

const nonEmpty = (v: unknown): v is string => typeof v === "string" && v.trim().length > 0;

/** Version 2 payload to DecisionInput. Returns a decline reason string when a field is missing or wrong. */
function toDecisionInput(body: unknown, nowMs: number): DecisionInput | string {
  if (!isRecord(body)) return "body is not a JSON object";
  if (body.version !== 2) return "payload version is not 2";
  if (typeof body.transaction_type !== "string" || !SWIPE_TYPES.has(body.transaction_type)) {
    return "unsupported transaction_type";
  }
  if (!nonEmpty(body.card_id)) return "missing card_id";
  const amountMinor = majorToMinor(body.transaction_amount);
  if (amountMinor === undefined || amountMinor <= 0) return "missing or bad transaction_amount";
  if (!nonEmpty(body.transaction_currency)) return "missing transaction_currency";
  const merchant = body.merchant;
  if (!isRecord(merchant)) return "missing merchant";
  if (!nonEmpty(merchant.category_code)) return "missing merchant.category_code";
  if (!nonEmpty(merchant.name)) return "missing merchant.name";
  return {
    mode: "ra",
    cardId: body.card_id,
    amountMinor,
    currency: body.transaction_currency,
    mcc: merchant.category_code,
    merchantName: merchant.name,
    now: new Date(nowMs).toISOString(),
    ra: { signatureValid: true, nonceFresh: true, nonceSeen: false },
  };
}

/** Resolves undefined on timeout. A late AUTHORIZED is ignored: the reply already said DECLINED. A late rejection is swallowed. */
async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T | undefined> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const observed = p.then(
    (value) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, error }),
  );
  const timeout = new Promise<undefined>((resolve) => {
    timer = setTimeout(() => resolve(undefined), ms);
  });
  try {
    const raced = await Promise.race([observed, timeout]);
    if (raced === undefined) return undefined;
    if (!raced.ok) throw raced.error;
    return raced.value;
  } finally {
    clearTimeout(timer);
  }
}

/** Reads at most limit + 1 bytes. A chunk past the cap is clipped, then the stream is cancelled. */
export async function readCapped(req: Request, limit: number): Promise<Uint8Array> {
  if (!req.body) return new Uint8Array(0);
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (total <= limit) {
      const { done, value } = await reader.read();
      if (done) break;
      const room = limit + 1 - total;
      if (value.byteLength > room) {
        chunks.push(value.subarray(0, room));
        total += room;
        break;
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

export interface RaServerOptions {
  port: number;
  secret: string;
  decide: RaDecide;
  now?: () => number;
  nonces?: NonceCache;
  decideTimeoutMs?: number;
}

/** Binds 127.0.0.1 only. TLS ends at the tunnel in front of it. The secret is never logged. */
export function startRaServer(opts: RaServerOptions): ReturnType<typeof Bun.serve> {
  const nonces = opts.nonces ?? new NonceCache();
  const now = opts.now ?? Date.now;
  return Bun.serve({
    hostname: "127.0.0.1",
    port: opts.port,
    async fetch(request) {
      const url = new URL(request.url);
      if (url.pathname !== RA_PATH) return new Response("not found", { status: 404 });
      if (request.method !== "POST") return new Response("method not allowed", { status: 405 });
      let result: RaResult;
      try {
        const rawBody = await readCapped(request, MAX_BODY_BYTES);
        const handled: RaRequest = { headers: request.headers, rawBody, nowMs: now(), secret: opts.secret, decide: opts.decide, nonces };
        if (opts.decideTimeoutMs !== undefined) handled.decideTimeoutMs = opts.decideTimeoutMs;
        result = await handleRemoteAuth(handled);
      } catch {
        result = declined("", "internal error");
      }
      return Response.json(result.body, { status: result.status });
    },
  });
}
