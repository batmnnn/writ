// In-enclave Airwallex session, live balance and clock.
// The balance and the time used for every decision come from Airwallex responses read here, over the
// loopback bridge in enclave/boot.sh, so TLS ends inside the enclave. The host cannot supply either.
// Time: the Date header of the balance response, advanced by the monotonic clock until the next good poll.
// The wall clock of this machine is never read, and nothing here logs. The token and the API key never leave this file.

import { majorToMinor } from "../airwallex/units";
import type { IsoTime } from "../types";

export const AIRWALLEX_BASE = "https://api.sandbox.airwallex.com";
export const LOGIN_URL = `${AIRWALLEX_BASE}/api/v1/authentication/login`;
export const BALANCE_URL = `${AIRWALLEX_BASE}/api/v1/balances/current`;
export const BALANCE_POLL_MS = 10_000;
/** Airwallex tokens last 30 minutes. Refresh well before that. */
const TOKEN_TTL_MS = 20 * 60_000;
const FETCH_TIMEOUT_MS = 5_000;
const MAX_BODY_CHARS = 256 * 1024;

export interface HttpInit {
  method: string;
  headers: Record<string, string>;
  body?: string;
}
export interface HttpReply {
  status: number;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
}
export type HttpFetch = (url: string, init: HttpInit) => Promise<HttpReply>;

/** Real fetch with a time limit and no redirects. */
export const enclaveHttpFetch: HttpFetch = async (url, init) => {
  const res = await fetch(url, { ...init, redirect: "error", signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  return { status: res.status, headers: res.headers, text: () => res.text() };
};

/** Same shape as LiveBalance in src/core/gate.ts. at is the Airwallex Date header of the response. */
export interface BalanceObservation {
  amountMinor: number;
  at: IsoTime;
}

const monotonic = () => performance.now();
const ok2xx = (status: number) => status >= 200 && status < 300;

const IMF_FIXDATE = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/;

/** An HTTP Date header (IMF-fixdate) as an ISO string. Missing or any other form is undefined. */
export function dateHeaderIso(value: string | null | undefined): IsoTime | undefined {
  if (typeof value !== "string" || !IMF_FIXDATE.test(value.trim())) return undefined;
  const ms = Date.parse(value.trim());
  return Number.isFinite(ms) ? new Date(ms).toISOString() : undefined;
}

/** The single USD row's available_amount in minor units. No row, two USD rows, or a bad amount is undefined. */
export function usdAvailableMinor(body: unknown): number | undefined {
  if (!Array.isArray(body)) return undefined;
  const rows = body.filter((r) => typeof r === "object" && r !== null && (r as { currency?: unknown }).currency === "USD");
  if (rows.length !== 1) return undefined;
  const minor = majorToMinor((rows[0] as { available_amount?: unknown }).available_amount);
  return minor !== undefined && minor >= 0 ? minor : undefined;
}

/** Holds the unsealed API key and a cached bearer token. zero() wipes both. */
export class AirwallexSession {
  private cached: { token: string; until: number } | undefined;
  private zeroed = false;

  constructor(
    private readonly key: Uint8Array,
    private readonly clientId: string,
    private readonly fetch: HttpFetch,
    private readonly mono: () => number = monotonic,
  ) {}

  /** Why the last login gave no token: NO_CLIENT_ID, LOGIN_HTTP_<status>, LOGIN_BAD_REPLY or LOGIN_FAILED. Codes only. */
  lastError: string | undefined;

  async token(): Promise<string | undefined> {
    if (this.zeroed) return undefined;
    if (this.clientId.length === 0) {
      this.lastError = "NO_CLIENT_ID";
      return undefined;
    }
    if (this.cached && this.mono() < this.cached.until) return this.cached.token;
    this.cached = undefined;
    const keyBuf = Buffer.from(this.key);
    try {
      const res = await this.fetch(LOGIN_URL, { method: "POST", headers: { "x-client-id": this.clientId, "x-api-key": keyBuf.toString("utf8") } });
      const text = await res.text();
      if (!ok2xx(res.status)) {
        this.lastError = `LOGIN_HTTP_${res.status}`;
        return undefined;
      }
      if (text.length > MAX_BODY_CHARS) {
        this.lastError = "LOGIN_BAD_REPLY";
        return undefined;
      }
      const token = (JSON.parse(text) as { token?: unknown }).token;
      if (typeof token !== "string" || token.length === 0 || this.zeroed) {
        this.lastError = "LOGIN_BAD_REPLY";
        return undefined;
      }
      this.cached = { token, until: this.mono() + TOKEN_TTL_MS };
      this.lastError = undefined;
      return token;
    } catch {
      this.lastError = "LOGIN_FAILED";
      return undefined;
    } finally {
      keyBuf.fill(0);
    }
  }

  invalidate(): void {
    this.cached = undefined;
  }

  zero(): void {
    this.zeroed = true;
    this.cached = undefined;
    this.key.fill(0);
  }
}

export interface TimerHandle {
  stop(): void;
}
export type SetTimer = (fn: () => void, ms: number) => TimerHandle;

const intervalTimer: SetTimer = (fn, ms) => {
  const t = setInterval(fn, ms);
  return { stop: () => clearInterval(t) };
};

export interface PollerOptions {
  session: Pick<AirwallexSession, "token" | "invalidate">;
  fetch: HttpFetch;
  /** Default 10 s. */
  intervalMs?: number;
  /** The caller owns the timer. Default setInterval. */
  setTimer?: SetTimer;
  mono?: () => number;
  /** Called with each good observation. */
  onObservation?: (obs: BalanceObservation) => void;
}

/**
 * Reads the USD balance on a timer. A failed poll keeps the last good observation, and the clock keeps
 * running from its last Date header, so an old observation goes stale. No good poll yet means latest()
 * and now() are both undefined.
 */
export class BalancePoller {
  private observation: BalanceObservation | undefined;
  private anchor: { atMs: number; mono: number } | undefined;
  private timer: TimerHandle | undefined;
  private inFlight: Promise<boolean> | undefined;
  private readonly mono: () => number;
  private err: string | undefined;
  private polls = 0;
  private good = 0;

  constructor(private readonly opts: PollerOptions) {
    this.mono = opts.mono ?? monotonic;
  }

  latest(): BalanceObservation | undefined {
    return this.observation ? { ...this.observation } : undefined;
  }

  /** Last Airwallex Date header plus the monotonic time since that response. NaN before the first good poll. */
  nowMs(): number {
    if (!this.anchor) return Number.NaN;
    return this.anchor.atMs + Math.max(0, this.mono() - this.anchor.mono);
  }

  now(): IsoTime | undefined {
    const ms = this.nowMs();
    return Number.isFinite(ms) ? new Date(ms).toISOString() : undefined;
  }

  pollOnce(): Promise<boolean> {
    if (!this.inFlight) {
      this.inFlight = this.poll().finally(() => {
        this.inFlight = undefined;
      });
    }
    return this.inFlight;
  }

  /** First poll, awaited, then the timer. */
  async start(): Promise<boolean> {
    const first = await this.pollOnce();
    if (!this.timer) {
      this.timer = (this.opts.setTimer ?? intervalTimer)(() => {
        void this.pollOnce();
      }, this.opts.intervalMs ?? BALANCE_POLL_MS);
    }
    return first;
  }

  stop(): void {
    this.timer?.stop();
    this.timer = undefined;
  }

  /** Code for the last failed poll, cleared by a good one. No body, header or token ever goes in it. */
  get lastError(): string | undefined {
    return this.err;
  }

  /** Polls done and polls that gave an observation, since start. */
  get counts(): { polls: number; good: number } {
    return { polls: this.polls, good: this.good };
  }

  private async poll(): Promise<boolean> {
    this.polls += 1;
    const fail = (code: string) => {
      this.err = code;
      return false;
    };
    try {
      const token = await this.opts.session.token();
      if (token === undefined) return fail((this.opts.session as { lastError?: string }).lastError ?? "NO_TOKEN");
      const res = await this.opts.fetch(BALANCE_URL, { method: "GET", headers: { authorization: `Bearer ${token}` } });
      const mono = this.mono();
      const text = await res.text();
      if (res.status === 401) this.opts.session.invalidate();
      if (!ok2xx(res.status)) return fail(`BALANCE_HTTP_${res.status}`);
      if (text.length > MAX_BODY_CHARS) return fail("BALANCE_TOO_LARGE");
      const at = dateHeaderIso(res.headers.get("date"));
      if (at === undefined) return fail("NO_DATE_HEADER");
      const amountMinor = usdAvailableMinor(JSON.parse(text));
      if (amountMinor === undefined) return fail("NO_USD_BALANCE");
      const atMs = Date.parse(at);
      if (this.anchor && atMs < this.anchor.atMs) return fail("CLOCK_WENT_BACK");
      this.observation = { amountMinor, at };
      this.anchor = { atMs, mono };
      this.err = undefined;
      this.good += 1;
      this.opts.onObservation?.({ amountMinor, at });
      return true;
    } catch {
      return fail("BALANCE_FETCH_FAILED");
    }
  }
}
