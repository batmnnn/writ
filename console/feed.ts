// Shared console event types and sanitizer. No PANs, keys, or signatures on the wire.

export const CONSOLE_EVENT_KINDS = [
  "reset",
  "log",
  "decision",
  "approval",
  "pool",
  "reserve",
  "taint",
  "swipe",
  "final",
  "done",
] as const;

export type ConsoleEventKind = (typeof CONSOLE_EVENT_KINDS)[number];

export interface ApprovalView {
  team: string;
  agent: string;
  purpose: string;
  merchantName: string;
  mcc: string;
  amountMinor: number;
  currency: string;
  expiresAt: string;
  approvedAt: string;
  approvedBy: "auto" | "human";
  hash: string;
  signatureValid: boolean;
}

export interface FinalRow {
  scene: string;
  agent: string;
  task: string;
  amount: string;
  result: string;
  reason: string;
}

export type ConsoleEvent =
  | { kind: "reset"; at: string; mode: "frozen"; replay: boolean }
  | { kind: "log"; at: string; scene: string; text: string }
  | {
      kind: "decision";
      at: string;
      scene: string;
      status: "AUTHORIZED" | "DECLINED";
      code: string;
      reason: string;
      writId?: string;
    }
  | { kind: "approval"; at: string; scene: string; approval: ApprovalView }
  | {
      kind: "pool";
      at: string;
      team: string;
      poolLimitMinor: number;
      reservedMinor: number;
      pendingMinor: number;
      settledMinor: number;
      releasedMinor: number;
    }
  | {
      kind: "reserve";
      at: string;
      liveBalanceMinor: number;
      ringFenceMinor: number;
      reserveFloorMinor: number;
      openReservationsMinor: number;
      simulated?: boolean;
    }
  | { kind: "taint"; at: string; source: string }
  | { kind: "swipe"; at: string; scene: string; accepted: boolean; reason: string; cardLast4?: string }
  | { kind: "final"; at: string; rows: FinalRow[]; ok: boolean }
  | { kind: "done"; at: string; ok: boolean };

const SECRET_KEY =
  /^(card_number|pan|cvv|cvc|cvv2|pin|token|access_token|refresh_token|api_key|x-api-key|authorization|secret|shared_secret|signature|private_key|privatekey|privatekeypem|apikey)$/i;
const DIGIT_RUN = /\d{13,19}/g;
const KIND_SET = new Set<string>(CONSOLE_EVENT_KINDS);

export function sanitizeText(s: string): string {
  return s.replace(DIGIT_RUN, "[digits removed]");
}

export function sanitizeValue(value: unknown): unknown {
  if (typeof value === "string") return sanitizeText(value);
  if (typeof value === "number") {
    return Number.isInteger(value) && /^-?\d{13,19}$/.test(String(value)) ? "[digits removed]" : value;
  }
  if (Array.isArray(value)) return value.map(sanitizeValue);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = SECRET_KEY.test(k) ? "[removed]" : sanitizeValue(v);
    }
    return out;
  }
  return value;
}

export function sanitizeEvent(raw: unknown): ConsoleEvent | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const kind = (raw as { kind?: unknown }).kind;
  if (typeof kind !== "string" || !KIND_SET.has(kind)) return undefined;
  return sanitizeValue(raw) as ConsoleEvent;
}

export function defaultConsoleUrl(): string {
  const raw = process.env.WRIT_CONSOLE_URL ?? "http://127.0.0.1:3000";
  return raw.replace(/\/$/, "");
}

export function isConsoleUrl(url: string, base: string): boolean {
  return url === base || url.startsWith(`${base}/`);
}

export type FeedEvent = {
  [K in ConsoleEventKind]: Omit<Extract<ConsoleEvent, { kind: K }>, "at"> & { at?: string };
}[ConsoleEventKind];

export interface Feed {
  url: string;
  up: () => boolean;
  ping: () => Promise<boolean>;
  emit: (event: FeedEvent) => Promise<void>;
}

export function makeEmitter(opts: { url: string; fetchImpl: typeof fetch }): Feed {
  let up = false;
  const fetchImpl = opts.fetchImpl;
  const url = opts.url.replace(/\/$/, "");

  const ping = async (): Promise<boolean> => {
    try {
      const r = await fetchImpl(`${url}/health`, { signal: AbortSignal.timeout(200) });
      up = r.ok;
    } catch {
      up = false;
    }
    return up;
  };

  const emit = async (event: FeedEvent): Promise<void> => {
    if (!up) return;
    const at = event.at ?? new Date().toISOString();
    const body = sanitizeEvent({ ...event, at });
    if (!body) return;
    try {
      await fetchImpl(`${url}/ingest`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(400),
      });
    } catch {
      up = false;
    }
  };

  return { url, up: () => up, ping, emit };
}
