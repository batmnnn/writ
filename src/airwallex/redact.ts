// Strip anything card-number-like or secret-like before a response is logged, returned as raw,
// or written to fixtures/. A 13 to 19 digit run is treated as a possible PAN and removed.

const SECRET_KEY = /^(card_number|pan|cvv|cvc|cvv2|pin|token|access_token|refresh_token|api_key|x-api-key|authorization|secret|shared_secret|.*_secret)$/i;
const DIGIT_RUN = /\d{13,19}/g;
export const DIGITS_REMOVED = "[digits removed]";

export function redactString(s: string): string {
  return s.replace(DIGIT_RUN, DIGITS_REMOVED);
}

export function redact(value: unknown): unknown {
  if (typeof value === "string") return redactString(value);
  if (typeof value === "number") {
    return Number.isInteger(value) && /^-?\d{13,19}$/.test(String(value)) ? DIGITS_REMOVED : value;
  }
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = SECRET_KEY.test(k) ? "[removed]" : redact(v);
    }
    return out;
  }
  return value;
}

/** Last 4 of a masked or full card number, never more. */
export function last4(masked: unknown): string | undefined {
  if (typeof masked !== "string") return undefined;
  const digits = masked.replace(/\D/g, "");
  return digits.length >= 4 ? digits.slice(-4) : undefined;
}
