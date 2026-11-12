// Minor units (cents) inside Writ, major units on the Airwallex wire. Conversion lives here only.
// Both directions go through decimal strings, so no binary float math touches an amount.

import { isMinor } from "../core/money";

/** 18000 -> 180, 18050 -> 180.5, 1 -> 0.01. Returns undefined for anything that is not an integer. */
export function minorToMajor(minor: number): number | undefined {
  if (!isMinor(minor)) return undefined;
  const sign = minor < 0 ? "-" : "";
  const abs = Math.abs(minor);
  const whole = Math.floor(abs / 100);
  const cents = abs % 100;
  return Number(`${sign}${whole}.${String(cents).padStart(2, "0")}`);
}

/** 180.5 -> 18050. Refuses more than 2 decimals, exponent forms and non numbers. */
export function majorToMinor(major: unknown): number | undefined {
  if (typeof major !== "number" && typeof major !== "string") return undefined;
  const text = String(major).trim();
  const m = /^(-?)(\d+)(?:\.(\d{1,2}))?$/.exec(text);
  if (!m) return undefined;
  const whole = Number(m[2]);
  const cents = Number((m[3] ?? "").padEnd(2, "0"));
  const minor = whole * 100 + cents;
  if (!Number.isSafeInteger(minor)) return undefined;
  return m[1] === "-" ? -minor : minor;
}
