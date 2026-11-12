import type { IsoTime } from "../types";

/** Milliseconds since epoch, or NaN when the string is not a full ISO 8601 time with an offset or Z. */
export function parseIso(iso: IsoTime | undefined): number {
  if (typeof iso !== "string") return Number.NaN;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})$/.test(iso)) return Number.NaN;
  return Date.parse(iso.replace(/([+-]\d{2})(\d{2})$/, "$1:$2"));
}
