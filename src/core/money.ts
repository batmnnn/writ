// Integer minor units only. Formatting is for reason strings and the console.

export const isMinor = (n: unknown): n is number => typeof n === "number" && Number.isSafeInteger(n);

export const isPositiveMinor = (n: unknown): n is number => isMinor(n) && n > 0;

/** 48050 -> "$480.50", 48000 -> "$480", -1500 -> "-$15". */
export function formatMinor(minor: number): string {
  if (!isMinor(minor)) return "$?";
  const sign = minor < 0 ? "-" : "";
  const abs = Math.abs(minor);
  const dollars = Math.floor(abs / 100).toLocaleString("en-US");
  const cents = abs % 100;
  return cents === 0 ? `${sign}$${dollars}` : `${sign}$${dollars}.${String(cents).padStart(2, "0")}`;
}
