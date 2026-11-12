// Merchant names compare case and spacing insensitive. Airwallex pads names with trailing underscores.

export function normalizeMerchant(name: string): string {
  return name.normalize("NFKC").trim().replace(/_+$/, "").trim().replace(/\s+/g, " ").toUpperCase();
}
