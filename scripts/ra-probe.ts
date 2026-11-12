// Posts four bad Remote Authorization requests. Each one must decline.
// Usage: bun run scripts/ra-probe.ts <origin>

import { createHmac, randomBytes } from "node:crypto";

function hmac(key: string, value: string): string {
  return createHmac("sha256", key).update(value, "utf8").digest("base64");
}

function nonce(ms: number): string {
  return `${ms}.${randomBytes(8).toString("hex")}`;
}

function parseOrigin(raw: string | undefined): string | undefined {
  if (raw === undefined || raw.length === 0) {
    console.error("Usage: bun run scripts/ra-probe.ts <origin>");
    return undefined;
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    console.error("Usage: bun run scripts/ra-probe.ts <origin>");
    return undefined;
  }
  if (url.username !== "" || url.password !== "") {
    console.error("Origin must not include credentials");
    return undefined;
  }
  const localHttp = url.protocol === "http:" && url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !localHttp) {
    console.error("Origin must be https://host or http://127.0.0.1:8787");
    return undefined;
  }
  if ((url.pathname !== "/" && url.pathname !== "") || url.search !== "" || url.hash !== "") {
    console.error("Pass the origin only, with no path");
    return undefined;
  }
  return url.origin;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function postCase(origin: string, label: string, headers: Record<string, string>, body: string): Promise<boolean> {
  let res: Response;
  try {
    res = await fetch(`${origin}/remote-auth`, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    console.log(`${label}: FAILED`);
    return false;
  }

  let responseStatus = "";
  try {
    const parsed: unknown = await res.json();
    if (isRecord(parsed) && typeof parsed.response_status === "string") responseStatus = parsed.response_status;
  } catch {
    responseStatus = "";
  }

  const declined = res.status === 200 && responseStatus === "DECLINED";
  const shown = declined ? "DECLINED" : res.status === 200 && responseStatus !== "" ? responseStatus : `HTTP ${res.status}`;
  console.log(`${label}: ${shown}`);
  return declined;
}

async function main(): Promise<number> {
  const secret = process.env.AIRWALLEX_RA_SHARED_SECRET;
  if (secret === undefined || secret.length === 0) {
    console.error("AIRWALLEX_RA_SHARED_SECRET is not set");
    return 1;
  }
  const origin = parseOrigin(process.argv[2]);
  if (origin === undefined) return 1;

  const body = JSON.stringify({
    version: 2,
    card_id: "card-probe",
    card_transaction_event_id: "probe-event-1",
    transaction_type: "AUTHORIZATION",
    transaction_amount: 1,
    transaction_currency: "USD",
    merchant: { name: "Probe Merchant", category_code: "5734" },
  });

  const badNonce = nonce(Date.now());
  const missingNonce = nonce(Date.now());
  const staleNonce = nonce(1_000_000_000_000);
  const bodyNonce = nonce(Date.now());
  const badKey = `${secret}.not`;

  const cases: { label: string; headers: Record<string, string> }[] = [
    { label: "bad signature", headers: { "x-nonce": badNonce, "x-signature": hmac(badKey, badNonce) } },
    { label: "missing signature", headers: { "x-nonce": missingNonce } },
    { label: "stale nonce", headers: { "x-nonce": staleNonce, "x-signature": hmac(secret, staleNonce) } },
    { label: "signature over the body", headers: { "x-nonce": bodyNonce, "x-signature": hmac(secret, body) } },
  ];

  let allDeclined = true;
  for (const item of cases) {
    const declined = await postCase(origin, item.label, item.headers, body);
    if (!declined) allDeclined = false;
  }
  return allDeclined ? 0 : 1;
}

let code = 1;
try {
  code = await main();
} catch {
  console.error("probe failed");
  code = 1;
}
process.exit(code);
