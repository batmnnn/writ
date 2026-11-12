// One live Remote Authorization check, then turn it off.
// Prints the transaction result only. Never prints the shared secret, the API key, or a card number.

import { randomUUID } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const BASE = process.env.AIRWALLEX_BASE_URL ?? "https://api.sandbox.airwallex.com";
const CLIENT = process.env.AIRWALLEX_CLIENT_ID ?? "";
const KEY = process.env.AIRWALLEX_API_KEY ?? "";
const CARD = "58da73fc-6f14-4146-861d-bb45a57e2b30";
const URL = "https://35-95-168-131.sslip.io/remote-auth";

function die(message: string): never {
  console.error(message);
  process.exit(1);
}

if (!CLIENT || !KEY) die("Airwallex client id or API key is missing");

async function login(): Promise<string> {
  const res = await fetch(`${BASE}/api/v1/authentication/login`, {
    method: "POST",
    headers: { "x-client-id": CLIENT, "x-api-key": KEY },
  });
  const body = (await res.json()) as { token?: string };
  if (!res.ok || !body.token) die(`login failed: HTTP ${res.status}`);
  return body.token;
}

async function api(token: string, method: string, path: string, body?: unknown): Promise<{ status: number; json: unknown }> {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "content-type": "application/json" }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json: unknown = undefined;
  try {
    json = text ? JSON.parse(text) : undefined;
  } catch {
    json = undefined;
  }
  return { status: res.status, json };
}

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

function saveSecret(secret: string): void {
  const path = ".env";
  const text = readFileSync(path, "utf8");
  const line = `AIRWALLEX_RA_SHARED_SECRET=${secret}`;
  const next = /^AIRWALLEX_RA_SHARED_SECRET=.*$/m.test(text)
    ? text.replace(/^AIRWALLEX_RA_SHARED_SECRET=.*$/m, line)
    : `${text.replace(/\n?$/, "\n")}${line}\n`;
  writeFileSync(path, next, { mode: 0o600 });
}

function printRemote(tx: unknown): void {
  const row = asRecord(tx);
  const ra = asRecord(row?.remote_auth);
  const status = typeof row?.status === "string" ? row.status : typeof row?.process_result === "string" ? row.process_result : "";
  const reason = typeof row?.failure_reason === "string" ? row.failure_reason : "";
  console.log(`transaction status=${status || "none"} failure_reason=${reason || "none"}`);
  if (!ra) {
    console.log("remote_auth absent");
    return;
  }
  const used = ra.default_action_used === true ? "true" : ra.default_action_used === false ? "false" : "absent";
  const response = typeof ra.response_status === "string" ? ra.response_status : "";
  const why = typeof ra.status_reason === "string" ? ra.status_reason : "";
  console.log(`remote_auth default_action_used=${used} response_status=${response || "none"} status_reason=${why || "none"}`);
}

async function main(): Promise<number> {
  const token = await login();
  let secretSaved = false;
  try {
    const turned = await api(token, "POST", "/api/v1/issuing/config/update", {
      remote_auth: { enabled: true, url: URL, default_action: "DECLINED", version: 2 },
    });
    if (turned.status !== 200 && turned.status !== 201) die(`config update failed: HTTP ${turned.status}`);
    secretSaved = true;
    console.log("remote auth enabled");

    const armed = await api(token, "POST", `/api/v1/issuing/cards/${CARD}/update`, {
      request_id: randomUUID(),
      card_status: "ACTIVE",
      authorization_controls: {
        allowed_currencies: ["USD"],
        allowed_merchant_categories: ["5734"],
        transaction_limits: {
          currency: "USD",
          limits: [
            { amount: 1, interval: "PER_TRANSACTION" },
            { amount: 50, interval: "ALL_TIME" },
          ],
        },
      },
    });
    console.log(`card arm HTTP ${armed.status}`);
    const sim = await api(token, "POST", "/api/v1/simulation/issuing/create", {
      card_id: CARD,
      transaction_amount: 1,
      transaction_currency: "USD",
      merchant_category_code: "5734",
      merchant_info: "DataCo",
    });
    printRemote(sim.json);
    const ra = asRecord(asRecord(sim.json)?.remote_auth);
    const frozen = await api(token, "POST", `/api/v1/issuing/cards/${CARD}/update`, {
      request_id: randomUUID(),
      card_status: "INACTIVE",
    });
    console.log(`card freeze HTTP ${frozen.status}`);
    if (!ra) {
      const listed = await api(token, "GET", `/api/v1/issuing/transactions?card_id=${CARD}`);
      const items = asRecord(listed.json)?.items;
      const first = Array.isArray(items) ? items[0] : undefined;
      console.log("latest stored transaction:");
      printRemote(first);
    }
    return 0;
  } finally {
    const off = await api(token, "POST", "/api/v1/issuing/config/update", {
      remote_auth: { enabled: false, url: URL, default_action: "DECLINED", version: 2 },
    });
    const enabled = asRecord(asRecord(off.json)?.remote_auth_settings)?.enabled;
    console.log(`remote auth disabled HTTP ${off.status} enabled=${enabled === true ? "true" : "false"} secret_saved=${secretSaved ? "yes" : "no"}`);
  }
}

process.exit(await main());
