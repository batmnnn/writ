// Creates one sandbox virtual card per baked agent and writes the card ids into enclave/config/serve.json.
// Runs on the Mac with .env (AIRWALLEX_CLIENT_ID, AIRWALLEX_API_KEY). Sandbox only.
// Usage: bun run scripts/make-serve-cards.ts
//
// Every card is set INACTIVE right after create and read back to confirm. Output is agent, card id and
// last 4 only. The PAN, CVV, token and API key are never printed or stored. An agent that already has a
// card in serve.json keeps it: the script only checks that card is INACTIVE.
// Optional WRIT_CARDHOLDER_ID reuses a cardholder instead of creating one.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { AirwallexClient } from "../src/airwallex/client";
import { last4 } from "../src/airwallex/redact";
import { RestAdapter } from "../src/airwallex/rest-adapter";
import type { AdapterError } from "../src/types";

const root = join(import.meta.dir, "..");
const servePath = join(root, "enclave", "config", "serve.json");

export const SERVE_TEAMS = [
  { team: "research", poolLimitMinor: 50_000 },
  { team: "ops", poolLimitMinor: 1_000_000 },
] as const;

export const SERVE_AGENTS = [
  { team: "research", agent: "research-1" },
  { team: "research", agent: "research-2" },
  { team: "research", agent: "research-3" },
  { team: "research", agent: "research-agent" },
  { team: "ops", agent: "ops-1" },
] as const;

interface ServeCard {
  cardId: string;
  team: string;
  agent: string;
  last4?: string;
}

const failText = (e: AdapterError) => `${e.kind}${e.status !== undefined ? ` HTTP ${e.status}` : ""}${e.code ? ` ${e.code}` : ""}: ${e.message}`;

async function main(): Promise<number> {
  const baseUrl = process.env.AIRWALLEX_BASE_URL ?? "https://api.sandbox.airwallex.com";
  const client = new AirwallexClient({
    baseUrl,
    clientId: process.env.AIRWALLEX_CLIENT_ID ?? "",
    apiKey: process.env.AIRWALLEX_API_KEY ?? "",
    log: () => undefined,
  });
  if (client.configProblem) {
    console.error(`Refusing: ${client.configProblem.message}`);
    return 1;
  }
  const adapter = new RestAdapter({ client, mode: "frozen", createdBy: "Writ" });

  const serve = JSON.parse(readFileSync(servePath, "utf8")) as Record<string, unknown> & { cards?: ServeCard[] };
  const existing = new Map<string, ServeCard>();
  for (const c of Array.isArray(serve.cards) ? serve.cards : []) existing.set(`${c.team}/${c.agent}`, c);

  let cardholderId = process.env.WRIT_CARDHOLDER_ID ?? "";
  const cards: ServeCard[] = [];
  let failed = false;
  for (const a of SERVE_AGENTS) {
    const known = existing.get(`${a.team}/${a.agent}`);
    if (known) {
      cards.push(known);
      continue;
    }
    if (cardholderId === "") {
      const ch = await adapter.createCardholder("Writ Agents");
      if (!ch.ok) {
        console.error(`cardholder create failed: ${failText(ch.error)}`);
        return 1;
      }
      cardholderId = ch.value.cardholderId;
    }
    const made = await adapter.createAgentCard({ cardholderId, team: a.team, agent: a.agent });
    if (!made.ok) {
      console.error(`${a.agent}: card create failed: ${failText(made.error)}`);
      failed = true;
      continue;
    }
    const card: ServeCard = { cardId: made.value.cardId, team: a.team, agent: a.agent };
    if (made.value.last4) card.last4 = made.value.last4;
    cards.push(card);
  }

  serve.teams = SERVE_TEAMS.map((t) => ({ ...t }));
  serve.cards = cards;
  writeFileSync(servePath, `${JSON.stringify(serve, null, 2)}\n`);

  for (const c of cards) {
    const g = await adapter.getCard(c.cardId);
    if (!g.ok) {
      console.error(`${c.agent}: card read failed: ${failText(g.error)}`);
      failed = true;
      continue;
    }
    let status = typeof g.value.card_status === "string" ? g.value.card_status : "?";
    if (status !== "INACTIVE") {
      const off = await adapter.disarm(c.cardId);
      status = off.ok ? "INACTIVE" : `${status} (freeze failed: ${failText(off.error)})`;
      if (!off.ok) failed = true;
    }
    const mask = c.last4 ?? last4(g.value.masked_card_number);
    if (mask && !c.last4) c.last4 = mask;
    console.log(`${c.agent} ${c.cardId} last4 ${mask ?? "????"} ${status}`);
  }
  writeFileSync(servePath, `${JSON.stringify(serve, null, 2)}\n`);
  return failed ? 1 : 0;
}

if (import.meta.main) process.exit(await main());
