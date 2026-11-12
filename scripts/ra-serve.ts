// Local Remote Authorization listener for the bad-signature probe.
// decide() always declines. This process does not arm a card.

import { startRaServer } from "../src/airwallex/ra-server";
import type { Decision } from "../src/types";

const secret = process.env.AIRWALLEX_RA_SHARED_SECRET;
if (secret === undefined || secret.length === 0) {
  console.error("AIRWALLEX_RA_SHARED_SECRET is not set");
  process.exit(1);
}

function listenPort(): number {
  const raw = process.env.WRIT_RA_PORT;
  if (raw === undefined || raw.length === 0) return 8787;
  if (!/^[0-9]+$/.test(raw)) {
    console.error("WRIT_RA_PORT is not a port number");
    process.exit(1);
  }
  const port = Number(raw);
  if (port < 1 || port > 65535) {
    console.error("WRIT_RA_PORT is not a port number");
    process.exit(1);
  }
  return port;
}

const decide = (): Decision => ({
  status: "DECLINED",
  code: "NO_WRIT_FOR_CARD",
  reason: "No writ for this card.",
});

const server = startRaServer({ port: listenPort(), secret, decide });
const bound = server.port;
if (bound === undefined) {
  console.error("RA server failed to bind");
  process.exit(1);
}
console.log(`RA server listening on 127.0.0.1:${bound}`);
