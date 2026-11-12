import { describe, expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { startRaServer } from "../src/airwallex/ra-server";
import type { Decision } from "../src/types";

const emDash = "\u2014";

function source(name: string): string {
  return readFileSync(join(import.meta.dir, "..", name), "utf8");
}

describe("ra serve and probe", () => {
  test("ra-serve.ts and ra-probe.ts do not call config/update and have no em dash", () => {
    for (const name of ["scripts/ra-serve.ts", "scripts/ra-probe.ts"]) {
      const text = source(name);
      expect(text.includes("config/update")).toBe(false);
      expect(text.includes(emDash)).toBe(false);
    }
  });

  test("a bad signature on an ephemeral server is HTTP 200 and DECLINED", async () => {
    const secret = "serve-test-secret";
    const decide = (): Decision => ({
      status: "AUTHORIZED",
      writId: "writ-probe",
      reason: "should not be reached",
    });
    const server = startRaServer({ port: 0, secret, decide });
    try {
      const port = server.port;
      expect(typeof port).toBe("number");
      if (typeof port !== "number") return;

      const nonce = `${Date.now()}.badprobe`;
      const signature = createHmac("sha256", "other-secret").update(nonce).digest("base64");
      const body = JSON.stringify({
        version: 2,
        card_id: "card-probe",
        card_transaction_event_id: "evt-probe",
        transaction_type: "AUTHORIZATION",
        transaction_amount: 1,
        transaction_currency: "USD",
        merchant: { name: "Probe", category_code: "5734" },
      });
      const res = await fetch(`http://127.0.0.1:${port}/remote-auth`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-nonce": nonce,
          "x-signature": signature,
        },
        body,
      });
      expect(res.status).toBe(200);
      const json = (await res.json()) as { response_status?: string };
      expect(json.response_status).toBe("DECLINED");
    } finally {
      await server.stop(true);
    }
  });
});
