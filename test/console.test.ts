import { afterAll, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { sanitizeEvent, sanitizeText } from "../console/feed";
import { startConsole } from "../console/server";

const root = resolve(import.meta.dir, "..");

describe("console page", () => {
  const html = readFileSync(resolve(root, "console/index.html"), "utf8");
  const css = readFileSync(resolve(root, "console/console.css"), "utf8");
  const js = readFileSync(resolve(root, "console/console.js"), "utf8");

  test("has five panels, Frozen card, and no attestation strip", () => {
    const panels = [...html.matchAll(/data-panel="([^"]+)"/g)].map((m) => m[1]);
    expect(panels).toEqual(["events", "pool", "reserve", "approval", "final"]);
    expect(html).toContain('data-badge="frozen"');
    expect(html).toContain("Frozen card");
    expect(html.toLowerCase()).not.toContain("attestation");
    expect(html.toLowerCase()).not.toContain("pcr0");
    expect(css).toContain("#events");
    expect(js).toContain("EventSource");
  });

  test("copy has no em dash", () => {
    expect(html.includes("\u2014") || css.includes("\u2014") || js.includes("\u2014")).toBe(false);
  });
});

describe("sanitize", () => {
  test("strips PAN-like digits and secret keys, keeps last4 and signatureValid", () => {
    expect(sanitizeText("card 4111111111111111 used")).toBe("card [digits removed] used");
    const clean = sanitizeEvent({
      kind: "swipe",
      at: "2026-11-09T12:00:00.000Z",
      scene: "Pass",
      accepted: true,
      reason: "ok",
      cardLast4: "4242",
      card_number: "4111111111111111",
      signature: "not-a-real-sig",
      api_key: "secret",
    });
    expect(clean).toBeDefined();
    const row = clean as Record<string, unknown>;
    expect(row.cardLast4).toBe("4242");
    expect(row.card_number).toBe("[removed]");
    expect(row.signature).toBe("[removed]");
    expect(row.api_key).toBe("[removed]");
  });

  test("drops unknown kinds", () => {
    expect(sanitizeEvent({ kind: "arm-card", cardId: "nope" })).toBeUndefined();
  });
});

describe("console server", () => {
  const c = startConsole({ port: 0 });
  afterAll(() => c.stop());

  test("health, ingest, and SSE round trip", async () => {
    const health = (await (await fetch(`${c.url}/health`)).json()) as { ok: boolean; badge: string };
    expect(health.ok).toBe(true);
    expect(health.badge).toBe("Frozen card");

    const page = await fetch(`${c.url}/`);
    expect(page.ok).toBe(true);
    const body = await page.text();
    expect(body).toContain("Frozen card");
    expect(body).toContain('data-panel="events"');

    const ingested = await fetch(`${c.url}/ingest`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        kind: "decision",
        at: "2026-11-09T12:00:00.000Z",
        scene: "Pass",
        status: "AUTHORIZED",
        code: "AUTHORIZED",
        reason: "$180 at DataCo.",
        card_number: "4111111111111111",
      }),
    });
    expect(((await ingested.json()) as { ingested: number }).ingested).toBe(1);
    expect(JSON.stringify(c.history())).not.toContain("4111111111111111");

    const res = await fetch(`${c.url}/events`, { headers: { accept: "text/event-stream" } });
    expect(res.ok).toBe(true);
    const reader = res.body?.getReader();
    expect(reader).toBeDefined();
    const dec = new TextDecoder();
    let text = "";
    while (text.length < 8000 && !text.includes("AUTHORIZED")) {
      const chunk = await reader!.read();
      if (chunk.done) break;
      text += dec.decode(chunk.value);
    }
    await reader!.cancel();
    expect(text).toContain("event: writ");
    expect(text).toContain("AUTHORIZED");
    expect(text).not.toContain("4111111111111111");
  });
});

describe("demo replay", () => {
  test("exits 0 with no Airwallex keys", async () => {
    const env = { ...process.env };
    env.AIRWALLEX_CLIENT_ID = "";
    env.AIRWALLEX_API_KEY = "";
    env.AIRWALLEX_RA_SHARED_SECRET = "";
    env.AIRWALLEX_BASE_URL = "https://example.invalid";
    env.WRIT_CONSOLE_URL = "http://127.0.0.1:9";
    const proc = Bun.spawn(["bun", "run", "scripts/demo.ts", "--replay"], {
      cwd: root,
      env,
      stdout: "pipe",
      stderr: "pipe",
    });
    const [stdout, stderr, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);
    expect(code).toBe(0);
    expect(stdout).toContain("Pass");
    expect(stdout).toContain("TEAM_POOL_EXHAUSTED");
    expect(stdout).toContain("TAINTED_RUN");
    expect(stdout).toContain("RESERVE_FLOOR");
    expect(stdout + stderr).not.toMatch(/\d{13,19}/);
  }, 20_000);
});
