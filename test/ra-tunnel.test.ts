import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// Reads the script text only. Does not start cloudflared.
const source = readFileSync(join(import.meta.dir, "../scripts/ra-tunnel.sh"), "utf8");

function codeOnly(text: string): string {
  return text
    .split("\n")
    .filter((line) => !line.trim().startsWith("#"))
    .join("\n");
}

describe("ra-tunnel.sh", () => {
  test("does not call config/update or pass --debug-mode", () => {
    expect(source.includes("config/update")).toBe(false);
    expect(source.includes("--debug-mode")).toBe(false);
    const code = codeOnly(source);
    expect(code.includes("config/update")).toBe(false);
    expect(code.includes("--debug-mode")).toBe(false);
  });

  test("requires --start before cloudflared and unsets secrets in the child", () => {
    const code = codeOnly(source);
    const cmd = 'exec "$cloudflared_bin" tunnel --url "$listener"';
    const cmdAt = code.indexOf(cmd);
    expect(cmdAt).toBeGreaterThan(-1);
    expect(code.indexOf(cmd, cmdAt + cmd.length)).toBe(-1);

    const before = code.slice(0, cmdAt);
    const startAt = before.indexOf("--start");
    expect(startAt).toBeGreaterThan(-1);
    const exitAt = before.indexOf("exit 0");
    expect(exitAt).toBeGreaterThan(startAt);
    expect(before.includes('!= "--start"')).toBe(true);
    expect(before.includes("WRIT_RA_PORT:-8787")).toBe(true);
    expect(before.includes("unset AIRWALLEX_API_KEY")).toBe(true);
    expect(before.includes("unset AIRWALLEX_RA_SHARED_SECRET")).toBe(true);
    expect(before.includes("is set.")).toBe(false);
    expect(code.includes("/tmp/writ-ra-url.txt")).toBe(true);
    expect(code.includes("trycloudflare.com")).toBe(true);
  });
});
