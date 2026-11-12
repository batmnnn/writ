import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const source = readFileSync(join(import.meta.dir, "../scripts/host-eif.sh"), "utf8");

function codeOnly(text: string): string {
  return text
    .split("\n")
    .filter((line) => !line.trim().startsWith("#"))
    .join("\n");
}

describe("host-eif.sh", () => {
  test("does not pass --debug-mode through", () => {
    const code = codeOnly(source);
    expect(code.includes("--debug-mode")).toBe(false);

    const buildLines = code.split("\n").filter((line) => line.includes("nitro-cli build-enclave"));
    expect(buildLines.length).toBe(1);
    const build = buildLines[0] ?? "";
    expect(build.includes("build-enclave")).toBe(true);
    expect(build.includes("--docker-uri writ-enclave:dev")).toBe(true);
    expect(build.includes("--output-file")).toBe(true);
    expect(build.includes("--debug-mode")).toBe(false);
    expect(build.includes("--private-key")).toBe(false);
    expect(build.includes("--signing-certificate")).toBe(false);
    expect(build.includes("--key-id")).toBe(false);
    expect(build.includes("alias")).toBe(false);
    expect(build.includes("$@")).toBe(false);
    expect(build.includes("$*")).toBe(false);

    const bunLines = code.split("\n").filter((line) => line.includes("bun run"));
    expect(bunLines.length).toBe(1);
    const bunLine = bunLines[0] ?? "";
    expect(bunLine.includes("bun run scripts/eif.ts")).toBe(true);
    expect(bunLine.includes("--debug-mode")).toBe(false);
    expect(bunLine.includes("$@")).toBe(false);
    expect(bunLine.includes("$*")).toBe(false);
    expect(bunLine.includes("--private-key")).toBe(false);
    expect(bunLine.includes("--key-id")).toBe(false);
  });

  test("a comment says never pass debug mode", () => {
    const comments = source.split("\n").filter((line) => line.trim().startsWith("#"));
    expect(comments.some((line) => line.includes("Never pass --debug-mode"))).toBe(true);
  });

  test("code does not copy .env, call aws, or start an enclave", () => {
    const code = codeOnly(source);
    expect(code.includes(".env")).toBe(false);
    expect(code.includes("aws ")).toBe(false);
    expect(code.includes("run-enclave")).toBe(false);
    expect(source.includes("This Mac cannot build an EIF.")).toBe(true);
    expect(source.includes("exit 2")).toBe(true);
  });
});
