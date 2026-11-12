import { describe, expect, test } from "bun:test";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";

const root = join(import.meta.dir, "..");
const decideModule = "src/core/decide";

const skipDirs = new Set(["node_modules", ".git", "dist", "coverage", "cdk.out"]);
const codeExt = /\.(?:[cm]?tsx?|[cm]?jsx?)$/;

function toPosix(path: string): string {
  return path.split(sep).join("/");
}

function listProductionSources(): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name.startsWith(".") || skipDirs.has(entry.name)) continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (toPosix(relative(root, full)) === "test") continue;
        walk(full);
        continue;
      }
      if (entry.isFile() && codeExt.test(entry.name)) out.push(full);
    }
  };
  walk(root);
  return out;
}

function specifiers(source: string): string[] {
  const specs: string[] = [];
  const patterns = [
    /(?:^|\n)\s*import\s+(?:type\s+)?[\s\S]*?\sfrom\s*["']([^"']+)["']/g,
    /(?:^|\n)\s*import\s*["']([^"']+)["']/g,
    /(?:^|\n)\s*export\s+(?:type\s+)?(?:\*|\{[\s\S]*?\})\s*from\s*["']([^"']+)["']/g,
    /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g,
    /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g,
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      if (match[1] !== undefined) specs.push(match[1]);
    }
  }
  return specs;
}

function stripModuleExt(spec: string): string {
  return spec.replace(/[?#].*$/, "").replace(/\.(?:d\.ts|[cm]?tsx?|[cm]?jsx?)$/, "");
}

function importsDecide(fromFile: string, spec: string): boolean {
  const bare = stripModuleExt(spec);
  if (bare.startsWith(".")) {
    return toPosix(relative(root, resolve(dirname(fromFile), bare))) === decideModule;
  }
  const norm = bare.replace(/\\/g, "/");
  return norm === decideModule || norm.endsWith(`/${decideModule}`);
}

function productionDecideImporters(): string[] {
  const found = new Set<string>();
  for (const file of listProductionSources()) {
    const source = readFileSync(file, "utf8");
    if (specifiers(source).some((spec) => importsDecide(file, spec))) {
      found.add(toPosix(relative(root, file)));
    }
  }
  return [...found].sort();
}

describe("boundaries", () => {
  test("only src/core/gate.ts imports src/core/decide outside test/", () => {
    const importers = productionDecideImporters();
    const others = importers.filter((file) => file !== "src/core/gate.ts");
    if (others.length > 0) {
      throw new Error(`other importers of src/core/decide: ${others.join(", ")}`);
    }
    expect(importers).toEqual(["src/core/gate.ts"]);
  });

  test("decide.ts has no Date.now, fetch, bun:sqlite, or process.env", () => {
    const source = readFileSync(join(root, "src/core/decide.ts"), "utf8");
    const banned: [string, RegExp][] = [
      ["Date.now", /\bDate\.now\b/],
      ["fetch", /\bfetch\b/],
      ["bun:sqlite", /bun:sqlite/],
      ["process.env", /\bprocess\.env\b/],
    ];
    const hits = banned.filter(([, re]) => re.test(source)).map(([label]) => label);
    expect(hits, `decide.ts contains: ${hits.join(", ")}`).toEqual([]);
  });

  test("README does not say decided at swipe time, even root can't, or trustless", () => {
    const path = join(root, "README.md");
    if (!existsSync(path)) return;
    const text = readFileSync(path, "utf8");
    const phrases = ["decided at swipe time", "even root can't", "trustless"];
    const hits = phrases.filter((phrase) => text.includes(phrase));
    expect(hits, `README contains: ${hits.join(", ")}`).toEqual([]);
  });

  test("src/host/kms-unseal.ts does not use a KMS alias", () => {
    const path = join(root, "src/host/kms-unseal.ts");
    // Later package: src/host/kms-unseal.ts. Skip alias/ until that file exists.
    if (!existsSync(path)) return;
    const text = readFileSync(path, "utf8");
    // includes("alias/") is the refusal check. A key alias is a quoted literal: "alias/ or 'alias/.
    const withoutRefusal = text.replaceAll('includes("alias/")', "");
    const hasAliasLiteral = withoutRefusal.includes('"alias/') || withoutRefusal.includes("'alias/");
    expect(hasAliasLiteral, "src/host/kms-unseal.ts contains a key alias literal").toBe(false);
  });
});
