// Checks tracked files (index and work tree), staged additions, and untracked
// files that are not gitignored.
// Prints path:line and the rule. A matched secret is masked to its last 4 characters.
//
// Filename: .env, *.pem, *.key, or a secret-store name (*secret*.json and similar).
// A .ts or .py source file is not a secret store just because its name contains "secret".
// Text: an em dash (U+2014). A 13 to 19 digit run that passes Luhn, except a
// Slack permalink (.../p<digits>), lockfiles, the two public test PANs under test/,
// and other public test card numbers quoted with spaces or hyphens in docs/context.
// AKIA or ASIA plus 16 alphanumerics, except the documented AWS example key and
// obvious ASIA placeholders under test/. A long hex or base64 value assigned to a
// name containing key, secret, or token, except that same example secret under test/.
// A PEM private key header, except a quoted header in test/ on a refusal or a
// generated-key line. The AWS account id, except under docs, infra, scripts,
// enclave, test, and src/host. A base64 blob over 200 characters that starts with AQ,
// outside fixtures, unless it is on the ciphertext allowlist. A "ciphertext"
// JSON value of 80 or more base64 characters (SEAL_ME in infra source is the
// placeholder). Banned words, except in AGENTS.md, CLAUDE.md, .cursor/rules,
// and prompts.

import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

export type FindingKind =
  | "env_file"
  | "pem_file"
  | "key_file"
  | "secret_file"
  | "card_number"
  | "kms_ciphertext"
  | "aws_access_key"
  | "em_dash"
  | "private_key"
  | "account_id"
  | "secret_value"
  | "banned_word";

export type Finding = {
  path: string;
  line: number;
  kind: FindingKind;
  /** Last 4 characters of a matched secret. Omitted when the finding is not a secret value. */
  last4?: string;
};

export type ScanOptions = {
  allowedPans?: ReadonlySet<string>;
  allowedBlobs?: ReadonlySet<string>;
  /** When set, every hit in this text is reported on this line (a staged diff line). */
  line?: number;
};

const CARD_RUN = /(?<!\d)\d{13,19}(?!\d)/;
const AWS_KEY = /(?<![A-Za-z0-9])((?:AKIA|ASIA)[A-Za-z0-9]{16})(?![A-Za-z0-9])/;
const CIPHERTEXT = /["']ciphertext["']\s*:\s*["']([^"']*)["']/gi;
const LONG_BASE64 = /^[A-Za-z0-9+/]{80,}={0,2}$/;
const KMS_BLOB = /(?<![A-Za-z0-9+/])(AQ[A-Za-z0-9+/]{199,}={0,2})(?![A-Za-z0-9+/=])/;
const SECRET_ASSIGN =
  /([A-Za-z0-9_.-]*(?:key|secret|token)[A-Za-z0-9_.-]*)\s*[:=]\s*(?:"([^"]*)"|'([^']*)'|([^\s#'",;]+))/gi;
const EM_DASH = String.fromCharCode(0x2014);
const ACCOUNT_ID = "401046" + "276943";
const ACCOUNT_RE = new RegExp(`(?<!\\d)${ACCOUNT_ID}(?!\\d)`);
const AWS_EXAMPLE_ACCESS_KEY = "AKIA" + "IOSFODNN7EXAMPLE";
const AWS_EXAMPLE_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY";
const TEST_ONLY_PANS = new Set(["4111" + "1111" + "1111" + "1111", "4242" + "4242" + "4242" + "4242"]);
const PRIVATE_KEY_MARKS = [
  "-----BEGIN " + "PRIVATE KEY-----",
  "-----BEGIN " + "RSA PRIVATE KEY-----",
  "-----BEGIN " + "EC PRIVATE KEY-----",
  "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
  "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----",
];
const BANNED = new RegExp(
  "\\b(?:" + ["ru" + "gs", "Bhad" + "ohi", "Et" + "sy", "OXYGENR" + "UGSIN"].join("|") + ")\\b",
  "i",
);

/** Exact ciphertext blobs that are not live account material. */
export const KMS_BLOB_ALLOWLIST: ReadonlySet<string> = new Set();

const GROUPED_PAN = /(?<!\d)(?:\d{4}[ -]){3}\d{3,7}(?!\d)/g;

export function passesLuhn(digits: string): boolean {
  let sum = 0;
  let doubleIt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (doubleIt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    doubleIt = !doubleIt;
  }
  return sum % 10 === 0;
}

/** Public test card numbers written as groups, the form docs/context already uses. */
export function pansQuotedIn(text: string): string[] {
  const out = new Set<string>();
  for (const match of text.matchAll(new RegExp(GROUPED_PAN.source, "g"))) {
    const digits = match[0].replace(/[ -]/g, "");
    if (digits.length >= 13 && digits.length <= 19 && passesLuhn(digits)) out.add(digits);
  }
  return [...out];
}

function gitEnv(): { [key: string]: string | undefined } {
  const env: { [key: string]: string | undefined } = {};
  for (const [key, value] of Object.entries(process.env)) env[key] = value;
  env.GIT_PAGER = "cat";
  env.GIT_TERMINAL_PROMPT = "0";
  for (const key of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_PREFIX", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR"]) {
    delete env[key];
  }
  return env;
}

function git(cwd: string, args: string[]): Buffer {
  const result = spawnSync("git", args, {
    cwd,
    env: gitEnv(),
    encoding: "buffer",
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) throw new Error("git_failed");
  return result.stdout ?? Buffer.alloc(0);
}

function nulSplit(buf: Buffer): string[] {
  return buf.toString("utf8").split("\0").filter((part) => part.length > 0);
}

export function normalizePath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^\.\//, "");
}

export function isUnder(path: string, root: string): boolean {
  const normalized = normalizePath(path);
  return normalized === root || normalized.startsWith(`${root}/`);
}

export function isInfraSource(path: string): boolean {
  return isUnder(path, "infra");
}

export function accountIdAllowed(path: string): boolean {
  return ["docs", "infra", "scripts", "enclave", "test", "src/host"].some((root) => isUnder(path, root));
}

function baseName(path: string): string {
  return (normalizePath(path).split("/").pop() ?? path).toLowerCase();
}

/** uv.lock, bun.lock, and package-lock.json. Digit runs there are hashes and wheel URLs. */
export function isLockFile(path: string): boolean {
  const base = baseName(path);
  return base === "uv.lock" || base === "bun.lock" || base === "package-lock.json";
}

function isSourceFile(path: string): boolean {
  const base = baseName(path);
  return base.endsWith(".ts") || base.endsWith(".py");
}

/** Documented example key, or ASIA plus zeros and a small number, or an obvious word placeholder. */
export function isPlaceholderAccessKey(key: string): boolean {
  if (key.length !== 20) return false;
  if (key === AWS_EXAMPLE_ACCESS_KEY) return true;
  if (/^ASIA0+\d{1,4}$/.test(key)) return true;
  return /^ASIA(?:EXAMPLE|REFRESHED|TEST|FAKE|DUMMY)[A-Z]*0+\d{1,4}$/.test(key);
}

export function isExampleSecret(value: string): boolean {
  return value === AWS_EXAMPLE_SECRET;
}

function quotedPrivateKeyHeader(line: string): boolean {
  return PRIVATE_KEY_MARKS.some((mark) => line.includes(`"${mark}"`) || line.includes(`'${mark}'`) || line.includes("`" + mark + "`"));
}

/** A quoted header in test/ on a refusal assertion, or next to a key generator. */
export function privateKeyHeaderAllowed(path: string, line: string): boolean {
  if (!isUnder(path, "test") || !quotedPrivateKeyHeader(line)) return false;
  if (/\b(?:toThrow|rejects|refused|refuse)\b/.test(line)) return true;
  return /\b(?:generateKeyPair(?:Sync)?|createPrivateKey|generateApproverKeys)\b/.test(line);
}

export function bannedWordAllowed(path: string): boolean {
  const normalized = normalizePath(path);
  return (
    normalized === "AGENTS.md" ||
    normalized === "CLAUDE.md" ||
    isUnder(normalized, ".cursor/rules") ||
    isUnder(normalized, "prompts")
  );
}

function textFromBlob(buf: Buffer): string | null {
  if (buf.includes(0)) return null;
  return buf.toString("utf8");
}

function hit(path: string, line: number, kind: FindingKind, secret?: string): Finding {
  if (secret !== undefined && secret.length >= 4) return { path, line, kind, last4: secret.slice(-4) };
  return { path, line, kind };
}

export function findingsForName(path: string): Finding[] {
  const base = path.split("/").pop() ?? path;
  const lower = base.toLowerCase();
  const findings: Finding[] = [];
  if (base === ".env") findings.push(hit(path, 1, "env_file"));
  if (lower.endsWith(".pem")) findings.push(hit(path, 1, "pem_file"));
  if (lower.endsWith(".key")) findings.push(hit(path, 1, "key_file"));
  if (lower.includes("secret") && !isSourceFile(path)) findings.push(hit(path, 1, "secret_file"));
  return findings;
}

function isSecretMaterial(value: string): boolean {
  if (/^[0-9a-fA-F]{32,}$/.test(value)) return true;
  return value.length >= 40 && /^[A-Za-z0-9+/]+={0,2}$/.test(value);
}

function scanLine(
  path: string,
  lineNo: number,
  lineText: string,
  allowedPans: ReadonlySet<string>,
  allowedBlobs: ReadonlySet<string>,
  findings: Finding[],
): void {
  if (lineText.includes(EM_DASH)) findings.push(hit(path, lineNo, "em_dash"));
  if (!bannedWordAllowed(path) && BANNED.test(lineText)) findings.push(hit(path, lineNo, "banned_word"));
  if (!accountIdAllowed(path) && ACCOUNT_RE.test(lineText)) findings.push(hit(path, lineNo, "account_id"));
  if (PRIVATE_KEY_MARKS.some((mark) => lineText.includes(mark)) && !privateKeyHeaderAllowed(path, lineText)) {
    findings.push(hit(path, lineNo, "private_key"));
  }

  if (!isLockFile(path)) {
    for (const match of lineText.matchAll(new RegExp(CARD_RUN.source, "g"))) {
      const digits = match[0];
      const at = match.index ?? 0;
      if (at >= 2 && lineText[at - 2] === "/" && lineText[at - 1] === "p") continue;
      if (isUnder(path, "test") && TEST_ONLY_PANS.has(digits)) continue;
      if (TEST_ONLY_PANS.has(digits)) {
        findings.push(hit(path, lineNo, "card_number", digits));
        break;
      }
      if (allowedPans.has(digits)) continue;
      if (!passesLuhn(digits)) continue;
      findings.push(hit(path, lineNo, "card_number", digits));
      break;
    }
  }

  for (const match of lineText.matchAll(new RegExp(AWS_KEY.source, "g"))) {
    const key = match[1] ?? "";
    if (isUnder(path, "test") && isPlaceholderAccessKey(key)) continue;
    if (key.length > 0) findings.push(hit(path, lineNo, "aws_access_key", key));
    break;
  }

  const assign = new RegExp(SECRET_ASSIGN.source, "gi");
  for (const match of lineText.matchAll(assign)) {
    const value = match[2] ?? match[3] ?? match[4] ?? "";
    if (!isSecretMaterial(value)) continue;
    if (isUnder(path, "test") && isExampleSecret(value)) continue;
    findings.push(hit(path, lineNo, "secret_value", value));
    break;
  }

  const cipher = new RegExp(CIPHERTEXT.source, "gi");
  for (const match of lineText.matchAll(cipher)) {
    const value = match[1] ?? "";
    if (value === "SEAL_ME" && isInfraSource(path)) continue;
    if (!LONG_BASE64.test(value)) continue;
    findings.push(hit(path, lineNo, "kms_ciphertext", value));
    break;
  }

  if (!isUnder(path, "fixtures")) {
    const blobRe = new RegExp(KMS_BLOB.source, "g");
    for (const match of lineText.matchAll(blobRe)) {
      const value = match[1] ?? "";
      if (value.length <= 200 || allowedBlobs.has(value)) continue;
      findings.push(hit(path, lineNo, "kms_ciphertext", value));
      break;
    }
  }
}

export function findingsForText(path: string, text: string, opts: ScanOptions = {}): Finding[] {
  const allowedPans = opts.allowedPans ?? new Set<string>();
  const allowedBlobs = opts.allowedBlobs ?? KMS_BLOB_ALLOWLIST;
  const findings: Finding[] = [];
  const parts = text.split("\n");
  for (let i = 0; i < parts.length; i++) {
    const lineNo = opts.line !== undefined ? opts.line : i + 1;
    scanLine(path, lineNo, parts[i] ?? "", allowedPans, allowedBlobs, findings);
  }
  return dedupe(findings);
}

function pathFromDiffHeader(line: string): string | null {
  let rest = line.slice(4);
  if (rest === "/dev/null") return null;
  if (rest.startsWith('"') && rest.endsWith('"')) {
    rest = rest.slice(1, -1).replaceAll('\\"', '"').replaceAll("\\\\", "\\");
  }
  if (rest.startsWith("b/")) return rest.slice(2);
  return rest.length > 0 ? rest : null;
}

export function addedLines(diff: string): { path: string; line: string; lineNo: number }[] {
  const out: { path: string; line: string; lineNo: number }[] = [];
  let path: string | null = null;
  let sawMinus = false;
  let newLine = 1;
  for (const line of diff.split("\n")) {
    if (line.startsWith("--- ")) {
      sawMinus = true;
      continue;
    }
    if (sawMinus && line.startsWith("+++ ")) {
      path = pathFromDiffHeader(line);
      sawMinus = false;
      newLine = 1;
      continue;
    }
    sawMinus = false;
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
    if (hunk?.[1]) {
      newLine = Number(hunk[1]);
      continue;
    }
    if (!path) continue;
    if (line.startsWith("+")) {
      out.push({ path, line: line.slice(1), lineNo: newLine });
      newLine += 1;
      continue;
    }
    if (line.startsWith("-") || line.startsWith("\\")) continue;
    if (line.startsWith(" ")) newLine += 1;
  }
  return out;
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const finding of findings) {
    const key = `${finding.kind}\0${finding.path}\0${finding.line}\0${finding.last4 ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(finding);
  }
  out.sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line || a.kind.localeCompare(b.kind));
  return out;
}

export function formatFinding(finding: Finding): string {
  const mask = finding.last4 ? ` ****${finding.last4}` : "";
  return `${finding.path}:${finding.line} ${finding.kind}${mask}`;
}

function walkFiles(dir: string, out: string[]): void {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return;
  }
  for (const name of names) {
    const path = join(dir, name);
    let info: ReturnType<typeof statSync>;
    try {
      info = statSync(path);
    } catch {
      continue;
    }
    if (info.isDirectory()) walkFiles(path, out);
    else if (info.isFile()) out.push(path);
  }
}

function loadAllowedPans(cwd: string): Set<string> {
  const set = new Set<string>();
  const files: string[] = [];
  walkFiles(join(cwd, "docs", "context"), files);
  for (const file of files) {
    let buf: Buffer;
    try {
      buf = readFileSync(file);
    } catch {
      continue;
    }
    const text = textFromBlob(buf);
    if (text === null) continue;
    for (const pan of pansQuotedIn(text)) set.add(pan);
  }
  return set;
}

function readWorktree(cwd: string, name: string): string | null {
  try {
    return textFromBlob(readFileSync(join(cwd, name)));
  } catch {
    return null;
  }
}

export function collectFindings(cwd: string): Finding[] {
  const tracked = nulSplit(git(cwd, ["ls-files", "-z"]));
  const untracked = nulSplit(git(cwd, ["ls-files", "--others", "--exclude-standard", "-z"]));
  const allowedPans = loadAllowedPans(cwd);
  const findings: Finding[] = [];
  const seen = new Set<string>();

  const take = (name: string, text: string | null): void => {
    findings.push(...findingsForName(name));
    if (text !== null) findings.push(...findingsForText(name, text, { allowedPans }));
  };

  for (const name of tracked) {
    seen.add(name);
    let indexed: string | null = null;
    try {
      indexed = textFromBlob(git(cwd, ["cat-file", "-p", `:${name}`]));
    } catch (err) {
      if (err instanceof Error && err.message === "git_failed") throw err;
      indexed = null;
    }
    take(name, indexed);
    const work = readWorktree(cwd, name);
    if (work !== null && work !== indexed) take(name, work);
  }
  for (const name of untracked) {
    if (seen.has(name)) continue;
    take(name, readWorktree(cwd, name));
  }

  const diff = git(cwd, ["diff", "--cached", "--no-color", "--unified=0", "--no-ext-diff"]).toString("utf8");
  for (const added of addedLines(diff)) {
    findings.push(...findingsForText(added.path, added.line, { allowedPans, line: added.lineNo }));
  }
  return dedupe(findings);
}

function main(): number {
  try {
    const findings = collectFindings(process.cwd());
    if (findings.length === 0) return 0;
    for (const finding of findings) console.log(formatFinding(finding));
    return 1;
  } catch (err) {
    const message = err instanceof Error ? err.message : "";
    console.error(message === "git_failed" ? "git_failed" : "check_failed");
    return 1;
  }
}

if (import.meta.main) process.exit(main());
