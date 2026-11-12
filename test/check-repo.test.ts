import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addedLines, findingsForName, findingsForText, pansQuotedIn, type FindingKind } from "../scripts/check-repo";

const KINDS: FindingKind[] = [
  "env_file",
  "pem_file",
  "key_file",
  "secret_file",
  "card_number",
  "kms_ciphertext",
  "aws_access_key",
  "em_dash",
  "private_key",
  "account_id",
  "secret_value",
  "banned_word",
];

const script = join(import.meta.dir, "../scripts/check-repo.ts");

function pan(): string {
  return "4242".repeat(4);
}

function passesLuhn(digits: string): boolean {
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

function luhnNumber(length: number, valid: boolean): string {
  const body = "1" + "0".repeat(length - 2);
  let check = -1;
  for (let digit = 0; digit < 10; digit++) {
    if (passesLuhn(body + String(digit))) {
      check = digit;
      break;
    }
  }
  if (check < 0) throw new Error("no luhn check digit");
  const chosen = valid ? check : (check + 1) % 10;
  return body + String(chosen);
}

function generatedPan(valid: boolean): string {
  const body = "1" + "0".repeat(14);
  let check = -1;
  for (let digit = 0; digit < 10; digit++) {
    if (passesLuhn(body + String(digit))) {
      check = digit;
      break;
    }
  }
  if (check < 0) throw new Error("no luhn check digit");
  const chosen = valid ? check : (check + 1) % 10;
  return body + String(chosen);
}

function awsKey(prefix: "AKIA" | "ASIA"): string {
  return prefix + "TEST".repeat(4);
}

function ciphertext(char: string): string {
  return char.repeat(80);
}

function gitEnv(): { [key: string]: string | undefined } {
  const env: { [key: string]: string | undefined } = {};
  for (const [key, value] of Object.entries(process.env)) env[key] = value;
  env.GIT_AUTHOR_NAME = "writ-check";
  env.GIT_AUTHOR_EMAIL = "writ-check@example.com";
  env.GIT_COMMITTER_NAME = "writ-check";
  env.GIT_COMMITTER_EMAIL = "writ-check@example.com";
  env.GIT_PAGER = "cat";
  env.GIT_TERMINAL_PROMPT = "0";
  for (const key of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"]) delete env[key];
  return env;
}

function git(cwd: string, args: string[]): void {
  const result = spawnSync("git", args, { cwd, encoding: "utf8", env: gitEnv() });
  if (result.status !== 0) throw new Error(`git ${args[0] ?? "command"} failed`);
}

function initRepo(dir: string): void {
  git(dir, ["init", "-b", "main"]);
}

function commit(dir: string, message: string): void {
  git(dir, ["add", "-A"]);
  git(dir, ["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "commit", "-m", message]);
}

function runCheck(cwd: string): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [script], { cwd, encoding: "utf8", env: gitEnv() });
  return { status: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

function assertReport(result: { stdout: string; stderr: string }, forbidden: string[]): void {
  expect(result.stderr).toBe("");
  const lines = result.stdout === "" ? [] : result.stdout.replace(/\n$/, "").split("\n");
  for (const line of lines) {
    const parsed = /^(.+):(\d+) ([a-z0-9_]+)( \*{4}.{4})?$/.exec(line);
    expect(parsed).not.toBeNull();
    const kind = parsed?.[3] ?? "";
    expect((KINDS as readonly string[]).includes(kind)).toBe(true);
    for (const secret of forbidden) expect(line).not.toContain(secret);
  }
  for (const secret of forbidden) {
    expect(result.stdout).not.toContain(secret);
    expect(result.stderr).not.toContain(secret);
  }
}

function withDir(fn: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "writ-check-"));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("finding rules", () => {
  test("flags secret filenames and leaves .env.example alone", () => {
    expect(findingsForName(".env")).toEqual([{ path: ".env", line: 1, kind: "env_file" }]);
    expect(findingsForName("team/.env")).toEqual([{ path: "team/.env", line: 1, kind: "env_file" }]);
    expect(findingsForName(".env.example")).toEqual([]);
    expect(findingsForName("keys/approver.pem")).toEqual([{ path: "keys/approver.pem", line: 1, kind: "pem_file" }]);
    expect(findingsForName("keys/approver.key")).toEqual([{ path: "keys/approver.key", line: 1, kind: "key_file" }]);
    expect(findingsForName("vault/api-secret.json")).toEqual([{ path: "vault/api-secret.json", line: 1, kind: "secret_file" }]);
    expect(findingsForName("src/api-secret.json")).toEqual([{ path: "src/api-secret.json", line: 1, kind: "secret_file" }]);
    expect(findingsForName("scripts/seal-secret.ts")).toEqual([]);
    expect(findingsForName("agent/seal-secret.py")).toEqual([]);
    expect(findingsForName("scripts/approve.ts")).toEqual([]);
  });

  test("flags a 16 digit run and ignores years, short ids, and longer runs", () => {
    const card = pan();
    expect(findingsForText("pay.txt", `charge ${card} now`)).toEqual([
      { path: "pay.txt", line: 1, kind: "card_number", last4: card.slice(-4) },
    ]);
    expect(JSON.stringify(findingsForText("pay.txt", card))).not.toContain(card);
    const clean = "year 2026 id 5734 last4 1803 ts 1793856117809 run " + "1".repeat(17) + " slack " + "9".repeat(19);
    expect(findingsForText("notes.txt", clean)).toEqual([]);
    expect(findingsForText("notes.txt", "p" + card)).toEqual([
      { path: "notes.txt", line: 1, kind: "card_number", last4: card.slice(-4) },
    ]);
    expect(findingsForText("slack.md", "C0CC9CYRHV4/p" + card)).toEqual([]);
  });

  test("a 16 digit run is a card only when it passes Luhn", () => {
    const valid = generatedPan(true);
    const invalid = generatedPan(false);
    expect(passesLuhn(valid)).toBe(true);
    expect(passesLuhn(invalid)).toBe(false);
    expect(findingsForText("pay.txt", valid)).toEqual([{ path: "pay.txt", line: 1, kind: "card_number", last4: valid.slice(-4) }]);
    expect(JSON.stringify(findingsForText("pay.txt", valid))).not.toContain(valid);
    expect(findingsForText("ids.txt", invalid)).toEqual([]);
    expect(findingsForText("ids.txt", "1".repeat(16))).toEqual([]);
    expect(findingsForText("notes.txt", "****" + valid.slice(-4))).toEqual([]);
  });

  test("allows redacted fixtures", () => {
    const redacted = [
      '{"card_number":"[removed]","masked_card_number":"************1803","network_transaction_id":"[digits removed]"}',
      "masked ************4242 and ************4111",
      "year 2026",
    ].join("\n");
    expect(findingsForText("fixtures/card_create.json", redacted)).toEqual([]);
  });

  test("allows SEAL_ME in infra source and flags a long ciphertext", () => {
    const placeholder = 'secretStringValue: SecretValue.unsafePlainText(\'{"ciphertext":"SEAL_ME"}\'),';
    expect(findingsForText("infra/lib/core-stack.ts", placeholder)).toEqual([]);
    const blob = ciphertext("A");
    const staged = `{"ciphertext":"${blob}"}`;
    expect(findingsForText("infra/lib/core-stack.ts", staged)).toEqual([
      { path: "infra/lib/core-stack.ts", line: 1, kind: "kms_ciphertext", last4: blob.slice(-4) },
    ]);
    expect(JSON.stringify(findingsForText("blob.json", staged))).not.toContain(blob);
    expect(findingsForText("notes.txt", '{"ciphertext":"SEAL_ME"}')).toEqual([]);
    expect(findingsForText("notes.txt", '{"ciphertext":"short"}')).toEqual([]);
  });

  test("a staged diff line that itself starts with plus signs stays on that file", () => {
    const diff = ["--- a/pay.txt", "+++ b/pay.txt", "+year 2026", "+++ still pay.txt"].join("\n");
    expect(addedLines(diff).map((row) => row.path)).toEqual(["pay.txt", "pay.txt"]);
  });

  test("flags AWS access key ids and ignores a short prefix", () => {
    for (const prefix of ["AKIA", "ASIA"] as const) {
      const key = awsKey(prefix);
      expect(findingsForText("creds.txt", `key ${key}`)).toEqual([
        { path: "creds.txt", line: 1, kind: "aws_access_key", last4: key.slice(-4) },
      ]);
      expect(JSON.stringify(findingsForText("creds.txt", key))).not.toContain(key);
    }
    expect(findingsForText("creds.txt", "AKIA" + "TEST".repeat(3))).toEqual([]);
    expect(findingsForText("creds.txt", "AKIA" + "TEST".repeat(4) + "X")).toEqual([]);
  });

  test("a 13, 15, or 19 digit Luhn number is a card, and 12 or 20 digits are not", () => {
    for (const length of [13, 15, 19]) {
      const digits = luhnNumber(length, true);
      expect(findingsForText("pay.txt", digits)).toEqual([
        { path: "pay.txt", line: 1, kind: "card_number", last4: digits.slice(-4) },
      ]);
      expect(JSON.stringify(findingsForText("pay.txt", digits))).not.toContain(digits);
      expect(findingsForText("ids.txt", luhnNumber(length, false))).toEqual([]);
    }
    expect(findingsForText("ids.txt", luhnNumber(12, true))).toEqual([]);
    expect(findingsForText("ids.txt", luhnNumber(20, true))).toEqual([]);
  });

  test("the two public test PANs are allowed under test/ only", () => {
    const groups = ["4111", "1111", "1111", "1111"];
    const digits = groups.join("");
    const stripe = "4242".repeat(4);
    expect(pansQuotedIn(`test card ${groups.join(" ")}.`).includes(digits)).toBe(true);
    for (const pan of [digits, stripe]) {
      expect(findingsForText("test/pay.ts", pan)).toEqual([]);
      expect(findingsForText("src/pay.ts", pan).map((f) => f.kind)).toEqual(["card_number"]);
      expect(JSON.stringify(findingsForText("src/pay.ts", pan))).not.toContain(pan);
    }
  });

  test("em dash is a finding on its line, and a hyphen or en dash is not", () => {
    const dash = String.fromCharCode(0x2014);
    const en = String.fromCharCode(0x2013);
    expect(findingsForText("README.md", `ok\nbad ${dash} here\n`)).toEqual([{ path: "README.md", line: 2, kind: "em_dash" }]);
    expect(JSON.stringify(findingsForText("README.md", dash))).not.toContain(dash);
    expect(findingsForText("README.md", "a - b")).toEqual([]);
    expect(findingsForText("README.md", `a ${en} b`)).toEqual([]);
  });

  test("banned words are findings except in the files that define the list", () => {
    const word = "ru" + "gs";
    const hit = { path: "README.md", line: 1, kind: "banned_word" as const };
    expect(findingsForText("README.md", `no ${word} here`)).toEqual([hit]);
    expect(findingsForText("README.md", ("Et" + "sy").toUpperCase())).toEqual([hit]);
    expect(findingsForText("AGENTS.md", word)).toEqual([]);
    expect(findingsForText("CLAUDE.md", word)).toEqual([]);
    expect(findingsForText(".cursor/rules/writing-style.mdc", word)).toEqual([]);
    expect(findingsForText("prompts/08-red-team-fresh-clone.md", "OXYGENR" + "UGSIN")).toEqual([]);
    expect(findingsForText("src/readme.ts", word).map((f) => f.kind)).toEqual(["banned_word"]);
  });

  test("a private key header is a finding and a certificate header is not", () => {
    const pem = ["-----BEGIN " + "PRIVATE KEY-----", "abc", "-----END " + "PRIVATE KEY-----"].join("\n");
    expect(findingsForText("keys/a.txt", pem)).toEqual([{ path: "keys/a.txt", line: 1, kind: "private_key" }]);
    expect(JSON.stringify(findingsForText("keys/a.txt", pem))).not.toContain("-----BEGIN " + "PRIVATE KEY-----");
    expect(findingsForText("src/attest/verify.ts", "-----BEGIN " + "CERTIFICATE-----")).toEqual([]);
  });

  test("the account id is allowed in docs, infra, scripts, enclave, test, and src/host", () => {
    const id = "401046" + "276943";
    expect(findingsForText("src/core/decide.ts", `account ${id}`)).toEqual([
      { path: "src/core/decide.ts", line: 1, kind: "account_id" },
    ]);
    expect(JSON.stringify(findingsForText("src/core/decide.ts", id))).not.toContain(id);
    for (const path of [
      "docs/DECISIONS.md",
      "infra/lib/core-stack.ts",
      "scripts/seal-secret.ts",
      "enclave/config/kms.json",
      "test/kms-unseal.test.ts",
      "src/host/enclave-arm.ts",
    ]) {
      expect(findingsForText(path, id)).toEqual([]);
    }
  });

  test("example AWS keys and ASIA placeholders are allowed under test/ only", () => {
    const example = "AKIA" + "IOSFODNN7EXAMPLE";
    const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY";
    const zeros = "ASIA" + "0".repeat(15) + "1";
    const refreshed = "ASIA" + "REFRESHEDKEY0001";
    const other = "AKIA" + "TEST".repeat(4);
    const line = `credentials: { accessKeyId: "${example}", secretAccessKey: "${secret}" }`;
    expect(findingsForText("test/enclave-arm.test.ts", line)).toEqual([]);
    expect(findingsForText("test/enclave-main.test.ts", `accessKeyId: "${zeros}"`)).toEqual([]);
    expect(findingsForText("test/enclave-main.test.ts", `accessKeyId: "${refreshed}"`)).toEqual([]);
    const src = findingsForText("src/airwallex/client.ts", line).map((f) => f.kind);
    expect(src).toContain("aws_access_key");
    expect(src).toContain("secret_value");
    expect(JSON.stringify(findingsForText("src/airwallex/client.ts", line))).not.toContain(example);
    expect(JSON.stringify(findingsForText("src/airwallex/client.ts", line))).not.toContain(secret);
    expect(findingsForText("src/host/creds.ts", `accessKeyId: "${zeros}"`).map((f) => f.kind)).toEqual(["aws_access_key"]);
    expect(findingsForText("test/creds.ts", `key ${other}`).map((f) => f.kind)).toEqual(["aws_access_key"]);
  });

  test("a quoted private key header is allowed in test/ only on a refusal or a generated key", () => {
    const header = "-----BEGIN " + "PRIVATE KEY-----";
    const refusal = `expect(() => start({ key: "${header}" })).toThrow(/refused/)`;
    const generated = `expect(generateApproverKeys().privateKeyPem.startsWith("${header}")).toBe(true)`;
    const stored = `const key = "${header}"`;
    expect(findingsForText("test/enclave-tls.test.ts", refusal)).toEqual([]);
    expect(findingsForText("test/writ.test.ts", generated)).toEqual([]);
    expect(findingsForText("src/host/tls.ts", refusal).map((f) => f.kind)).toEqual(["private_key"]);
    expect(findingsForText("test/keys.ts", stored).map((f) => f.kind)).toEqual(["private_key"]);
    expect(findingsForText("test/keys.ts", header).map((f) => f.kind)).toEqual(["private_key"]);
  });

  test("lockfiles skip the Luhn rule, and a card in src/ still fails", () => {
    const pan = luhnNumber(16, true);
    expect(findingsForText("agent/uv.lock", `wheel ${pan}`)).toEqual([]);
    expect(findingsForText("bun.lock", pan)).toEqual([]);
    expect(findingsForText("package-lock.json", pan)).toEqual([]);
    expect(findingsForText("src/pay.ts", pan).map((f) => f.kind)).toEqual(["card_number"]);
    expect(JSON.stringify(findingsForText("src/pay.ts", pan))).not.toContain(pan);
  });

  test("a long hex or base64 value assigned to a key, secret, or token name is masked", () => {
    const hex = "ab".repeat(32);
    const b64 = "A".repeat(44);
    expect(findingsForText("x.ts", `const API_KEY = "${hex}"`)).toEqual([
      { path: "x.ts", line: 1, kind: "secret_value", last4: hex.slice(-4) },
    ]);
    expect(findingsForText(".env.example", `TOKEN=${b64}`)).toEqual([
      { path: ".env.example", line: 1, kind: "secret_value", last4: b64.slice(-4) },
    ]);
    expect(JSON.stringify(findingsForText("x.ts", `SECRET=${hex}`))).not.toContain(hex);
    expect(findingsForText(".env.example", "AIRWALLEX_API_KEY=\n")).toEqual([]);
    expect(findingsForText("x.ts", 'const API_KEY = "short"')).toEqual([]);
    expect(findingsForText("x.ts", `const hash = "${hex}"`)).toEqual([]);
  });

  test("a KMS-looking blob over 200 characters is a finding outside fixtures, unless allowlisted", () => {
    const blob = "AQ" + "B".repeat(199);
    expect(blob.length).toBeGreaterThan(200);
    expect(findingsForText("src/sealed.ts", blob)).toEqual([
      { path: "src/sealed.ts", line: 1, kind: "kms_ciphertext", last4: blob.slice(-4) },
    ]);
    expect(JSON.stringify(findingsForText("src/sealed.ts", blob))).not.toContain(blob);
    expect(findingsForText("fixtures/live.json", blob)).toEqual([]);
    expect(findingsForText("src/sealed.ts", blob, { allowedBlobs: new Set([blob]) })).toEqual([]);
    expect(findingsForText("src/sealed.ts", "AQ" + "B".repeat(100))).toEqual([]);
  });

  test("a staged hunk keeps the new file line number", () => {
    const diff = ["--- a/pay.txt", "+++ b/pay.txt", "@@ -1,0 +4,1 @@", "+year 2026"].join("\n");
    expect(addedLines(diff)).toEqual([{ path: "pay.txt", line: "year 2026", lineNo: 4 }]);
  });
});

describe("check script", () => {
  test("exits 0 when the index holds only years, short ids, and redacted fixtures", () => {
    withDir((dir) => {
      initRepo(dir);
      mkdirSync(join(dir, "fixtures"));
      mkdirSync(join(dir, "infra/lib"), { recursive: true });
      writeFileSync(join(dir, "fixtures/card_create.json"), '{"card_number":"[removed]","masked_card_number":"************1803","network_transaction_id":"[digits removed]"}\n');
      writeFileSync(join(dir, "infra/lib/core-stack.ts"), '{"ciphertext":"SEAL_ME"}\n');
      writeFileSync(join(dir, ".env.example"), "AIRWALLEX_API_KEY=\nYEAR=2026\n");
      writeFileSync(join(dir, "notes.txt"), "year 2026 id 5734 ts 1793856117809\n");
      commit(dir, "clean");
      const result = runCheck(dir);
      expect(result.status).toBe(0);
      assertReport(result, [pan(), awsKey("AKIA"), ciphertext("A")]);
      expect(result.stdout).toBe("");
    });
  });

  test("an untracked file that is not gitignored is checked", () => {
    withDir((dir) => {
      initRepo(dir);
      writeFileSync(join(dir, "notes.txt"), "year 2026\n");
      commit(dir, "notes");
      const dash = String.fromCharCode(0x2014);
      writeFileSync(join(dir, "draft.md"), `wait ${dash} now\n`);
      const result = runCheck(dir);
      expect(result.status).toBe(1);
      expect(result.stdout).toContain("draft.md:1 em_dash");
      expect(result.stdout).not.toContain(dash);
      assertReport(result, [dash]);
    });
  });

  test("a contiguous public test card is allowed when docs/context quotes it in groups", () => {
    withDir((dir) => {
      initRepo(dir);
      mkdirSync(join(dir, "docs/context"), { recursive: true });
      mkdirSync(join(dir, "test"), { recursive: true });
      const groups = ["4111", "1111", "1111", "1111"];
      writeFileSync(join(dir, "docs/context/note.md"), `test card ${groups.join(" ")}\n`);
      writeFileSync(join(dir, "test/pay.ts"), groups.join("") + "\n");
      commit(dir, "cards");
      const result = runCheck(dir);
      expect(result.status).toBe(0);
      expect(result.stdout).toBe("");
    });
  });

  test("a gitignored untracked .env is not a finding", () => {
    withDir((dir) => {
      initRepo(dir);
      writeFileSync(join(dir, ".gitignore"), ".env\n");
      writeFileSync(join(dir, "notes.txt"), "year 2026\n");
      const marker = "UNTRACKED_ENV_MARKER_" + "7".repeat(8);
      writeFileSync(join(dir, ".env"), `AIRWALLEX_API_KEY=${marker}\n`);
      commit(dir, "notes");
      const result = runCheck(dir);
      expect(result.status).toBe(0);
      assertReport(result, [marker]);
    });
  });

  test("a tracked .env exits 1 and the value is not printed", () => {
    withDir((dir) => {
      initRepo(dir);
      writeFileSync(join(dir, "notes.txt"), "year 2026\n");
      const marker = "TRACKED_ENV_MARKER_" + "8".repeat(8);
      writeFileSync(join(dir, ".env"), `AIRWALLEX_API_KEY=${marker}\n`);
      git(dir, ["add", "notes.txt"]);
      git(dir, ["add", "-f", ".env"]);
      git(dir, ["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "commit", "-m", "add env"]);
      const result = runCheck(dir);
      expect(result.status).toBe(1);
      expect(result.stdout).toContain(".env:1 env_file");
      assertReport(result, [marker]);
    });
  });

  test("a staged card number is a finding even after the work tree copy is reverted", () => {
    withDir((dir) => {
      initRepo(dir);
      writeFileSync(join(dir, "pay.txt"), "year 2026\n");
      commit(dir, "pay");
      const card = pan();
      writeFileSync(join(dir, "pay.txt"), `charge ${card}\n`);
      git(dir, ["add", "pay.txt"]);
      writeFileSync(join(dir, "pay.txt"), "year 2026\n");
      const result = runCheck(dir);
      expect(result.status).toBe(1);
      expect(result.stdout).toContain("pay.txt:1 card_number");
      assertReport(result, [card]);
    });
  });

  test("staged pem, key, and secret filenames exit 1", () => {
    withDir((dir) => {
      initRepo(dir);
      writeFileSync(join(dir, "notes.txt"), "ok\n");
      commit(dir, "notes");
      writeFileSync(join(dir, "approver.pem"), "ok\n");
      writeFileSync(join(dir, "approver.key"), "ok\n");
      writeFileSync(join(dir, "api-secret.json"), "ok\n");
      git(dir, ["add", "approver.pem", "approver.key", "api-secret.json"]);
      const result = runCheck(dir);
      expect(result.status).toBe(1);
      expect(result.stdout).toContain("approver.pem:1 pem_file");
      expect(result.stdout).toContain("approver.key:1 key_file");
      expect(result.stdout).toContain("api-secret.json:1 secret_file");
      assertReport(result, []);
    });
  });

  test("a staged AWS key and a staged ciphertext are findings and are not printed", () => {
    withDir((dir) => {
      initRepo(dir);
      mkdirSync(join(dir, "infra/lib"), { recursive: true });
      writeFileSync(join(dir, "infra/lib/core-stack.ts"), '{"ciphertext":"SEAL_ME"}\n');
      writeFileSync(join(dir, "notes.txt"), "year 2026\n");
      commit(dir, "placeholder");
      expect(runCheck(dir).status).toBe(0);

      const key = awsKey("ASIA");
      const blob = ciphertext("B");
      writeFileSync(join(dir, "notes.txt"), `aws ${key}\n`);
      writeFileSync(join(dir, "infra/lib/core-stack.ts"), `{"ciphertext":"${blob}"}\n`);
      git(dir, ["add", "notes.txt", "infra/lib/core-stack.ts"]);
      const result = runCheck(dir);
      expect(result.status).toBe(1);
      expect(result.stdout).toContain("notes.txt:1 aws_access_key");
      expect(result.stdout).toContain("infra/lib/core-stack.ts:1 kms_ciphertext");
      assertReport(result, [key, blob, awsKey("AKIA")]);
    });
  });

  test("removing a tracked .env leaves the index clean", () => {
    withDir((dir) => {
      initRepo(dir);
      const marker = "REMOVED_ENV_MARKER_" + "6".repeat(8);
      writeFileSync(join(dir, ".env"), marker + "\n");
      git(dir, ["add", "-f", ".env"]);
      git(dir, ["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "commit", "-m", "env"]);
      expect(runCheck(dir).status).toBe(1);
      git(dir, ["rm", "-f", ".env"]);
      const result = runCheck(dir);
      expect(result.status).toBe(0);
      assertReport(result, [marker]);
    });
  });

  test("exits 1 outside a git repo and does not print git stderr", () => {
    withDir((dir) => {
      const result = runCheck(dir);
      expect(result.status).toBe(1);
      expect(result.stderr).toBe("git_failed\n");
      expect(result.stdout).toBe("");
    });
  });
});
