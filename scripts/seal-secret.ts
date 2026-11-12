// Seals the Airwallex API key into KMS, then stores only the ciphertext in Secrets Manager.
// Usage: bun run scripts/seal-secret.ts < infra/key.txt
// The file is read from stdin so the key is not a process argument. Wipe the file after.

import { spawnSync } from "node:child_process";

const chunks: Buffer[] = [];
for await (const chunk of Bun.stdin.stream()) chunks.push(Buffer.from(chunk));
const raw = Buffer.concat(chunks);
const key = raw.toString("utf8").trim();
if (key.length < 8) {
  console.error("Refusing: stdin did not contain an API key.");
  process.exit(1);
}

const region = "us-west-2";
const encrypted = spawnSync(
  "aws",
  ["kms", "encrypt", "--region", region, "--key-id", "arn:aws:kms:us-west-2:401046276943:key/04d013d8-fb9b-4261-bf67-4d87370a31bb", "--plaintext", "fileb:///dev/stdin", "--output", "text", "--query", "CiphertextBlob"],
  { input: key, encoding: "utf8" },
);
raw.fill(0);
if (encrypted.status !== 0) {
  console.error(encrypted.stderr || "kms encrypt failed");
  process.exit(encrypted.status ?? 1);
}
const ciphertext = encrypted.stdout.trim();
const stored = spawnSync(
  "aws",
  ["secretsmanager", "put-secret-value", "--region", region, "--secret-id", "writ/airwallex/api-key.kms", "--secret-string", JSON.stringify({ ciphertext })],
  { encoding: "utf8" },
);
if (stored.status !== 0) {
  console.error(stored.stderr || "secretsmanager put failed");
  process.exit(stored.status ?? 1);
}
console.log("Sealed. Secrets Manager now holds ciphertext only. Delete the file you piped in.");
