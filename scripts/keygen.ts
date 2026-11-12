// Makes the approver's Ed25519 keypair. Private key goes outside the repo, public key into keys/.
// Usage: bun run scripts/keygen.ts [--force]

import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { generateApproverKeys } from "../src/core/writ";

const privatePath = process.env.WRIT_APPROVER_KEY_PATH ?? join(homedir(), ".writ", "approver.key");
const publicPath = resolve(process.env.WRIT_APPROVER_PUBKEY_PATH ?? "keys/approver.pub");
const force = process.argv.includes("--force");

if (resolve(privatePath).startsWith(resolve("."))) {
  console.error(`Refusing: the private key path ${privatePath} is inside the repo.`);
  process.exit(1);
}
if (existsSync(privatePath) && !force) {
  console.error(`A private key already exists at ${privatePath}. Pass --force to replace it.`);
  process.exit(1);
}

const { publicKeyPem, privateKeyPem } = generateApproverKeys();
mkdirSync(dirname(privatePath), { recursive: true, mode: 0o700 });
writeFileSync(privatePath, privateKeyPem, { mode: 0o600 });
chmodSync(privatePath, 0o600);
mkdirSync(dirname(publicPath), { recursive: true });
writeFileSync(publicPath, publicKeyPem);

console.log(`Private key: ${privatePath} (mode 600, keep it off the server)`);
console.log(`Public key:  ${publicPath} (the server reads only this)`);
