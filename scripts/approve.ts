// The approver runs this on their own machine to sign one writ proposal.
// Usage: bun run scripts/approve.ts <proposal.json> [--yes] [--out signed.json]

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { formatMinor } from "../src/core/money";
import { signWrit, validateProposal } from "../src/core/writ";
import type { WritProposal } from "../src/types";

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith("--"));
const outIdx = args.indexOf("--out");
const out = outIdx >= 0 ? args[outIdx + 1] : undefined;
if (!file) {
  console.error("Usage: bun run scripts/approve.ts <proposal.json> [--yes] [--out signed.json]");
  process.exit(1);
}

const keyPath = process.env.WRIT_APPROVER_KEY_PATH ?? join(homedir(), ".writ", "approver.key");
if (!existsSync(keyPath)) {
  console.error(`No private key at ${keyPath}. Run bun run scripts/keygen.ts first.`);
  process.exit(1);
}

const proposal = JSON.parse(readFileSync(file, "utf8")) as WritProposal;
const errors = validateProposal(proposal);
if (errors.length > 0) {
  console.error(`Proposal is not valid: ${errors.join("; ")}`);
  process.exit(1);
}

console.log(`You are approving one purchase for agent ${proposal.agent} (team ${proposal.team}):`);
console.log(`  ${formatMinor(proposal.amountMinor)} ${proposal.currency} at ${proposal.merchantName}, MCC ${proposal.mcc}`);
console.log(`  Purpose: ${proposal.purpose}`);
console.log(`  Valid until ${proposal.expiresAt}. Single use.`);
if (!args.includes("--yes")) {
  const answer = prompt("Sign it? [y/N]");
  if (answer?.trim().toLowerCase() !== "y") {
    console.log("Not signed.");
    process.exit(1);
  }
}

const signed = signWrit(proposal, new Date().toISOString(), readFileSync(keyPath, "utf8"));
const json = JSON.stringify(signed, null, 2);
if (out) writeFileSync(out, json);
else console.log(json);
console.error(`Signed. Hash ${signed.hash.slice(0, 16)}.`);
