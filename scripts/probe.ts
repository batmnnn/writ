// Sandbox smoke test: `bun run probe`. Records real response shapes in fixtures/ and checks that
// the bank side refusals a frozen Writ card relies on actually happen. Exits 1 on any surprise.

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Exchange } from "../src/airwallex/client";
import { redact } from "../src/airwallex/redact";
import { buildPlainAdapter } from "../src/host/plain";
import { formatMinor } from "../src/core/money";
import type { AdapterError, Result, SwipeOutcome } from "../src/types";

const FIXTURES = join(import.meta.dir, "..", "fixtures");
mkdirSync(FIXTURES, { recursive: true });

let exchanges: Exchange[] = [];
const built = buildPlainAdapter({ onExchange: (x) => exchanges.push(x), createdBy: "Writ Probe" });
if (!built.ok) {
  console.error(`probe: ${built.error.message}`);
  process.exit(1);
}
const adapter = built.value;

interface Row {
  step: string;
  expected: string;
  got: string;
  ok: boolean | "info";
}
const rows: Row[] = [];

function save(name: string, data: unknown): void {
  writeFileSync(join(FIXTURES, `${name}.json`), `${JSON.stringify(redact(data), null, 2)}\n`);
}

async function step<T>(name: string, fn: () => Promise<T>): Promise<T> {
  exchanges = [];
  const out = await fn();
  save(name, { step: name, recorded_at: new Date().toISOString(), exchanges });
  return out;
}

function errText(e: AdapterError): string {
  return `${e.kind}${e.status ? ` ${e.status}` : ""}${e.code ? ` ${e.code}` : ""}: ${e.message}`;
}

function must<T>(name: string, r: Result<T>): T {
  if (r.ok) return r.value;
  console.error(`probe: ${name} failed. ${errText(r.error)}`);
  for (const x of exchanges) console.error(JSON.stringify(x, null, 2));
  rows.push({ step: name, expected: "ok", got: errText(r.error), ok: false });
  printTable();
  process.exit(1);
}

/** A swipe result as a short word: PASS, HELD, or the failure reason. */
function verdict(r: Result<SwipeOutcome>): string {
  if (!r.ok) return `ERROR(${errText(r.error)})`;
  if (r.value.accepted) return "PASS";
  if (r.value.failureReason) return r.value.failureReason;
  const raw = r.value.raw as { transaction_type?: string; status?: string; type?: string; process_result?: string };
  const type = raw.transaction_type ?? raw.type;
  const status = raw.status ?? raw.process_result;
  if (type === "AUTHORIZATION" && status === "APPROVED") return "AUTHORIZED";
  return `HELD(${type ?? "?"} ${status ?? "?"})`;
}

function expect(stepName: string, expected: string, got: string): void {
  rows.push({ step: stepName, expected, got, ok: got === expected });
}

function printTable(): void {
  const w = (s: string, n: number) => s.padEnd(n);
  console.log("");
  console.log(`${w("step", 28)}${w("expected", 32)}${w("got", 40)}result`);
  for (const r of rows) {
    console.log(`${w(r.step, 28)}${w(r.expected, 32)}${w(r.got, 40)}${r.ok === "info" ? "info" : r.ok ? "ok" : "WRONG"}`);
  }
}

const MCC = "5734";
const MERCHANT = "WRIT PROBE SOFTWARE";
const inOneHour = () => new Date(Date.now() + 60 * 60 * 1000).toISOString();

console.log(`probe: mode ${adapter.mode}`);

const config = await step("issuing_config_call", () => adapter.getIssuingConfig());
const cfg = must("issuing config", config);
save("issuing_config", cfg.raw);
const raPresent = typeof cfg.raw === "object" && cfg.raw !== null && "remote_auth_settings" in cfg.raw;
console.log(`remote_auth_settings present: ${raPresent ? "yes" : "no"} (enabled: ${cfg.remoteAuthEnabled})`);
console.log(`USD per transaction cap: ${cfg.perTransactionMaxMinor !== undefined ? formatMinor(cfg.perTransactionMaxMinor) : "not listed"}`);
rows.push({ step: "issuing config", expected: "read", got: `RA ${raPresent ? "present" : "absent"}`, ok: "info" });

const balance = must("balance", await step("balance", () => adapter.getBalance("USD")));
console.log(`USD available: ${formatMinor(balance)}`);
rows.push({ step: "balance", expected: "read", got: formatMinor(balance), ok: "info" });

const holder = must("cardholder", await step("cardholder_create", () => adapter.createCardholder("Writ Probe")));
console.log(`cardholder: ${holder.cardholderId}`);

const card = must(
  "card create",
  await step("card_create", () => adapter.createAgentCard({ cardholderId: holder.cardholderId, team: "probe", agent: "probe-1" })),
);
const trace = adapter.lastCardCreate;
console.log(
  `card: ${card.cardId} last4 ${card.last4 ?? "n/a"}, create status ${trace?.createStatus}, trail ${trace?.statusTrail.join(" > ")}, frozen after create ${trace?.frozenAfterCreate}`,
);
rows.push({ step: "card create", expected: "ACTIVE then INACTIVE", got: `${trace?.statusTrail.join(">")}${trace?.frozenAfterCreate ? ">INACTIVE" : ""}`, ok: "info" });

const swipe = (name: string, amountMinor: number, mcc = MCC) =>
  step(name, () => adapter.simulateSwipe({ cardId: card.cardId, amountMinor, currency: "USD", mcc, merchantName: MERCHANT }));

let acceptedSpend = 0;
const track = (r: Result<SwipeOutcome>, amountMinor: number) => {
  const v = verdict(r);
  if (v === "PASS" || v === "AUTHORIZED") acceptedSpend += amountMinor;
};

must("arm 50", await step("arm_50", () => adapter.arm(card.cardId, { amountMinor: 5000, currency: "USD", mcc: MCC, activeTo: inOneHour(), writHashPrefix: "probe0001" })));

const s40 = await swipe("swipe_40_pass", 4000);
track(s40, 4000);
expect("swipe 40 (armed 50)", "AUTHORIZED", verdict(s40));
if (s40.ok) {
  const cap = await step("capture_40", () => adapter.simulateCapture(s40.value, 4000, MERCHANT));
  expect("capture 40", "PASS", verdict(cap));
}

const s60 = await swipe("swipe_60_limit", 6000);
track(s60, 6000);
expect("swipe 60 (armed 50)", "LIMIT_EXCEEDED", verdict(s60));

must("arm 50 again", await step("arm_50_again", () => adapter.arm(card.cardId, { amountMinor: 5000, currency: "USD", mcc: MCC, activeTo: inOneHour(), writHashPrefix: "probe0002" })));
const s50 = await swipe("swipe_50_after_rearm", 5000);
track(s50, 5000);
const allTimeVerdict = verdict(s50);
const allTimeCountsOld = allTimeVerdict === "LIMIT_EXCEEDED" ? "yes" : allTimeVerdict === "AUTHORIZED" || allTimeVerdict === "PASS" ? "no" : "unclear";
rows.push({ step: "swipe 50 after rearm 50", expected: "info", got: `${allTimeVerdict} (ALL_TIME counts old spend: ${allTimeCountsOld})`, ok: "info" });

must("disarm", await step("disarm", () => adapter.disarm(card.cardId)));
const s10 = await swipe("swipe_10_inactive", 1000);
track(s10, 1000);
expect("swipe 10 (disarmed)", "CARD_INACTIVE", verdict(s10));

// Rearm with room for prior spend so ALL_TIME cannot be the reason this one fails.
const mccArm = 5000 + acceptedSpend;
must("arm for mcc", await step("arm_for_mcc", () => adapter.arm(card.cardId, { amountMinor: mccArm, currency: "USD", mcc: MCC, activeTo: inOneHour(), writHashPrefix: "probe0003" })));
const s5999 = await swipe("swipe_mcc_5999", 1000, "5999");
expect("swipe MCC 5999 (armed 5734)", "MERCHANT_CATEGORY_NOT_ALLOWED", verdict(s5999));

must("final disarm", await step("disarm_final", () => adapter.disarm(card.cardId)));

const since = new Date(Date.now() - 60 * 60 * 1000).toISOString();
const latest = await step("transactions_read", () => adapter.readTransaction(card.cardId, since));
rows.push({ step: "read transactions", expected: "read", got: latest.ok ? (latest.value ? `latest ${latest.value.failureReason ?? (latest.value.accepted ? "PASS" : "HELD")}` : "none") : errText(latest.error), ok: "info" });

save("probe_summary", { card_start_status: trace?.createStatus, status_trail: trace?.statusTrail, remote_auth_settings_present: raPresent, per_transaction_max_minor: cfg.perTransactionMaxMinor, all_time_counts_old_spend: allTimeCountsOld, rows });

printTable();
const wrong = rows.filter((r) => r.ok === false);
if (wrong.length > 0) {
  console.error(`\nprobe: ${wrong.length} outcome(s) did not match`);
  process.exit(1);
}
console.log("\nprobe: all expected outcomes matched");
