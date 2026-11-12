// Four demo scenes. Live talks to the sandbox through buildPlainAdapter.
// Replay uses FakeAdapter and must not call fetch except the local console.
// Exit 0 only if every scene matches.

import { mkdirSync, rmSync } from "node:fs";
import { dirname } from "node:path";
import { FakeAdapter } from "../src/airwallex/fake-adapter";
import { defaultConsoleUrl, isConsoleUrl, makeEmitter, type FinalRow } from "../console/feed";
import { disarmAndRecord } from "../src/core/disarm";
import { Gate } from "../src/core/gate";
import { Ledger } from "../src/core/ledger";
import { formatMinor } from "../src/core/money";
import { TaintRegistry } from "../src/core/taint";
import { generateApproverKeys, signWrit, verifyWrit } from "../src/core/writ";
import { buildPlainAdapter } from "../src/host/plain";
import type {
  AirwallexAdapter,
  ApprovedTask,
  Decision,
  DecisionInput,
  IsoTime,
  Result,
  SwipeOutcome,
  WritProposal,
} from "../src/types";
import { runEnclaveDemoFromArgv } from "./demo-enclave";

const hostFlag = process.argv.indexOf("--host");
if (hostFlag >= 0) {
  const hostValue = process.argv[hostFlag + 1];
  if (hostValue === "enclave") process.exit(await runEnclaveDemoFromArgv(process.argv));
  if (hostValue !== "plain") {
    console.error("Host must be plain or enclave.");
    process.exit(1);
  }
}

const TEAM = "research";
const MCC = "5734";
const MERCHANT = "DataCo";
const POOL_MINOR = 50_000;
const RING_FENCE_MINOR = 2_500_000;
const RESERVE_FLOOR_MINOR = 2_000_000;
const AUTO_APPROVE_MINOR = 25_000;
const MAX_BALANCE_AGE_MS = 60_000;
const RETRIES = 4;
const RETRY_GAP_MS = 5_000;

const replay = process.argv.includes("--replay");
const CONSOLE_URL = defaultConsoleUrl();
const realFetch = globalThis.fetch.bind(globalThis);

class SceneFail extends Error {
  constructor(
    readonly scene: string,
    message: string,
  ) {
    super(message);
    this.name = "SceneFail";
  }
}

function isoNow(): IsoTime {
  return new Date().toISOString();
}

function isoAhead(ms: number): IsoTime {
  return new Date(Date.now() + ms).toISOString();
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function maskId(id: string): string {
  return id.length <= 4 ? id : id.slice(-4);
}

function errText(e: { kind: string; status?: number; code?: string; message: string }): string {
  return `${e.kind}${e.status ? ` ${e.status}` : ""}${e.code ? ` ${e.code}` : ""}: ${e.message}`;
}

function isTransient(e: { kind: string; message: string }): boolean {
  return e.kind === "timeout" || /failed to process transaction/i.test(e.message);
}

function codeOf(d: Decision): string {
  return d.status === "AUTHORIZED" ? "AUTHORIZED" : d.code;
}

function printScene(name: string, d: Decision): void {
  console.log(`${name}  ${codeOf(d)}  ${d.reason}`);
}

function txType(outcome: SwipeOutcome): string | undefined {
  const raw = outcome.raw;
  if (!raw || typeof raw !== "object") return undefined;
  const o = raw as { transaction_type?: unknown; type?: unknown };
  if (typeof o.transaction_type === "string") return o.transaction_type;
  if (typeof o.type === "string") return o.type;
  return undefined;
}

function hasCapture(
  adapter: AirwallexAdapter,
): adapter is AirwallexAdapter & {
  simulateCapture: (authorization: SwipeOutcome, amountMinor: number, merchantName: string) => Promise<Result<SwipeOutcome>>;
} {
  return typeof (adapter as { simulateCapture?: unknown }).simulateCapture === "function";
}

function swipeSucceeded(outcome: SwipeOutcome): boolean {
  return outcome.accepted || (txType(outcome) === "AUTHORIZATION" && !outcome.failureReason);
}

async function recoverSwipe(cardId: string, since: IsoTime): Promise<SwipeOutcome | undefined> {
  const r = await adapter.readTransaction(cardId, since);
  if (!r.ok || !r.value) return undefined;
  return swipeSucceeded(r.value) ? r.value : undefined;
}

/** Retry sandbox timeouts. If a timed out simulate still landed, reuse that transaction. Do not fire a second swipe. */
async function swipeUntilAccepted(scene: string, spec: { cardId: string; amountMinor: number; currency: string; mcc: string; merchantName: string }): Promise<SwipeOutcome> {
  const since = isoNow();
  let last = "no attempt";
  for (let attempt = 0; attempt <= RETRIES; attempt++) {
    const r = await adapter.simulateSwipe(spec);
    if (r.ok && swipeSucceeded(r.value)) return r.value;
    const recovered = await recoverSwipe(spec.cardId, since);
    if (recovered) {
      await feed.emit({ kind: "log", scene, text: "Sandbox swipe recovered after a timeout. Using the landed transaction." });
      return recovered;
    }
    if (r.ok) {
      last = r.value.failureReason ?? txType(r.value) ?? "not accepted";
      if (r.value.failureReason === "CARD_INACTIVE" && attempt < RETRIES) {
        await sleep(RETRY_GAP_MS);
        continue;
      }
      throw new SceneFail(scene, `swipe refused: ${last}`);
    }
    last = errText(r.error);
    if (!isTransient(r.error) || attempt === RETRIES) throw new SceneFail(scene, `swipe: ${last}`);
    await sleep(RETRY_GAP_MS);
  }
  throw new SceneFail(scene, `swipe: ${last}`);
}

async function withRetry<T>(scene: string, label: string, fn: () => Promise<Result<T>>): Promise<T> {
  let last = "no attempt";
  for (let attempt = 0; attempt <= RETRIES; attempt++) {
    const r = await fn();
    if (r.ok) return r.value;
    last = errText(r.error);
    if (!isTransient(r.error) || attempt === RETRIES) {
      throw new SceneFail(scene, `${label}: ${last}`);
    }
    await sleep(RETRY_GAP_MS);
  }
  throw new SceneFail(scene, `${label}: ${last}`);
}

function expectCode(scene: string, d: Decision, expected: string): void {
  const got = codeOf(d);
  if (got !== expected) throw new SceneFail(scene, `expected ${expected}, got ${got}: ${d.reason}`);
}

function requestUrl(input: string | URL | Request): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

if (replay) {
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = requestUrl(input);
    if (isConsoleUrl(url, CONSOLE_URL)) return realFetch(input, init);
    throw new Error("replay must not call fetch");
  }) as typeof fetch;
}

function cleanLedgerPath(): string {
  if (replay) return ":memory:";
  const path = process.env.WRIT_DB_PATH?.trim() || ".writ/writ.sqlite";
  if (path !== ":memory:") {
    const dir = dirname(path);
    if (dir && dir !== ".") mkdirSync(dir, { recursive: true });
    for (const extra of ["", "-wal", "-shm", "-journal"]) rmSync(`${path}${extra}`, { force: true });
  }
  return path;
}

const ledgerPath = cleanLedgerPath();
const keys = generateApproverKeys();
const taint = new TaintRegistry();
const ledger = new Ledger(ledgerPath);
const feed = makeEmitter({ url: CONSOLE_URL, fetchImpl: realFetch });
const finalRows: FinalRow[] = [];

const adapter: AirwallexAdapter = await (async () => {
  if (replay) return new FakeAdapter({ mode: "frozen" });
  const built = buildPlainAdapter({
    createdBy: "Writ Demo",
    log: (line) => console.error(line.replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, (id) => `...${id.slice(-4)}`)),
  });
  if (!built.ok) {
    ledger.close();
    console.error(`setup failed: ${built.error.message}`);
    process.exit(1);
  }
  return built.value;
})();

let liveBalance = { amountMinor: 1_000_000_000, at: isoNow() };

async function refreshBalance(scene: string): Promise<void> {
  const r = await adapter.getBalance("USD");
  if (!r.ok) throw new SceneFail(scene, `balance: ${errText(r.error)}`);
  liveBalance = { amountMinor: r.value, at: isoNow() };
}

const gate = new Gate({
  ledger,
  config: {
    publicKeyPem: keys.publicKeyPem,
    autoApproveMinor: AUTO_APPROVE_MINOR,
    ringFenceMinor: RING_FENCE_MINOR,
    reserveFloorMinor: RESERVE_FLOOR_MINOR,
    maxBalanceAgeMs: MAX_BALANCE_AGE_MS,
  },
  taint: (runId) => taint.get(runId),
  liveBalance: () => liveBalance,
});

function proposal(over: Partial<WritProposal> = {}): WritProposal {
  return {
    id: crypto.randomUUID(),
    team: TEAM,
    agent: "research-1",
    runId: crypto.randomUUID(),
    purpose: "Dataset licence for the churn study",
    merchantName: MERCHANT,
    mcc: MCC,
    amountMinor: 18000,
    currency: "USD",
    expiresAt: isoAhead(30 * 60 * 1000),
    nonce: crypto.randomUUID(),
    ...over,
  };
}

function sign(over: Partial<WritProposal> = {}): ApprovedTask {
  return signWrit(proposal(over), isoNow(), keys.privateKeyPem);
}

function decisionInput(cardId: string, writ: ApprovedTask, now: IsoTime): DecisionInput {
  const input: DecisionInput = {
    mode: adapter.mode,
    cardId,
    amountMinor: writ.amountMinor,
    currency: writ.currency,
    mcc: writ.mcc,
    merchantName: writ.merchantName,
    now,
  };
  if (adapter.mode === "ra") input.ra = { nonceFresh: true, nonceSeen: false, signatureValid: true };
  return input;
}

async function emitApproval(scene: string, writ: ApprovedTask): Promise<void> {
  const check = verifyWrit(writ, keys.publicKeyPem, {
    autoApproveMinor: AUTO_APPROVE_MINOR,
    knownMerchants: ledger.knownMerchants(writ.team),
  });
  await feed.emit({
    kind: "approval",
    scene,
    approval: {
      team: writ.team,
      agent: writ.agent,
      purpose: writ.purpose,
      merchantName: writ.merchantName,
      mcc: writ.mcc,
      amountMinor: writ.amountMinor,
      currency: writ.currency,
      expiresAt: writ.expiresAt,
      approvedAt: writ.approvedAt,
      approvedBy: writ.approvedBy,
      hash: writ.hash,
      signatureValid: check.signatureValid && check.hashValid,
    },
  });
}

async function emitDecision(scene: string, d: Decision): Promise<void> {
  const payload: {
    kind: "decision";
    scene: string;
    status: "AUTHORIZED" | "DECLINED";
    code: string;
    reason: string;
    writId?: string;
  } = {
    kind: "decision",
    scene,
    status: d.status,
    code: codeOf(d),
    reason: d.reason,
  };
  if (d.writId !== undefined) payload.writId = d.writId;
  await feed.emit(payload);
}

async function emitPoolAndReserve(opts?: {
  ledger?: Ledger;
  liveBalanceMinor?: number;
  simulated?: boolean;
}): Promise<void> {
  const src = opts?.ledger ?? ledger;
  const snap = src.snapshot(TEAM);
  if (snap) {
    await feed.emit({
      kind: "pool",
      team: snap.team,
      poolLimitMinor: snap.poolLimitMinor,
      reservedMinor: snap.reservedMinor,
      pendingMinor: snap.pendingMinor,
      settledMinor: snap.settledMinor,
      releasedMinor: snap.releasedMinor,
    });
  }
  const reserve: {
    kind: "reserve";
    liveBalanceMinor: number;
    ringFenceMinor: number;
    reserveFloorMinor: number;
    openReservationsMinor: number;
    simulated?: boolean;
  } = {
    kind: "reserve",
    liveBalanceMinor: opts?.liveBalanceMinor ?? liveBalance.amountMinor,
    ringFenceMinor: RING_FENCE_MINOR,
    reserveFloorMinor: RESERVE_FLOOR_MINOR,
    openReservationsMinor: src.openReservationsMinor(),
  };
  if (opts?.simulated) reserve.simulated = true;
  await feed.emit(reserve);
}

function remember(scene: string, agent: string, task: string, amountMinor: number, d: Decision): void {
  finalRows.push({
    scene,
    agent,
    task,
    amount: formatMinor(amountMinor),
    result: codeOf(d),
    reason: d.reason,
  });
}

async function createCard(scene: string, holderId: string, agent: string): Promise<{ cardId: string; last4?: string }> {
  const card = await adapter.createAgentCard({ cardholderId: holderId, team: TEAM, agent });
  if (!card.ok) throw new SceneFail(scene, `create card ${agent}: ${errText(card.error)}`);
  ledger.registerCard(card.value.cardId, TEAM, agent, isoNow());
  const last4 = card.value.last4 ?? maskId(card.value.cardId);
  await feed.emit({ kind: "log", scene, text: `Card for ${agent} …${last4}` });
  return card.value;
}

async function armCard(scene: string, cardId: string, writ: ApprovedTask): Promise<void> {
  const r = await adapter.arm(cardId, {
    amountMinor: writ.amountMinor,
    currency: writ.currency,
    mcc: writ.mcc,
    activeTo: writ.expiresAt,
    writHashPrefix: writ.hash.slice(0, 12),
  });
  if (!r.ok) throw new SceneFail(scene, `arm ...${maskId(cardId)}: ${errText(r.error)}`);
  await feed.emit({
    kind: "log",
    scene,
    text: `Armed card …${maskId(cardId)} for ${formatMinor(writ.amountMinor)} at ${writ.merchantName}.`,
  });
  if (!replay) await sleep(2000);
}

async function disarmCard(scene: string, cardId: string, reason: string, writId?: string): Promise<void> {
  const ok = await disarmAndRecord(adapter, ledger, cardId, {
    opId: `${scene}:${writId ?? cardId}:${crypto.randomUUID()}`,
    reason,
    ...(writId !== undefined ? { writId } : {}),
    now: isoNow,
  });
  if (!ok) throw new SceneFail(scene, `disarm ...${maskId(cardId)} failed after retries, ALERT recorded`);
  await feed.emit({ kind: "log", scene, text: `Disarmed card …${maskId(cardId)}.` });
}

async function maybeCapture(scene: string, swipe: SwipeOutcome, amountMinor: number, merchantName: string): Promise<SwipeOutcome> {
  if (txType(swipe) !== "AUTHORIZATION") return swipe;
  if (swipe.failureReason) return swipe;
  if (!hasCapture(adapter)) return swipe;
  return withRetry(scene, "capture", () => adapter.simulateCapture(swipe, amountMinor, merchantName));
}

function postBankEvent(cardId: string, writId: string, amountMinor: number, outcome: SwipeOutcome, at: IsoTime): void {
  const eventId = outcome.transactionId ? `awx:${outcome.transactionId}` : `awx:${crypto.randomUUID()}`;
  const e = { eventId, cardId, writId, amountMinor, at, reason: `Swipe ${amountMinor} cents.` };
  const type = txType(outcome);
  if (type === "AUTHORIZATION") ledger.onAuthorization(e);
  else ledger.onClearing(e);
}

async function spend(
  scene: string,
  cardId: string,
  writ: ApprovedTask,
  last4?: string,
): Promise<SwipeOutcome> {
  await armCard(scene, cardId, writ);
  const swipe = await swipeUntilAccepted(scene, {
    cardId,
    amountMinor: writ.amountMinor,
    currency: writ.currency,
    mcc: writ.mcc,
    merchantName: writ.merchantName,
  });
  const cardLast4 = last4 ?? maskId(cardId);
  if (!swipeSucceeded(swipe)) {
    await disarmAndRecord(adapter, ledger, cardId, { opId: `${scene}:${writ.id}:refused`, reason: "swipe refused", writId: writ.id, now: isoNow });
    await feed.emit({
      kind: "swipe",
      scene,
      accepted: false,
      reason: swipe.failureReason ?? txType(swipe) ?? "not accepted",
      cardLast4,
    });
    throw new SceneFail(scene, `swipe refused: ${swipe.failureReason ?? txType(swipe) ?? "not accepted"}`);
  }
  try {
    const final = await maybeCapture(scene, swipe, writ.amountMinor, writ.merchantName);
    postBankEvent(cardId, writ.id, writ.amountMinor, final, isoNow());
    await feed.emit({
      kind: "swipe",
      scene,
      accepted: true,
      reason: `${formatMinor(writ.amountMinor)} at ${writ.merchantName}.`,
      cardLast4,
    });
    return final;
  } finally {
    await disarmCard(scene, cardId, "swiped once", writ.id);
  }
}

try {
  const consoleUp = await feed.ping();
  console.error(consoleUp ? `console: ${CONSOLE_URL}` : `console not running at ${CONSOLE_URL}; terminal only`);
  console.error(replay ? "ledger: memory (replay)" : `ledger: clean ${ledgerPath}`);
  await feed.emit({ kind: "reset", mode: "frozen", replay });

  ledger.setTeam(TEAM, POOL_MINOR, isoNow());
  await refreshBalance("setup");
  await emitPoolAndReserve();

  const holder = await adapter.createCardholder("Writ Research");
  if (!holder.ok) throw new SceneFail("setup", `cardholder: ${errText(holder.error)}`);
  const holderId = holder.value.cardholderId;

  const cardA = await createCard("setup", holderId, "research-1");
  const cardB = await createCard("setup", holderId, "research-2");

  // 1. Pass
  {
    const scene = "Pass";
    await refreshBalance(scene);
    const writ = sign({ agent: "research-1", amountMinor: 18000 });
    ledger.registerWrit(writ, cardA.cardId, isoNow());
    await emitApproval(scene, writ);
    const now = isoNow();
    const result = await gate.authorize(decisionInput(cardA.cardId, writ, now), `demo-pass-${writ.id}`);
    expectCode(scene, result.decision, "AUTHORIZED");
    await spend(scene, cardA.cardId, writ, cardA.last4);
    const snap = ledger.snapshot(TEAM);
    const pendingOrSettled = (snap?.pendingMinor ?? 0) + (snap?.settledMinor ?? 0);
    if (!snap || pendingOrSettled !== 18000) {
      throw new SceneFail(
        scene,
        `ledger expected pending or settled 18000, got reserved=${snap?.reservedMinor ?? "none"} pending=${snap?.pendingMinor ?? "none"} settled=${snap?.settledMinor ?? "none"}`,
      );
    }
    if (!ledger.wasConsumed(writ.id)) throw new SceneFail(scene, "writ was not consumed");
    remember(scene, writ.agent, writ.purpose, writ.amountMinor, result.decision);
    await emitDecision(scene, result.decision);
    await emitPoolAndReserve();
    printScene(scene, result.decision);
  }

  // 2. Team pool
  {
    const scene = "Team pool";
    await refreshBalance(scene);
    const writB = sign({ agent: "research-2", runId: crypto.randomUUID(), amountMinor: 30000, purpose: "Second dataset licence" });
    ledger.registerWrit(writB, cardB.cardId, isoNow());
    await emitApproval(scene, writB);
    const okB = await gate.authorize(decisionInput(cardB.cardId, writB, isoNow()), `demo-pool-ok-${writB.id}`);
    expectCode(scene, okB.decision, "AUTHORIZED");
    await spend(scene, cardB.cardId, writB, cardB.last4);
    remember("Team pool spend", writB.agent, writB.purpose, writB.amountMinor, okB.decision);

    const writOver = sign({
      agent: "research-1",
      runId: crypto.randomUUID(),
      amountMinor: 6000,
      purpose: "Over the team pool",
    });
    ledger.registerWrit(writOver, cardA.cardId, isoNow());
    await emitApproval(scene, writOver);
    const declined = await gate.authorize(decisionInput(cardA.cardId, writOver, isoNow()), `demo-pool-no-${writOver.id}`);
    expectCode(scene, declined.decision, "TEAM_POOL_EXHAUSTED");
    remember(scene, writOver.agent, writOver.purpose, writOver.amountMinor, declined.decision);
    await emitDecision(scene, declined.decision);
    await emitPoolAndReserve();
    printScene(scene, declined.decision);
  }

  // 3. Taint
  {
    const scene = "Taint";
    const cardC = await createCard(scene, holderId, "research-3");
    await refreshBalance(scene);
    const writ = sign({ agent: "research-3", runId: crypto.randomUUID(), amountMinor: 18000, purpose: "Tainted run" });
    ledger.registerWrit(writ, cardC.cardId, isoNow());
    await emitApproval(scene, writ);
    taint.mark(writ.runId, "https://evil.example/enterprise", isoAhead(1000));
    await feed.emit({ kind: "taint", source: "https://evil.example/enterprise" });
    const result = await gate.authorize(decisionInput(cardC.cardId, writ, isoNow()), `demo-taint-${writ.id}`);
    expectCode(scene, result.decision, "TAINTED_RUN");
    if (!result.freezeCard) throw new SceneFail(scene, "authorize must set freezeCard true");
    await disarmCard(scene, cardC.cardId, "run tainted", writ.id);
    const swipe = await withRetry(scene, "taint swipe", () =>
      adapter.simulateSwipe({
        cardId: cardC.cardId,
        amountMinor: 199900,
        currency: "USD",
        mcc: MCC,
        merchantName: "Enterprise Plans Inc",
      }),
    );
    const refused = !swipe.accepted || swipe.failureReason === "CARD_INACTIVE";
    if (!refused) throw new SceneFail(scene, `expected CARD_INACTIVE or not accepted, got ${swipe.failureReason ?? txType(swipe) ?? "accepted"}`);
    await feed.emit({
      kind: "swipe",
      scene,
      accepted: false,
      reason: swipe.failureReason ?? "not accepted",
      cardLast4: cardC.last4 ?? maskId(cardC.cardId),
    });
    remember(scene, writ.agent, writ.purpose, writ.amountMinor, result.decision);
    await emitDecision(scene, result.decision);
    await emitPoolAndReserve();
    printScene(scene, result.decision);
  }

  // 4. Reserve. Simulated live balance, no wallet movement, no arm.
  {
    const scene = "simulated balance";
    const now = isoNow();
    const reserveLedger = new Ledger();
    reserveLedger.setTeam(TEAM, POOL_MINOR, now);
    reserveLedger.registerCard("reserve-card", TEAM, "research-reserve", now);
    const writ = sign({ agent: "research-reserve", runId: crypto.randomUUID(), amountMinor: 18000, purpose: "Would breach the cash reserve" });
    reserveLedger.registerWrit(writ, "reserve-card", now);
    await emitApproval("Reserve", writ);
    const reserveGate = new Gate({
      ledger: reserveLedger,
      config: {
        publicKeyPem: keys.publicKeyPem,
        autoApproveMinor: AUTO_APPROVE_MINOR,
        ringFenceMinor: 2_500_000,
        reserveFloorMinor: 2_000_000,
        maxBalanceAgeMs: 60_000,
      },
      taint: (runId) => taint.get(runId),
      liveBalance: () => ({ amountMinor: 2_010_000, at: now }),
    });
    const result = await reserveGate.authorize(decisionInput("reserve-card", writ, now), `demo-reserve-${writ.id}`);
    expectCode(scene, result.decision, "RESERVE_FLOOR");
    remember("Reserve", writ.agent, writ.purpose, writ.amountMinor, result.decision);
    await emitDecision("Reserve", result.decision);
    await emitPoolAndReserve({ ledger: reserveLedger, liveBalanceMinor: 2_010_000, simulated: true });
    printScene(scene, result.decision);
    reserveLedger.close();
  }

  const snap = ledger.snapshot(TEAM);
  const used = (snap?.reservedMinor ?? 0) + (snap?.pendingMinor ?? 0) + (snap?.settledMinor ?? 0);
  console.log("");
  console.log(`Final state  ${TEAM} pool ${formatMinor(used)} of ${formatMinor(snap?.poolLimitMinor ?? POOL_MINOR)}`);
  for (const row of finalRows) console.log(`${row.scene}  ${row.agent}  ${row.amount}  ${row.result}  ${row.reason}`);
  await feed.emit({ kind: "final", rows: finalRows, ok: true });
  await feed.emit({ kind: "done", ok: true });
  ledger.close();
} catch (err) {
  await feed.emit({ kind: "done", ok: false });
  ledger.close();
  if (err instanceof SceneFail) {
    console.error(`${err.scene} failed: ${err.message}`);
    process.exit(1);
  }
  const message = err instanceof Error ? err.message : String(err);
  console.error(`demo failed: ${message}`);
  process.exit(1);
}
