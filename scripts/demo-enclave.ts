// Live demo against the Writ Nitro Enclave.
// The Mac signs writs and simulates two swipes. The enclave decides and arms.
// bun run demo --host enclave
// Plain and --replay stay in scripts/demo.ts.

import { createHash, createPublicKey } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { dirname, join } from "node:path";
import { redact } from "../src/airwallex/redact";
import type { ListedTransaction } from "../src/airwallex/rest-adapter";
import { defaultConsoleUrl, makeEmitter, type Feed, type FinalRow } from "../console/feed";
import { formatMinor } from "../src/core/money";
import { canonicalJson, signWrit, verifyWrit } from "../src/core/writ";
import { buildPlainAdapter } from "../src/host/plain";
import type { ApprovedTask, Result, SwipeOutcome, SwipeSpec, WritProposal } from "../src/types";

/** Base URL, paths, and the taint signing key. WRIT_ENCLAVE_URL overrides the base. */
export const ENCLAVE_DEMO = {
  baseUrl: "https://35-95-168-131.sslip.io",
  paths: {
    writs: "/writs",
    decisions: "/decisions",
    state: "/state",
    taint: "/taint",
  },
  taintKeyId: "arn:aws:kms:us-west-2:401046276943:key/d2517670-179b-4a02-ad1e-450aaa1f9caf",
  taintRegion: "us-west-2",
  taintSigningAlgorithm: "ECDSA_SHA_256",
  taintMessageType: "RAW",
  taintUrl: "https://evil.example/enterprise",
  merchant: "DataCo",
  mcc: "5734",
  passMinor: 18_000,
  offWritMinor: 19_500,
  /** Fresh pool: $500 minus the $180 swipe, minus $20 left on purpose. */
  poolOkMinor: 30_000,
  poolNoMinor: 25_000,
  /** Unswiped reservations drop when the writ expires. 3 minutes, not 30. */
  writExpiryMs: 3 * 60 * 1000,
  /** Leave this much so the next research writ is over the pool. */
  poolCushionMinor: 2_000,
  /** Smallest second-writ ask when the room is under the cushion. */
  poolMinAskMinor: 100,
  editedSignedMinor: 4_000,
  editedSentMinor: 5_000,
  taintMinor: 18_000,
  reserveMinor: 600_000,
  sceneDelayMs: 1_500,
  pollIntervalMs: 2_000,
  disarmTimeoutMs: 60_000,
  retryGapMs: 2_000,
  swipeAttempts: 4,
} as const;

export function heldMinor(team: { reservedMinor: number; pendingMinor: number; settledMinor: number }): number {
  return team.reservedMinor + team.pendingMinor + team.settledMinor;
}

/** What research-2 may ask: room left after the approved swipe, minus $20, and at least $1. */
export function poolAskMinor(roomMinor: number): number {
  return Math.max(roomMinor - ENCLAVE_DEMO.poolCushionMinor, ENCLAVE_DEMO.poolMinAskMinor);
}

export function poolExhaustedLine(usedMinor: number, limitMinor: number, askMinor: number): string {
  return `Team budget used up: ${formatMinor(usedMinor)} of ${formatMinor(limitMinor)} spent or held, this needs ${formatMinor(askMinor)}.`;
}

/** PAN-like runs and secrets go first. Then every UUID keeps only its last 4. */
export function maskReverseFixture(body: unknown): unknown {
  const redacted = redact(body);
  const text = JSON.stringify(redacted);
  return JSON.parse(text.replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, (id) => `…${id.slice(-4)}`));
}

export function writeReverseFixtureFile(body: unknown): void {
  const path = join(import.meta.dir, "../fixtures/reverse_180.json");
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(maskReverseFixture(body), null, 2)}\n`);
}

export interface EnclaveTeamBudget {
  poolLimitMinor: number;
  reservedMinor: number;
  pendingMinor: number;
  settledMinor: number;
  releasedMinor: number;
}

export interface EnclaveCard {
  agent: string;
  team: string;
  last4: string | null;
  armed: boolean;
}

export interface EnclaveReserve {
  liveBalanceMinor: number | null;
  ringFenceMinor: number;
  reserveFloorMinor: number;
  openReservationsMinor: number;
  asOf: string | null;
}

export interface EnclaveState {
  teams: Record<string, EnclaveTeamBudget>;
  reserve: EnclaveReserve;
  cards: EnclaveCard[];
  chain: { seq: number; hash: string };
  ledgerPublicKey: string;
  decisions: unknown[];
}

export interface EnclaveWritResult {
  writId: string;
  status: "AUTHORIZED" | "DECLINED" | "ARM_FAILED";
  reason: string;
  code?: string;
  cardLast4?: string;
  seq?: number;
}

export interface EnclaveDemoRow {
  scene: string;
  agent: string;
  task: string;
  amount: string;
  result: string;
  code: string;
  reason: string;
}

export interface KmsSpawnResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export type KmsSpawn = (argv: readonly string[]) => Promise<KmsSpawnResult>;

export interface EnclaveDemoOptions {
  fetchImpl: typeof fetch;
  feed: Feed;
  swipe: (spec: SwipeSpec) => Promise<Result<SwipeOutcome>>;
  /** When a simulate call times out, reuse a transaction that already landed. */
  recoverSwipe?: (cardId: string, since: string) => Promise<Result<SwipeOutcome | undefined>>;
  /** Legacy issuing transaction list. Amounts are already minor units. */
  listTransactions?: (cardId: string, sinceIso: string) => Promise<Result<ListedTransaction[]>>;
  /** Reverse one approved authorization by lifecycle id. */
  reverseSwipe?: (lifecycleId: string, amountMinor: number) => Promise<Result<SwipeOutcome>>;
  /** Writes the redacted reverse body. The live command saves fixtures/reverse_180.json. */
  writeReverseFixture?: (body: unknown) => void;
  /** Before the scenes, reverse pending research authorizations older than 3 minutes. */
  cleanup?: boolean;
  nowMs?: () => number;
  reverseTimeoutMs?: number;
  privateKeyPem: string;
  cardIds: Record<string, string>;
  cardMapSource: string;
  env: Record<string, string | undefined>;
  baseUrl?: string;
  sleep?: (ms: number) => Promise<void>;
  now?: () => string;
  randomUUID?: () => string;
  /** When set, used instead of `aws kms sign`. Tests pass this so they do not spawn aws. */
  kmsSign?: (message: string) => Promise<string>;
  sceneDelayMs?: number;
  pollIntervalMs?: number;
  disarmTimeoutMs?: number;
  retryGapMs?: number;
  log?: (line: string) => void;
  error?: (line: string) => void;
}

export class SceneFail extends Error {
  constructor(
    readonly scene: string,
    message: string,
  ) {
    super(message);
    this.name = "SceneFail";
  }
}

function isObj(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function clip(s: string): string {
  const noKey = s.replace(/-----BEGIN[\s\S]*?-----END [A-Z0-9 ]+-----/g, "[key removed]");
  const noDigits = noKey.replace(/\d{13,19}/g, "[digits]");
  const oneLine = noDigits.replace(/\s+/g, " ").trim();
  return oneLine.length > 200 ? oneLine.slice(0, 200) : oneLine;
}

function maskIds(s: string): string {
  return clip(s).replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, (id) => `…${id.slice(-4)}`);
}

function needString(obj: Record<string, unknown>, key: string, where: string): string {
  const v = obj[key];
  if (typeof v !== "string" || v.trim() === "") throw new Error(`enclave ${where} missing ${key}`);
  return v;
}

function needInt(obj: Record<string, unknown>, key: string, where: string): number {
  const v = obj[key];
  if (typeof v !== "number" || !Number.isSafeInteger(v)) throw new Error(`enclave ${where} missing ${key}`);
  return v;
}

function needArray(obj: Record<string, unknown>, key: string, where: string): unknown[] {
  const v = obj[key];
  if (!Array.isArray(v)) throw new Error(`enclave ${where} missing ${key}`);
  return v;
}

function releasedOf(raw: Record<string, unknown>, where: string): number {
  if (!("releasedMinor" in raw) || raw.releasedMinor === undefined) return 0;
  return needInt(raw, "releasedMinor", where);
}

function needIntOrNull(obj: Record<string, unknown>, key: string, where: string): number | null {
  if (obj[key] === null) return null;
  return needInt(obj, key, where);
}

function needStringOrNull(obj: Record<string, unknown>, key: string, where: string): string | null {
  if (obj[key] === null) return null;
  return needString(obj, key, where);
}

function parseTeamBudget(raw: Record<string, unknown>, where: string): EnclaveTeamBudget {
  return {
    poolLimitMinor: needInt(raw, "poolLimitMinor", where),
    reservedMinor: needInt(raw, "reservedMinor", where),
    pendingMinor: needInt(raw, "pendingMinor", where),
    settledMinor: needInt(raw, "settledMinor", where),
    releasedMinor: releasedOf(raw, where),
  };
}

/** The contract uses a map. The enclave also sends a list of `{team, ...}`. */
function parseTeams(raw: unknown): Record<string, EnclaveTeamBudget> {
  if (Array.isArray(raw)) {
    const teams: Record<string, EnclaveTeamBudget> = {};
    for (const [i, item] of raw.entries()) {
      if (!isObj(item)) throw new Error(`enclave state missing teams[${i}]`);
      const team = needString(item, "team", `state teams[${i}]`);
      teams[team] = parseTeamBudget(item, `state teams.${team}`);
    }
    return teams;
  }
  if (!isObj(raw)) throw new Error("enclave state missing teams");
  const teams: Record<string, EnclaveTeamBudget> = {};
  for (const [team, item] of Object.entries(raw)) {
    if (!isObj(item)) throw new Error(`enclave state missing teams.${team}`);
    teams[team] = parseTeamBudget(item, `state teams.${team}`);
  }
  return teams;
}

/** Drops unknown fields. Throws when a required field is missing or the wrong type. */
export function parseEnclaveState(body: unknown): EnclaveState {
  if (!isObj(body)) throw new Error("enclave state is not an object");
  const teams = parseTeams(body.teams);
  if (!isObj(body.reserve)) throw new Error("enclave state missing reserve");
  const reserveWhere = "state reserve";
  const reserve: EnclaveReserve = {
    liveBalanceMinor: needIntOrNull(body.reserve, "liveBalanceMinor", reserveWhere),
    ringFenceMinor: needInt(body.reserve, "ringFenceMinor", reserveWhere),
    reserveFloorMinor: needInt(body.reserve, "reserveFloorMinor", reserveWhere),
    openReservationsMinor: needInt(body.reserve, "openReservationsMinor", reserveWhere),
    asOf: needStringOrNull(body.reserve, "asOf", reserveWhere),
  };
  const cards: EnclaveCard[] = needArray(body, "cards", "state").map((item, i) => {
    if (!isObj(item)) throw new Error(`enclave state missing cards[${i}]`);
    if (typeof item.armed !== "boolean") throw new Error(`enclave state missing cards[${i}].armed`);
    const where = `state cards[${i}]`;
    return {
      agent: needString(item, "agent", where),
      team: needString(item, "team", where),
      last4: needStringOrNull(item, "last4", where),
      armed: item.armed,
    };
  });
  if (!isObj(body.chain)) throw new Error("enclave state missing chain");
  return {
    teams,
    reserve,
    cards,
    chain: {
      seq: needInt(body.chain, "seq", "state chain"),
      hash: needString(body.chain, "hash", "state chain"),
    },
    ledgerPublicKey: needString(body, "ledgerPublicKey", "state"),
    decisions: needArray(body, "decisions", "state"),
  };
}

export function unwrapWrit(body: unknown): unknown {
  if (!isObj(body)) return body;
  if (typeof body.status === "string" || typeof body.writId === "string") return body;
  for (const key of ["decision", "result"]) {
    const inner = body[key];
    if (isObj(inner) && typeof inner.status === "string") return inner;
  }
  return body;
}

export function parseWritResult(body: unknown, where: string): EnclaveWritResult {
  const unwrapped = unwrapWrit(body);
  if (!isObj(unwrapped)) throw new Error(`enclave ${where} response is not an object`);
  const status = unwrapped.status;
  if (status !== "AUTHORIZED" && status !== "DECLINED" && status !== "ARM_FAILED") {
    if (typeof status !== "string") throw new Error(`enclave ${where} response missing status`);
    throw new Error(`enclave ${where} response status must be AUTHORIZED, DECLINED, or ARM_FAILED`);
  }
  const result: EnclaveWritResult = {
    writId: needString(unwrapped, "writId", `${where} response`),
    status,
    reason: needString(unwrapped, "reason", `${where} response`),
  };
  if (unwrapped.code !== undefined) {
    if (typeof unwrapped.code !== "string" || unwrapped.code.trim() === "") {
      throw new Error(`enclave ${where} response missing code`);
    }
    result.code = unwrapped.code;
  } else if (status !== "AUTHORIZED") {
    throw new Error(`enclave ${where} response missing code`);
  }
  if (unwrapped.cardLast4 !== undefined) {
    if (typeof unwrapped.cardLast4 !== "string" || unwrapped.cardLast4.trim() === "") {
      throw new Error(`enclave ${where} response missing cardLast4`);
    }
    result.cardLast4 = unwrapped.cardLast4;
  }
  if (unwrapped.seq !== undefined) {
    if (typeof unwrapped.seq !== "number" || !Number.isSafeInteger(unwrapped.seq)) {
      throw new Error(`enclave ${where} response missing seq`);
    }
    result.seq = unwrapped.seq;
  }
  return result;
}

/** serve.json uses cards[]. A flat object maps agent to card id. */
export function readCardMap(body: unknown, source: string): Record<string, string> {
  if (!isObj(body)) throw new Error(`${source} is not a JSON object.`);
  if ("cards" in body) {
    if (!Array.isArray(body.cards)) throw new Error(`${source} cards must be a list.`);
    const out: Record<string, string> = {};
    for (const [i, item] of body.cards.entries()) {
      if (!isObj(item)) throw new Error(`${source} cards[${i}] needs agent and cardId.`);
      const agent = item.agent;
      const cardId = item.cardId;
      if (typeof agent !== "string" || agent.trim() === "" || typeof cardId !== "string" || cardId.trim() === "") {
        throw new Error(`${source} cards[${i}] needs agent and cardId.`);
      }
      out[agent] = cardId;
    }
    return out;
  }
  const out: Record<string, string> = {};
  for (const [agent, cardId] of Object.entries(body)) {
    if (typeof cardId !== "string" || cardId.trim() === "" || agent.trim() === "") continue;
    out[agent] = cardId;
  }
  return out;
}

export function loadCardMapFile(path: string): Record<string, string> {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    throw new Error(`Could not read card map at ${path}.`);
  }
  let json: unknown;
  try {
    json = JSON.parse(text) as unknown;
  } catch {
    throw new Error(`Card map at ${path} is not JSON.`);
  }
  return readCardMap(json, path);
}

export function defaultCardMapPath(): string {
  return join(import.meta.dir, "../enclave/config/serve.json");
}

/** https origin plus path. Userinfo, query, and hash are dropped so they are never logged. */
export function normalizeEnclaveBase(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("Enclave URL is not a valid https URL.");
  }
  if (url.protocol !== "https:") throw new Error("Enclave URL must use https.");
  const path = url.pathname.replace(/\/$/, "");
  return `${url.origin}${path === "/" ? "" : path}`;
}

export function kmsSignArgv(messagePath: string): string[] {
  return [
    "aws",
    "kms",
    "sign",
    "--region",
    ENCLAVE_DEMO.taintRegion,
    "--key-id",
    ENCLAVE_DEMO.taintKeyId,
    "--signing-algorithm",
    ENCLAVE_DEMO.taintSigningAlgorithm,
    "--message-type",
    ENCLAVE_DEMO.taintMessageType,
    "--output",
    "json",
    "--message",
    `fileb://${messagePath}`,
  ];
}

async function defaultKmsSpawn(argv: readonly string[]): Promise<KmsSpawnResult> {
  const proc = Bun.spawn([...argv], { stdin: "ignore", stdout: "pipe", stderr: "pipe" });
  const timer = setTimeout(() => proc.kill(), 20_000);
  try {
    const [exitCode, stdout, stderr] = await Promise.all([
      proc.exited,
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ]);
    return { exitCode: exitCode ?? 1, stdout, stderr };
  } finally {
    clearTimeout(timer);
  }
}

/** Signs canonical JSON with `aws kms sign`. The message file is removed before this returns. */
export async function kmsSignMessage(message: string, spawn: KmsSpawn = defaultKmsSpawn): Promise<string> {
  const path = join(tmpdir(), `writ-taint-${crypto.randomUUID()}.bin`);
  writeFileSync(path, message, { mode: 0o600 });
  try {
    const result = await spawn(kmsSignArgv(path));
    if (result.exitCode !== 0) {
      throw new Error(`aws kms sign failed (${result.exitCode}): ${maskIds(result.stderr || "no stderr")}`);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(result.stdout) as unknown;
    } catch {
      throw new Error("aws kms sign returned a body that is not JSON.");
    }
    const signature = isObj(parsed) && typeof parsed.Signature === "string" ? parsed.Signature : "";
    if (signature === "") throw new Error("aws kms sign returned no Signature.");
    return signature;
  } finally {
    rmSync(path, { force: true });
  }
}

function publicFromPrivate(privateKeyPem: string): string {
  try {
    return createPublicKey(privateKeyPem).export({ type: "spki", format: "pem" });
  } catch {
    throw new SceneFail("setup", "Demo approver key could not be read.");
  }
}

function txType(outcome: SwipeOutcome): string | undefined {
  const raw = outcome.raw;
  if (!raw || typeof raw !== "object") return undefined;
  const o = raw as { transaction_type?: unknown; type?: unknown };
  if (typeof o.transaction_type === "string") return o.transaction_type;
  if (typeof o.type === "string") return o.type;
  return undefined;
}

function swipeSucceeded(outcome: SwipeOutcome): boolean {
  return outcome.accepted || (txType(outcome) === "AUTHORIZATION" && !outcome.failureReason);
}

function pad(s: string, n: number): string {
  return s.length >= n ? `${s} ` : s + " ".repeat(n - s.length);
}

function toFinal(rows: EnclaveDemoRow[]): FinalRow[] {
  return rows.map((r) => ({
    scene: r.scene,
    agent: r.agent,
    task: r.task,
    amount: r.amount,
    result: r.code,
    reason: r.reason,
  }));
}

function resultCode(got: EnclaveWritResult): string {
  return got.status === "AUTHORIZED" ? "AUTHORIZED" : (got.code ?? got.status);
}

interface TaintEvent {
  agent: string;
  runId: string;
  urlSha256: string;
  at: string;
  seq: number;
}

export async function runEnclaveDemo(opts: EnclaveDemoOptions): Promise<EnclaveDemoRow[]> {
  const base = normalizeEnclaveBase(opts.baseUrl ?? opts.env.WRIT_ENCLAVE_URL ?? ENCLAVE_DEMO.baseUrl);
  const log = opts.log ?? ((line: string) => console.log(line));
  const error = opts.error ?? ((line: string) => console.error(line));
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const now = opts.now ?? (() => new Date().toISOString());
  const randomUUID = opts.randomUUID ?? (() => crypto.randomUUID());
  const sceneDelayMs = opts.sceneDelayMs ?? ENCLAVE_DEMO.sceneDelayMs;
  const pollIntervalMs = opts.pollIntervalMs ?? ENCLAVE_DEMO.pollIntervalMs;
  const disarmTimeoutMs = opts.disarmTimeoutMs ?? ENCLAVE_DEMO.disarmTimeoutMs;
  const retryGapMs = opts.retryGapMs ?? ENCLAVE_DEMO.retryGapMs;
  const publicKeyPem = publicFromPrivate(opts.privateKeyPem);
  const rows: EnclaveDemoRow[] = [];
  let latest: EnclaveState | undefined;
  let passWrit: ApprovedTask | undefined;
  let swipeSince = now();
  const nowMs = opts.nowMs ?? (() => Date.now());
  const reverseTimeoutMs = opts.reverseTimeoutMs ?? disarmTimeoutMs;

  const researchCardId = opts.cardIds["research-1"];
  if (researchCardId === undefined || researchCardId === "") {
    throw new SceneFail("setup", `No card id for research-1 in ${opts.cardMapSource}.`);
  }
  const passCardId: string = researchCardId;

  const toScene = (scene: string, e: unknown): SceneFail => {
    if (e instanceof SceneFail) return e;
    return new SceneFail(scene, e instanceof Error ? e.message : String(e));
  };

  async function call(method: "GET" | "POST", url: string, body: unknown | undefined, timeoutMs: number, allowEmpty: boolean): Promise<unknown> {
    const headers: Record<string, string> = { accept: "application/json" };
    if (body !== undefined) headers["content-type"] = "application/json";
    let res: Response;
    try {
      res = await opts.fetchImpl(url, {
        method,
        headers,
        redirect: "error",
        signal: AbortSignal.timeout(timeoutMs),
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      });
    } catch (e) {
      throw new Error(`enclave ${method} ${url} failed: ${maskIds(e instanceof Error ? e.message : String(e))}`);
    }
    const text = await res.text();
    if (!res.ok) throw new Error(`enclave ${method} ${url} returned HTTP ${res.status}: ${maskIds(text)}`);
    if (text.trim() === "") {
      if (allowEmpty) return {};
      throw new Error(`enclave ${method} ${url} returned an empty body`);
    }
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new Error(`enclave ${method} ${url} returned a body that is not JSON`);
    }
  }

  async function publish(state: EnclaveState): Promise<void> {
    latest = state;
    const names = Object.keys(state.teams);
    const ordered = [...names.filter((n) => n !== "research"), ...names.filter((n) => n === "research")];
    for (const team of ordered) {
      const row = state.teams[team];
      if (!row) continue;
      await opts.feed.emit({
        kind: "pool",
        team,
        poolLimitMinor: row.poolLimitMinor,
        reservedMinor: row.reservedMinor,
        pendingMinor: row.pendingMinor,
        settledMinor: row.settledMinor,
        releasedMinor: row.releasedMinor,
      });
    }
    await opts.feed.emit({
      kind: "reserve",
      liveBalanceMinor: state.reserve.liveBalanceMinor ?? 0,
      ringFenceMinor: state.reserve.ringFenceMinor,
      reserveFloorMinor: state.reserve.reserveFloorMinor,
      openReservationsMinor: state.reserve.openReservationsMinor,
    });
  }

  async function getState(scene: string): Promise<EnclaveState> {
    try {
      const body = await call("GET", `${base}${ENCLAVE_DEMO.paths.state}`, undefined, 10_000, false);
      const state = parseEnclaveState(body);
      await publish(state);
      return state;
    } catch (e) {
      throw toScene(scene, e);
    }
  }

  function cardFor(state: EnclaveState, agent: string, scene: string): EnclaveCard {
    const card = state.cards.find((c) => c.agent === agent);
    if (!card) throw new SceneFail(scene, `enclave state missing card for ${agent}`);
    return card;
  }

  async function postWrit(scene: string, writ: ApprovedTask): Promise<EnclaveWritResult> {
    let posted: EnclaveWritResult;
    try {
      const body = await call("POST", `${base}${ENCLAVE_DEMO.paths.writs}`, { writ }, 25_000, false);
      posted = parseWritResult(body, "POST /writs");
    } catch (e) {
      throw toScene(scene, e);
    }
    const path = `${ENCLAVE_DEMO.paths.decisions}/${encodeURIComponent(posted.writId)}`;
    let last = "no attempt";
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const body = await call("GET", `${base}${path}`, undefined, 10_000, false);
        // The enclave keeps the first AUTHORIZED answer on GET, so a replay POST can be WRIT_REPLAY while GET stays AUTHORIZED.
        parseWritResult(decisionBody(body, posted.writId), "GET /decisions");
        return posted;
      } catch (e) {
        last = e instanceof Error ? e.message : String(e);
        if (!/HTTP 404/.test(last) || attempt === 2) throw toScene(scene, new Error(last));
        await sleep(200);
      }
    }
    throw new SceneFail(scene, last);
  }

  function decisionBody(body: unknown, writId: string): unknown {
    const direct = unwrapWrit(body);
    if (isObj(direct) && typeof direct.status === "string") return direct;
    if (isObj(body) && Array.isArray(body.decisions)) {
      const hit = body.decisions.find((item) => isObj(item) && item.writId === writId);
      if (hit) return hit;
    }
    return direct;
  }

  async function emitApproval(scene: string, writ: ApprovedTask): Promise<void> {
    const check = verifyWrit(writ, publicKeyPem, { autoApproveMinor: 0, knownMerchants: [] });
    await opts.feed.emit({
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

  async function emitDecision(scene: string, got: EnclaveWritResult): Promise<void> {
    const status: "AUTHORIZED" | "DECLINED" = got.status === "AUTHORIZED" ? "AUTHORIZED" : "DECLINED";
    const code = resultCode(got);
    if (got.writId) {
      await opts.feed.emit({ kind: "decision", scene, status, code, reason: got.reason, writId: got.writId });
      return;
    }
    await opts.feed.emit({ kind: "decision", scene, status, code, reason: got.reason });
  }

  function remember(row: EnclaveDemoRow): void {
    rows.push(row);
    log(`${row.scene}  ${row.code}  ${row.reason}`);
  }

  function expectStatus(scene: string, got: EnclaveWritResult, status: "AUTHORIZED" | "DECLINED", codes?: readonly string[]): void {
    if (got.status !== status) {
      const code = got.code ? ` ${got.code}` : "";
      throw new SceneFail(scene, `expected ${status}, got ${got.status}${code}: ${got.reason}`);
    }
    if (codes && (got.code === undefined || !codes.includes(got.code))) {
      throw new SceneFail(scene, `expected ${codes.join(" or ")}, got ${got.code ?? "no code"}: ${got.reason}`);
    }
  }

  function sign(over: Partial<WritProposal> = {}): ApprovedTask {
    const approvedAt = now();
    const proposal: WritProposal = {
      id: randomUUID(),
      team: "research",
      agent: "research-1",
      runId: randomUUID(),
      purpose: "Dataset licence for the churn study",
      merchantName: ENCLAVE_DEMO.merchant,
      mcc: ENCLAVE_DEMO.mcc,
      amountMinor: ENCLAVE_DEMO.passMinor,
      currency: "USD",
      expiresAt: new Date(Date.parse(approvedAt) + ENCLAVE_DEMO.writExpiryMs).toISOString(),
      nonce: randomUUID(),
      ...over,
    };
    return signWrit(proposal, approvedAt, opts.privateKeyPem);
  }

  async function pause(): Promise<void> {
    if (sceneDelayMs > 0) await sleep(sceneDelayMs);
  }

  async function tryRecover(cardId: string, since: string): Promise<SwipeOutcome | undefined> {
    if (!opts.recoverSwipe) return undefined;
    try {
      const r = await opts.recoverSwipe(cardId, since);
      if (!r.ok || !r.value) return undefined;
      return r.value;
    } catch {
      return undefined;
    }
  }

  async function postSwipe(scene: string, spec: SwipeSpec): Promise<SwipeOutcome> {
    const since = now();
    let last = "no attempt";
    for (let attempt = 0; attempt <= ENCLAVE_DEMO.swipeAttempts; attempt++) {
      let r: Result<SwipeOutcome>;
      try {
        r = await opts.swipe(spec);
      } catch (e) {
        throw new SceneFail(scene, `swipe: ${maskIds(e instanceof Error ? e.message : String(e))}`);
      }
      if (r.ok) return r.value;
      if (r.error.kind === "timeout") {
        const landed = await swipeAfterTimeout(spec, since);
        if (landed) {
          const status = txType(landed) === "AUTHORIZATION" ? (asStatus(landed) ?? "landed") : "landed";
          await opts.feed.emit({
            kind: "log",
            scene,
            text: `Sandbox swipe timed out. The transaction read is ${status}. Using that.`,
          });
          return landed;
        }
      }
      const recovered = await tryRecover(spec.cardId, since);
      if (recovered) {
        await opts.feed.emit({ kind: "log", scene, text: "Sandbox swipe recovered after a timeout. Using the landed transaction." });
        return recovered;
      }
      last = `${r.error.kind}: ${r.error.message}`;
      const transient = r.error.kind === "timeout" || r.error.kind === "network" || /failed to process transaction/i.test(r.error.message);
      if (!transient || attempt === ENCLAVE_DEMO.swipeAttempts) throw new SceneFail(scene, `swipe: ${maskIds(last)}`);
      await sleep(retryGapMs);
    }
    throw new SceneFail(scene, `swipe: ${maskIds(last)}`);
  }

  async function swipeAccepted(scene: string, spec: SwipeSpec): Promise<SwipeOutcome> {
    let last = "no attempt";
    for (let attempt = 0; attempt <= ENCLAVE_DEMO.swipeAttempts; attempt++) {
      const outcome = await postSwipe(scene, spec);
      if (swipeSucceeded(outcome)) return outcome;
      last = outcome.failureReason ?? txType(outcome) ?? "not accepted";
      if (outcome.failureReason === "CARD_INACTIVE" && attempt < ENCLAVE_DEMO.swipeAttempts) {
        await sleep(retryGapMs);
        continue;
      }
      throw new SceneFail(scene, `swipe refused: ${last}`);
    }
    throw new SceneFail(scene, `swipe refused: ${last}`);
  }

  async function pollDisarmed(scene: string, agent: string): Promise<EnclaveState> {
    const deadline = Date.now() + disarmTimeoutMs;
    for (;;) {
      const state = await getState(scene);
      const card = cardFor(state, agent, scene);
      if (!card.armed) return state;
      if (Date.now() >= deadline) {
        throw new SceneFail(scene, `card for ${agent} still armed after ${Math.round(disarmTimeoutMs / 1000)}s`);
      }
      await sleep(pollIntervalMs);
    }
  }

  function printFinal(): void {
    const research = latest?.teams.research;
    if (latest && research) {
      const used = research.reservedMinor + research.pendingMinor + research.settledMinor;
      log("");
      log(`Final state  research pool ${formatMinor(used)} of ${formatMinor(research.poolLimitMinor)}`);
      const live = latest.reserve.liveBalanceMinor;
      log(
        `Reserve  live ${live === null ? "not reported" : formatMinor(live)}, ring fence ${formatMinor(latest.reserve.ringFenceMinor)}, floor ${formatMinor(latest.reserve.reserveFloorMinor)}.`,
      );
    }
    log("");
    log(`${pad("scene", 16)}${pad("agent", 16)}${pad("amount", 10)}${pad("result", 12)}${pad("code", 22)}reason`);
    for (const row of rows) {
      log(`${pad(row.scene, 16)}${pad(row.agent, 16)}${pad(row.amount, 10)}${pad(row.result, 12)}${pad(row.code, 22)}${row.reason}`);
    }
  }

  async function finish(ok: boolean): Promise<void> {
    printFinal();
    try {
      await opts.feed.emit({ kind: "final", rows: toFinal(rows), ok });
      await opts.feed.emit({ kind: "done", ok });
    } catch {
      /* The console feed is best effort. The terminal table still printed. */
    }
  }

  function authStatus(item: ListedTransaction): string {
    return (item.status ?? "").toUpperCase();
  }

  function openAuth(item: ListedTransaction): boolean {
    if ((item.type ?? "").toUpperCase() !== "AUTHORIZATION") return false;
    const status = authStatus(item);
    if (status === "REVERSED") return false;
    return status === "PENDING" || status === "APPROVED";
  }

  function landedSwipe(item: ListedTransaction): SwipeOutcome {
    const status = authStatus(item);
    return {
      transactionId: item.lifecycleId ?? "",
      accepted: false,
      raw: { transaction_type: "AUTHORIZATION", type: "AUTHORIZATION", status },
    };
  }

  function asStatus(outcome: SwipeOutcome): string | undefined {
    const raw = outcome.raw;
    if (!raw || typeof raw !== "object") return undefined;
    const status = (raw as { status?: unknown }).status;
    return typeof status === "string" ? status : undefined;
  }

  function swipeLanded(item: ListedTransaction, spec: SwipeSpec, since: string): boolean {
    if ((item.type ?? "").toUpperCase() !== "AUTHORIZATION") return false;
    const status = authStatus(item);
    if (status !== "PENDING" && status !== "APPROVED" && status !== "REVERSED") return false;
    if (item.amountMinor !== spec.amountMinor) return false;
    if (!item.at) return true;
    const at = Date.parse(item.at);
    const sinceMs = Date.parse(since);
    return !Number.isFinite(at) || !Number.isFinite(sinceMs) || at >= sinceMs;
  }

  async function swipeAfterTimeout(spec: SwipeSpec, since: string): Promise<SwipeOutcome | undefined> {
    if (!opts.listTransactions) return undefined;
    const listed = await opts.listTransactions(spec.cardId, since);
    if (!listed.ok) return undefined;
    const hit = listed.value.find((item) => swipeLanded(item, spec, since));
    return hit ? landedSwipe(hit) : undefined;
  }

  async function authorizationReversed(cardId: string, since: string, lifecycleId: string): Promise<boolean> {
    if (!opts.listTransactions) return false;
    const listed = await opts.listTransactions(cardId, since);
    if (!listed.ok) return false;
    return listed.value.some((item) => item.lifecycleId === lifecycleId && authStatus(item) === "REVERSED");
  }

  function httpDetail(status: number | undefined, message: string): string {
    const clipped = message.replace(/\s+/g, " ").trim().slice(0, 500);
    return status !== undefined ? `HTTP ${status}: ${clipped}` : clipped;
  }

  async function releaseOldAuthorizations(): Promise<void> {
    if (!opts.listTransactions || !opts.reverseSwipe) {
      error("Cleanup skipped: Airwallex list or reverse is not wired.");
      return;
    }
    const since = new Date(nowMs() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const cutoff = nowMs() - ENCLAVE_DEMO.writExpiryMs;
    const before = await getState("setup");
    const pendingBefore = before.teams.research?.pendingMinor ?? 0;
    let released = 0;
    const seen = new Set<string>();
    for (const [agent, cardId] of Object.entries(opts.cardIds)) {
      if (!agent.startsWith("research") || cardId === "") continue;
      const listed = await opts.listTransactions(cardId, since);
      if (!listed.ok) {
        error(`Cleanup list for ${agent} failed: ${httpDetail(listed.error.status, listed.error.message)}`);
        continue;
      }
      for (const item of listed.value) {
        if (authStatus(item) === "REVERSED") continue;
        if (!openAuth(item) || !item.lifecycleId || item.amountMinor === undefined) continue;
        if (seen.has(item.lifecycleId)) continue;
        const at = item.at ? Date.parse(item.at) : Number.NaN;
        if (!Number.isFinite(at) || at > cutoff) continue;
        seen.add(item.lifecycleId);
        const rev = await opts.reverseSwipe(item.lifecycleId, item.amountMinor);
        if (!rev.ok) {
          if (rev.error.kind === "timeout" && (await authorizationReversed(cardId, since, item.lifecycleId))) {
            released += item.amountMinor;
            error(`Cleanup: reverse timed out. The ${agent} authorization is REVERSED.`);
            continue;
          }
          error(`Cleanup reverse for ${agent} failed: ${httpDetail(rev.error.status, rev.error.message)}`);
          continue;
        }
        released += item.amountMinor;
        error(`Cleanup: reversed ${formatMinor(item.amountMinor)} on ${agent}.`);
      }
    }
    if (released === 0) {
      error("Cleanup: no pending authorization older than 3 minutes.");
      return;
    }
    const deadline = Date.now() + reverseTimeoutMs;
    const target = pendingBefore - released;
    for (;;) {
      const state = await getState("setup");
      const pending = state.teams.research?.pendingMinor;
      if (pending !== undefined && pending <= target) {
        error(`Cleanup: the pool released ${formatMinor(released)}.`);
        return;
      }
      if (Date.now() >= deadline) {
        error(`Cleanup reversed ${formatMinor(released)} at Airwallex. The pool had not released it within ${Math.round(reverseTimeoutMs / 1000)}s.`);
        return;
      }
      await sleep(pollIntervalMs);
    }
  }

  async function runReversal(): Promise<{ ok: true; line: string } | { ok: false; reason: string }> {
    const baseline = await getState("Reversal");
    const pendingBefore = baseline.teams.research?.pendingMinor ?? 0;
    if (!opts.listTransactions || !opts.reverseSwipe) {
      return { ok: false, reason: "Reversal failed: Airwallex list or reverse is not wired." };
    }
    const listed = await opts.listTransactions(passCardId, swipeSince);
    if (!listed.ok) return { ok: false, reason: `Reversal failed: ${httpDetail(listed.error.status, listed.error.message)}` };
    const sinceMs = Date.parse(swipeSince);
    const hits = listed.value.filter((item) => {
      if (!openAuth(item) || !item.lifecycleId || item.amountMinor !== ENCLAVE_DEMO.passMinor) return false;
      if (!item.at) return true;
      const at = Date.parse(item.at);
      return !Number.isFinite(sinceMs) || !Number.isFinite(at) || at >= sinceMs;
    });
    hits.sort((a, b) => Date.parse(b.at ?? "") - Date.parse(a.at ?? ""));
    const hit = hits[0];
    if (!hit?.lifecycleId) return { ok: false, reason: "Reversal failed: no pending $180 authorization on research-1." };
    const rev = await opts.reverseSwipe(hit.lifecycleId, ENCLAVE_DEMO.passMinor);
    if (!rev.ok) {
      if (rev.error.kind !== "timeout") return { ok: false, reason: `Reversal failed: ${httpDetail(rev.error.status, rev.error.message)}` };
      const reversed = await authorizationReversed(passCardId, swipeSince, hit.lifecycleId);
      if (!reversed) return { ok: false, reason: `Reversal failed: ${httpDetail(rev.error.status, rev.error.message)}` };
      error("Reverse timed out. The authorization status is REVERSED.");
    } else {
      if (rev.value.failureReason) return { ok: false, reason: `Reversal failed: ${rev.value.failureReason}` };
      opts.writeReverseFixture?.(maskReverseFixture(rev.value.raw));
    }
    const deadline = Date.now() + reverseTimeoutMs;
    const target = pendingBefore - ENCLAVE_DEMO.passMinor;
    for (;;) {
      const state = await getState("Reversal");
      const team = state.teams.research;
      if (team && team.pendingMinor <= target) {
        const line = `Reversal: Airwallex reversed the $180. The team pool released it: ${formatMinor(heldMinor(team))} of ${formatMinor(team.poolLimitMinor)} now held.`;
        return { ok: true, line };
      }
      if (Date.now() >= deadline) {
        return { ok: false, reason: `Reversal failed: Airwallex reversed the $180. The team pool did not release it within ${Math.round(reverseTimeoutMs / 1000)}s.` };
      }
      await sleep(pollIntervalMs);
    }
  }

  try {
    const consoleUp = await opts.feed.ping();
    error(consoleUp ? `console: ${opts.feed.url}` : `console not running at ${opts.feed.url}; terminal only`);
    error(`enclave: ${base}`);
    await opts.feed.emit({ kind: "reset", mode: "frozen", replay: false });
    await opts.feed.emit({
      kind: "log",
      scene: "setup",
      text: `Enclave ${base}. This Mac signs writs and simulates swipes. The enclave decides.`,
    });

    if (opts.cleanup) await releaseOldAuthorizations();
    const start = await getState("setup");
    const research = start.teams.research;
    if (!research) throw new SceneFail("setup", "enclave state missing team research");
    const heldAtStart = heldMinor(research);
    error(`Earlier runs hold ${formatMinor(heldAtStart)} of the ${formatMinor(research.poolLimitMinor)} research pool.`);
    error("Pending from swiped writs stays until the bank clears or reverses it in the sandbox.");
    error(`ring fence ${formatMinor(start.reserve.ringFenceMinor)}, floor ${formatMinor(start.reserve.reserveFloorMinor)}`);

    // 1. Approved writ, one sandbox swipe, then the enclave disarms.
    {
      const scene = "Approved";
      const room = research.poolLimitMinor - heldAtStart;
      if (room < ENCLAVE_DEMO.passMinor) {
        const line = `Research pool is full from earlier runs. It holds ${formatMinor(heldAtStart)} of ${formatMinor(research.poolLimitMinor)}. ${formatMinor(ENCLAVE_DEMO.passMinor)} does not fit. Wait 3 minutes for an unswiped writ to expire, or clear or reverse the pending swipe in the sandbox, then run again.`;
        await opts.feed.emit({ kind: "log", scene, text: line });
        throw new SceneFail(scene, line);
      }
      const writ = sign({ agent: "research-1", amountMinor: ENCLAVE_DEMO.passMinor, purpose: "Dataset licence for the churn study" });
      passWrit = writ;
      await emitApproval(scene, writ);
      const got = await postWrit(scene, writ);
      expectStatus(scene, got, "AUTHORIZED");
      await emitDecision(scene, got);
      const armed = await getState(scene);
      const card = cardFor(armed, "research-1", scene);
      if (!card.armed) throw new SceneFail(scene, "enclave authorized research-1 but the card is not armed");
      if (got.cardLast4 !== undefined && card.last4 !== null && got.cardLast4 !== card.last4) {
        throw new SceneFail(scene, `enclave card for research-1 is …${card.last4}. POST /writs said …${got.cardLast4}.`);
      }
      await opts.feed.emit({
        kind: "log",
        scene,
        text: `Card ${card.last4 ? `…${card.last4}` : "for research-1"} armed for ${formatMinor(writ.amountMinor)}.`,
      });
      swipeSince = now();
      await swipeAccepted(scene, {
        cardId: passCardId,
        amountMinor: writ.amountMinor,
        currency: writ.currency,
        mcc: writ.mcc,
        merchantName: writ.merchantName,
      });
      await opts.feed.emit({
        kind: "swipe",
        scene,
        accepted: true,
        reason: `${formatMinor(writ.amountMinor)} at ${writ.merchantName}.`,
        ...(card.last4 ? { cardLast4: card.last4 } : {}),
      });
      const quiet = await pollDisarmed(scene, "research-1");
      const after = cardFor(quiet, "research-1", scene);
      await opts.feed.emit({ kind: "log", scene, text: `Card ${after.last4 ? `…${after.last4}` : "for research-1"} is inactive.` });
      remember({
        scene,
        agent: writ.agent,
        task: writ.purpose,
        amount: formatMinor(writ.amountMinor),
        result: "AUTHORIZED",
        code: "AUTHORIZED",
        reason: got.reason,
      });
    }
    await pause();

    // 2. The same card is inactive. Airwallex refuses a second swipe.
    {
      const scene = "Off-writ swipe";
      const outcome = await postSwipe(scene, {
        cardId: passCardId,
        amountMinor: ENCLAVE_DEMO.offWritMinor,
        currency: "USD",
        mcc: ENCLAVE_DEMO.mcc,
        merchantName: ENCLAVE_DEMO.merchant,
      });
      if (swipeSucceeded(outcome)) throw new SceneFail(scene, "expected Airwallex to decline the inactive card");
      const code = outcome.failureReason ?? "NOT_ACCEPTED";
      const reason = outcome.failureReason ? `Airwallex declined the swipe: ${outcome.failureReason}.` : "Airwallex did not accept the swipe.";
      const last4 = latest?.cards.find((c) => c.agent === "research-1")?.last4;
      await opts.feed.emit({
        kind: "swipe",
        scene,
        accepted: false,
        reason,
        ...(last4 ? { cardLast4: last4 } : {}),
      });
      await getState(scene);
      remember({
        scene,
        agent: "research-1",
        task: "Swipe after the card was disarmed",
        amount: formatMinor(ENCLAVE_DEMO.offWritMinor),
        result: "DECLINED",
        code,
        reason,
      });
    }
    await pause();

    // 3. Size research-2 from the room left. Leave $20 so research-3's $250 is over the pool.
    {
      const scene = "Team pool";
      const before = await getState(scene);
      const budget = before.teams.research;
      if (!budget) throw new SceneFail(scene, "enclave state missing team research");
      const room = budget.poolLimitMinor - heldMinor(budget);
      const askMinor = poolAskMinor(room);
      if (askMinor > room) {
        const line = `Research pool has ${formatMinor(Math.max(room, 0))} free after the approved swipe. That is not enough for another writ. Wait 3 minutes for an unswiped writ to expire, or clear or reverse the pending swipe in the sandbox, then run again.`;
        await opts.feed.emit({ kind: "log", scene, text: line });
        throw new SceneFail(scene, line);
      }
      error(`research-2 asks for ${formatMinor(askMinor)}. ${formatMinor(room)} of ${formatMinor(budget.poolLimitMinor)} is free.`);
      const okWrit = sign({
        agent: "research-2",
        amountMinor: askMinor,
        purpose: "Second dataset licence",
      });
      await emitApproval(scene, okWrit);
      const ok = await postWrit(scene, okWrit);
      expectStatus(scene, ok, "AUTHORIZED");
      await emitDecision(scene, ok);
      const afterOk = await getState(scene);
      const afterBudget = afterOk.teams.research;
      if (!afterBudget) throw new SceneFail(scene, "enclave state missing team research");
      const exhausted = poolExhaustedLine(heldMinor(afterBudget), afterBudget.poolLimitMinor, ENCLAVE_DEMO.poolNoMinor);
      remember({
        scene,
        agent: okWrit.agent,
        task: okWrit.purpose,
        amount: formatMinor(okWrit.amountMinor),
        result: "AUTHORIZED",
        code: "AUTHORIZED",
        reason: ok.reason,
      });
      await pause();

      const noWrit = sign({
        agent: "research-3",
        amountMinor: ENCLAVE_DEMO.poolNoMinor,
        purpose: "Over the team pool",
      });
      await emitApproval(scene, noWrit);
      const no = await postWrit(scene, noWrit);
      expectStatus(scene, no, "DECLINED", ["TEAM_POOL_EXHAUSTED"]);
      await emitDecision(scene, no);
      await getState(scene);
      error(exhausted);
      remember({
        scene,
        agent: noWrit.agent,
        task: noWrit.purpose,
        amount: formatMinor(noWrit.amountMinor),
        result: "DECLINED",
        code: resultCode(no),
        reason: exhausted,
      });
    }
    await pause();

    // 4. Amount changes after the signature. The pool scene leaves at most $20, so a missed hash check still cannot arm $50.
    {
      const scene = "Edited writ";
      const signed = sign({
        agent: "research-agent",
        amountMinor: ENCLAVE_DEMO.editedSignedMinor,
        purpose: "Edited after signing",
      });
      const edited: ApprovedTask = { ...signed, amountMinor: ENCLAVE_DEMO.editedSentMinor };
      await emitApproval(scene, edited);
      const got = await postWrit(scene, edited);
      expectStatus(scene, got, "DECLINED", ["WRIT_HASH_MISMATCH", "WRIT_BAD_SIGNATURE"]);
      await emitDecision(scene, got);
      await getState(scene);
      remember({
        scene,
        agent: edited.agent,
        task: edited.purpose,
        amount: formatMinor(edited.amountMinor),
        result: "DECLINED",
        code: resultCode(got),
        reason: got.reason,
      });
    }
    await pause();

    // 5. The scene 1 writ, posted again.
    {
      const scene = "Replay";
      const writ = passWrit;
      if (!writ) throw new SceneFail(scene, "scene 1 writ is missing");
      await emitApproval(scene, writ);
      const got = await postWrit(scene, writ);
      expectStatus(scene, got, "DECLINED", ["WRIT_REPLAY"]);
      await emitDecision(scene, got);
      await getState(scene);
      remember({
        scene,
        agent: writ.agent,
        task: writ.purpose,
        amount: formatMinor(writ.amountMinor),
        result: "DECLINED",
        code: resultCode(got),
        reason: got.reason,
      });
    }
    await pause();

    // 6. Reverse the $180 authorization so the pending hold leaves the pool.
    {
      const scene = "Reversal";
      const task = "Release the approved authorization";
      const outcome = await runReversal();
      if (outcome.ok) {
        log(outcome.line);
        await opts.feed.emit({ kind: "log", scene, text: outcome.line });
        remember({
          scene,
          agent: "research-1",
          task,
          amount: formatMinor(ENCLAVE_DEMO.passMinor),
          result: "REVERSED",
          code: "REVERSED",
          reason: outcome.line,
        });
      } else {
        error(outcome.reason);
        await opts.feed.emit({ kind: "log", scene, text: outcome.reason });
        remember({
          scene,
          agent: "research-1",
          task,
          amount: formatMinor(ENCLAVE_DEMO.passMinor),
          result: "FAILED",
          code: "FAILED",
          reason: outcome.reason,
        });
      }
    }
    await pause();

    // 7. Taint needs a KMS signature. Skip unless the operator opts in.
    {
      const scene = "Taint";
      const plan = taintPlan(opts.env);
      if (plan.kind === "skip") {
        await opts.feed.emit({ kind: "log", scene, text: `SKIPPED. ${plan.reason}` });
        remember({
          scene,
          agent: "research-agent",
          task: "Tainted run",
          amount: formatMinor(ENCLAVE_DEMO.taintMinor),
          result: "SKIPPED",
          code: "SKIPPED",
          reason: plan.reason,
        });
      } else {
        const writ = sign({
          agent: "research-agent",
          amountMinor: ENCLAVE_DEMO.taintMinor,
          purpose: "Tainted run",
        });
        await emitApproval(scene, writ);
        const state = latest ?? (await getState(scene));
        const event: TaintEvent = {
          agent: writ.agent,
          runId: writ.runId,
          urlSha256: createHash("sha256").update(ENCLAVE_DEMO.taintUrl).digest("hex"),
          at: writ.approvedAt,
          seq: state.chain.seq + 1,
        };
        let tainted = false;
        if (plan.kind === "kms") {
          const signMessage = opts.kmsSign ?? ((message: string) => kmsSignMessage(message));
          let signature: string | undefined;
          try {
            signature = await signMessage(canonicalJson(event));
          } catch (err) {
            const text = err instanceof Error ? err.message : String(err);
            if (!text.includes("AccessDenied")) throw err;
            const reason = "KMS refused this Mac's credentials. Only the taint interceptor role may sign taint events.";
            await opts.feed.emit({ kind: "log", scene, text: `SKIPPED. ${reason}` });
            remember({ scene, agent: writ.agent, task: writ.purpose, amount: formatMinor(writ.amountMinor), result: "SKIPPED", code: "SKIPPED", reason });
          }
          if (signature !== undefined) {
            await postTaintEvent(event, signature);
            error("Taint event signed with KMS and posted.");
          }
          tainted = signature !== undefined;
        } else {
          await postInterceptor(plan.url, event);
          error("Taint sent through the AgentCore interceptor.");
          tainted = true;
        }
        if (tainted) {
          await opts.feed.emit({ kind: "taint", source: ENCLAVE_DEMO.taintUrl });
          const got = await postWrit(scene, writ);
          expectStatus(scene, got, "DECLINED", ["TAINTED_RUN"]);
          await emitDecision(scene, got);
          await getState(scene);
          remember({
            scene,
            agent: writ.agent,
            task: writ.purpose,
            amount: formatMinor(writ.amountMinor),
            result: "DECLINED",
            code: resultCode(got),
            reason: got.reason,
          });
        }
      }
    }
    await pause();

    // 8. $6,000 on ops. The ring fence leaves this under the floor.
    {
      const scene = "Reserve";
      const before = latest ?? (await getState(scene));
      const live = before.reserve.liveBalanceMinor;
      error(
        `ops-1 asks for ${formatMinor(ENCLAVE_DEMO.reserveMinor)}. ${live === null ? "Live balance not reported" : `Live ${formatMinor(live)}`}, ring fence ${formatMinor(before.reserve.ringFenceMinor)}, floor ${formatMinor(before.reserve.reserveFloorMinor)}.`,
      );
      const writ = sign({
        team: "ops",
        agent: "ops-1",
        amountMinor: ENCLAVE_DEMO.reserveMinor,
        purpose: "Would breach the cash reserve",
      });
      await emitApproval(scene, writ);
      const got = await postWrit(scene, writ);
      expectStatus(scene, got, "DECLINED", ["RESERVE_FLOOR"]);
      await emitDecision(scene, got);
      await getState(scene);
      remember({
        scene,
        agent: writ.agent,
        task: writ.purpose,
        amount: formatMinor(writ.amountMinor),
        result: "DECLINED",
        code: resultCode(got),
        reason: got.reason,
      });
    }
    await pause();

    await finish(true);
    return rows;
  } catch (err) {
    await finish(false);
    throw err;
  }

  async function postTaintEvent(event: TaintEvent, signature: string): Promise<void> {
    try {
      const body = await call("POST", `${base}${ENCLAVE_DEMO.paths.taint}`, { event, signature }, 10_000, true);
      if (isObj(body) && body.ok === false) {
        const reason = typeof body.reason === "string" ? body.reason : "enclave rejected the taint event";
        throw new Error(reason);
      }
    } catch (e) {
      throw toScene("Taint", e);
    }
  }

  async function postInterceptor(url: string, event: TaintEvent): Promise<void> {
    try {
      const body = await call("POST", url, { event, url: ENCLAVE_DEMO.taintUrl }, 10_000, true);
      if (isObj(body) && body.ok === false) {
        const reason = typeof body.reason === "string" ? body.reason : "AgentCore interceptor rejected the taint";
        throw new Error(reason);
      }
    } catch (e) {
      throw toScene("Taint", e);
    }
  }
}

function taintPlan(env: Record<string, string | undefined>): { kind: "kms" } | { kind: "interceptor"; url: string } | { kind: "skip"; reason: string } {
  if (env.WRIT_TAINT_SIGN === "kms") return { kind: "kms" };
  const signer = env.WRIT_TAINT_SIGNER?.trim() ?? "";
  if (signer === "") {
    return { kind: "skip", reason: "WRIT_TAINT_SIGNER is not set. The Mac cannot sign a taint event." };
  }
  let url: string;
  try {
    url = normalizeEnclaveBase(signer);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes("https")) throw new SceneFail("Taint", "WRIT_TAINT_SIGNER must use https.");
    throw new SceneFail("Taint", "WRIT_TAINT_SIGNER must be the AgentCore interceptor https URL.");
  }
  return { kind: "interceptor", url };
}

export async function runEnclaveDemoFromArgv(argv: string[]): Promise<number> {
  if (argv.includes("--replay")) {
    console.error("Replay is bun run demo --replay. Drop --replay for --host enclave.");
    return 1;
  }
  const flag = argv.indexOf("--card-map");
  let cardMapPath = defaultCardMapPath();
  if (flag >= 0) {
    const value = argv[flag + 1];
    if (value === undefined || value.startsWith("--")) {
      console.error("--card-map needs a json path.");
      return 1;
    }
    cardMapPath = value;
  }
  const keyPath = join(homedir(), ".writ", "demo-approver.key");
  if (!existsSync(keyPath)) {
    console.error(`No demo approver key at ${keyPath}.`);
    return 1;
  }
  let pem: string;
  try {
    pem = readFileSync(keyPath, "utf8");
  } catch {
    console.error(`Could not read demo approver key at ${keyPath}.`);
    return 1;
  }
  if (!pem.includes("PRIVATE KEY")) {
    console.error(`Demo approver key at ${keyPath} is not a PEM private key.`);
    return 1;
  }
  let cardIds: Record<string, string>;
  try {
    cardIds = loadCardMapFile(cardMapPath);
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    return 1;
  }
  const built = buildPlainAdapter({
    log: (line) => console.error(maskIds(line)),
  });
  if (!built.ok) {
    console.error(`Airwallex: ${built.error.message}`);
    return 1;
  }
  const adapter = built.value;
  const feed = makeEmitter({ url: defaultConsoleUrl(), fetchImpl: globalThis.fetch });
  try {
    await runEnclaveDemo({
      fetchImpl: globalThis.fetch,
      feed,
      swipe: (spec) => adapter.simulateSwipe(spec),
      recoverSwipe: (cardId, since) => adapter.readTransaction(cardId, since),
      listTransactions: (cardId, since) => adapter.listTransactions(cardId, since),
      reverseSwipe: (lifecycleId, amountMinor) => adapter.reverseSwipe(lifecycleId, amountMinor),
      writeReverseFixture: writeReverseFixtureFile,
      cleanup: argv.includes("--cleanup"),
      privateKeyPem: pem,
      cardIds,
      cardMapSource: cardMapPath,
      env: process.env,
    });
    return 0;
  } catch (err) {
    if (err instanceof SceneFail) {
      console.error(`${err.scene} failed: ${err.message}`);
      return 1;
    }
    console.error(`demo failed: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
}

if (import.meta.main) {
  process.exit(await runEnclaveDemoFromArgv(process.argv));
}
