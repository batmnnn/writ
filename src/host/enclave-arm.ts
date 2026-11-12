// In-enclave step after a successful unseal: one S3 checkpoint, then arm one card, prove the limit
// with two sandbox swipes, and disarm it.
// Runs with the unsealed Airwallex key still in memory and zeroes it before returning.
// Network goes through the loopback bridges in enclave/boot.sh, so TLS ends here, not on the host.
// Nothing in this file logs. Results carry a code only, never a key, credential, token or body.

import { createHash, createHmac, randomUUID } from "node:crypto";
import { GENESIS_PREV, entryHash } from "../core/chain";
import { canonicalJson } from "../core/writ";
import { minorToMajor } from "../airwallex/units";
import type { AwsCredentials } from "./kms-unseal";
import type { ArmOrder } from "./enclave-serve";
import type { S3Client, S3PutRequest, S3PutResponse, S3Store } from "./s3-committer";

export const LEDGER_BUCKET = "writ-ledger-401046276943";
export const S3_REGION = "us-west-2";
export const S3_HOST = `s3.${S3_REGION}.amazonaws.com`;
export const AIRWALLEX_BASE = "https://api.sandbox.airwallex.com";
export const ARM_AMOUNT_MINOR = 100;
export const ARM_MCC = "5734";
export const ARM_CURRENCY = "USD";
export const ARM_MERCHANT = "DataCo";
export const OVER_LIMIT_MINOR = 200;
const FETCH_TIMEOUT_MS = 5_000;

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface FetchInit {
  method: string;
  headers: Record<string, string>;
  body?: string;
}
export interface FetchReply {
  status: number;
  text(): Promise<string>;
}
export type FetchLike = (url: string, init: FetchInit) => Promise<FetchReply>;

export interface ArmDeps {
  fetch: FetchLike;
  now(): Date;
  uuid(): string;
}

export interface ArmTarget {
  cardId: string;
  clientId: string;
}

export type ArmCode = "BAD_INPUT" | "COMMIT_FAILED" | "ARM_FAILED";
export type ArmResult = { ok: true } | { ok: false; code: ArmCode };

/** Real fetch with a time limit and no redirects. */
export const timedFetch: FetchLike = async (url, init) => {
  const res = await fetch(url, { ...init, redirect: "error", signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  return { status: res.status, text: () => res.text() };
};

export const enclaveArmDeps: ArmDeps = { fetch: timedFetch, now: () => new Date(), uuid: () => randomUUID() };

const sha256Hex = (data: string | Uint8Array): string => createHash("sha256").update(data).digest("hex");
const hmac = (key: Uint8Array | string, data: string): Buffer => createHmac("sha256", key).update(data).digest();

/** 2026-11-11T03:43:00.123Z -> 20261111T034300Z */
export function amzDate(d: Date): string {
  return d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
}

export interface SigV4Request {
  method: string;
  path: string;
  /** Lowercase names. Must include host and x-amz-date. Every header given here is signed. */
  headers: Record<string, string>;
  payloadSha256: string;
  region: string;
  service: string;
  credentials: Pick<AwsCredentials, "accessKeyId" | "secretAccessKey">;
  /** Query parameters, unencoded. Sorted and RFC 3986 encoded here. */
  query?: Record<string, string>;
}

const rfc3986 = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

/** Canonical query string: keys sorted by code unit, both sides RFC 3986 encoded. */
export function canonicalQuery(query: Record<string, string> | undefined): string {
  if (!query) return "";
  return Object.keys(query)
    .sort()
    .map((k) => `${rfc3986(k)}=${rfc3986(query[k]!)}`)
    .join("&");
}

/** AWS Signature Version 4 Authorization header value. */
export function sigV4Authorization(req: SigV4Request): string {
  const names = Object.keys(req.headers).map((k) => k.toLowerCase()).sort();
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) lower[k.toLowerCase()] = v.trim().replace(/\s+/g, " ");
  const date = lower["x-amz-date"];
  if (typeof date !== "string" || !/^\d{8}T\d{6}Z$/.test(date)) throw new Error("x-amz-date missing");
  const signedHeaders = names.join(";");
  const canonical = [
    req.method,
    req.path,
    canonicalQuery(req.query),
    ...names.map((n) => `${n}:${lower[n]}`),
    "",
    signedHeaders,
    req.payloadSha256,
  ].join("\n");
  const day = date.slice(0, 8);
  const scope = `${day}/${req.region}/${req.service}/aws4_request`;
  const toSign = ["AWS4-HMAC-SHA256", date, scope, sha256Hex(canonical)].join("\n");
  const kDate = hmac(`AWS4${req.credentials.secretAccessKey}`, day);
  const kRegion = hmac(kDate, req.region);
  const kService = hmac(kRegion, req.service);
  const kSigning = hmac(kService, "aws4_request");
  const signature = createHmac("sha256", kSigning).update(toSign).digest("hex");
  return `AWS4-HMAC-SHA256 Credential=${req.credentials.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}

/** Body of the arm checkpoint: canonical JSON, keys sorted. */
export function armCheckpointBody(cardId: string): string {
  return canonicalJson({ seq: 1, prev: GENESIS_PREV, kind: "arm", cardId, amountMinor: ARM_AMOUNT_MINOR });
}

/** Chain hash of the same entry. The enclave has no trusted clock, so at is 0 and the hash is reproducible from the body. */
export function armCheckpointHash(cardId: string): string {
  return entryHash(GENESIS_PREV, { seq: 1, prev: GENESIS_PREV, at: 0, kind: "arm", payload: { cardId, amountMinor: ARM_AMOUNT_MINOR } });
}

/** Conditional PUT of the checkpoint. Only 200 or 201 is a commit; 412 (key already there) is a failure. */
export async function putArmCheckpoint(cardId: string, credentials: AwsCredentials, deps: ArmDeps): Promise<boolean> {
  const body = armCheckpointBody(cardId);
  const path = `/${LEDGER_BUCKET}/checkpoints/arm/${encodeURIComponent(cardId)}.json`;
  const payloadSha256 = sha256Hex(body);
  const headers: Record<string, string> = {
    "content-md5": createHash("md5").update(body).digest("base64"),
    "content-type": "application/json",
    host: S3_HOST,
    "if-none-match": "*",
    "x-amz-content-sha256": payloadSha256,
    "x-amz-date": amzDate(deps.now()),
    "x-amz-meta-entry-hash": armCheckpointHash(cardId),
    "x-amz-security-token": credentials.sessionToken,
  };
  const authorization = sigV4Authorization({ method: "PUT", path, headers, payloadSha256, region: S3_REGION, service: "s3", credentials });
  const { host: _host, ...sent } = headers;
  const res = await deps.fetch(`https://${S3_HOST}${path}`, { method: "PUT", headers: { ...sent, authorization }, body });
  await res.text().catch(() => "");
  return res.status === 200 || res.status === 201;
}

export interface S3PutDeps {
  fetch: FetchLike;
  /** Signing time. Undefined (no trusted time yet) refuses the put. */
  now(): Date | undefined;
}

/** S3Client for S3CheckpointCommitter: the same signed conditional PUT as putArmCheckpoint, for any key. */
export function sigV4S3Client(credentials: AwsCredentials, deps: S3PutDeps): S3Client {
  return {
    async putObject(req: S3PutRequest): Promise<S3PutResponse> {
      const at = deps.now();
      if (at === undefined || Number.isNaN(at.getTime())) throw new Error("no trusted time to sign the checkpoint");
      const path = `/${encodeURIComponent(req.bucket)}/${req.key.split("/").map(encodeURIComponent).join("/")}`;
      const payloadSha256 = sha256Hex(req.body);
      const headers: Record<string, string> = {
        "content-md5": createHash("md5").update(req.body).digest("base64"),
        "content-type": req.contentType,
        host: S3_HOST,
        "if-none-match": req.ifNoneMatch,
        "x-amz-content-sha256": payloadSha256,
        "x-amz-date": amzDate(at),
        "x-amz-security-token": credentials.sessionToken,
      };
      const authorization = sigV4Authorization({ method: "PUT", path, headers, payloadSha256, region: S3_REGION, service: "s3", credentials });
      const { host: _host, ...sent } = headers;
      const res = await deps.fetch(`https://${S3_HOST}${path}`, { method: "PUT", headers: { ...sent, authorization }, body: req.body });
      await res.text().catch(() => "");
      return { status: res.status };
    },
  };
}

const EMPTY_SHA256 = sha256Hex("");
const MAX_LIST_PAGES = 100;
const MAX_S3_BODY_CHARS = 1024 * 1024;

const xmlText = (s: string) =>
  s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");

export interface S3StoreDeps {
  fetch: FetchLike;
  /** Signing time. Undefined (no trusted time yet) refuses every call. */
  now(): Date | undefined;
}

/**
 * Signed S3 client for the ledger bucket: conditional PUT, ListObjectsV2 and GET, all through the S3
 * bridge so TLS ends in the enclave. Credentials are read per call, so a refresh from the host takes
 * effect at once. No credentials, or no trusted time, throws before anything is sent.
 */
export function sigV4S3Store(credentials: () => AwsCredentials | undefined, deps: S3StoreDeps): S3Store {
  const signed = async (method: "GET" | "PUT", path: string, query: Record<string, string> | undefined, extra: Record<string, string>, body?: string) => {
    const creds = credentials();
    if (creds === undefined) throw new Error("no AWS credentials");
    const at = deps.now();
    if (at === undefined || Number.isNaN(at.getTime())) throw new Error("no trusted time to sign the request");
    const payloadSha256 = body === undefined ? EMPTY_SHA256 : sha256Hex(body);
    const headers: Record<string, string> = {
      ...extra,
      host: S3_HOST,
      "x-amz-content-sha256": payloadSha256,
      "x-amz-date": amzDate(at),
      "x-amz-security-token": creds.sessionToken,
    };
    const authorization = sigV4Authorization({ method, path, headers, payloadSha256, region: S3_REGION, service: "s3", credentials: creds, ...(query ? { query } : {}) });
    const { host: _host, ...sent } = headers;
    const qs = canonicalQuery(query);
    return deps.fetch(`https://${S3_HOST}${path}${qs ? `?${qs}` : ""}`, { method, headers: { ...sent, authorization }, ...(body !== undefined ? { body } : {}) });
  };
  const objectPath = (bucket: string, key: string) => `/${encodeURIComponent(bucket)}/${key.split("/").map(encodeURIComponent).join("/")}`;
  return {
    async putObject(req: S3PutRequest): Promise<S3PutResponse> {
      const res = await signed(
        "PUT",
        objectPath(req.bucket, req.key),
        undefined,
        { "content-md5": createHash("md5").update(req.body).digest("base64"), "content-type": req.contentType, "if-none-match": req.ifNoneMatch },
        req.body,
      );
      await res.text().catch(() => "");
      return { status: res.status };
    },
    async listKeys(bucket: string, prefix: string): Promise<string[]> {
      const keys: string[] = [];
      let token: string | undefined;
      for (let page = 0; page < MAX_LIST_PAGES; page++) {
        const query: Record<string, string> = { "list-type": "2", prefix };
        if (token !== undefined) query["continuation-token"] = token;
        const res = await signed("GET", `/${encodeURIComponent(bucket)}`, query, {});
        const text = await res.text();
        if (res.status !== 200) throw new Error(`list refused with status ${res.status}`);
        if (text.length > MAX_S3_BODY_CHARS) throw new Error("list reply too large");
        for (const m of text.matchAll(/<Key>([^<]*)<\/Key>/g)) keys.push(xmlText(m[1]!));
        if (!/<IsTruncated>true<\/IsTruncated>/.test(text)) return keys;
        const next = /<NextContinuationToken>([^<]+)<\/NextContinuationToken>/.exec(text)?.[1];
        if (next === undefined) throw new Error("list is truncated with no continuation token");
        token = xmlText(next);
      }
      throw new Error("list has too many pages");
    },
    async getObject(bucket: string, key: string): Promise<string | undefined> {
      const res = await signed("GET", objectPath(bucket, key), undefined, {});
      const text = await res.text();
      if (res.status === 404) return undefined;
      if (res.status !== 200) throw new Error(`get refused with status ${res.status}`);
      if (text.length > MAX_S3_BODY_CHARS) throw new Error("object too large");
      return text;
    },
  };
}

const ok2xx = (status: number) => status >= 200 && status < 300;

async function login(clientId: string, key: Uint8Array, deps: ArmDeps): Promise<string | undefined> {
  const keyBuf = Buffer.from(key);
  try {
    const res = await deps.fetch(`${AIRWALLEX_BASE}/api/v1/authentication/login`, {
      method: "POST",
      headers: { "x-client-id": clientId, "x-api-key": keyBuf.toString("utf8") },
    });
    const text = await res.text();
    if (!ok2xx(res.status)) return undefined;
    const token = (JSON.parse(text) as { token?: unknown }).token;
    return typeof token === "string" && token.length > 0 ? token : undefined;
  } finally {
    keyBuf.fill(0);
  }
}

async function updateCard(cardId: string, token: string, body: Record<string, unknown>, deps: Pick<ArmDeps, "fetch">): Promise<boolean> {
  const res = await deps.fetch(`${AIRWALLEX_BASE}/api/v1/issuing/cards/${encodeURIComponent(cardId)}/update`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  await res.text().catch(() => "");
  return ok2xx(res.status);
}

/** ACTIVE body for one swipe of at most ARM_AMOUNT_MINOR. Amount is major units, from units.ts. */
export function activeBody(requestId: string): Record<string, unknown> | undefined {
  const amount = minorToMajor(ARM_AMOUNT_MINOR);
  if (amount === undefined) return undefined;
  return {
    request_id: requestId,
    card_status: "ACTIVE",
    authorization_controls: {
      transaction_limits: {
        currency: ARM_CURRENCY,
        limits: [
          { amount, interval: "PER_TRANSACTION" },
          { amount, interval: "ALL_TIME" },
        ],
      },
      allowed_currencies: [ARM_CURRENCY],
      allowed_merchant_categories: [ARM_MCC],
    },
  };
}

/** ACTIVE body for one order from EnclaveServe: both limits equal the writ amount, its one MCC, its one currency. */
export function orderActiveBody(order: ArmOrder, requestId: string): Record<string, unknown> | undefined {
  const amount = minorToMajor(order.amountMinor);
  if (amount === undefined || order.amountMinor <= 0) return undefined;
  return {
    request_id: requestId,
    card_status: "ACTIVE",
    authorization_controls: {
      transaction_limits: {
        currency: order.currency,
        limits: [
          { amount, interval: "PER_TRANSACTION" },
          { amount, interval: "ALL_TIME" },
        ],
      },
      allowed_currencies: [order.currency],
      allowed_merchant_categories: [order.mcc],
    },
  };
}

/**
 * Arms one card for an order EnclaveServe has already authorized and checkpointed. Only EnclaveServe's
 * armCard calls this. A failed ACTIVE tries INACTIVE once so the card stays frozen. Any throw is false.
 */
export async function armOrderCard(order: ArmOrder, token: string, deps: Pick<ArmDeps, "fetch" | "uuid">): Promise<boolean> {
  if (!UUID_RE.test(order.cardId)) return false;
  const body = orderActiveBody(order, deps.uuid());
  if (body === undefined) return false;
  let armed = false;
  try {
    armed = await updateCard(order.cardId, token, body, deps);
  } catch {
    armed = false;
  }
  if (armed) return true;
  try {
    await updateCard(order.cardId, token, { request_id: deps.uuid(), card_status: "INACTIVE" }, deps);
  } catch {
    // the card was never confirmed ACTIVE
  }
  return false;
}

/** One INACTIVE update with a fresh request_id. Any non 2xx or throw is false, and the caller retries. */
export async function disarmCard(cardId: string, token: string, deps: Pick<ArmDeps, "fetch" | "uuid">): Promise<boolean> {
  if (!UUID_RE.test(cardId)) return false;
  try {
    return await updateCard(cardId, token, { request_id: deps.uuid(), card_status: "INACTIVE" }, deps);
  } catch {
    return false;
  }
}

export type SwipeVerdict = "APPROVED" | "DECLINED" | "UNKNOWN";

/**
 * Reads a simulation/issuing/create reply. Same fields as toOutcome in rest-adapter.ts, but here an
 * approved AUTHORIZATION counts: the card is never cleared in this step.
 * FAILED, DECLINED or any failure_reason is DECLINED. APPROVED, or type AUTHORIZATION with no
 * failure_reason, is APPROVED. Anything else is UNKNOWN.
 */
export function swipeVerdict(tx: unknown): SwipeVerdict {
  if (typeof tx !== "object" || tx === null || Array.isArray(tx)) return "UNKNOWN";
  const t = tx as Record<string, unknown>;
  const str = (v: unknown) => (typeof v === "string" && v.length > 0 ? v : undefined);
  const type = str(t.type) ?? str(t.transaction_type);
  const status = str(t.process_result) ?? str(t.status);
  if (status === "FAILED" || status === "DECLINED" || str(t.failure_reason) !== undefined) return "DECLINED";
  // A held authorization comes back PENDING, not APPROVED. A clearing is not this swipe.
  if (type === "CLEARING") return "UNKNOWN";
  if (status === "APPROVED" || status === "PENDING" || (type === "AUTHORIZATION" && status === undefined)) return "APPROVED";
  return "UNKNOWN";
}

/** One sandbox swipe. HTTP status alone decides nothing: a non 2xx, bad JSON or a throw is UNKNOWN. */
async function simulateSwipe(cardId: string, token: string, amountMinor: number, deps: ArmDeps): Promise<SwipeVerdict> {
  const amount = minorToMajor(amountMinor);
  if (amount === undefined) return "UNKNOWN";
  try {
    const res = await deps.fetch(`${AIRWALLEX_BASE}/api/v1/simulation/issuing/create`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({
        card_id: cardId,
        transaction_amount: amount,
        transaction_currency: ARM_CURRENCY,
        merchant_category_code: ARM_MCC,
        merchant_info: ARM_MERCHANT,
      }),
    });
    const text = await res.text();
    if (!ok2xx(res.status)) return "UNKNOWN";
    return swipeVerdict(JSON.parse(text));
  } catch {
    return "UNKNOWN";
  }
}

/**
 * Checkpoint, login, ACTIVE, a $1 swipe that must be approved, a $2 swipe over the limit that must
 * be declined, INACTIVE. A failed checkpoint stops before Airwallex. A failed ACTIVE skips the swipes
 * and still tries INACTIVE once. A failed swipe check never skips INACTIVE. Any throw is ARM_FAILED
 * (or COMMIT_FAILED before the commit landed). The key is zeroed on every path.
 */
export async function armAfterUnseal(key: Uint8Array, target: ArmTarget, credentials: AwsCredentials, deps: ArmDeps): Promise<ArmResult> {
  try {
    if (!UUID_RE.test(target.cardId) || target.clientId.length === 0) return { ok: false, code: "BAD_INPUT" };

    let committed = false;
    try {
      committed = await putArmCheckpoint(target.cardId, credentials, deps);
    } catch {
      committed = false;
    }
    if (!committed) return { ok: false, code: "COMMIT_FAILED" };

    try {
      const token = await login(target.clientId, key, deps);
      key.fill(0);
      if (token === undefined) return { ok: false, code: "ARM_FAILED" };

      let armed = false;
      const active = activeBody(deps.uuid());
      if (active !== undefined) {
        try {
          armed = await updateCard(target.cardId, token, active, deps);
        } catch {
          armed = false;
        }
      }
      let swipesOk = false;
      if (armed) {
        const small = await simulateSwipe(target.cardId, token, ARM_AMOUNT_MINOR, deps);
        const over = await simulateSwipe(target.cardId, token, OVER_LIMIT_MINOR, deps);
        swipesOk = small === "APPROVED" && over === "DECLINED";
      }
      const disarmed = await updateCard(target.cardId, token, { request_id: deps.uuid(), card_status: "INACTIVE" }, deps);
      return armed && swipesOk && disarmed ? { ok: true } : { ok: false, code: "ARM_FAILED" };
    } catch {
      return { ok: false, code: "ARM_FAILED" };
    }
  } finally {
    key.fill(0);
  }
}
