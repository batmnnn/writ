import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { canonicalQuery, sigV4Authorization, sigV4S3Store, type FetchInit } from "../src/host/enclave-arm";
import { CredentialBox, parseCredsLine } from "../src/host/enclave-creds";
import { deriveLedgerSigner } from "../src/host/enclave-keys";
import { S3CheckpointCommitter, SIGNED_CHECKPOINT_PREFIX, loadSignedChain } from "../src/host/s3-committer";
import { FakeS3Store } from "./fake-s3";

const root = join(import.meta.dir, "..");
const CREDS = { accessKeyId: "ASIAFAKEFAKEFAKE", secretAccessKey: "fake-secret-not-a-real-key", sessionToken: "fake-session-token" };
const AT = new Date("2026-11-12T08:35:00.000Z");

function recorder(replies: { status: number; body: string }[]) {
  const calls: { url: string; init: FetchInit }[] = [];
  const fetch = async (url: string, init: FetchInit) => {
    calls.push({ url, init });
    const r = replies.shift() ?? { status: 500, body: "" };
    return { status: r.status, text: async () => r.body };
  };
  return { calls, fetch };
}

describe("signed S3 store", () => {
  test("canonical query sorts keys and RFC 3986 encodes both sides", () => {
    expect(canonicalQuery({ prefix: "checkpoints/v2/", "list-type": "2", "continuation-token": "a+b=c!" })).toBe(
      "continuation-token=a%2Bb%3Dc%21&list-type=2&prefix=checkpoints%2Fv2%2F",
    );
    expect(canonicalQuery(undefined)).toBe("");
  });

  test("the query is part of the signature", () => {
    const base = { method: "GET", path: "/b", headers: { host: "s3.us-west-2.amazonaws.com", "x-amz-date": "20261112T083500Z", "x-amz-content-sha256": "e3b0" }, payloadSha256: "e3b0", region: "us-west-2", service: "s3", credentials: CREDS };
    expect(sigV4Authorization({ ...base, query: { prefix: "a" } })).not.toBe(sigV4Authorization({ ...base, query: { prefix: "b" } }));
    expect(sigV4Authorization(base)).toBe(sigV4Authorization({ ...base }));
  });

  test("listKeys follows continuation tokens and signs each page", async () => {
    const page1 = `<ListBucketResult><IsTruncated>true</IsTruncated><Contents><Key>checkpoints/v2/000000000001.json</Key></Contents><NextContinuationToken>tok&amp;1</NextContinuationToken></ListBucketResult>`;
    const page2 = `<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>checkpoints/v2/000000000002.json</Key></Contents></ListBucketResult>`;
    const r = recorder([{ status: 200, body: page1 }, { status: 200, body: page2 }]);
    const store = sigV4S3Store(() => CREDS, { fetch: r.fetch, now: () => AT });
    expect(await store.listKeys("writ-ledger", "checkpoints/v2/")).toEqual(["checkpoints/v2/000000000001.json", "checkpoints/v2/000000000002.json"]);
    expect(r.calls[0]!.url).toBe("https://s3.us-west-2.amazonaws.com/writ-ledger?list-type=2&prefix=checkpoints%2Fv2%2F");
    expect(r.calls[1]!.url).toContain("continuation-token=tok%261");
    for (const c of r.calls) {
      expect(c.init.method).toBe("GET");
      expect(c.init.headers.authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=ASIAFAKEFAKEFAKE\/20261112\/us-west-2\/s3\/aws4_request/);
      expect(c.init.headers["x-amz-security-token"]).toBe(CREDS.sessionToken);
      expect(JSON.stringify(c.init.headers)).not.toContain(CREDS.secretAccessKey);
    }
  });

  test("a refused list throws, a 404 get is undefined, any other get failure throws", async () => {
    const store = sigV4S3Store(() => CREDS, { fetch: recorder([{ status: 403, body: "" }, { status: 404, body: "" }, { status: 500, body: "" }]).fetch, now: () => AT });
    await expect(store.listKeys("b", "p/")).rejects.toThrow(/403/);
    expect(await store.getObject("b", "k")).toBeUndefined();
    await expect(store.getObject("b", "k")).rejects.toThrow(/500/);
  });

  test("no credentials or no trusted time sends nothing", async () => {
    const r = recorder([]);
    await expect(sigV4S3Store(() => undefined, { fetch: r.fetch, now: () => AT }).listKeys("b", "p/")).rejects.toThrow(/credentials/);
    await expect(sigV4S3Store(() => CREDS, { fetch: r.fetch, now: () => undefined }).getObject("b", "k")).rejects.toThrow(/time/);
    expect(r.calls.length).toBe(0);
  });

  test("PUT keeps If-None-Match: * and a content MD5", async () => {
    const r = recorder([{ status: 200, body: "" }]);
    const store = sigV4S3Store(() => CREDS, { fetch: r.fetch, now: () => AT });
    expect(await store.putObject({ bucket: "b", key: "checkpoints/v2/000000000001.json", body: "{}", contentType: "application/json", ifNoneMatch: "*" })).toEqual({ status: 200 });
    expect(r.calls[0]!.init.headers["if-none-match"]).toBe("*");
    expect(r.calls[0]!.init.headers["content-md5"]).toBeDefined();
    expect(r.calls[0]!.init.headers["x-amz-meta-retention"]).toBeUndefined();
  });

  test("signed checkpoints written by the committer load back, and an empty prefix is an empty chain", async () => {
    const signer = deriveLedgerSigner(new TextEncoder().encode("k"));
    const store = new FakeS3Store();
    expect(await loadSignedChain(store, "b", SIGNED_CHECKPOINT_PREFIX, signer.publicKeyRaw)).toEqual({ ok: true, entries: [] });
    const c = new S3CheckpointCommitter({ client: store, bucket: "b", prefix: SIGNED_CHECKPOINT_PREFIX, signer });
    expect(await c.append("alert", { eventId: "a-1", cardId: "c" }, "2026-11-12T08:35:00.000Z")).toMatchObject({ ok: true, seq: 1 });
    expect(await c.append("alert", { eventId: "a-1", cardId: "c" }, "2026-11-12T08:35:00.000Z")).toMatchObject({ ok: false, replay: true });
    expect(await c.append("consume", { eventId: "a-2" }, "2026-11-12T08:35:00.000Z")).toMatchObject({ ok: false });
    const loaded = await loadSignedChain(store, "b", SIGNED_CHECKPOINT_PREFIX, signer.publicKeyRaw);
    expect(loaded.ok && loaded.entries.length).toBe(1);
    const other = deriveLedgerSigner(new TextEncoder().encode("other"));
    expect((await loadSignedChain(store, "b", SIGNED_CHECKPOINT_PREFIX, other.publicKeyRaw)).ok).toBe(false);
  });
});

describe("credential refresh parsing", () => {
  const now = Date.parse("2026-11-12T08:35:00.000Z");
  const line = (o: Record<string, unknown>) => new TextEncoder().encode(JSON.stringify(o));
  const good = { accessKeyId: "ASIAREFRESHEDKEY0001", secretAccessKey: "refreshed-secret-value-0001", sessionToken: "refreshed-session-token-0001", expiration: "2026-11-12T14:00:00Z" };

  test("takes exactly the four fields with a future expiration", () => {
    const r = parseCredsLine(line(good), now);
    expect(r.ok).toBe(true);
    expect(parseCredsLine(line({ ...good, expiration: "2026-11-12T08:00:00Z" }), now)).toEqual({ ok: false, code: "EXPIRED" });
    expect(parseCredsLine(line(good), Number.NaN)).toEqual({ ok: false, code: "NO_CLOCK" });
    for (const bad of [{ ...good, extra: 1 }, { ...good, accessKeyId: "lower case" }, { ...good, sessionToken: "short" }, { ...good, expiration: "tomorrow" }]) {
      expect(parseCredsLine(line(bad), now)).toEqual({ ok: false, code: "BAD_INPUT" });
    }
    expect(parseCredsLine(new Uint8Array([0xff, 0xfe]), now)).toEqual({ ok: false, code: "BAD_INPUT" });
  });

  test("the box hides credentials once they expire on the enclave clock", () => {
    let t = now;
    const box = new CredentialBox(CREDS, () => t);
    expect(box.get()).toEqual(CREDS);
    box.set(CREDS, now + 1_000);
    expect(box.get()).toEqual(CREDS);
    t = now + 1_000;
    expect(box.get()).toBeUndefined();
  });
});

describe("scripts/host-refresh-creds.sh", () => {
  const path = join(root, "scripts/host-refresh-creds.sh");

  test("is executable, uses IMDSv2 and vsock 5001, and never echoes a credential", () => {
    expect(statSync(path).mode & 0o777).toBe(0o755);
    const s = readFileSync(path, "utf8");
    expect(s).toContain('"$imds/api/token"');
    expect(s).toContain("X-aws-ec2-metadata-token-ttl-seconds");
    expect(s).toContain('VSOCK-CONNECT:${cid}:${port}');
    expect(s).toContain('cid="${WRIT_ENCLAVE_CID:-16}"');
    expect(s).toContain("port=5001");
    const live = s.split("\n").filter((l) => !l.trim().startsWith("#"));
    for (const l of live.filter((x) => /^\s*echo /.test(x))) expect(l).not.toMatch(/\$(creds|line|token)|AccessKey|Secret|sessionToken/i);
    expect(s.includes("--" + "debug-mode")).toBe(false);
    expect(s.includes("\u2014")).toBe(false);
  });

  test("exits 2 and sends nothing off the enclave host", () => {
    const r = spawnSync("/bin/bash", [path], { encoding: "utf8", env: { PATH: "/usr/bin:/bin" } });
    expect(r.status).toBe(2);
    expect(r.stdout).toBe("");
  });

  test("refuses a debug flag", () => {
    const r = spawnSync("/bin/bash", [path, "--" + "debug-mode"], { encoding: "utf8", env: { PATH: "/usr/bin:/bin" } });
    expect(r.status).toBe(1);
  });
});
