// S3 checkpoint committer with an injected fake client. No network, no AWS, no keys.

import { describe, expect, test } from "bun:test";
import { GENESIS_PREV, verifyChain, type ChainEntry } from "../src/core/chain";
import type { ConsumeEntry } from "../src/core/committer";
import { S3CheckpointCommitter, type S3Client, type S3PutRequest } from "../src/host/s3-committer";
import { NOW, signed } from "./helpers";

class FakeS3 implements S3Client {
  objects = new Map<string, string>();
  puts: S3PutRequest[] = [];
  mode: "normal" | "throw412" | "status500" | "network" = "normal";

  async putObject(req: S3PutRequest): Promise<{ status: number }> {
    this.puts.push(req);
    if (this.mode === "network") throw new Error("socket closed");
    if (this.mode === "status500") return { status: 500 };
    if (this.mode === "throw412") throw Object.assign(new Error("PreconditionFailed"), { $metadata: { httpStatusCode: 412 } });
    if (req.ifNoneMatch === "*" && this.objects.has(req.key)) return { status: 412 };
    this.objects.set(req.key, req.body);
    return { status: 200 };
  }
}

function entry(eventId: string, over: Partial<ConsumeEntry> = {}): ConsumeEntry {
  return {
    eventId,
    writ: signed({ id: `writ-${eventId}` }),
    cardId: "card-1",
    amountMinor: 12345,
    at: NOW,
    decision: { status: "AUTHORIZED", writId: `writ-${eventId}`, reason: "ok" },
    ...over,
  };
}

function make(client = new FakeS3(), resume?: ChainEntry[]) {
  const opts = { client, bucket: "test-bucket", prefix: "chk", ...(resume ? { resume } : {}) };
  return { client, committer: new S3CheckpointCommitter(opts) };
}

describe("S3CheckpointCommitter", () => {
  test("ok only after the conditional PUT is accepted", async () => {
    const { client, committer } = make();
    const res = await committer.commit(entry("e1"));
    expect(res).toEqual({ ok: true });
    expect(client.puts).toHaveLength(1);
    expect(client.puts[0]?.ifNoneMatch).toBe("*");
    expect(client.puts[0]?.bucket).toBe("test-bucket");
    expect(client.objects.has("chk/000000000001.json")).toBe(true);
  });

  test("sends no retention or lock fields", async () => {
    const { client, committer } = make();
    await committer.commit(entry("e1"));
    const keys = Object.keys(client.puts[0] ?? {}).sort();
    expect(keys).toEqual(["body", "bucket", "contentType", "ifNoneMatch", "key"]);
  });

  test("checkpoint body uses the chain hash and carries integer cents unchanged", async () => {
    const { client, committer } = make();
    await committer.commit(entry("e1"));
    await committer.commit(entry("e2", { amountMinor: 700 }));
    const bodies = [...client.objects.values()].map((b) => JSON.parse(b) as { seq: number; head: string; entry: ChainEntry });
    expect(bodies.map((b) => b.seq)).toEqual([1, 2]);
    expect(bodies[0]?.entry.prev).toBe(GENESIS_PREV);
    expect(bodies[1]?.entry.prev).toBe(bodies[0]?.head ?? "");
    const chain = bodies.map((b) => b.entry);
    expect(verifyChain(chain).ok).toBe(true);
    expect((chain[0]?.payload as { amountMinor: number }).amountMinor).toBe(12345);
    expect((chain[1]?.payload as { amountMinor: number }).amountMinor).toBe(700);
  });

  test("a 412 status is ok: false and local state does not move", async () => {
    const { client, committer } = make();
    client.objects.set("chk/000000000001.json", "{}");
    const res = await committer.commit(entry("e1"));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toContain("412");
    // Same seq again: still 412, never success.
    const again = await committer.commit(entry("e1"));
    expect(again.ok).toBe(false);
    expect(client.puts.map((p) => p.key)).toEqual(["chk/000000000001.json", "chk/000000000001.json"]);
    expect(client.objects.get("chk/000000000001.json")).toBe("{}");
  });

  test("a client that throws on 412 is ok: false too", async () => {
    const { client, committer } = make();
    client.mode = "throw412";
    const res = await committer.commit(entry("e1"));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toContain("412");
  });

  test("a second writer on the same seq gets 412 and fails", async () => {
    const client = new FakeS3();
    const a = make(client).committer;
    const b = make(client).committer;
    expect(await a.commit(entry("a1"))).toEqual({ ok: true });
    const res = await b.commit(entry("b1"));
    expect(res.ok).toBe(false);
  });

  test("server error, network error and odd status all fail closed", async () => {
    for (const mode of ["status500", "network"] as const) {
      const { client, committer } = make();
      client.mode = mode;
      const res = await committer.commit(entry("e1"));
      expect(res.ok).toBe(false);
      expect(client.objects.size).toBe(0);
    }
  });

  test("a failed write does not advance seq: the next good commit is seq 1", async () => {
    const { client, committer } = make();
    client.mode = "status500";
    expect((await committer.commit(entry("e1"))).ok).toBe(false);
    client.mode = "normal";
    expect(await committer.commit(entry("e2"))).toEqual({ ok: true });
    expect([...client.objects.keys()]).toEqual(["chk/000000000001.json"]);
  });

  test("an event id that was checkpointed is refused as a replay without a new PUT", async () => {
    const { client, committer } = make();
    expect(await committer.commit(entry("e1"))).toEqual({ ok: true });
    const res = await committer.commit(entry("e1"));
    expect(res).toMatchObject({ ok: false, replay: true });
    expect(client.puts).toHaveLength(1);
  });

  test("rejects a non integer amount and a bad time before any PUT", async () => {
    const { client, committer } = make();
    expect((await committer.commit(entry("e1", { amountMinor: 12.5 }))).ok).toBe(false);
    expect((await committer.commit(entry("e2", { at: "not a time" }))).ok).toBe(false);
    expect((await committer.commit(entry("", {}))).ok).toBe(false);
    expect(client.puts).toHaveLength(0);
  });

  test("concurrent commits get distinct seqs", async () => {
    const { client, committer } = make();
    const results = await Promise.all([1, 2, 3, 4, 5].map((n) => committer.commit(entry(`e${n}`))));
    expect(results.every((r) => r.ok)).toBe(true);
    expect([...client.objects.keys()].sort()).toEqual([1, 2, 3, 4, 5].map((n) => `chk/${String(n).padStart(12, "0")}.json`));
  });

  test("resume continues the chain and refuses a broken one", async () => {
    const first = make();
    await first.committer.commit(entry("e1"));
    const stored = JSON.parse([...first.client.objects.values()][0] ?? "{}") as { entry: ChainEntry };
    const second = make(new FakeS3(), [stored.entry]);
    expect(await second.committer.commit(entry("e2"))).toEqual({ ok: true });
    const body = JSON.parse([...second.client.objects.values()][0] ?? "{}") as { seq: number; entry: ChainEntry };
    expect(body.seq).toBe(2);
    expect(body.entry.prev).toBe(stored.entry.hash);
    expect(await second.committer.commit(entry("e1"))).toMatchObject({ ok: false, replay: true });

    const bad = { ...stored.entry, hash: "f".repeat(64) };
    expect(() => make(new FakeS3(), [bad])).toThrow();
  });
});
