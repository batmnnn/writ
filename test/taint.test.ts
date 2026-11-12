import { describe, expect, test } from "bun:test";
import { cleanRun, markTainted, TaintRegistry, taintedSince } from "../src/core/taint";
import { createAgentFetch, isAllowed, parseAllowlist, type TaintNotice } from "../src/proxy";

describe("taint state", () => {
  test("keeps the latest taint time", () => {
    let s = markTainted(cleanRun("r"), "https://a.example", "2026-11-12T08:00:00Z");
    s = markTainted(s, "https://b.example", "2026-11-12T09:00:00Z");
    s = markTainted(s, "https://c.example", "2026-11-12T08:30:00Z");
    expect(s.taintedAt).toBe("2026-11-12T09:00:00Z");
    expect(s.source).toBe("https://b.example");
  });

  test("taintedSince is inclusive and fails closed on bad times", () => {
    const s = markTainted(cleanRun("r"), "x", "2026-11-12T08:30:00Z");
    expect(taintedSince(s, "2026-11-12T08:30:00Z")).toBe(true);
    expect(taintedSince(s, "2026-11-12T08:30:01Z")).toBe(false);
    expect(taintedSince(s, "bad")).toBe(true);
    expect(taintedSince(cleanRun("r"), "2026-11-12T08:30:00Z")).toBe(false);
  });

  test("registry tracks runs separately", () => {
    const reg = new TaintRegistry();
    reg.mark("a", "x", "2026-11-12T08:30:00Z");
    expect(reg.get("a").taintedAt).toBeDefined();
    expect(reg.get("b").taintedAt).toBeUndefined();
  });
});

describe("agent fetch proxy", () => {
  const allow = parseAllowlist("dataco.example, *.docs.example");

  test("allowlist matching", () => {
    expect(isAllowed("https://dataco.example/quote", allow)).toBe(true);
    expect(isAllowed("https://api.docs.example/x", allow)).toBe(true);
    expect(isAllowed("https://docs.example/x", allow)).toBe(false);
    expect(isAllowed("https://dataco.example.evil.example/", allow)).toBe(false);
    expect(isAllowed("http://dataco.example/", allow)).toBe(false);
    expect(isAllowed("not a url", allow)).toBe(false);
  });

  const setup = (redirectTo?: string) => {
    const notices: TaintNotice[] = [];
    const fakeFetch = (async (input: string | URL | Request) => {
      const res = new Response("ok");
      if (redirectTo) {
        Object.defineProperty(res, "redirected", { value: true });
        Object.defineProperty(res, "url", { value: redirectTo });
      } else {
        Object.defineProperty(res, "url", { value: String(input) });
      }
      return res;
    }) as unknown as typeof fetch;
    const agentFetch = createAgentFetch({ runId: "run-1", allowlist: allow, onTaint: (n) => notices.push(n), now: () => "2026-11-12T08:31:00Z", fetchImpl: fakeFetch });
    return { notices, agentFetch };
  };

  test("allowlisted read does not taint", async () => {
    const { notices, agentFetch } = setup();
    await agentFetch("https://dataco.example/quote");
    expect(notices).toEqual([]);
  });

  test("off-list read taints before the response returns", async () => {
    const { notices, agentFetch } = setup();
    await agentFetch("https://evil.example/buy-now");
    expect(notices).toEqual([{ runId: "run-1", url: "https://evil.example/buy-now", at: "2026-11-12T08:31:00Z" }]);
  });

  test("redirect to an off-list host taints", async () => {
    const { notices, agentFetch } = setup("https://evil.example/landing");
    await agentFetch("https://dataco.example/quote");
    expect(notices.map((n) => n.url)).toEqual(["https://evil.example/landing"]);
  });

  test("if marking taint fails, the read does not happen", async () => {
    let called = false;
    const agentFetch = createAgentFetch({
      runId: "r",
      allowlist: allow,
      onTaint: () => {
        throw new Error("db down");
      },
      fetchImpl: (async () => {
        called = true;
        return new Response("x");
      }) as unknown as typeof fetch,
    });
    await expect(agentFetch("https://evil.example")).rejects.toThrow("db down");
    expect(called).toBe(false);
  });
});
