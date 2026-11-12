import { describe, expect, test } from "bun:test";
import { autoApprove, canonicalJson, needsHumanApproval, verifyWrit, writHash } from "../src/core/writ";
import type { ApprovedTask } from "../src/types";
import { APPROVED_AT, KEYS, OTHER_KEYS, proposal, signed } from "./helpers";

const policy = { autoApproveMinor: 25000, knownMerchants: ["DataCo"] };

describe("canonical JSON and hash", () => {
  test("key order does not change the output", () => {
    expect(canonicalJson({ b: 1, a: { d: [1, 2], c: "x" } })).toBe(canonicalJson({ a: { c: "x", d: [1, 2] }, b: 1 }));
    expect(canonicalJson({ b: 1, a: undefined })).toBe('{"b":1}');
  });

  test("hash is stable and ignores hash and signature fields", () => {
    const w = signed();
    expect(writHash(w)).toBe(w.hash);
    expect(writHash({ ...w, signature: "x", hash: "y" })).toBe(w.hash);
  });
});

describe("verifyWrit", () => {
  test("a signed writ verifies", () => {
    expect(verifyWrit(signed(), KEYS.publicKeyPem, policy)).toEqual({ hashValid: true, signatureValid: true });
  });

  test("editing any signed field breaks the hash", () => {
    const w = signed({ evidenceUrl: "https://dataco.example/quote/1" });
    const edits: Partial<ApprovedTask>[] = [
      { id: "writ-2" },
      { team: "growth" },
      { agent: "research-2" },
      { runId: "run-2" },
      { purpose: "Something else" },
      { merchantName: "DataCo Ltd" },
      { mcc: "5999" },
      { amountMinor: 18001 },
      { expiresAt: "2026-11-13T09:00:00.000Z" },
      { nonce: "n-2" },
      { approvedAt: "2026-11-12T08:31:00.000Z" },
      { evidenceUrl: "https://evil.example" },
      { approvedBy: "auto" },
    ];
    for (const e of edits) {
      expect(verifyWrit({ ...w, ...e }, KEYS.publicKeyPem, policy).hashValid).toBe(false);
    }
  });

  test("re-hashing an edited writ still fails the signature", () => {
    const edited = { ...signed(), amountMinor: 99900 };
    const rehashed = { ...edited, hash: writHash(edited) };
    expect(verifyWrit(rehashed, KEYS.publicKeyPem, policy)).toEqual({ hashValid: true, signatureValid: false });
  });

  test("wrong key fails the signature", () => {
    expect(verifyWrit(signed(), OTHER_KEYS.publicKeyPem, policy).signatureValid).toBe(false);
  });

  test("garbage signature fails closed without throwing", () => {
    expect(verifyWrit({ ...signed(), signature: "!!" }, KEYS.publicKeyPem, policy).signatureValid).toBe(false);
    expect(verifyWrit({ ...signed(), signature: "" }, "not a key", policy).signatureValid).toBe(false);
  });
});

describe("approval rules", () => {
  test("over $250 or a new merchant needs a human", () => {
    expect(needsHumanApproval({ amountMinor: 25000, merchantName: "dataco" }, policy)).toBe(false);
    expect(needsHumanApproval({ amountMinor: 25001, merchantName: "DataCo" }, policy)).toBe(true);
    expect(needsHumanApproval({ amountMinor: 100, merchantName: "NewCo" }, policy)).toBe(true);
  });

  test("auto approval is hashed, unsigned, and only valid inside the rule", () => {
    const w = autoApprove(proposal({ amountMinor: 4000 }), APPROVED_AT, policy);
    expect(w.approvedBy).toBe("auto");
    expect(w.signature).toBe("");
    expect(verifyWrit(w, KEYS.publicKeyPem, policy)).toEqual({ hashValid: true, signatureValid: true });
    expect(verifyWrit(w, KEYS.publicKeyPem, { ...policy, knownMerchants: [] }).signatureValid).toBe(false);
  });

  test("auto approval refuses what needs a human", () => {
    expect(() => autoApprove(proposal({ amountMinor: 30000 }), APPROVED_AT, policy)).toThrow();
  });

  test("bad proposals are rejected", () => {
    expect(() => signed({ amountMinor: 180.5 })).toThrow();
    expect(() => signed({ mcc: "57" })).toThrow();
    expect(() => signed({ expiresAt: "2026-11-12T08:00:00.000Z" })).toThrow();
  });
});
