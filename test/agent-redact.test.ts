import { describe, expect, test } from "bun:test";
import { redact } from "../scripts/agent-redact";

describe("agent scene redaction", () => {
  test("removes presigned queries, JWTs, account ids, long digit runs and card ids", () => {
    const raw = JSON.stringify({
      url: "https://writ-ledger-123456789012.s3.us-west-2.amazonaws.com/scene/p.html?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Security-Token=abc&X-Amz-Signature=def",
      auth: "Bearer eyJhbGciOi.eyJjbGllbnRfaWQiOi.c2lnbmF0dXJl",
      runtime: "arn:aws:bedrock-agentcore:us-west-2:123456789012:runtime/x",
      pan: "4111111111111111",
      cardId: "c-abc-123",
      last4: "4605",
    });
    const out = redact(raw);
    for (const bad of ["X-Amz-", "eyJ", "123456789012", "4111111111111111", "c-abc-123"]) expect(out).not.toContain(bad);
    expect(out).toContain("4605");
    expect(out).toContain("p.html?<presigned query removed>");
  });
});
