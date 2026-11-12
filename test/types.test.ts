import { describe, expect, test } from "bun:test";
import { DECLINE_CODES, failClosed, type Decision } from "../src/types";

describe("scaffold", () => {
  test("decline codes are unique and none mention the old name", () => {
    expect(new Set(DECLINE_CODES).size).toBe(DECLINE_CODES.length);
    for (const code of DECLINE_CODES) expect(code.includes("WARRANT")).toBe(false);
  });

  test("failClosed always declines", () => {
    const d: Decision = failClosed("INTERNAL_ERROR", "state missing");
    expect(d.status).toBe("DECLINED");
    if (d.status === "DECLINED") expect(d.code).toBe("INTERNAL_ERROR");
  });
});
