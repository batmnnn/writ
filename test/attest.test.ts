import { describe, expect, test } from "bun:test";
import { X509Certificate, createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import {
  AWS_NITRO_ROOT_G1_PEM,
  AWS_NITRO_ROOT_G1_SHA256,
  DEFAULT_MAX_AGE_MS,
  MAX_FUTURE_SKEW_MS,
  checkClaims,
  decodeCbor,
  encodeCbor,
  parseCoseSign1,
  sigStructure,
  verifyAttestation,
  verifyChain,
  verifyCoseSignature,
  type Cbor,
  type ExpectedPcrs,
  type VerifyOptions,
} from "../src/attest/verify";

// No document in this file verifies as genuine. Test certificates are built here at run time
// under a throwaway root that is not the AWS root, so every full document stops at the chain.

const NOW = Date.UTC(2026, 10, 11, 4, 40, 0);
const NONCE = new Uint8Array(32).map((_, i) => i + 1);
const P0 = "a0".repeat(48);
const P1 = "b1".repeat(48);
const P2 = "c2".repeat(48);
const EXPECTED: ExpectedPcrs = { pcr0: P0, pcr1: P1, pcr2: P2 };
const hex = (h: string) => new Uint8Array(Buffer.from(h, "hex"));
const AWS_ROOT_DER = new Uint8Array(new X509Certificate(AWS_NITRO_ROOT_G1_PEM).raw);

// --- minimal DER writer for test certificates -------------------------------------------

function derLen(n: number): number[] {
  if (n < 0x80) return [n];
  const out: number[] = [];
  while (n > 0) {
    out.unshift(n & 0xff);
    n >>= 8;
  }
  return [0x80 | out.length, ...out];
}
const tlv = (tag: number, ...parts: Uint8Array[]): Uint8Array => {
  const body = Buffer.concat(parts);
  return new Uint8Array([tag, ...derLen(body.length), ...body]);
};
const seq = (...p: Uint8Array[]) => tlv(0x30, ...p);
const raw = (...b: number[]) => new Uint8Array(b);
const OID_ECDSA_SHA384 = raw(0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03);
const OID_CN = raw(0x06, 0x03, 0x55, 0x04, 0x03);
const OID_BASIC_CONSTRAINTS = raw(0x06, 0x03, 0x55, 0x1d, 0x13);
const name = (cn: string) => seq(tlv(0x31, seq(OID_CN, tlv(0x0c, new TextEncoder().encode(cn)))));
const utcTime = (ms: number) => {
  const d = new Date(ms).toISOString();
  return tlv(0x17, new TextEncoder().encode(d.slice(2, 4) + d.slice(5, 7) + d.slice(8, 10) + d.slice(11, 13) + d.slice(14, 16) + d.slice(17, 19) + "Z"));
};

function makeCert(opts: { subject: string; issuer: string; subjectKey: KeyObject; issuerKey: KeyObject; ca: boolean; serial: number }): Uint8Array {
  const alg = seq(OID_ECDSA_SHA384);
  const bc = seq(OID_BASIC_CONSTRAINTS, raw(0x01, 0x01, 0xff), tlv(0x04, opts.ca ? seq(raw(0x01, 0x01, 0xff)) : seq()));
  const tbs = seq(
    tlv(0xa0, raw(0x02, 0x01, 0x02)),
    raw(0x02, 0x01, opts.serial),
    alg,
    name(opts.issuer),
    seq(utcTime(Date.UTC(2026, 0, 1)), utcTime(Date.UTC(2030, 0, 1))),
    name(opts.subject),
    new Uint8Array(opts.subjectKey.export({ type: "spki", format: "der" })),
    tlv(0xa3, seq(bc)),
  );
  const sig = sign("sha384", tbs, opts.issuerKey);
  return seq(tbs, alg, tlv(0x03, raw(0x00), new Uint8Array(sig)));
}

const ec384 = () => generateKeyPairSync("ec", { namedCurve: "secp384r1" });
const fakeRoot = ec384();
const leafKeys = ec384();
const FAKE_ROOT_DER = makeCert({ subject: "not-aws-root", issuer: "not-aws-root", subjectKey: fakeRoot.publicKey, issuerKey: fakeRoot.privateKey, ca: true, serial: 1 });
const LEAF_DER = makeCert({ subject: "test-leaf", issuer: "not-aws-root", subjectKey: leafKeys.publicKey, issuerKey: fakeRoot.privateKey, ca: false, serial: 2 });

// --- document builder -------------------------------------------------------------------

type DocParts = {
  alg?: number;
  pcrs?: Map<Cbor, Cbor>;
  nonce?: Uint8Array | null;
  timestamp?: number;
  certificate?: Uint8Array;
  cabundle?: Uint8Array[];
  signer?: KeyObject;
  dropPcrs?: boolean;
};

function payloadMap(p: DocParts): Map<Cbor, Cbor> {
  const m = new Map<Cbor, Cbor>([
    ["module_id", "i-0test-enc0test"],
    ["digest", "SHA384"],
    ["timestamp", p.timestamp ?? NOW - 1000],
    ["pcrs", p.pcrs ?? new Map<Cbor, Cbor>([[0, hex(P0)], [1, hex(P1)], [2, hex(P2)]])],
    ["certificate", p.certificate ?? LEAF_DER],
    ["cabundle", p.cabundle ?? [FAKE_ROOT_DER]],
    ["public_key", null],
    ["user_data", null],
    ["nonce", p.nonce === undefined ? NONCE : p.nonce],
  ]);
  if (p.dropPcrs) m.delete("pcrs");
  return m;
}

function buildDoc(p: DocParts = {}): Uint8Array {
  const protectedBytes = encodeCbor(new Map<Cbor, Cbor>([[1, p.alg ?? -35]]));
  const payloadBytes = encodeCbor(payloadMap(p));
  const sig = sign("sha384", sigStructure({ protectedBytes, payloadBytes }), { key: p.signer ?? leafKeys.privateKey, dsaEncoding: "ieee-p1363" });
  return encodeCbor({ tag: 18, value: [protectedBytes, new Map(), payloadBytes, new Uint8Array(sig)] });
}

const opts = (o: Partial<VerifyOptions> = {}): VerifyOptions => ({ nonce: NONCE, expected: EXPECTED, now: NOW, ...o });
const code = (doc: Uint8Array, o?: Partial<VerifyOptions>) => {
  const r = verifyAttestation(doc, opts(o));
  return r.ok ? "OK" : r.error.code;
};

// ---------------------------------------------------------------------------------------

describe("pinned AWS root", () => {
  test("the PEM in the source hashes to the fingerprint AWS publishes", () => {
    const der = new X509Certificate(AWS_NITRO_ROOT_G1_PEM).raw;
    const fp = createHash("sha256").update(der).digest("hex").toUpperCase().match(/../g)!.join(":");
    expect(fp).toBe(AWS_NITRO_ROOT_G1_SHA256);
    expect(new X509Certificate(AWS_NITRO_ROOT_G1_PEM).subject).toContain("aws.nitro-enclaves");
  });
});

describe("not COSE_Sign1", () => {
  const cases: [string, Uint8Array][] = [
    ["empty", new Uint8Array(0)],
    ["random bytes", new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00, 0x11])],
    ["JSON text", new TextEncoder().encode('{"pcrs":{}}')],
    ["a CBOR map", encodeCbor(new Map<Cbor, Cbor>([["a", 1]]))],
    ["a 3 item array", encodeCbor([new Uint8Array(0), new Map(), new Uint8Array(0)])],
    ["wrong tag", encodeCbor({ tag: 98, value: [new Uint8Array(0), new Map(), new Uint8Array(0), new Uint8Array(96)] })],
    ["indefinite length array", raw(0x9f, 0x40, 0xa0, 0x40, 0x40, 0xff)],
    ["truncated", buildDoc().slice(0, 50)],
    ["trailing bytes", new Uint8Array([...buildDoc(), 0x00])],
  ];
  for (const [label, bytes] of cases) {
    test(label, () => expect(code(bytes)).toBe("NOT_COSE_SIGN1"));
  }

  test("a detached payload is refused", () => {
    const doc = encodeCbor({ tag: 18, value: [encodeCbor(new Map<Cbor, Cbor>([[1, -35]])), new Map(), null, new Uint8Array(96)] });
    expect(code(doc)).toBe("NOT_COSE_SIGN1");
  });

  test("an alg other than ES384 is refused", () => expect(code(buildDoc({ alg: -7 }))).toBe("UNSUPPORTED_ALG"));

  test("a payload without pcrs is refused before the chain", () => expect(code(buildDoc({ dropPcrs: true }))).toBe("MALFORMED_PAYLOAD"));

  test("a document over the size cap is refused", () => expect(code(new Uint8Array(40_000))).toBe("DOCUMENT_TOO_LARGE"));
});

describe("certificate chain", () => {
  test("a correctly signed document under a root that is not AWS is refused", () => {
    expect(code(buildDoc())).toBe("CHAIN_NOT_PINNED_ROOT");
  });

  test("an empty first entry or a chain that only ends in the AWS root is refused", () => {
    expect(code(buildDoc({ cabundle: [FAKE_ROOT_DER, AWS_ROOT_DER] }))).toBe("CHAIN_NOT_PINNED_ROOT");
  });

  test("the AWS root first, but the leaf was not issued by it", () => {
    expect(code(buildDoc({ cabundle: [AWS_ROOT_DER] }))).toBe("CHAIN_INVALID");
  });

  test("the AWS root first, then a CA it never signed", () => {
    expect(code(buildDoc({ cabundle: [AWS_ROOT_DER, FAKE_ROOT_DER] }))).toBe("CHAIN_INVALID");
  });

  test("a certificate that does not parse", () => {
    expect(code(buildDoc({ cabundle: [AWS_ROOT_DER, raw(0x30, 0x03, 0x02, 0x01, 0x01)] }))).toBe("CHAIN_INVALID");
  });

  test("verifyChain refuses the fake root directly", () => {
    const r = verifyChain(LEAF_DER, [FAKE_ROOT_DER], NOW);
    expect(r.ok ? "OK" : r.error.code).toBe("CHAIN_NOT_PINNED_ROOT");
  });
});

describe("COSE signature", () => {
  const leaf = new X509Certificate(LEAF_DER);
  const parsed = (doc: Uint8Array) => {
    const r = parseCoseSign1(doc);
    if (!r.ok) throw new Error(r.error.code);
    return r.value;
  };

  test("verifies under the signing key and fails under another", () => {
    expect(verifyCoseSignature(parsed(buildDoc()), leaf)).toBe(true);
    expect(verifyCoseSignature(parsed(buildDoc({ signer: ec384().privateKey })), leaf)).toBe(false);
  });

  test("a changed payload byte breaks it", () => {
    const s = parsed(buildDoc());
    const payloadBytes = s.payloadBytes.slice();
    payloadBytes[payloadBytes.length - 1]! ^= 0x01;
    expect(verifyCoseSignature({ ...s, payloadBytes }, leaf)).toBe(false);
  });

  test("a P-256 leaf is refused", () => {
    const k = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const p256 = new X509Certificate(makeCert({ subject: "p256", issuer: "not-aws-root", subjectKey: k.publicKey, issuerKey: fakeRoot.privateKey, ca: false, serial: 3 }));
    expect(verifyCoseSignature(parsed(buildDoc()), p256)).toBe(false);
  });
});

describe("options are checked first", () => {
  test("a nonce shorter than 32 bytes", () => {
    expect(code(buildDoc(), { nonce: NONCE.slice(0, 31) })).toBe("NONCE_TOO_SHORT");
    expect(code(new Uint8Array(0), { nonce: new Uint8Array(0) })).toBe("NONCE_TOO_SHORT");
  });

  test("expected PCRs must all be present", () => {
    for (const drop of ["pcr0", "pcr1", "pcr2"] as const) {
      const expected = { ...EXPECTED } as Partial<ExpectedPcrs>;
      delete expected[drop];
      expect(code(buildDoc(), { expected: expected as ExpectedPcrs })).toBe("PCR_MISSING");
    }
  });

  test("the type requires all three PCRs", () => {
    // @ts-expect-error pcr1 and pcr2 are required
    const onlyPcr0: ExpectedPcrs = { pcr0: P0 };
    expect(code(buildDoc(), { expected: onlyPcr0 })).toBe("PCR_MISSING");
  });

  test("expected PCRs that are short, non hex or all zeros", () => {
    expect(code(buildDoc(), { expected: { ...EXPECTED, pcr1: "ab".repeat(32) } })).toBe("PCR_MALFORMED");
    expect(code(buildDoc(), { expected: { ...EXPECTED, pcr2: "zz".repeat(48) } })).toBe("PCR_MALFORMED");
    expect(code(buildDoc(), { expected: { ...EXPECTED, pcr0: "0".repeat(96) } })).toBe("PCR_ZERO");
  });

  test("bad now or maxAgeMs", () => {
    expect(code(buildDoc(), { now: Number.NaN })).toBe("BAD_OPTIONS");
    expect(code(buildDoc(), { maxAgeMs: 0 })).toBe("BAD_OPTIONS");
  });
});

describe("claims after the signature", () => {
  const pcrs = (m: [number, string][]) => new Map<number, Uint8Array>(m.map(([i, h]) => [i, hex(h)]));
  type Claims = Parameters<typeof checkClaims>[0];
  const good: Claims = { nonce: NONCE, timestamp: NOW - 1000, pcrs: pcrs([[0, P0], [1, P1], [2, P2]]) };
  const o = { nonce: NONCE, expected: EXPECTED, now: NOW, maxAgeMs: DEFAULT_MAX_AGE_MS };
  const c = (p: Partial<Claims>, oo: Partial<typeof o> & { expectedUserData?: Uint8Array } = {}) => {
    const r = checkClaims({ ...good, ...p }, { ...o, ...oo });
    return r.ok ? "OK" : r.error.code;
  };

  test("all three PCRs, the nonce and a fresh timestamp pass this stage", () => expect(c({})).toBe("OK"));

  test("nonce", () => {
    expect(c({}, { nonce: NONCE.slice(0, 16) })).toBe("NONCE_TOO_SHORT");
    expect(c({ nonce: null })).toBe("NONCE_MISMATCH");
    expect(c({ nonce: NONCE.map((b) => b ^ 1) })).toBe("NONCE_MISMATCH");
    expect(c({ nonce: NONCE.slice(0, 31) })).toBe("NONCE_MISMATCH");
  });

  test("timestamp", () => {
    expect(DEFAULT_MAX_AGE_MS).toBe(300_000);
    expect(c({ timestamp: NOW - DEFAULT_MAX_AGE_MS })).toBe("OK");
    expect(c({ timestamp: NOW - DEFAULT_MAX_AGE_MS - 1 })).toBe("TIMESTAMP_STALE");
    expect(c({ timestamp: NOW - 10_000 }, { maxAgeMs: 5_000 })).toBe("TIMESTAMP_STALE");
    expect(c({ timestamp: NOW + MAX_FUTURE_SKEW_MS + 1 })).toBe("TIMESTAMP_IN_FUTURE");
  });

  test("document PCRs missing, wrong length or all zeros", () => {
    expect(c({ pcrs: pcrs([[0, P0], [2, P2]]) })).toBe("PCR_MISSING");
    expect(c({ pcrs: pcrs([[0, P0], [1, P1]]) })).toBe("PCR_MISSING");
    expect(c({ pcrs: pcrs([[0, "ab".repeat(32)], [1, P1], [2, P2]]) })).toBe("PCR_MALFORMED");
    expect(c({ pcrs: pcrs([[0, "00".repeat(48)], [1, "00".repeat(48)], [2, "00".repeat(48)]]) })).toBe("PCR_ZERO");
    expect(c({ pcrs: pcrs([[0, P0], [1, "00".repeat(48)], [2, P2]]) })).toBe("PCR_ZERO");
  });

  test("PCR0 matching is not enough", () => {
    expect(c({ pcrs: pcrs([[0, "ff".repeat(48)], [1, P1], [2, P2]]) })).toBe("PCR_MISMATCH");
    expect(c({ pcrs: pcrs([[0, P0], [1, "ff".repeat(48)], [2, P2]]) })).toBe("PCR_MISMATCH");
    expect(c({ pcrs: pcrs([[0, P0], [1, P1], [2, "ff".repeat(48)]]) })).toBe("PCR_MISMATCH");
  });

  const UD = new Uint8Array(32).map((_, i) => 0x40 + i);

  test("user_data is not checked when the caller does not ask", () => {
    expect(c({ userData: null })).toBe("OK");
    expect(c({ userData: UD })).toBe("OK");
  });

  test("user_data that matches byte for byte passes", () => {
    expect(c({ userData: UD.slice() }, { expectedUserData: UD })).toBe("OK");
  });

  test("user_data that differs, is shorter or is absent is USER_DATA_MISMATCH", () => {
    expect(c({ userData: UD.map((b) => b ^ 1) }, { expectedUserData: UD })).toBe("USER_DATA_MISMATCH");
    expect(c({ userData: UD.slice(0, 31) }, { expectedUserData: UD })).toBe("USER_DATA_MISMATCH");
    expect(c({ userData: null }, { expectedUserData: UD })).toBe("USER_DATA_MISMATCH");
    expect(c({}, { expectedUserData: UD })).toBe("USER_DATA_MISMATCH");
  });

  test("PCR and nonce failures still win over a user_data mismatch", () => {
    expect(c({ nonce: null, userData: null }, { expectedUserData: UD })).toBe("NONCE_MISMATCH");
    expect(c({ pcrs: pcrs([[0, "ff".repeat(48)], [1, P1], [2, P2]]), userData: null }, { expectedUserData: UD })).toBe("PCR_MISMATCH");
  });
});

describe("expectedUserData option", () => {
  test("omitting it leaves the full verify result unchanged", () => {
    expect(code(buildDoc())).toBe("CHAIN_NOT_PINNED_ROOT");
    expect(code(buildDoc(), { expectedUserData: new Uint8Array(32) })).toBe("CHAIN_NOT_PINNED_ROOT");
  });

  test("a value that is not bytes is BAD_OPTIONS", () => {
    expect(code(buildDoc(), { expectedUserData: "abcd" as never })).toBe("BAD_OPTIONS");
  });
});

describe("CBOR", () => {
  test("round trips the shapes the document uses", () => {
    const v = new Map<Cbor, Cbor>([["timestamp", 1_762_830_000_000], [-1, new Uint8Array([1, 2])], ["a", [true, null]]]);
    expect(decodeCbor(encodeCbor(v))).toEqual(v);
  });

  test("duplicate keys and floats are refused", () => {
    expect(() => decodeCbor(raw(0xa2, 0x01, 0x01, 0x01, 0x02))).toThrow();
    expect(() => decodeCbor(raw(0xf9, 0x3c, 0x00))).toThrow();
  });
});

describe("scripts/verify-attestation.ts", () => {
  test("prints nothing on stdout and exits 1 for a bad document", () => {
    const dir = mkdtempSync(join(tmpdir(), "writ-attest-"));
    const path = join(dir, "doc.cbor");
    writeFileSync(path, buildDoc());
    const r = spawnSync("bun", ["run", join(import.meta.dir, "..", "scripts", "verify-attestation.ts"), path, Buffer.from(NONCE).toString("hex")], { encoding: "utf8" });
    expect(r.status).toBe(1);
    expect(r.stdout).toBe("");
    expect(r.stderr).toContain("CHAIN_NOT_PINNED_ROOT");
  });
});
