import { describe, expect, test } from "bun:test";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { createPublicKey, verify, X509Certificate } from "node:crypto";
import {
  buildLegoArgv,
  LEGO_BIN,
  LEGO_HTTP_ADDRESS,
  LEGO_VERSION,
  legoEnv,
  prepareAcmeWorkDir,
  runAcme,
  type SpawnFn,
} from "../src/host/enclave-acme";
import { ACME_PLAN, createTlsIdentity, csrPem, HTTP_PORT, RA_HOSTNAME, selfSignedCertPem, spkiSha256Hex } from "../src/host/enclave-tls";

const root = resolve(import.meta.dir, "..");
const read = (rel: string) => readFileSync(join(root, rel), "utf8");
const LEGO_SHA256 = "f02fc11b6f56b97e387fa7caa0268f86f5a336953b22458e6430e4651fea439a";
const NOW = Date.UTC(2026, 10, 11, 12, 0, 0);

function valueAfter(argv: readonly string[], flag: string): string | undefined {
  const i = argv.indexOf(flag);
  return i >= 0 ? argv[i + 1] : undefined;
}

/** Fake lego: writes the given PEM where lego would, exits with the given code. */
function fakeLego(pem: (argv: readonly string[]) => string | null, exitCode = 0) {
  const calls: { argv: readonly string[]; env: Record<string, string> }[] = [];
  const spawn: SpawnFn = async (argv, opts) => {
    calls.push({ argv, env: opts.env });
    const out = pem(argv);
    if (out !== null) {
      const file = join(valueAfter(argv, "--path")!, "certificates", `${valueAfter(argv, "--cert.name")}.crt`);
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, out);
    }
    return { exitCode, stderr: "" };
  };
  return { spawn, calls };
}

describe("buildLegoArgv", () => {
  test("staging is the default directory URL", () => {
    const id = createTlsIdentity();
    const plan = buildLegoArgv({ workDir: prepareAcmeWorkDir(id) });
    expect(plan.directoryUrl).toBe("https://acme-staging-v02.api.letsencrypt.org/directory");
    expect(plan.directoryUrl).toBe(ACME_PLAN.staging.directoryUrl);
    expect(valueAfter(plan.argv, "--server")).toBe(plan.directoryUrl);
  });

  test("production only when asked", () => {
    const id = createTlsIdentity();
    const plan = buildLegoArgv({ workDir: prepareAcmeWorkDir(id), acme: "production" });
    expect(plan.directoryUrl).toBe("https://acme-v02.api.letsencrypt.org/directory");
    expect(valueAfter(plan.argv, "--server")).toBe(plan.directoryUrl);
    expect(() => buildLegoArgv({ workDir: prepareAcmeWorkDir(id), acme: "prod" as never })).toThrow();
  });

  test("argv has http-01 on 8080, accepts terms, names the RA host, and no debug or skip-verify flag", () => {
    const plan = buildLegoArgv({ workDir: prepareAcmeWorkDir(createTlsIdentity()) });
    const argv = plan.argv;
    expect(argv[0]).toBe(LEGO_BIN);
    expect(argv[1]).toBe("run");
    expect(argv).toContain("--accept-tos");
    expect(argv).toContain("--http");
    expect(HTTP_PORT).toBe(8080);
    expect(valueAfter(argv, "--http.address")).toBe("127.0.0.1:8080");
    expect(LEGO_HTTP_ADDRESS).toBe("127.0.0.1:8080");
    expect(RA_HOSTNAME).toBe("35-95-168-131.sslip.io");
    expect(valueAfter(argv, "--cert.name")).toBe("35-95-168-131.sslip.io");
    const joined = argv.join(" ").toLowerCase();
    expect(joined).not.toContain("debug");
    expect(joined).not.toContain("tls-skip-verify");
    expect(argv).not.toContain("--private-key");
    expect(argv).not.toContain("--domains");
    expect(argv).not.toContain("--config");
    expect(argv).not.toContain("--env-file");
  });

  test("uses a CSR for the identity key, so lego never makes or sees a TLS key", () => {
    const id = createTlsIdentity();
    const dir = prepareAcmeWorkDir(id);
    const plan = buildLegoArgv({ workDir: dir });
    expect(valueAfter(plan.argv, "--csr")).toBe(dir.csrPath);
    const csr = readFileSync(dir.csrPath, "utf8");
    expect(csr).toStartWith("-----BEGIN CERTIFICATE REQUEST-----");
    expect(csr).not.toContain("PRIVATE KEY");
    expect(plan.certPath).toBe(join(dir.path, "certificates", "35-95-168-131.sslip.io.crt"));
  });

  test("a host-supplied key path or work dir is refused", () => {
    const id = createTlsIdentity();
    const dir = prepareAcmeWorkDir(id);
    for (const k of ["keyPath", "privateKey", "tlsKey", "key", "csrPath", "path", "hostname", "server", "debug"]) {
      expect(() => buildLegoArgv({ workDir: dir, [k]: "/host/tls.key" } as never)).toThrow(/refused/);
    }
    const forged = { path: "/host", csrPath: "/host/tls.csr", certPath: "/host/certificates/x.crt" };
    expect(() => buildLegoArgv({ workDir: forged })).toThrow(/prepareAcmeWorkDir/);
  });

  test("lego child gets PATH only, so LEGO_* variables from the host cannot add flags", () => {
    expect(Object.keys(legoEnv())).toEqual(["PATH"]);
  });
});

describe("csrPem", () => {
  test("CSR carries the identity SPKI and the RA hostname, signed by the identity key", () => {
    const id = createTlsIdentity();
    const pem = csrPem(id, [RA_HOSTNAME]);
    const der = new Uint8Array(Buffer.from(pem.replace(/-----[^-]+-----|\s/g, ""), "base64"));
    const tlvAt = (buf: Uint8Array, off: number) => {
      let len = buf[off + 1]!;
      let hdr = 2;
      if (len & 0x80) {
        const n = len & 0x7f;
        len = 0;
        for (let i = 0; i < n; i++) len = (len << 8) | buf[off + 2 + i]!;
        hdr += n;
      }
      return { tag: buf[off]!, start: off, body: off + hdr, end: off + hdr + len };
    };
    const outer = tlvAt(der, 0);
    const info = tlvAt(der, outer.body);
    const alg = tlvAt(der, info.end);
    const bits = tlvAt(der, alg.end);
    expect([outer.tag, info.tag, alg.tag, bits.tag]).toEqual([0x30, 0x30, 0x30, 0x03]);
    const infoDer = der.slice(info.start, info.end);
    const sig = der.slice(bits.body + 1, bits.end);
    const pub = createPublicKey({ key: Buffer.from(id.spkiDer), format: "der", type: "spki" });
    expect(verify("sha256", infoDer, pub, sig)).toBe(true);
    expect(Buffer.from(infoDer).includes(Buffer.from(id.spkiDer))).toBe(true);
    expect(Buffer.from(infoDer).includes(Buffer.from(RA_HOSTNAME))).toBe(true);
    expect(spkiSha256Hex(id.spkiDer)).toBe(id.spkiSha256);
  });
});

describe("runAcme with a fake spawn", () => {
  test("matching SPKI installs the chain and returns ok, on staging by default", async () => {
    const id = createTlsIdentity();
    const issuer = selfSignedCertPem(createTlsIdentity(), ["Fake Issuer"], NOW);
    const { spawn, calls } = fakeLego(() => selfSignedCertPem(id, [RA_HOSTNAME], NOW) + issuer);
    const installed: string[] = [];
    const res = await runAcme({ identity: id, spawn, install: (p) => void installed.push(p) });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.directoryUrl).toBe(ACME_PLAN.staging.directoryUrl);
    expect(res.spkiSha256).toBe(id.spkiSha256);
    expect(installed).toEqual([res.certificatePem]);
    expect(new X509Certificate(res.certificatePem).checkHost(RA_HOSTNAME)).toBe(RA_HOSTNAME);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.env).toEqual(legoEnv());
    expect(existsSync(valueAfter(calls[0]!.argv, "--path")!)).toBe(false);
  });

  test("production is passed through only when asked", async () => {
    const id = createTlsIdentity();
    const { spawn, calls } = fakeLego(() => selfSignedCertPem(id, [RA_HOSTNAME], NOW));
    const res = await runAcme({ identity: id, spawn, acme: "production" });
    expect(res.ok).toBe(true);
    expect(valueAfter(calls[0]!.argv, "--server")).toBe(ACME_PLAN.production.directoryUrl);
  });

  test("a certificate for a different key fails and does not install", async () => {
    const id = createTlsIdentity();
    const { spawn } = fakeLego(() => selfSignedCertPem(createTlsIdentity(), [RA_HOSTNAME], NOW));
    let installs = 0;
    const res = await runAcme({ identity: id, spawn, install: () => void installs++ });
    expect(res).toMatchObject({ ok: false, reason: "certificate SPKI does not match the TLS identity" });
    expect(installs).toBe(0);
  });

  test("wrong hostname, nonzero exit, missing file, or a throwing spawn all fail without install", async () => {
    const id = createTlsIdentity();
    let installs = 0;
    const install = () => void installs++;
    const cases: SpawnFn[] = [
      fakeLego(() => selfSignedCertPem(id, ["other.example"], NOW)).spawn,
      fakeLego(() => selfSignedCertPem(id, [RA_HOSTNAME], NOW), 1).spawn,
      fakeLego(() => null).spawn,
      fakeLego(() => "not a pem").spawn,
      async () => {
        throw new Error("no lego");
      },
    ];
    for (const spawn of cases) {
      const res = await runAcme({ identity: id, spawn, install });
      expect(res.ok).toBe(false);
    }
    expect(installs).toBe(0);
  });

  test("a host-supplied key is refused before lego runs", async () => {
    const { spawn, calls } = fakeLego(() => null);
    await expect(runAcme({ identity: createTlsIdentity(), spawn, privateKey: "-----BEGIN PRIVATE KEY-----" } as never)).rejects.toThrow(/refused/);
    await expect(runAcme({ identity: createTlsIdentity(), spawn, keyPath: "/host/tls.key" } as never)).rejects.toThrow(/refused/);
    expect(calls).toHaveLength(0);
  });
});

describe("image pins", () => {
  test("Dockerfile pins the lego version and sha256 and installs it at /usr/bin/lego", () => {
    const d = read("enclave/Dockerfile");
    expect(LEGO_VERSION).toBe("5.6.0");
    expect(d).toContain(`lego v${LEGO_VERSION}`);
    expect(d).toContain(`https://github.com/go-acme/lego/releases/download/v${LEGO_VERSION}/lego_v${LEGO_VERSION}_linux_amd64.tar.gz`);
    expect(d).toContain(`${LEGO_SHA256}  /src/lego.tar.gz`);
    expect(d).toContain("sha256sum -c -");
    expect(d).toContain("COPY --from=legofetch /out/lego /usr/bin/lego");
    expect(d).toContain("COPY src/host/enclave-acme.ts /app/src/host/enclave-acme.ts");
    expect(d).not.toContain("--debug-mode");
  });

  test("eif.ts stages enclave-acme.ts and no lego binary", () => {
    const e = read("scripts/eif.ts");
    expect(e).toContain('"src/host/enclave-acme.ts"');
    expect(e).not.toMatch(/"[^"]*lego[^"]*"/);
  });

  test("no em dash in the files this change touches", () => {
    for (const p of ["src/host/enclave-acme.ts", "src/host/enclave-tls.ts", "enclave/Dockerfile", "scripts/eif.ts", "test/enclave-acme.test.ts"]) {
      expect(read(p)).not.toContain("\u2014");
    }
  });
});
