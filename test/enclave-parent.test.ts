import { afterEach, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { createServer, connect, type Server, type Socket } from "node:net";
import { join } from "node:path";
import {
  buildInboundForwarderArgv,
  buildRunEnclaveArgv,
  buildVsockProxyArgv,
  EGRESS_ALLOWLIST,
  RelayRefusal,
  startRelay,
  type RelayHandle,
} from "../src/host/enclave-parent";

const root = join(import.meta.dir, "..");
const parentSource = readFileSync(join(root, "src/host/enclave-parent.ts"), "utf8");
const yamlText = readFileSync(join(root, "enclave/parent/vsock-proxy.yaml"), "utf8");

const ALLOWED_HOSTS = [
  "api.sandbox.airwallex.com",
  "kms.us-west-2.amazonaws.com",
  "s3.us-west-2.amazonaws.com",
  "secretsmanager.us-west-2.amazonaws.com",
  "acme-v02.api.letsencrypt.org",
  "acme-staging-v02.api.letsencrypt.org",
];

const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

/** Echo server standing in for the far side of a vsock bridge. */
async function startEcho(): Promise<{ port: number; server: Server }> {
  const server = createServer({ allowHalfOpen: true }, (sock: Socket) => {
    sock.on("error", () => sock.destroy());
    sock.pipe(sock);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address();
  if (addr === null || typeof addr === "string") throw new Error("no address");
  cleanups.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
  return { port: addr.port, server };
}

async function relayTo(upstreamPort: number): Promise<RelayHandle> {
  const handle = await startRelay({
    routes: [{ name: "loop", listenPort: 0, upstream: { host: "127.0.0.1", port: upstreamPort } }],
    allowlist: [{ host: "127.0.0.1", port: upstreamPort }],
  });
  cleanups.push(() => handle.close());
  return handle;
}

/**
 * Writes the payload and collects bytes until as many have come back as went in (the far side echoes).
 * Bun closes a client socket as soon as it half closes, so this client never sends a FIN first.
 */
function roundTrip(port: number, payload: Uint8Array): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    const timer = setTimeout(() => {
      sock.destroy();
      resolve(Buffer.concat(chunks));
    }, 5000);
    const sock = connect({ host: "127.0.0.1", port }, () => {
      sock.write(Buffer.from(payload));
    });
    sock.on("data", (chunk: Buffer) => {
      chunks.push(chunk);
      total += chunk.length;
      if (total >= payload.length) {
        clearTimeout(timer);
        sock.destroy();
        resolve(Buffer.concat(chunks));
      }
    });
    sock.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

// Small deterministic generator, so a failure is reproducible.
function lcg(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s;
  };
}

function randomBytes(next: () => number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = next() & 0xff;
  return out;
}

describe("byte relay", () => {
  test("property: random bytes written to the relay come out unchanged", async () => {
    const echo = await startEcho();
    const relay = await relayTo(echo.port);
    const port = relay.routes[0]!.listenPort;
    const next = lcg(20261110);
    const sizes = [1, 2, 7, 255, 256, 1024, 4096, 65535, 65536, 200_000];
    for (let round = 0; round < 40; round++) {
      const length = round < sizes.length ? sizes[round]! : next() % 70_000;
      const payload = randomBytes(next, length);
      const got = await roundTrip(port, payload);
      expect(got.length).toBe(payload.length);
      expect(Buffer.compare(got, Buffer.from(payload))).toBe(0);
    }
  }, 30_000);

  test("bytes that look like JSON, TLS records or money fields are not touched", async () => {
    const echo = await startEcho();
    const relay = await relayTo(echo.port);
    const port = relay.routes[0]!.listenPort;
    const samples = [
      Buffer.from('{"amountMinor":199900,"currency":"USD"}'),
      Buffer.from([0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc]),
      Buffer.from([0x00, 0xff, 0x00, 0xff]),
    ];
    for (const sample of samples) {
      const got = await roundTrip(port, sample);
      expect(Buffer.compare(got, sample)).toBe(0);
    }
  });

  test("handles concurrent connections and counts bytes", async () => {
    const echo = await startEcho();
    const relay = await relayTo(echo.port);
    const port = relay.routes[0]!.listenPort;
    const next = lcg(7);
    const payloads = Array.from({ length: 8 }, () => randomBytes(next, 10_000));
    const results = await Promise.all(payloads.map((p) => roundTrip(port, p)));
    results.forEach((got, i) => expect(Buffer.compare(got, Buffer.from(payloads[i]!))).toBe(0));
    const stats = relay.stats()[0]!;
    expect(stats.connections).toBe(8);
    expect(stats.bytesToUpstream).toBe(80_000);
    expect(stats.bytesFromUpstream).toBe(80_000);
  });

  test("close stops the listener", async () => {
    const echo = await startEcho();
    const relay = await relayTo(echo.port);
    const port = relay.routes[0]!.listenPort;
    await relay.close();
    await relay.close();
    const err = await roundTrip(port, new Uint8Array([1])).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(Error);
  });
});

describe("refusals", () => {
  const upstream = { host: "127.0.0.1", port: 9 };
  const base = { routes: [{ name: "r", listenPort: 0, upstream }], allowlist: [upstream] };

  const cases: [string, Record<string, unknown>, string][] = [
    ["debug flag", { debugMode: true }, "DEBUG_MODE"],
    ["dev mode flag", { devMode: true }, "DEBUG_MODE"],
    ["eif signing key", { eifSigningKey: "/tmp/x.pem" }, "SIGNING_KEY"],
    ["api key", { airwallexApiKey: "x" }, "API_KEY"],
    ["clock", { clock: () => 0 }, "ENCLAVE_CLOCK"],
    ["now", { now: () => 0 }, "ENCLAVE_CLOCK"],
    ["tls cert", { tlsCert: "x" }, "TERMINATES_TLS"],
    ["money field", { amountMinor: 100 }, "PARSES_PAYLOAD"],
    ["unknown key", { whatever: 1 }, "BAD_CONFIG"],
  ];
  for (const [label, extra, code] of cases) {
    test(`startRelay refuses ${label}`, async () => {
      const err = await startRelay({ ...base, ...extra } as never).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(RelayRefusal);
      expect((err as RelayRefusal).code as string).toBe(code);
    });
  }

  test("startRelay refuses a route key that parses payloads", async () => {
    const route = { name: "r", listenPort: 0, upstream, parseBody: true };
    const err = await startRelay({ routes: [route], allowlist: [upstream] } as never).catch((e: unknown) => e);
    expect((err as RelayRefusal).code).toBe("PARSES_PAYLOAD");
  });

  test("startRelay refuses an upstream off the allowlist", async () => {
    const err = await startRelay({
      routes: [{ name: "r", listenPort: 0, upstream: { host: "evil.example.com", port: 443 } }],
    }).catch((e: unknown) => e);
    expect((err as RelayRefusal).code).toBe("NOT_ALLOWLISTED");
  });

  test("default allowlist refuses a listed host on another port", async () => {
    const err = await startRelay({
      routes: [{ name: "r", listenPort: 0, upstream: { host: "api.sandbox.airwallex.com", port: 80 } }],
    }).catch((e: unknown) => e);
    expect((err as RelayRefusal).code).toBe("NOT_ALLOWLISTED");
  });

  test("production allowlist is accepted for the six hosts", async () => {
    const handle = await startRelay({
      routes: ALLOWED_HOSTS.map((host, i) => ({ name: `h${i}`, listenPort: 0, upstream: { host, port: 443 } })),
    });
    await handle.close();
  });
});

describe("command builders never pass a debug flag", () => {
  const spec = { eifPath: "/opt/writ/writ.eif", cpuCount: 2, memoryMiB: 3072, cid: 16 };
  const envKeys = ["WRIT_DEBUG", "DEBUG", "NITRO_DEBUG", "DEBUG_MODE", "WRIT_DEV", "NODE_ENV", "WRIT_HOST"];

  test("run-enclave argv has no debug flag, with a clean env", () => {
    const argv = buildRunEnclaveArgv(spec);
    expect(argv.join(" ")).not.toMatch(/debug/i);
    expect(argv.slice(0, 2)).toEqual(["nitro-cli", "run-enclave"]);
  });

  test("run-enclave argv has no debug flag when env looks like dev mode", () => {
    const saved = envKeys.map((k) => [k, process.env[k]] as const);
    try {
      for (const k of envKeys) process.env[k] = k === "NODE_ENV" ? "development" : "1";
      const argv = buildRunEnclaveArgv(spec);
      const proxy = buildVsockProxyArgv({ localPort: 8000, upstream: { host: "kms.us-west-2.amazonaws.com", port: 443 }, configPath: "enclave/parent/vsock-proxy.yaml" });
      const inbound = buildInboundForwarderArgv({ tcpPort: 443, cid: 16, vsockPort: 443 });
      for (const list of [argv, proxy, inbound]) {
        expect(list.some((a) => /debug/i.test(a))).toBe(false);
      }
    } finally {
      for (const [k, v] of saved) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  });

  test("builder refuses a debug spec instead of passing it on", () => {
    expect(() => buildRunEnclaveArgv({ ...spec, debugMode: true } as never)).toThrow(RelayRefusal);
    expect(() => buildRunEnclaveArgv({ ...spec, eifPath: "/opt/writ/--debug.eif" })).toThrow(RelayRefusal);
  });

  test("builder refuses a signing key path as the image", () => {
    expect(() => buildRunEnclaveArgv({ ...spec, eifPath: "/home/ec2/signing.pem" })).toThrow(RelayRefusal);
    expect(() => buildRunEnclaveArgv({ ...spec, signingKey: "/home/ec2/signing.pem" } as never)).toThrow(RelayRefusal);
  });

  test("vsock-proxy builder refuses a host off the list", () => {
    expect(() =>
      buildVsockProxyArgv({ localPort: 8000, upstream: { host: "example.com", port: 443 }, configPath: "enclave/parent/vsock-proxy.yaml" }),
    ).toThrow(RelayRefusal);
  });

  test("inbound forwarder is raw TCP to vsock", () => {
    expect(buildInboundForwarderArgv({ tcpPort: 443, cid: 16, vsockPort: 443 })).toEqual([
      "socat",
      "TCP-LISTEN:443,fork,reuseaddr",
      "VSOCK-CONNECT:16:443",
    ]);
  });
});

describe("vsock-proxy.yaml", () => {
  const entries = [...yamlText.matchAll(/^\s*-\s*\{\s*address:\s*([^,\s]+)\s*,\s*port:\s*(\d+)\s*\}\s*$/gm)].map((m) => ({
    host: m[1]!,
    port: Number(m[2]),
  }));

  test("lists exactly the six hosts, port 443 only", () => {
    expect(entries.map((e) => e.host).sort()).toEqual([...ALLOWED_HOSTS].sort());
    expect(entries.every((e) => e.port === 443)).toBe(true);
  });

  test("has no other address lines", () => {
    const addressLines = yamlText.split("\n").filter((line) => !line.trim().startsWith("#") && /address/.test(line));
    expect(addressLines.length).toBe(6);
  });

  test("matches EGRESS_ALLOWLIST in the relay", () => {
    expect(EGRESS_ALLOWLIST.map((e) => `${e.host}:${e.port}`).sort()).toEqual(entries.map((e) => `${e.host}:${e.port}`).sort());
  });

  test("has no em dash", () => {
    expect(yamlText.includes("\u2014")).toBe(false);
    expect(parentSource.includes("\u2014")).toBe(false);
  });
});

describe("source boundaries", () => {
  const specs = [...parentSource.matchAll(/(?:^|\n)\s*(?:import|export)\s[^;]*?from\s*["']([^"']+)["']/g)].map((m) => m[1]!);

  test("imports only node:net", () => {
    expect(specs).toEqual(["node:net"]);
  });

  test("does not import src/core or src/airwallex", () => {
    expect(specs.some((s) => /core|airwallex/.test(s))).toBe(false);
  });

  test("does not terminate TLS, parse JSON, read env or time", () => {
    const banned: [string, RegExp][] = [
      ["node:tls", /node:tls|from\s*["']tls["']/],
      ["node:https", /node:https|node:http2|from\s*["']https["']/],
      ["tls option", /\bSecureContext\b|createSecureContext|\brejectUnauthorized\b/],
      ["JSON.parse", /JSON\.parse/],
      ["process.env", /process\.env/],
      ["Date", /Date\.now|new Date\b/],
      ["nginx", /nginx/i],
      ["debug flag literal", /--debug/],
      ["money field", /amountMinor|reserveFloor|poolLimit/],
    ];
    const hits = banned.filter(([, re]) => re.test(parentSource)).map(([label]) => label);
    expect(hits).toEqual([]);
  });
});
