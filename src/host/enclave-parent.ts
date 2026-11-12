// Enclave host relay. This file runs on the EC2 parent, outside the enclave.
// It is a byte relay and nothing else (docs/REFERENCES.md section 1, Evervault split).
//
// What it refuses, by construction:
// 1. It never parses a payload. It counts bytes and copies them. It imports nothing from src/core or src/airwallex.
// 2. It never ends an encrypted connection. No TLS server, no certificates. Only the enclave decrypts.
// 3. It never passes a debug flag to nitro-cli, whatever the environment says. Env is not read at all.
// 4. It holds no EIF signing key and no plaintext API key. Config keys that name one are refused.
// 5. It never supplies the enclave's time. Config keys that name a time source are refused.
//
// Real vsock is not reachable from Bun. In production the argv builders below produce the commands for
// vsock-proxy (outbound, allowlisted) and socat (inbound, raw TCP to vsock). startRelay is an in-process
// byte pipe over TCP, used for loopback bridges and for tests. Tests do not need a real vsock.

import { createServer, connect, type Server, type Socket } from "node:net";

export interface Endpoint {
  readonly host: string;
  readonly port: number;
}

/** Same six hosts as enclave/parent/vsock-proxy.yaml. Port 443 only. */
export const EGRESS_ALLOWLIST: readonly Endpoint[] = Object.freeze([
  Object.freeze({ host: "api.sandbox.airwallex.com", port: 443 }),
  Object.freeze({ host: "kms.us-west-2.amazonaws.com", port: 443 }),
  Object.freeze({ host: "s3.us-west-2.amazonaws.com", port: 443 }),
  Object.freeze({ host: "secretsmanager.us-west-2.amazonaws.com", port: 443 }),
  Object.freeze({ host: "acme-v02.api.letsencrypt.org", port: 443 }),
  Object.freeze({ host: "acme-staging-v02.api.letsencrypt.org", port: 443 }),
]);

export interface RelayRoute {
  /** Label for logs and stats. */
  readonly name: string;
  /** Local bind address. Default 127.0.0.1. */
  readonly listenHost?: string;
  /** Local port. 0 picks a free port. */
  readonly listenPort: number;
  /** Where the bytes go. Must be in the allowlist. */
  readonly upstream: Endpoint;
}

export interface RelayConfig {
  readonly routes: readonly RelayRoute[];
  /** Endpoints the relay may dial. Default is EGRESS_ALLOWLIST. Override only for loopback bridges and tests. */
  readonly allowlist?: readonly Endpoint[];
  /** Close a connection after this many idle ms. Default 120000. */
  readonly idleTimeoutMs?: number;
  /** Refuse new connections past this count. Default 256. */
  readonly maxConnections?: number;
}

export interface RouteStats {
  readonly name: string;
  readonly listenPort: number;
  readonly connections: number;
  readonly bytesToUpstream: number;
  readonly bytesFromUpstream: number;
}

export interface RelayHandle {
  readonly routes: readonly { readonly name: string; readonly listenHost: string; readonly listenPort: number }[];
  stats(): readonly RouteStats[];
  /** Stops listening and destroys open connections. Safe to call twice. */
  close(): Promise<void>;
}

export type RefusalCode =
  | "DEBUG_MODE"
  | "SIGNING_KEY"
  | "API_KEY"
  | "ENCLAVE_CLOCK"
  | "TERMINATES_TLS"
  | "PARSES_PAYLOAD"
  | "NOT_ALLOWLISTED"
  | "BAD_CONFIG";

export class RelayRefusal extends Error {
  readonly code: RefusalCode;
  constructor(code: RefusalCode, message: string) {
    super(message);
    this.name = "RelayRefusal";
    this.code = code;
  }
}

const REFUSED_KEYS: readonly [RegExp, RefusalCode, string][] = [
  [/debug|^dev(?:elopment)?(?:mode)?$|^devmode$/i, "DEBUG_MODE", "the relay never starts an enclave in debug or dev mode"],
  [/sign(?:ing)?key|eifkey|privatekey|private_key|^pem$/i, "SIGNING_KEY", "the host never holds an EIF signing key"],
  [/api[_-]?key|secret|token|password|credential|plaintext/i, "API_KEY", "the host never holds the API key or any secret"],
  [/clock|^now$|^time$|timesource|^ntp|^epoch$|^date$/i, "ENCLAVE_CLOCK", "the host never supplies the enclave's time"],
  [/tls|ssl|cert|https|^key$/i, "TERMINATES_TLS", "the host never ends an encrypted connection"],
  [/amount|balance|currency|price|merchant|^mcc$|minor|parse|decode|inspect|transform|filter|rewrite/i, "PARSES_PAYLOAD", "the host relays bytes and reads none of them"],
];

function refuseUnknownKeys(label: string, value: object, allowed: readonly string[]): void {
  for (const key of Object.keys(value)) {
    if (allowed.includes(key)) continue;
    for (const [re, code, why] of REFUSED_KEYS) {
      if (re.test(key)) throw new RelayRefusal(code, `${label}: key "${key}" refused: ${why}`);
    }
    throw new RelayRefusal("BAD_CONFIG", `${label}: unknown key "${key}"`);
  }
}

function sameEndpoint(a: Endpoint, b: Endpoint): boolean {
  return a.host.toLowerCase() === b.host.toLowerCase() && a.port === b.port;
}

function validPort(port: unknown, allowZero: boolean): port is number {
  return typeof port === "number" && Number.isInteger(port) && port >= (allowZero ? 0 : 1) && port <= 65535;
}

function validateConfig(config: RelayConfig): { allowlist: readonly Endpoint[]; idleTimeoutMs: number; maxConnections: number } {
  if (typeof config !== "object" || config === null) throw new RelayRefusal("BAD_CONFIG", "config must be an object");
  refuseUnknownKeys("config", config, ["routes", "allowlist", "idleTimeoutMs", "maxConnections"]);
  if (!Array.isArray(config.routes) || config.routes.length === 0) {
    throw new RelayRefusal("BAD_CONFIG", "config.routes must list at least one route");
  }
  const allowlist = config.allowlist ?? EGRESS_ALLOWLIST;
  const idleTimeoutMs = config.idleTimeoutMs ?? 120_000;
  const maxConnections = config.maxConnections ?? 256;
  if (!Number.isInteger(idleTimeoutMs) || idleTimeoutMs < 1) throw new RelayRefusal("BAD_CONFIG", "idleTimeoutMs must be a positive integer");
  if (!Number.isInteger(maxConnections) || maxConnections < 1) throw new RelayRefusal("BAD_CONFIG", "maxConnections must be a positive integer");
  const names = new Set<string>();
  for (const route of config.routes) {
    if (typeof route !== "object" || route === null) throw new RelayRefusal("BAD_CONFIG", "route must be an object");
    refuseUnknownKeys("route", route, ["name", "listenHost", "listenPort", "upstream"]);
    if (typeof route.name !== "string" || route.name === "" || names.has(route.name)) {
      throw new RelayRefusal("BAD_CONFIG", "route.name must be a unique non-empty string");
    }
    names.add(route.name);
    if (!validPort(route.listenPort, true)) throw new RelayRefusal("BAD_CONFIG", `route ${route.name}: bad listenPort`);
    const up = route.upstream;
    if (typeof up !== "object" || up === null) throw new RelayRefusal("BAD_CONFIG", `route ${route.name}: upstream missing`);
    refuseUnknownKeys(`route ${route.name} upstream`, up, ["host", "port"]);
    if (typeof up.host !== "string" || up.host === "" || !validPort(up.port, false)) {
      throw new RelayRefusal("BAD_CONFIG", `route ${route.name}: bad upstream`);
    }
    if (!allowlist.some((entry) => sameEndpoint(entry, up))) {
      throw new RelayRefusal("NOT_ALLOWLISTED", `route ${route.name}: ${up.host}:${up.port} is not in the allowlist`);
    }
  }
  return { allowlist, idleTimeoutMs, maxConnections };
}

/**
 * Starts one TCP listener per route and copies bytes both ways, unchanged.
 * Rejects with RelayRefusal on any config that asks the host to do more than relay.
 */
export async function startRelay(config: RelayConfig): Promise<RelayHandle> {
  const { idleTimeoutMs, maxConnections } = validateConfig(config);

  interface Live {
    name: string;
    server: Server;
    host: string;
    port: number;
    connections: number;
    toUpstream: number;
    fromUpstream: number;
  }
  const live: Live[] = [];
  const sockets = new Set<Socket>();
  let closed = false;

  const closeAll = async (): Promise<void> => {
    closed = true;
    for (const socket of sockets) socket.destroy();
    sockets.clear();
    await Promise.all(
      live.map((entry) => new Promise<void>((resolve) => (entry.server.listening ? entry.server.close(() => resolve()) : resolve()))),
    );
  };

  try {
    for (const route of config.routes) {
      const entry: Live = { name: route.name, server: createServer({ allowHalfOpen: true }), host: route.listenHost ?? "127.0.0.1", port: 0, connections: 0, toUpstream: 0, fromUpstream: 0 };
      live.push(entry);

      entry.server.on("connection", (client: Socket) => {
        if (closed || sockets.size >= maxConnections) {
          client.destroy();
          return;
        }
        const upstream = connect({ host: route.upstream.host, port: route.upstream.port, allowHalfOpen: true });
        sockets.add(client);
        sockets.add(upstream);
        entry.connections += 1;
        client.setTimeout(idleTimeoutMs);
        upstream.setTimeout(idleTimeoutMs);

        let done = false;
        const finish = (): void => {
          if (done) return;
          done = true;
          sockets.delete(client);
          sockets.delete(upstream);
          client.destroy();
          upstream.destroy();
        };
        client.on("error", finish);
        upstream.on("error", finish);
        client.on("timeout", finish);
        upstream.on("timeout", finish);
        client.on("close", finish);
        upstream.on("close", finish);

        client.on("data", (chunk: Buffer) => {
          entry.toUpstream += chunk.length;
        });
        upstream.on("data", (chunk: Buffer) => {
          entry.fromUpstream += chunk.length;
        });
        // pipe handles backpressure and half close. Bytes pass through untouched.
        client.pipe(upstream);
        upstream.pipe(client);
      });

      await new Promise<void>((resolve, reject) => {
        entry.server.once("error", reject);
        entry.server.listen(route.listenPort, entry.host, () => {
          entry.server.off("error", reject);
          const addr = entry.server.address();
          if (addr === null || typeof addr === "string") {
            reject(new RelayRefusal("BAD_CONFIG", `route ${route.name}: no TCP address`));
            return;
          }
          entry.port = addr.port;
          resolve();
        });
      });
    }
  } catch (err) {
    await closeAll();
    throw err;
  }

  return {
    routes: live.map((entry) => ({ name: entry.name, listenHost: entry.host, listenPort: entry.port })),
    stats: () =>
      live.map((entry) => ({
        name: entry.name,
        listenPort: entry.port,
        connections: entry.connections,
        bytesToUpstream: entry.toUpstream,
        bytesFromUpstream: entry.fromUpstream,
      })),
    close: closeAll,
  };
}

// ---------------------------------------------------------------------------
// Command builders. They return argv arrays, never a shell string, so nothing is expanded.
// Env is not an input. A dev or debug looking environment changes nothing.
// ---------------------------------------------------------------------------

function assertNoDebugArgs(argv: readonly string[]): readonly string[] {
  for (const arg of argv) {
    if (/debug/i.test(arg)) throw new RelayRefusal("DEBUG_MODE", "refusing an argv that mentions debug");
  }
  return argv;
}

export interface RunEnclaveSpec {
  /** Path to the signed EIF. Built elsewhere. The host holds the image, never the signing key. */
  readonly eifPath: string;
  readonly cpuCount: number;
  readonly memoryMiB: number;
  readonly cid: number;
}

/** nitro-cli run-enclave argv. No debug flag, ever. */
export function buildRunEnclaveArgv(spec: RunEnclaveSpec): readonly string[] {
  refuseUnknownKeys("run-enclave", spec, ["eifPath", "cpuCount", "memoryMiB", "cid"]);
  if (typeof spec.eifPath !== "string" || !/^[\w./-]+\.eif$/.test(spec.eifPath) || spec.eifPath.includes("..")) {
    throw new RelayRefusal("BAD_CONFIG", "eifPath must be a plain path ending in .eif");
  }
  for (const [label, value, min] of [["cpuCount", spec.cpuCount, 1], ["memoryMiB", spec.memoryMiB, 64], ["cid", spec.cid, 4]] as const) {
    if (!Number.isInteger(value) || value < min) throw new RelayRefusal("BAD_CONFIG", `${label} must be an integer >= ${min}`);
  }
  return assertNoDebugArgs([
    "nitro-cli",
    "run-enclave",
    "--eif-path",
    spec.eifPath,
    "--cpu-count",
    String(spec.cpuCount),
    "--memory",
    String(spec.memoryMiB),
    "--enclave-cid",
    String(spec.cid),
  ]);
}

export interface VsockProxySpec {
  /** Local vsock port the enclave dials for this host. */
  readonly localPort: number;
  readonly upstream: Endpoint;
  /** Path to enclave/parent/vsock-proxy.yaml. */
  readonly configPath: string;
}

/** vsock-proxy argv for one outbound route. The upstream must be on the allowlist. */
export function buildVsockProxyArgv(spec: VsockProxySpec): readonly string[] {
  refuseUnknownKeys("vsock-proxy", spec, ["localPort", "upstream", "configPath"]);
  if (!validPort(spec.localPort, false)) throw new RelayRefusal("BAD_CONFIG", "bad localPort");
  if (!EGRESS_ALLOWLIST.some((entry) => sameEndpoint(entry, spec.upstream))) {
    throw new RelayRefusal("NOT_ALLOWLISTED", `${spec.upstream.host}:${spec.upstream.port} is not in the allowlist`);
  }
  if (typeof spec.configPath !== "string" || !/^[\w./-]+\.yaml$/.test(spec.configPath)) {
    throw new RelayRefusal("BAD_CONFIG", "configPath must be a plain path ending in .yaml");
  }
  return assertNoDebugArgs([
    "vsock-proxy",
    String(spec.localPort),
    spec.upstream.host,
    String(spec.upstream.port),
    "--config",
    spec.configPath,
  ]);
}

export interface InboundForwarderSpec {
  /** Public TCP port on the host, 443 for RA or 80 for ACME. */
  readonly tcpPort: 80 | 443;
  readonly cid: number;
  readonly vsockPort: number;
}

/** socat argv that forwards raw inbound TCP to the enclave. The enclave ends the encrypted connection. */
export function buildInboundForwarderArgv(spec: InboundForwarderSpec): readonly string[] {
  refuseUnknownKeys("inbound", spec, ["tcpPort", "cid", "vsockPort"]);
  if (spec.tcpPort !== 80 && spec.tcpPort !== 443) throw new RelayRefusal("BAD_CONFIG", "tcpPort must be 80 or 443");
  if (!Number.isInteger(spec.cid) || spec.cid < 4) throw new RelayRefusal("BAD_CONFIG", "cid must be an integer >= 4");
  if (!validPort(spec.vsockPort, false)) throw new RelayRefusal("BAD_CONFIG", "bad vsockPort");
  return assertNoDebugArgs([
    "socat",
    `TCP-LISTEN:${spec.tcpPort},fork,reuseaddr`,
    `VSOCK-CONNECT:${spec.cid}:${spec.vsockPort}`,
  ]);
}
