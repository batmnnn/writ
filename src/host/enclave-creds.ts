// Host-only refresh of the AWS role credentials the enclave signs S3 calls with. The boot line credentials
// expire in hours, and after that every checkpoint fails closed (COMMIT_FAILED). The host reads fresh role
// credentials from IMDSv2 and sends one JSON line here (scripts/host-refresh-creds.sh).
//
// Reach: boot.sh relays vsock port 5001 to 127.0.0.1:5001, and only the parent instance can open a vsock
// connection to the enclave. The public TLS server on 8443 has no route to this listener.
// These credentials are not a trust root: the role cannot decrypt without the attestation, and every
// checkpoint is signed by the enclave ledger key. They are still never logged or echoed.

import type { AwsCredentials } from "./kms-unseal";

export const CREDS_HOST = "127.0.0.1";
export const CREDS_PORT = 5001;
const MAX_LINE_BYTES = 8 * 1024;
const LINE_TIMEOUT_MS = 5_000;
const ACCESS_KEY_RE = /^[A-Z0-9]{16,128}$/;
const SECRET_RE = /^[\x21-\x7e]{16,4096}$/;
const ISO_Z_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

/** Holds the live credentials. get() is undefined once a known expiration has passed on the enclave clock. */
export class CredentialBox {
  private creds: AwsCredentials;
  private expiresAtMs: number | undefined;

  constructor(
    initial: AwsCredentials,
    private readonly nowMs: () => number,
  ) {
    this.creds = { ...initial };
  }

  get(): AwsCredentials | undefined {
    if (this.expiresAtMs !== undefined) {
      const now = this.nowMs();
      if (!Number.isFinite(now) || now >= this.expiresAtMs) return undefined;
    }
    return this.creds;
  }

  set(creds: AwsCredentials, expiresAtMs: number): void {
    this.creds = { ...creds };
    this.expiresAtMs = expiresAtMs;
  }

  get expiration(): string | undefined {
    return this.expiresAtMs === undefined ? undefined : new Date(this.expiresAtMs).toISOString();
  }
}

export type CredsParse = { ok: true; creds: AwsCredentials; expiresAtMs: number } | { ok: false; code: string };

/** Exactly accessKeyId, secretAccessKey, sessionToken and expiration. The expiration must be in the future on the enclave clock. */
export function parseCredsLine(line: Uint8Array, nowMs: number): CredsParse {
  let raw: unknown;
  try {
    raw = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(line));
  } catch {
    return { ok: false, code: "BAD_INPUT" };
  }
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return { ok: false, code: "BAD_INPUT" };
  const r = raw as Record<string, unknown>;
  if (Object.keys(r).sort().join(",") !== "accessKeyId,expiration,secretAccessKey,sessionToken") return { ok: false, code: "BAD_INPUT" };
  if (typeof r.accessKeyId !== "string" || !ACCESS_KEY_RE.test(r.accessKeyId)) return { ok: false, code: "BAD_INPUT" };
  if (typeof r.secretAccessKey !== "string" || !SECRET_RE.test(r.secretAccessKey)) return { ok: false, code: "BAD_INPUT" };
  if (typeof r.sessionToken !== "string" || !SECRET_RE.test(r.sessionToken)) return { ok: false, code: "BAD_INPUT" };
  if (typeof r.expiration !== "string" || !ISO_Z_RE.test(r.expiration)) return { ok: false, code: "BAD_INPUT" };
  const expiresAtMs = Date.parse(r.expiration);
  if (!Number.isFinite(expiresAtMs)) return { ok: false, code: "BAD_INPUT" };
  if (!Number.isFinite(nowMs)) return { ok: false, code: "NO_CLOCK" };
  if (expiresAtMs <= nowMs) return { ok: false, code: "EXPIRED" };
  return { ok: true, creds: { accessKeyId: r.accessKeyId, secretAccessKey: r.secretAccessKey, sessionToken: r.sessionToken }, expiresAtMs };
}

export interface CredsListenerOptions {
  box: CredentialBox;
  nowMs(): number;
  /** Default 5001. 0 picks a free port (tests). */
  port?: number;
}

export interface CredsListenerHandle {
  readonly port: number;
  stop(): void;
}

interface Conn {
  chunks: Buffer[];
  size: number;
  done: boolean;
  timer: ReturnType<typeof setTimeout>;
}

/**
 * Plain TCP on 127.0.0.1, one line per connection. Replies `OK <expiration>` or `DECLINED <code>` and
 * closes. No TLS, no HTTP, no other command. The line buffer is zeroed after use.
 */
export function startCredsListener(opts: CredsListenerOptions): CredsListenerHandle {
  const finish = (sock: { data: Conn; write(s: string): number; end(): void }, reply: string) => {
    const c = sock.data;
    if (c.done) return;
    c.done = true;
    clearTimeout(c.timer);
    for (const b of c.chunks) b.fill(0);
    c.chunks = [];
    sock.write(`${reply}\n`);
    sock.end();
  };
  const server = Bun.listen<Conn>({
    hostname: CREDS_HOST,
    port: opts.port ?? CREDS_PORT,
    socket: {
      open(sock) {
        sock.data = { chunks: [], size: 0, done: false, timer: setTimeout(() => finish(sock, "DECLINED TIMEOUT"), LINE_TIMEOUT_MS) };
      },
      data(sock, chunk) {
        const c = sock.data;
        const buf = Buffer.from(chunk);
        if (c.done) {
          buf.fill(0);
          return;
        }
        const nl = buf.indexOf(0x0a);
        const take = nl === -1 ? buf.length : nl;
        if (c.size + take > MAX_LINE_BYTES) {
          buf.fill(0);
          finish(sock, "DECLINED LINE_TOO_LONG");
          return;
        }
        c.chunks.push(Buffer.from(buf.subarray(0, take)));
        c.size += take;
        buf.fill(0);
        if (nl === -1) return;
        const line = Buffer.concat(c.chunks, c.size);
        const parsed = parseCredsLine(line, opts.nowMs());
        line.fill(0);
        if (!parsed.ok) {
          finish(sock, `DECLINED ${parsed.code}`);
          return;
        }
        opts.box.set(parsed.creds, parsed.expiresAtMs);
        finish(sock, `OK ${opts.box.expiration}`);
      },
      close(sock) {
        const c = sock.data;
        if (!c) return;
        clearTimeout(c.timer);
        for (const b of c.chunks) b.fill(0);
        c.chunks = [];
      },
      error() {
        // the connection is dropped; nothing was swapped
      },
    },
  });
  return { port: server.port, stop: () => server.stop(true) };
}
