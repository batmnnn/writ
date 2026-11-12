// Fetch wrapper for the Airwallex sandbox. Reads no env and no files: the caller passes config.
// Every call returns a Result and nothing throws past this file. Logs carry method, path, status
// and request id only, never bodies, tokens or keys.

import type { AdapterError, Result } from "../types";
import { redact, redactString } from "./redact";

export interface ClientOptions {
  baseUrl: string;
  clientId: string;
  apiKey: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  /** Minimum gap between request starts. 120 ms keeps us under 10 req/s. */
  minIntervalMs?: number;
  log?: (line: string) => void;
  /** Sees every non login exchange, body already redacted. The probe uses it to write fixtures. */
  onExchange?: (x: Exchange) => void;
}

export interface Exchange {
  method: string;
  path: string;
  status: number | undefined;
  requestId?: string;
  requestBody?: unknown;
  responseBody?: unknown;
}

export interface RequestOptions {
  body?: unknown;
  query?: Record<string, string | number | undefined>;
  requestId?: string;
  /** Overrides the client timeout for this call. Card updates keep the client default. */
  timeoutMs?: number;
}

const TOKEN_REFRESH_MARGIN_MS = 2 * 60 * 1000;
const DEFAULT_TOKEN_LIFE_MS = 25 * 60 * 1000;

const fail = (error: AdapterError): { ok: false; error: AdapterError } => ({ ok: false, error });

export function checkSandboxUrl(baseUrl: string): AdapterError | undefined {
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    return { kind: "config", message: "AIRWALLEX_BASE_URL is not a valid URL" };
  }
  if (!baseUrl.includes("sandbox")) {
    return { kind: "config", message: "AIRWALLEX_BASE_URL must point at the sandbox. Refusing to start." };
  }
  if (url.protocol !== "https:") return { kind: "config", message: "AIRWALLEX_BASE_URL must use https" };
  return undefined;
}

export class AirwallexClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly minIntervalMs: number;
  private readonly log: (line: string) => void;
  private readonly configError: AdapterError | undefined;
  private token: { value: string; refreshAt: number } | undefined;
  private loginInFlight: Promise<Result<string>> | undefined;
  private nextSlot = 0;

  constructor(private readonly opts: ClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? 5000;
    this.minIntervalMs = opts.minIntervalMs ?? 120;
    this.log = opts.log ?? ((line) => console.log(line));
    this.configError =
      checkSandboxUrl(opts.baseUrl) ??
      (!opts.clientId || !opts.apiKey
        ? { kind: "config", message: "AIRWALLEX_CLIENT_ID and AIRWALLEX_API_KEY are required" }
        : undefined);
  }

  /** Undefined when the client may talk to Airwallex. */
  get configProblem(): AdapterError | undefined {
    return this.configError;
  }

  async request<T = unknown>(method: "GET" | "POST", path: string, ro: RequestOptions = {}): Promise<Result<T>> {
    try {
      if (this.configError) return fail(this.configError);
      const token = await this.getToken();
      if (!token.ok) return token;
      let res = await this.send<T>(method, path, ro, token.value);
      if (!res.ok && res.error.status === 401) {
        this.token = undefined;
        const again = await this.getToken();
        if (!again.ok) return again;
        res = await this.send<T>(method, path, ro, again.value);
      }
      return res;
    } catch (e) {
      return fail({ kind: "network", message: `unexpected: ${redactString(String(e))}`, ...(ro.requestId ? { requestId: ro.requestId } : {}) });
    }
  }

  private async getToken(): Promise<Result<string>> {
    if (this.token && Date.now() < this.token.refreshAt) return { ok: true, value: this.token.value };
    if (!this.loginInFlight) {
      this.loginInFlight = this.login().finally(() => {
        this.loginInFlight = undefined;
      });
    }
    return this.loginInFlight;
  }

  private async login(): Promise<Result<string>> {
    const path = "/api/v1/authentication/login";
    const r = await this.raw("POST", path, {
      "x-client-id": this.opts.clientId,
      "x-api-key": this.opts.apiKey,
    });
    if (!r.ok) return r;
    const body = r.value.body as { token?: unknown; expires_at?: unknown } | undefined;
    if (typeof body?.token !== "string" || body.token.length === 0) {
      return fail({ kind: "invalid_response", status: r.value.status, message: "login returned no token" });
    }
    const expiresAt = typeof body.expires_at === "string" ? Date.parse(body.expires_at) : NaN;
    const life = Number.isFinite(expiresAt) ? expiresAt - Date.now() : DEFAULT_TOKEN_LIFE_MS;
    this.token = { value: body.token, refreshAt: Date.now() + Math.max(life - TOKEN_REFRESH_MARGIN_MS, 30_000) };
    return { ok: true, value: body.token };
  }

  private async send<T>(method: string, path: string, ro: RequestOptions, token: string): Promise<Result<T>> {
    let fullPath = path;
    if (ro.query) {
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(ro.query)) if (v !== undefined) qs.set(k, String(v));
      const s = qs.toString();
      if (s) fullPath += `?${s}`;
    }
    const headers: Record<string, string> = { authorization: `Bearer ${token}` };
    if (ro.body !== undefined) headers["content-type"] = "application/json";
    const r = await this.raw(method, fullPath, headers, ro.body, ro.requestId, ro.timeoutMs);
    this.opts.onExchange?.({
      method,
      path: fullPath,
      status: r.ok ? r.value.status : r.error.status,
      ...(ro.requestId ? { requestId: ro.requestId } : {}),
      ...(ro.body !== undefined ? { requestBody: redact(ro.body) } : {}),
      responseBody: redact(r.ok ? r.value.body : r.error),
    });
    if (!r.ok) return r;
    return { ok: true, value: r.value.body as T };
  }

  /** One HTTP exchange with limiter and timeout. Non 2xx becomes a failure with the error body. */
  private async raw(
    method: string,
    path: string,
    headers: Record<string, string>,
    body?: unknown,
    requestId?: string,
    timeoutMs?: number,
  ): Promise<Result<{ status: number; body: unknown }>> {
    await this.waitForSlot();
    const waitMs = timeoutMs ?? this.timeoutMs;
    const rid = requestId ? { requestId } : {};
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<"timeout">((resolve) => {
      timer = setTimeout(() => {
        controller.abort();
        resolve("timeout");
      }, waitMs);
    });
    try {
      const call = this.fetchImpl(`${this.baseUrl}${path}`, {
        method,
        headers,
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
        signal: controller.signal,
      }).then(async (res) => ({ res, text: await res.text() }));
      call.catch(() => undefined);
      const out = await Promise.race([call, timeout]);
      if (out === "timeout") {
        this.logLine(method, path, "timeout", requestId);
        return fail({ kind: "timeout", message: `no answer within ${waitMs} ms`, ...rid });
      }
      const { res, text } = out;
      this.logLine(method, path, String(res.status), requestId);
      let parsed: unknown = undefined;
      if (text.length > 0) {
        try {
          parsed = JSON.parse(text);
        } catch {
          if (res.ok) return fail({ kind: "invalid_response", status: res.status, message: "body is not JSON", ...rid });
        }
      }
      if (!res.ok) {
        const eb = parsed as { code?: unknown; message?: unknown } | undefined;
        return fail({
          kind: "http",
          status: res.status,
          ...(typeof eb?.code === "string" ? { code: eb.code } : {}),
          message: redactString(typeof eb?.message === "string" ? eb.message : text.slice(0, 500) || `HTTP ${res.status}`),
          ...rid,
        });
      }
      return { ok: true, value: { status: res.status, body: parsed } };
    } catch (e) {
      const aborted = controller.signal.aborted;
      this.logLine(method, path, aborted ? "timeout" : "network_error", requestId);
      return fail({
        kind: aborted ? "timeout" : "network",
        message: aborted ? `no answer within ${waitMs} ms` : redactString(String(e)),
        ...rid,
      });
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private async waitForSlot(): Promise<void> {
    const now = Date.now();
    const slot = Math.max(now, this.nextSlot);
    this.nextSlot = slot + this.minIntervalMs;
    if (slot > now) await new Promise((r) => setTimeout(r, slot - now));
  }

  private logLine(method: string, path: string, status: string, requestId?: string): void {
    const p = path.split("?")[0];
    this.log(`[airwallex] ${method} ${p} ${status}${requestId ? ` request_id=${requestId}` : ""}`);
  }
}
