// Every agent web read goes through this wrapper. Any URL off the allowlist taints the run
// before the response reaches the agent. Redirects to an off-list host taint too.

import type { IsoTime } from "./types";

export interface TaintNotice {
  runId: string;
  url: string;
  at: IsoTime;
}

export interface AgentFetchOptions {
  runId: string;
  allowlist: string[]; // hosts, "*.example.com" matches subdomains
  onTaint: (notice: TaintNotice) => void;
  now?: () => IsoTime;
  fetchImpl?: typeof fetch;
}

export function parseAllowlist(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

export function isAllowed(url: string, allowlist: string[]): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:") return false;
  const host = parsed.hostname.toLowerCase();
  return allowlist.some((entry) =>
    entry.startsWith("*.") ? host.endsWith(entry.slice(1)) && host.length > entry.length - 1 : host === entry,
  );
}

const requestUrl = (input: string | URL | Request): string =>
  typeof input === "string" ? input : input instanceof URL ? input.href : input.url;

export function createAgentFetch(opts: AgentFetchOptions) {
  const now = opts.now ?? (() => new Date().toISOString());
  const doFetch = opts.fetchImpl ?? fetch;
  const taint = (url: string) => opts.onTaint({ runId: opts.runId, url, at: now() });

  return async function agentFetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
    const url = requestUrl(input);
    if (!isAllowed(url, opts.allowlist)) taint(url);
    const res = await doFetch(input, init);
    if (res.redirected && res.url && !isAllowed(res.url, opts.allowlist)) taint(res.url);
    return res;
  };
}
