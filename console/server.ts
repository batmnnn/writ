// Five panel console on localhost:3000. SSE from the demo. No secrets, no sixth panel.

import { sanitizeEvent, type ConsoleEvent } from "./feed";

const DIR = import.meta.dir;
const MAX_HISTORY = 500;

export interface ConsoleServer {
  port: number;
  url: string;
  history: () => ConsoleEvent[];
  stop: () => void;
}

export function startConsole(opts: { port?: number; hostname?: string } = {}): ConsoleServer {
  const history: ConsoleEvent[] = [];
  const clients = new Set<ReadableStreamDefaultController<Uint8Array>>();
  const enc = new TextEncoder();

  const send = (controller: ReadableStreamDefaultController<Uint8Array>, event: ConsoleEvent, id: number): void => {
    const chunk = `id: ${id}\nevent: writ\ndata: ${JSON.stringify(event)}\n\n`;
    try {
      controller.enqueue(enc.encode(chunk));
    } catch {
      clients.delete(controller);
    }
  };

  const broadcast = (event: ConsoleEvent): void => {
    const id = history.length;
    for (const c of clients) send(c, event, id);
  };

  const push = (event: ConsoleEvent): void => {
    if (event.kind === "reset") history.length = 0;
    history.push(event);
    if (history.length > MAX_HISTORY) history.splice(0, history.length - MAX_HISTORY);
    broadcast(event);
  };

  const file = (name: string, type: string): Response => {
    const f = Bun.file(`${DIR}/${name}`);
    return new Response(f, { headers: { "content-type": type } });
  };

  const server = Bun.serve({
    port: opts.port ?? 3000,
    hostname: opts.hostname ?? "127.0.0.1",
    async fetch(req) {
      const url = new URL(req.url);
      const path = url.pathname;

      if (req.method === "GET" && (path === "/" || path === "/index.html")) return file("index.html", "text/html; charset=utf-8");
      if (req.method === "GET" && path === "/console.css") return file("console.css", "text/css; charset=utf-8");
      if (req.method === "GET" && path === "/console.js") return file("console.js", "text/javascript; charset=utf-8");

      if (req.method === "GET" && path === "/health") {
        return Response.json({ ok: true, events: history.length, badge: "Frozen card" });
      }

      if (req.method === "GET" && path === "/events") {
        let tick: ReturnType<typeof setInterval> | undefined;
        const stream = new ReadableStream<Uint8Array>({
          start(controller) {
            clients.add(controller);
            controller.enqueue(enc.encode("retry: 2000\n\n"));
            history.forEach((event, i) => send(controller, event, i + 1));
            tick = setInterval(() => {
              try {
                controller.enqueue(enc.encode(": keepalive\n\n"));
              } catch {
                if (tick) clearInterval(tick);
                clients.delete(controller);
              }
            }, 15_000);
          },
          cancel() {
            if (tick) clearInterval(tick);
          },
        });
        return new Response(stream, {
          headers: {
            "content-type": "text/event-stream; charset=utf-8",
            "cache-control": "no-cache",
            connection: "keep-alive",
          },
        });
      }

      if (req.method === "POST" && path === "/ingest") {
        let raw: unknown;
        try {
          raw = await req.json();
        } catch {
          return Response.json({ ok: false, error: "bad json" }, { status: 400 });
        }
        const items = Array.isArray(raw) ? raw : [raw];
        let n = 0;
        for (const item of items) {
          const event = sanitizeEvent(item);
          if (!event) continue;
          push(event);
          n += 1;
        }
        return Response.json({ ok: true, ingested: n });
      }

      return new Response("not found", { status: 404 });
    },
  });

  const port = server.port;
  if (port === undefined) throw new Error("console did not bind a port");
  const url = `http://${server.hostname}:${port}`;
  return {
    port,
    url,
    history: () => history.slice(),
    stop: () => {
      for (const c of clients) {
        try {
          c.close();
        } catch {
          /* already closed */
        }
      }
      clients.clear();
      server.stop(true);
    },
  };
}

if (import.meta.main) {
  const port = Number(process.env.WRIT_CONSOLE_PORT ?? 3000);
  const c = startConsole({ port });
  console.log(`Writ console on ${c.url}. Badge: Frozen card. Five panels, no attestation strip.`);
}
