/**
 * Authenticated, stateless Streamable HTTP transport for the Code Atlas MCP server.
 *
 * Secure by default, in this order of checks on every request:
 *   1. Host header allowlist  - defeats DNS rebinding (a page on evil.example resolving
 *      to 127.0.0.1 would send "Host: evil.example" and is refused);
 *   2. Origin allowlist       - a browser Origin must be explicitly allowed; non-browser
 *      clients send none. No CORS headers are ever emitted;
 *   3. request rate limit, and a tighter limit on FAILED authentication per client;
 *   4. bearer key (constant-time compare) before the body is read;
 *   5. a bounded JSON body.
 *
 * Defaults: bind 127.0.0.1, READ-ONLY (atlas_triage is not registered unless the
 * operator passes --allow-triage), non-loopback binds refused without --allow-remote.
 * Stateless: a fresh server + transport per POST, as the SDK requires.
 */
import { timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { buildServer, type AtlasCtx } from "./server.js";

export const MIN_API_KEY_LENGTH = 32;
export const MAX_HTTP_BODY_BYTES = 1_000_000;
const LOOPBACK = new Set(["127.0.0.1", "localhost", "::1"]);

export interface HttpServerOptions {
  apiKey: string;
  /** Interface to bind. Default 127.0.0.1. */
  host?: string;
  /** 0 picks a free port (tests). Default 8000. */
  port?: number;
  /** Register the write tool atlas_triage. Default false. */
  allowTriage?: boolean;
  /** Permit binding a non-loopback interface. Default false. */
  allowRemote?: boolean;
  /** Extra Host header names to accept (public DNS name behind a proxy). */
  allowedHosts?: string[];
  /** Browser Origins to accept, e.g. "https://app.example". Default none. */
  allowedOrigins?: string[];
  /** Requests per client per minute. Default 300. */
  maxRequestsPerMinute?: number;
  /** Failed authentications per client per minute before 429. Default 10. */
  maxAuthFailuresPerMinute?: number;
}

export function isValidBearerToken(authorization: string | undefined, apiKey: string): boolean {
  const match = /^Bearer ([^\s]+)$/i.exec(authorization ?? "");
  if (!match) return false;
  const actual = Buffer.from(match[1], "utf8");
  const expected = Buffer.from(apiKey, "utf8");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

/** Hostname part of a Host header value (`name:port`, `[::1]:port`), lower-cased. */
export function hostnameOf(hostHeader: string | undefined): string | null {
  if (!hostHeader) return null;
  const h = hostHeader.trim().toLowerCase();
  const v6 = /^\[([^\]]+)\](?::\d+)?$/.exec(h);
  if (v6) return v6[1];
  const m = /^([^:]+)(?::\d+)?$/.exec(h);
  return m ? m[1] : null;
}

/** Fixed-window per-client counters (in memory; one process). */
class WindowCounter {
  private hits = new Map<string, { start: number; n: number }>();
  constructor(private limit: number, private windowMs = 60_000) {}
  /** Count one event; true when the client is now OVER the limit. */
  over(key: string, now = Date.now()): boolean {
    if (this.hits.size > 10_000) this.prune(now);
    const e = this.hits.get(key);
    if (!e || now - e.start >= this.windowMs) { this.hits.set(key, { start: now, n: 1 }); return this.limit < 1; }
    e.n += 1;
    return e.n > this.limit;
  }
  /** Has the client USED UP its allowance (limit events counted), without counting? */
  reached(key: string, now = Date.now()): boolean {
    const e = this.hits.get(key);
    return !!e && now - e.start < this.windowMs && e.n >= this.limit;
  }
  private prune(now: number) { for (const [k, e] of this.hits) if (now - e.start >= this.windowMs) this.hits.delete(k); }
}

function sendJson(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extra });
  res.end(JSON.stringify(body));
}

async function readHttpJson(req: IncomingMessage, res: ServerResponse): Promise<unknown | null> {
  const contentType = req.headers["content-type"]?.split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/json") {
    sendJson(res, 415, { error: "Content-Type must be application/json" });
    req.resume();
    return null;
  }
  const contentLength = Number(req.headers["content-length"]);
  if (Number.isFinite(contentLength) && contentLength > MAX_HTTP_BODY_BYTES) {
    sendJson(res, 413, { error: "Request body is too large" });
    req.resume();
    return null;
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > MAX_HTTP_BODY_BYTES) {
      sendJson(res, 413, { error: "Request body is too large" });
      req.resume();
      return null;
    }
    chunks.push(buffer);
  }
  try {
    const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      sendJson(res, 400, { error: "Request body must be a JSON object" });
      return null;
    }
    return parsed;
  } catch {
    sendJson(res, 400, { error: "Request body must contain valid JSON" });
    return null;
  }
}

export async function startHttpServer(ctx: AtlasCtx, options: HttpServerOptions): Promise<Server> {
  if (options.apiKey.length < MIN_API_KEY_LENGTH)
    throw new Error(`ATLAS_MCP_API_KEY must be at least ${MIN_API_KEY_LENGTH} characters`);
  const bindHost = options.host ?? "127.0.0.1";
  if (!LOOPBACK.has(bindHost.toLowerCase()) && !options.allowRemote)
    throw new Error(`Refusing to bind ${bindHost}: a non-loopback address exposes your source to the network. Pass --allow-remote (and put TLS in front) if that is intended.`);

  const allowedHosts = new Set<string>([...LOOPBACK, ...(options.allowedHosts ?? []).map((h) => h.toLowerCase())]);
  const wildcard = bindHost === "0.0.0.0" || bindHost === "::";
  if (!wildcard) allowedHosts.add(bindHost.toLowerCase());
  const allowedOrigins = new Set((options.allowedOrigins ?? []).map((o) => o.replace(/\/$/, "").toLowerCase()));
  const requests = new WindowCounter(options.maxRequestsPerMinute ?? 300);
  const authFailures = new WindowCounter(options.maxAuthFailuresPerMinute ?? 10);

  const httpServer = createServer((req, res) => {
    void (async () => {
      // 1) DNS-rebinding guard
      const hostname = hostnameOf(req.headers.host);
      if (!hostname || !allowedHosts.has(hostname)) {
        sendJson(res, 403, { error: "Host not allowed" });
        req.resume();
        return;
      }
      // 2) Origin guard (browsers always send Origin on cross-origin requests)
      const origin = req.headers.origin;
      if (origin !== undefined && !allowedOrigins.has(String(origin).replace(/\/$/, "").toLowerCase())) {
        sendJson(res, 403, { error: "Origin not allowed" });
        req.resume();
        return;
      }
      // 3) rate limits, per client address
      const client = req.socket.remoteAddress ?? "unknown";
      if (requests.over(client) || authFailures.reached(client)) {
        sendJson(res, 429, { error: "Too many requests" }, { "retry-after": "60" });
        req.resume();
        return;
      }

      if (req.url === "/healthz" && req.method === "GET") { sendJson(res, 200, { status: "ok" }); return; }
      if (req.url !== "/mcp") { sendJson(res, 404, { error: "Not found" }); return; }

      // 4) authenticate before reading any body
      if (!isValidBearerToken(req.headers.authorization, options.apiKey)) {
        authFailures.over(client);
        sendJson(res, 401, { error: "Unauthorized" }, { "www-authenticate": 'Bearer realm="code-atlas-mcp"' });
        req.resume();
        return;
      }
      if (req.method !== "POST") { sendJson(res, 405, { error: "Only POST is supported at the MCP endpoint" }, { allow: "POST" }); return; }

      // 5) bounded body, then a fresh stateless server + transport
      const parsedBody = await readHttpJson(req, res);
      if (parsedBody === null) return;
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      try {
        await buildServer(ctx, { allowTriage: options.allowTriage === true }).connect(transport);
        await transport.handleRequest(req, res, parsedBody);
      } catch (error) {
        console.error("MCP HTTP request failed:", error);
        if (!res.headersSent) sendJson(res, 500, { error: "MCP request failed" });
        else res.destroy();
      } finally {
        try { await transport.close(); } catch (error) { console.error("MCP transport close failed:", error); }
      }
    })().catch((error: unknown) => {
      console.error("MCP HTTP handler failed:", error);
      if (!res.headersSent) sendJson(res, 500, { error: "MCP request failed" });
      else res.destroy();
    });
  });
  httpServer.headersTimeout = 15_000;
  httpServer.requestTimeout = 60_000;
  httpServer.maxHeadersCount = 100;

  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(options.port ?? 8000, bindHost, () => { httpServer.removeListener("error", reject); resolve(); });
  });
  return httpServer;
}

/** CLI/env -> options. Flags: --http --port N --host H --allow-remote --allow-triage
 *  --allowed-host H --allowed-origin O (repeatable). Env: ATLAS_MCP_API_KEY (required),
 *  PORT, HOST, ATLAS_ALLOWED_HOSTS / ATLAS_ALLOWED_ORIGINS (comma-separated). */
export function httpOptionsFromArgs(args: string[], env: NodeJS.ProcessEnv): Required<Pick<HttpServerOptions, "apiKey" | "host" | "port" | "allowTriage">> & HttpServerOptions {
  const apiKey = env.ATLAS_MCP_API_KEY;
  if (!apiKey) throw new Error("Set ATLAS_MCP_API_KEY to a randomly generated secret (>= 32 characters) before starting HTTP mode");
  const flag = (name: string) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
  const all = (name: string) => args.flatMap((a, i) => (a === name && args[i + 1] ? [args[i + 1]] : []));
  const csv = (v: string | undefined) => (v ?? "").split(",").map((x) => x.trim()).filter(Boolean);
  const port = Number(flag("--port") ?? env.PORT ?? "8000");
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error("--port / PORT must be an integer from 0 to 65535");
  return {
    apiKey,
    host: flag("--host") ?? env.HOST ?? "127.0.0.1",
    port,
    allowTriage: args.includes("--allow-triage"),
    allowRemote: args.includes("--allow-remote"),
    allowedHosts: [...csv(env.ATLAS_ALLOWED_HOSTS), ...all("--allowed-host")],
    allowedOrigins: [...csv(env.ATLAS_ALLOWED_ORIGINS), ...all("--allowed-origin")],
  };
}
