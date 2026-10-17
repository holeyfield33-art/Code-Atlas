/**
 * Streamable HTTP transport: secure by default.
 *  - binds loopback; refuses a non-loopback bind without --allow-remote;
 *  - rejects a foreign Host (DNS rebinding) and any non-allowlisted Origin;
 *  - bearer auth is checked before the body is read; constant-time compare;
 *  - failed auth and request volume are rate limited per client (429);
 *  - READ-ONLY by default: atlas_triage is not even listed unless allowTriage;
 *  - bodies are bounded; initialize / tools/list / tools/call work end to end.
 */
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";
import { parseBundle } from "../src/schema.js";
import { makeCtx } from "../src/mcp/server.js";
import { isValidBearerToken, hostnameOf, httpOptionsFromArgs, startHttpServer, WindowCounter } from "../src/mcp/http.js";

const apiKey = "0123456789abcdef0123456789abcdef";
const bundle = parseBundle({
  schemaVersion: "1.0",
  product: { name: "Code Atlas" },
  repository: { label: "http-test", revision: "test" },
  generatedAt: new Date().toISOString(),
  graph: { version: "test", revision: "test", nodes: [], edges: [], diagnostics: [] },
});
const ctx = () => makeCtx(bundle, null);

// ---- pure helpers
assert.ok(isValidBearerToken(`Bearer ${apiKey}`, apiKey), "valid bearer key is accepted");
assert.ok(!isValidBearerToken(undefined, apiKey), "missing authorization is rejected");
assert.ok(!isValidBearerToken(`Bearer ${apiKey}x`, apiKey), "wrong bearer key is rejected");
assert.ok(!isValidBearerToken(apiKey, apiKey), "bare API key is rejected");
assert.strictEqual(hostnameOf("LocalHost:8000"), "localhost");
assert.strictEqual(hostnameOf("[::1]:8000"), "::1");
assert.strictEqual(hostnameOf(undefined), null);
assert.throws(() => httpOptionsFromArgs(["--http"], {}), /ATLAS_MCP_API_KEY/, "a key is required");
const parsed = httpOptionsFromArgs(["--http", "--port", "9000", "--allow-triage", "--allowed-origin", "https://a.example"], { ATLAS_MCP_API_KEY: apiKey });
assert.strictEqual(parsed.host, "127.0.0.1", "CLI default host is loopback");
assert.strictEqual(parsed.port, 9000);
assert.strictEqual(parsed.allowTriage, true);
assert.deepStrictEqual(parsed.allowedOrigins, ["https://a.example"]);
assert.strictEqual(httpOptionsFromArgs(["--http"], { ATLAS_MCP_API_KEY: apiKey }).allowTriage, false, "triage is off unless asked");

// ---- the rate-limit table is bounded (many distinct source addresses cannot grow it)
{
  const wc = new WindowCounter(5, 60_000, 100);
  for (let i = 0; i < 1000; i++) wc.over("10.0." + Math.floor(i / 250) + "." + (i % 250), 1000 + i);
  assert.ok(wc.size <= 100, "entries never exceed maxEntries (got " + wc.size + ")");
  assert.strictEqual(wc.over("same", 5000), false);
  for (let i = 0; i < 5; i++) wc.over("same", 5001 + i);
  assert.ok(wc.reached("same", 5010), "an active client is still counted and limited");
  const t0 = Date.now(); const big = new WindowCounter(5, 60_000, 10_000);
  for (let i = 0; i < 50_000; i++) big.over("k" + i, 1000);
  assert.ok(big.size <= 10_000 && Date.now() - t0 < 3000, "50,000 distinct clients stay bounded and fast (O(1) per insert)");
}

// ---- startup refusals
await assert.rejects(startHttpServer(ctx(), { apiKey: "too-short" }), /at least 32 characters/);
await assert.rejects(startHttpServer(ctx(), { apiKey, host: "0.0.0.0", port: 0 }), /Refusing to bind/, "a network bind needs --allow-remote");

// ---- helpers for a running server
type Opts = Parameters<typeof startHttpServer>[1];
async function withServer(extra: Partial<Opts>, fn: (url: string, port: number) => Promise<void>): Promise<void> {
  const server = await startHttpServer(ctx(), { apiKey, port: 0, ...extra });
  const { address, port } = server.address() as AddressInfo;
  try { await fn(`http://127.0.0.1:${port}`, port); assert.strictEqual(address, "127.0.0.1", "default bind is loopback"); }
  finally { await new Promise<void>((res, rej) => server.close((e) => (e ? rej(e) : res()))); }
}
const jsonHeaders = { authorization: `Bearer ${apiKey}`, "content-type": "application/json", accept: "application/json, text/event-stream" };
const post = (url: string, body: unknown, headers: Record<string, string> = jsonHeaders) =>
  fetch(`${url}/mcp`, { method: "POST", headers, body: JSON.stringify(body) });
const rpc = async (url: string, id: number, method: string, params: unknown = {}) =>
  (await (await post(url, { jsonrpc: "2.0", id, method, params })).json()) as any;
/** Raw request so we can set Host / Origin, which fetch forbids. */
function raw(port: number, headers: Record<string, string>, path = "/healthz", method = "GET"): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method, headers }, (res) => {
      let b = ""; res.on("data", (c) => (b += c)); res.on("end", () => resolve({ status: res.statusCode ?? 0, body: b }));
    });
    r.on("error", reject); r.end();
  });
}

// ---- default (read-only) server
await withServer({}, async (url, port) => {
  const health = await fetch(`${url}/healthz`);
  assert.strictEqual(health.status, 200);
  assert.deepStrictEqual(await health.json(), { status: "ok" });

  assert.strictEqual((await raw(port, { host: "evil.example" })).status, 403, "foreign Host header is refused (DNS rebinding)");
  assert.strictEqual((await raw(port, { host: `localhost:${port}` })).status, 200, "localhost Host is accepted");
  assert.strictEqual((await raw(port, { host: `127.0.0.1:${port}`, origin: "https://evil.example" })).status, 403, "unlisted browser Origin is refused");

  const noKey = await post(url, { jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, { ...jsonHeaders, authorization: "" });
  assert.strictEqual(noKey.status, 401);
  assert.ok(noKey.headers.has("www-authenticate"));
  const badKey = await post(url, { jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, { ...jsonHeaders, authorization: `Bearer ${"x".repeat(32)}` });
  assert.strictEqual(badKey.status, 401);
  assert.strictEqual((await fetch(`${url}/mcp`, { headers: { authorization: `Bearer ${apiKey}` } })).status, 405, "GET is not supported (stateless)");

  const tooLarge = await fetch(`${url}/mcp`, { method: "POST", headers: jsonHeaders, body: JSON.stringify({ data: "x".repeat(1_000_001) }) });
  assert.strictEqual(tooLarge.status, 413);

  const init = await rpc(url, 1, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } });
  assert.strictEqual(init.result.serverInfo.name, "code-atlas");
  const ready = await post(url, { jsonrpc: "2.0", method: "notifications/initialized" });
  assert.ok(ready.status === 200 || ready.status === 202);

  const names = (await rpc(url, 2, "tools/list")).result.tools.map((t: { name: string }) => t.name);
  assert.ok(names.includes("atlas_overview") && names.includes("atlas_exec"), "read tools are served");
  assert.ok(!names.includes("atlas_triage"), "the WRITE tool is not exposed over HTTP by default");
  const denied = await rpc(url, 3, "tools/call", { name: "atlas_triage", arguments: { findingId: "x", status: "confirmed", by: "t" } });
  assert.ok(denied.error || denied.result?.isError, "calling atlas_triage over read-only HTTP fails");

  const ov = await rpc(url, 4, "tools/call", { name: "atlas_overview", arguments: {} });
  assert.strictEqual(JSON.parse(ov.result.content[0].text).repository.label, "http-test");
});

// ---- opt-in triage
await withServer({ allowTriage: true }, async (url) => {
  const names = (await rpc(url, 1, "tools/list")).result.tools.map((t: { name: string }) => t.name);
  assert.ok(names.includes("atlas_triage"), "--allow-triage exposes the write tool");
});

// ---- allowlists
await withServer({ allowedOrigins: ["https://app.example/"] }, async (_url, port) => {
  assert.strictEqual((await raw(port, { host: `localhost:${port}`, origin: "https://app.example" })).status, 200, "an allowlisted Origin is accepted");
});
await withServer({ allowedHosts: ["atlas.internal"] }, async (_url, port) => {
  assert.strictEqual((await raw(port, { host: "atlas.internal" })).status, 200, "an operator-allowed Host is accepted");
});

// ---- key in the URL: OFF by default, opt-in for clients that cannot send a header
const noAuthHeaders = { "content-type": "application/json", accept: "application/json, text/event-stream" };
const listBody = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" });
await withServer({}, async (url) => {
  const viaQuery = await fetch(`${url}/mcp?key=${apiKey}`, { method: "POST", headers: noAuthHeaders, body: listBody });
  assert.strictEqual(viaQuery.status, 404, "by default a URL key is not even routed");
  const viaPath = await fetch(`${url}/mcp/${apiKey}`, { method: "POST", headers: noAuthHeaders, body: listBody });
  assert.strictEqual(viaPath.status, 404, "by default /mcp/<key> does not exist");
});
await withServer({ allowUrlKey: true }, async (url) => {
  const ok = async (u: string) => { const r = await fetch(u, { method: "POST", headers: noAuthHeaders, body: listBody }); return r.status === 200 ? ((await r.json()) as any).result.tools.length : r.status; };
  assert.strictEqual(await ok(`${url}/mcp?key=${apiKey}`), 9, "?key= authenticates");
  assert.strictEqual(await ok(`${url}/mcp/${apiKey}`), 9, "/mcp/<key> authenticates");
  assert.strictEqual(await ok(`${url}/mcp/${apiKey}/`), 9, "a trailing slash is tolerated");
  assert.strictEqual(await ok(`${url}/mcp?key=${"x".repeat(32)}`), 401, "a wrong URL key is rejected");
  assert.strictEqual(await ok(`${url}/mcp`), 401, "no key anywhere is rejected");
  assert.strictEqual(await ok(`${url}/mcp?key=`), 401, "an empty key is rejected");
  assert.strictEqual(await ok(`${url}/mcp/${apiKey}/extra`), 404, "extra path segments are not routed");
  assert.strictEqual((await post(url, { jsonrpc: "2.0", id: 1, method: "tools/list" })).status, 200, "the header still works alongside");
  assert.strictEqual((await fetch(`${url}/healthz`)).status, 200);
});
await withServer({ allowUrlKey: true, maxAuthFailuresPerMinute: 3 }, async (url) => {
  const bad = () => fetch(`${url}/mcp?key=${"z".repeat(32)}`, { method: "POST", headers: noAuthHeaders, body: listBody });
  for (let i = 0; i < 3; i++) assert.strictEqual((await bad()).status, 401);
  assert.strictEqual((await bad()).status, 429, "wrong URL keys count toward the lockout");
});

// ---- rate limits
await withServer({ maxAuthFailuresPerMinute: 3 }, async (url) => {
  const attempt = () => post(url, { jsonrpc: "2.0", id: 1, method: "tools/list" }, { ...jsonHeaders, authorization: `Bearer ${"y".repeat(32)}` });
  for (let i = 0; i < 3; i++) assert.strictEqual((await attempt()).status, 401, `failure ${i + 1} is a plain 401`);
  const limited = await attempt();
  assert.strictEqual(limited.status, 429, "repeated bad keys are throttled");
  assert.strictEqual(limited.headers.get("retry-after"), "60");
  const goodWhileLocked = await post(url, { jsonrpc: "2.0", id: 2, method: "tools/list" });
  assert.strictEqual(goodWhileLocked.status, 429, "a locked-out client is throttled even with the right key until the window resets");
});
await withServer({ maxRequestsPerMinute: 5 }, async (url) => {
  const codes: number[] = [];
  for (let i = 0; i < 8; i++) codes.push((await fetch(`${url}/healthz`)).status);
  assert.deepStrictEqual(codes, [200, 200, 200, 200, 200, 429, 429, 429], "request volume is capped per client");
});

console.log("mcp-http.test: loopback + Host/Origin allowlists, bearer auth, rate limits, read-only by default (triage opt-in), bounded bodies, MCP round trip");
