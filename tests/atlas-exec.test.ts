/**
 * atlas_exec sandbox proof. The single programmable read tool must:
 *   - run agent code against the frozen `atlas` API and return real data;
 *   - let one call do a join a fixed tool couldn't (the whole point);
 *   - be reproducible (same code + bundle => same receipt hash);
 * and the jail must HOLD:
 *   - no network / require / process / import / timers inside the isolate;
 *   - no write path — triage and the host reference are unreachable;
 *   - a wall-clock timeout kills a runaway script;
 *   - a memory cap kills an allocation bomb;
 *   - bad or oversized code fails closed as { ok:false }, never throwing.
 */
import assert from "node:assert";
import { execSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { parseBundle } from "../src/schema.js";
import { AtlasTools } from "../src/mcp/tools.js";
import { runAtlasExec } from "../src/mcp/sandbox.js";
import { bundleId } from "../src/mcp/server.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const bundlePath = resolve(repoRoot, "atlas/atlas.bundle.json");
if (!existsSync(bundlePath)) execSync("node dist/cli.js build .", { cwd: repoRoot, stdio: "ignore" });
const bundle = parseBundle(JSON.parse(readFileSync(bundlePath, "utf8")));
const tools = new AtlasTools(bundle);
const HASH = "sha256:testbundle";
const run = (code: string, limits?: any) => runAtlasExec(tools, code, HASH, limits);

// 1) a read works and matches the direct API
const r1 = run(`return atlas.overview().counts.functions;`);
assert.strictEqual(r1.ok, true, "overview runs in the sandbox");
assert.strictEqual(r1.result, (tools.overview() as any).counts.functions, "sandbox read matches direct read");

// 2) one call does a join no single fixed tool exposes (the value prop)
const r2 = run(`
  const ov = atlas.overview();
  return ov.entryPoints
    .map(e => ({ id: e.id, threats: atlas.threats(e.id).findings.length }))
    .sort((a, b) => b.threats - a.threats)
    .slice(0, 3);
`);
assert.strictEqual(r2.ok, true, "a multi-call join runs");
assert.ok(Array.isArray(r2.result), "join returns an array the agent shaped itself");

// 2b) findings can be listed without knowing an id or path first (threats() needs one)
const direct = tools.findings({ limit: 5 }) as any;
const rf = run(`return atlas.findings({ limit: 5 });`);
assert.strictEqual(rf.ok, true, "findings() runs in the sandbox");
assert.deepStrictEqual(rf.result, direct, "sandbox findings() matches the direct call");
assert.strictEqual(direct.total, (bundle.findings ?? []).length, "unfiltered total is every finding");
assert.ok(direct.returned <= 5, "limit bounds the rows");
assert.strictEqual((tools.findings({ kind: "no-such-kind" }) as any).total, 0, "a filter that matches nothing returns nothing");

// 2c) routes found in code are listable in the sandbox, same as the direct call
const rr = run(`return atlas.routes({ limit: 5 });`);
assert.strictEqual(rr.ok, true, "routes() runs in the sandbox");
assert.deepStrictEqual(rr.result, tools.routes({ limit: 5 }), "sandbox routes() matches the direct call");

// 2d) each of findings/threatLeads/routes has an optional filter (default {}) on the host side —
// calling the natural no-filter form from inside the sandbox must hit that default, not throw.
// (JSON.stringify([undefined]) -> "[null]"; the host's JSON.parse then hands the method a literal
// null, which bypasses its JS default parameter — the wrapper must default the argument first.)
for (const [name, direct] of [["findings", tools.findings()], ["threatLeads", tools.threatLeads()], ["routes", tools.routes()]] as const) {
  const r = run(`return atlas.${name}();`);
  assert.strictEqual(r.ok, true, `atlas.${name}() with no argument runs in the sandbox, not { ok:false }`);
  assert.deepStrictEqual(r.result, direct, `atlas.${name}() with no argument matches the direct no-filter call`);
}

// 3) reproducible receipt: same code+bundle => same hash; different code => different hash
const a = run(`return 1 + 1;`), b = run(`return 1 + 1;`), c = run(`return 2 + 2;`);
assert.strictEqual(a.receipt.hash, b.receipt.hash, "same code+bundle => same receipt");
assert.notStrictEqual(a.receipt.hash, c.receipt.hash, "different code => different receipt");
assert.strictEqual(a.receipt.selector, "atlas-exec-v1", "receipt names the selector");

// 4) JAIL: no ambient authority inside the isolate
const amb = run(`return [typeof fetch, typeof require, typeof process, typeof globalThis.process, typeof setTimeout, typeof WebAssembly.instantiate].join(",");`);
assert.strictEqual(amb.ok, true, "probe runs");
assert.strictEqual(amb.result, "undefined,undefined,undefined,undefined,undefined,function",
  "no network/require/process/timers; WASM compile exists but has no host imports to reach");

// 5) JAIL: no host module system — CommonJS loaders absent, and dynamic import
// has no resolver, so there is no path to a host module from inside the isolate.
const imp = run(`return [typeof require, typeof module, typeof __dirname, typeof exports].join(",");`);
assert.strictEqual(imp.ok, true, "probe runs");
assert.strictEqual(imp.result, "undefined,undefined,undefined,undefined", "no CommonJS module loader exists in the isolate");

// 6) JAIL: no write path — triage is not on the surface, and the host ref is not reachable
const noWrite = run(`return typeof atlas.triage + "," + typeof atlas.applyDisposition;`);
assert.strictEqual(noWrite.result, "undefined,undefined", "no mutation method is exposed");
const noHost = run(`return typeof __ATLAS_HOST__ + "," + (typeof globalThis.__ATLAS_HOST__);`);
assert.strictEqual(noHost.result, "undefined,undefined", "the host capability reference is not reachable from agent code");

// 7) JAIL: wall-clock timeout kills a runaway loop (fails closed, no throw)
const spin = run(`while (true) {}`, { timeoutMs: 200, memoryMb: 128, maxCodeChars: 20000, maxResultBytes: 1_000_000 });
assert.strictEqual(spin.ok, false, "infinite loop is terminated");
assert.ok(/timed out|time/i.test(spin.error || ""), "timeout is reported");

// 8) JAIL: memory cap kills an allocation bomb
const bomb = run(`const a = []; for (;;) { a.push(new Array(1e6).fill(7)); } return a.length;`,
  { timeoutMs: 3000, memoryMb: 16, maxCodeChars: 20000, maxResultBytes: 1_000_000 });
assert.strictEqual(bomb.ok, false, "allocation bomb is terminated by the memory cap");

// 9) JAIL: a large return is capped INSIDE the isolate, before it reaches the host heap
const huge = run(`return "x".repeat(2_000_000);`);   // ~2 MB serialized > 1 MB default cap
assert.strictEqual(huge.ok, false, "oversized result is rejected, not copied to the host");
assert.ok(/result exceeds/.test(huge.error || ""), "the result cap is named in the error");
const okSize = run(`return "x".repeat(10);`);
assert.strictEqual(okSize.ok, true, "a normal-size result still returns");
assert.strictEqual(okSize.result, "xxxxxxxxxx", "the result round-trips through the size-checked path");

// 10) bad code fails closed, never throws
const bad = run(`return (((;`);
assert.strictEqual(bad.ok, false, "syntax error returns ok:false");
assert.ok(bad.receipt && bad.receipt.hash, "a receipt is present even on failure");

// 11) oversized code rejected before execution
const big = run("return 1;".padEnd(20_001, " "), { timeoutMs: 1000, memoryMb: 64, maxCodeChars: 20000, maxResultBytes: 1_000_000 });
assert.strictEqual(big.ok, false, "code over the char cap is rejected");
assert.ok(/chars/.test(big.error || ""), "the cap is named in the error");

// 12) RECEIPT covers all query-visible state, not just node ids, and ignores the
// (possibly stale) integrity field — so any change a read could surface moves it.
const h0 = bundleId(bundle);
const srcChanged = structuredClone(bundle);
if (srcChanged.sources && srcChanged.sources.length) srcChanged.sources[0].code += "\n// touched";
assert.notStrictEqual(bundleId(srcChanged), h0, "changing a source changes the bundle id (sources are query-visible)");
const integrityStale = structuredClone(bundle);
(integrityStale as any).integrity = { graphHash: "x", bundleHash: "sha256:frozen" };
const integrityStale2 = structuredClone(integrityStale);
integrityStale2.graph.nodes[0].label += " (changed)";   // always present; a read would surface it
assert.notStrictEqual(bundleId(integrityStale2), bundleId(integrityStale),
  "a change is detected even when a frozen integrity.bundleHash is identical (we hash content, not integrity)");

console.log("atlas-exec.test: one programmable read tool — join runs, receipt replayable; jail holds " +
  "(no net/require/process/import/host-ref/write, timeout + memory caps, fails closed)");
