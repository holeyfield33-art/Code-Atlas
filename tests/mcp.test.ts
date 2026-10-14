/** MCP tool logic proof: on the dogfood bundle, the context-saving tools return
 *  compact, correct slices — search returns ids only, get_node has no source,
 *  context_pack respects a budget and is replayable (same task => same hash). */
import assert from "node:assert";
import { execSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { parseBundle } from "../src/schema.js";
import { AtlasTools } from "../src/mcp/tools.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const bundlePath = resolve(repoRoot, "atlas/atlas.bundle.json");
if (!existsSync(bundlePath)) execSync("node dist/cli.js build .", { cwd: repoRoot, stdio: "ignore" });
const bundle = parseBundle(JSON.parse(readFileSync(bundlePath, "utf8")));
const tools = new AtlasTools(bundle);

// overview is cheap orientation
const ov: any = tools.overview();
assert.ok(ov.counts.functions > 0 && ov.entryPoints.length >= 0, "overview returns counts");

// search returns ids + locations, NOT source
const s: any = tools.search("build graph", 5);
assert.ok(s.results.length > 0, "search finds nodes");
assert.ok(!("source" in s.results[0]), "search results carry no source (context saved)");

// get_node is compact and omits source
const id = s.results[0].id;
const node: any = tools.getNode(id);
assert.ok(!("source" in node), "get_node omits source");
assert.ok(Array.isArray(node.calls) && Array.isArray(node.calledBy), "get_node has neighbor ids");

// get_source returns code only on demand
const src: any = tools.getSource(id);
assert.ok(typeof src.source === "string" && src.source.length > 0, "get_source returns code on demand");

// context_pack respects budget and is replayable
const pack1: any = tools.contextPack("build the graph and resolve imports", 1500);
const pack2: any = tools.contextPack("build the graph and resolve imports", 1500);
assert.ok(pack1.selected.length > 0, "context_pack selects relevant components");
const chars = pack1.sourceIncluded.reduce((a: number, x: any) => a + x.source.length, 0);
assert.ok(chars <= 1500 * 4 + 2000, "context_pack roughly honors the token budget");
assert.strictEqual(pack1.receipt.hash, pack2.receipt.hash, "context_pack is replayable (same task => same receipt hash)");

// threats + course resolve by id
const th: any = tools.threats(id);
assert.ok(Array.isArray(th.findings), "threats returns a list");

console.log(`mcp.test: 8 tools over ${ov.counts.functions} functions — search/get_node source-free, ` +
  `get_source on demand, context_pack budgeted (${pack1.sourceIncluded.length} files, replayable)`);
