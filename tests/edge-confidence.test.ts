/**
 * Uncertain Python/Ruby call edges never render as proven. The tree-sitter
 * backend resolves calls by NAME only, so its `calls` edges are tagged
 * confidence:"inferred"; the Babel backend resolves via imports/same-file, so
 * its calls are not inferred. contains/imports stay "resolved". The MCP getNode
 * flags inferred callees so an agent can't treat them as proven.
 */
import assert from "node:assert";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildAtlas } from "../src/build.js";
import { parseBundle } from "../src/schema.js";
import { AtlasTools } from "../src/mcp/tools.js";

const root = mkdtempSync(join(tmpdir(), "atlas-conf-"));
mkdirSync(join(root, "src"), { recursive: true });
writeFileSync(join(root, "src", "app.ts"), "export function a(){ return b(); }\nexport function b(){ return 1; }\n");
writeFileSync(join(root, "lib.py"), "from helper import run\n\ndef main():\n    return run()\n");
writeFileSync(join(root, "helper.py"), "def run():\n    return 1\n");

const { bundle } = await buildAtlas(root, { product: "Code Atlas", security: false });
assert.doesNotThrow(() => parseBundle(bundle), "bundle validates with the confidence field");

const nodeById = new Map(bundle.graph.nodes.map((n) => [n.id, n]));
const method = (id: string) => nodeById.get(id)?.evidence.method;
const calls = bundle.graph.edges.filter((e) => e.kind === "calls");
assert.ok(calls.length >= 2, "there are call edges from both backends");

let sawTs = false, sawBabel = false;
for (const e of calls) {
  if (method(e.from) === "tree-sitter-static") { sawTs = true; assert.strictEqual(e.confidence, "inferred", "tree-sitter call edge is inferred (name-resolved)"); }
  if (method(e.from) === "babel-static") { sawBabel = true; assert.notStrictEqual(e.confidence, "inferred", "Babel call edge is not inferred (import/same-file resolved)"); }
}
assert.ok(sawTs, "a tree-sitter call edge exists (python main -> run)");
assert.ok(sawBabel, "a Babel call edge exists (ts a -> b)");

// tree-sitter contains/imports stay resolved
for (const e of bundle.graph.edges)
  if (method(e.from) === "tree-sitter-static" && e.kind !== "calls")
    assert.notStrictEqual(e.confidence, "inferred", `${e.kind} edge is resolved, not inferred`);

// MCP getNode flags the inferred callee
const tools = new AtlasTools(bundle);
const pyMain = bundle.graph.nodes.find((n) => n.kind === "function" && n.label === "main" && n.evidence.method === "tree-sitter-static")!;
const node = tools.getNode(pyMain.id) as any;
assert.ok(node.calls.some((c: any) => c.inferred === true), "getNode marks the name-inferred callee as inferred");

console.log("edge-confidence.test: tree-sitter calls are inferred, Babel calls are not, contains/imports resolved, MCP flags inferred callees");
