/**
 * Build-pipeline proof: a MIXED repo (JS/TS + Python + Ruby) routes to both
 * backends, merges into one AtlasGraph, and assembles a schema-valid bundle —
 * Babel and tree-sitter nodes coexist, every merged edge resolves, and the JS/TS
 * slice still yields a grounded course lesson.
 */
import assert from "node:assert";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildAtlas } from "../src/build.js";
import { parseBundle } from "../src/schema.js";

const root = mkdtempSync(join(tmpdir(), "atlas-build-"));
mkdirSync(join(root, "src"), { recursive: true });
writeFileSync(join(root, "src", "app.ts"), "export function a(x){ if(!x) return 0; return b(x); }\nexport function b(y){ return y + 1; }\n");
writeFileSync(join(root, "lib.py"), "import os\nfrom helper import run\n\ndef main():\n    return run()\n");
writeFileSync(join(root, "helper.py"), "def run():\n    return 1\n");
writeFileSync(join(root, "app.rb"), "require_relative 'util'\n\ndef go\n  helper\nend\n");
writeFileSync(join(root, "util.rb"), "def helper\n  2\nend\n");

const { bundle, langSummary } = await buildAtlas(root, { product: "Code Atlas" });

assert.doesNotThrow(() => parseBundle(bundle), "mixed-language bundle validates against the schema");

const byMethod: Record<string, number> = {};
for (const n of bundle.graph.nodes) byMethod[n.evidence.method] = (byMethod[n.evidence.method] ?? 0) + 1;
assert.ok((byMethod["babel-static"] ?? 0) > 0, "merged graph has Babel (JS/TS) nodes");
assert.ok((byMethod["tree-sitter-static"] ?? 0) > 0, "merged graph has tree-sitter (Python/Ruby) nodes");

const ids = new Set(bundle.graph.nodes.map((n) => n.id));
for (const e of bundle.graph.edges) assert.ok(ids.has(e.from) && ids.has(e.to), `merged edge ${e.id} endpoints resolve`);

assert.ok(bundle.course.lessons.length >= 1, "the JS/TS slice still yields a grounded course lesson");

console.log(`build.test: mixed repo (${langSummary}) -> ${bundle.graph.nodes.length} nodes, methods ${JSON.stringify(byMethod)}, ${bundle.course.lessons.length} lessons — parseBundle OK`);
