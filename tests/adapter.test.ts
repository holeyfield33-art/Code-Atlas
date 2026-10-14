/** vibe-explainer adapter proof: a REAL vibe-explainer report maps onto graph
 *  nodes, grades are capped honest (never OBSERVED/TESTED), ASI refs attach,
 *  and the resulting bundle validates. */
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import type { AtlasGraph, AtlasNode, Evidence } from "../src/schema.js";
import { ingestVibeExplainer } from "../src/scanner/findings.js";
import { assembleBundle } from "../src/generator/generator.js";
import { parseBundle } from "../src/schema.js";

const here = dirname(fileURLToPath(import.meta.url));
const ve = JSON.parse(readFileSync(resolve(here, "fixtures/vibe-explainer-report.json"), "utf8"));

// Build a graph whose file nodes match the files vibe-explainer referenced.
const ev = (path: string): Evidence =>
  ({ path, line: 1, column: 1, revision: "r", contentHash: "sha256:x", method: "babel-static", status: "static" });
const files = new Set<string>();
for (const items of Object.values(ve.ai_inventory.categories) as any[])
  for (const it of (items || [])) if (it?.file) files.add(it.file);
const nodes: AtlasNode[] = [...files].map((f) => ({ id: "file:" + f, kind: "file", label: f, evidence: ev(f) }));
const graph: AtlasGraph = { version: "0.1", revision: "r", nodes, edges: [], diagnostics: [] };

const { findings, asiSnapshot, unmapped } = ingestVibeExplainer(ve, graph);

assert.ok(findings.length > 0, "mapped at least one finding from the real report");
assert.ok(findings.some((f) => f.kind === "weakness"), "mapped weaknesses from risk scenarios");
for (const f of findings) {
  assert.ok(f.grade === "STATIC" || f.grade === "INFERRED", f.id + ": grade capped static (vibe-explainer is untested)");
  for (const r of f.nodeRefs) assert.ok(graph.nodes.some((n) => n.id === r), f.id + ": nodeRef resolves");
}
assert.ok(asiSnapshot && asiSnapshot.classes.length > 0, "ASI snapshot carries referenced classes");
const weakness = findings.find((f) => f.kind === "weakness")!;
assert.ok(weakness.asiRef && /^AAC-/.test(weakness.asiRef.id), "weakness carries an ASI class ref");
assert.ok(weakness.asiRef!.url.startsWith("http"), "ASI ref has a live URL");

const bundle = assembleBundle(graph, { title: "t", summary: "s", modules: [], lessons: [] },
  { product: "Code Atlas", repoLabel: "ve" }, { findings, asiSnapshot });
assert.doesNotThrow(() => parseBundle(bundle), "vibe-explainer bundle validates");

console.log(`adapter.test: ${findings.length} findings from real vibe-explainer report ` +
  `(${findings.filter((f) => f.kind === "weakness").length} weakness, ${findings.filter((f) => f.kind === "control").length} control), ` +
  `grades honest, ASI linked, ${unmapped.length} unmapped; bundle valid`);
