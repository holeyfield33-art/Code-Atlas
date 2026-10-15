/**
 * Multi-language seam proof: the tree-sitter backend (Python + Ruby) produces a
 * graph that becomes a schema-valid AtlasBundle with ZERO downstream change —
 * the existing generator/assembler and parseBundle accept it unchanged. Grounding
 * holds: every edge endpoint resolves to a node; unresolved imports are diagnostics.
 */
import assert from "node:assert";
import { readFileSync, readdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildMultiLangGraph, type MultiLang } from "../src/scanner/multilang.js";
import { generateCourse, assembleBundle } from "../src/generator/generator.js";
import { parseBundle } from "../src/schema.js";

const here = dirname(fileURLToPath(import.meta.url));

function loadFixture(dir: string, exts: string[]): Map<string, string> {
  const base = resolve(here, "fixtures/multilang", dir);
  const m = new Map<string, string>();
  for (const f of readdirSync(base)) if (exts.some((e) => f.endsWith(e))) m.set(f, readFileSync(resolve(base, f), "utf8"));
  return m;
}

const cases: Array<{ lang: MultiLang; dir: string; exts: string[] }> = [
  { lang: "python", dir: "python", exts: [".py"] },
  { lang: "ruby", dir: "ruby", exts: [".rb"] },
];

for (const { lang, dir, exts } of cases) {
  const files = loadFixture(dir, exts);
  assert.ok(files.size >= 2, `${lang}: fixture has files`);

  const graph = await buildMultiLangGraph(lang, files, `${lang}@test`, ".");

  // grounding: every edge endpoint resolves to a real node (no fabricated edges)
  const ids = new Set(graph.nodes.map((n) => n.id));
  for (const e of graph.edges) assert.ok(ids.has(e.from) && ids.has(e.to), `${lang}: edge ${e.id} endpoints resolve`);
  // an unresolved stdlib import must surface as a diagnostic, not an edge
  assert.ok(graph.diagnostics.length >= 1, `${lang}: unresolved import recorded as a diagnostic`);
  // every element carries the tree-sitter method literal + source-backed evidence
  assert.ok(graph.nodes.every((n) => n.evidence.method === "tree-sitter-static" && n.evidence.contentHash.startsWith("sha256:")),
    `${lang}: nodes are source-backed via the tree-sitter backend`);
  // unique ids
  assert.strictEqual(new Set(graph.edges.map((e) => e.id)).size, graph.edges.length, `${lang}: edge ids unique`);

  // the seam: feed the graph through the EXISTING assembler and validate.
  // (Course is JS/TS-only for now, so no sources are passed — the graph+threat
  //  layers are what we're proving accept a non-JS backend unchanged.)
  const course = generateCourse(graph, [], { product: "Code Atlas", repoLabel: lang });
  const bundle = assembleBundle(graph, course, { product: "Code Atlas", repoLabel: lang });
  assert.doesNotThrow(() => parseBundle(bundle), `${lang}: bundle validates against the locked AtlasBundle schema`);

  const kinds = [...new Set(graph.nodes.map((n) => n.kind))].join(",");
  console.log(`multilang.test(${lang}): ${graph.nodes.length} nodes [${kinds}], ${graph.edges.length} edges, ${graph.diagnostics.length} diagnostics — parseBundle OK`);
}

console.log("multilang.test: tree-sitter backend (python, ruby) emits schema-valid AtlasBundles through the existing seam");
