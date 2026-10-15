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
import { buildMultiLangGraph, lineCol, type MultiLang } from "../src/scanner/multilang.js";
import { generateCourse, assembleBundle } from "../src/generator/generator.js";
import { parseBundle } from "../src/schema.js";

const here = dirname(fileURLToPath(import.meta.url));

// #11: a tree-sitter BYTE offset must yield the exact CHARACTER column on non-ASCII
// source. "é" is 2 bytes, so byte offset 3 lands on "x" at line 2, col 1.
assert.deepStrictEqual(lineCol("é\nx", 3, false), { line: 2, column: 1 }, "#11: byte offset decodes to the right char column");
// (the old char-sliced path would have returned column 2 here — the bug #11 fixes.)
assert.deepStrictEqual(lineCol("ab\ncd", 3, true), { line: 2, column: 1 }, "#11: ASCII fast path still correct");

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
  // evidence line/column are 1-based, matching the Babel backend + viewer/MCP
  assert.ok(graph.nodes.every((n) => n.evidence.line >= 1 && n.evidence.column >= 1), `${lang}: evidence is 1-based`);
  // unique ids
  assert.strictEqual(new Set(graph.edges.map((e) => e.id)).size, graph.edges.length, `${lang}: edge ids unique`);
  // #5: a call inside a function attributes to the ENCLOSING function, not the file.
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const fnOriginCalls = graph.edges.filter((e) => e.kind === "calls" && byId.get(e.from)?.kind === "function");
  assert.ok(fnOriginCalls.length >= 1, `${lang}: at least one calls edge originates from a function node (enclosing attribution)`);

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
