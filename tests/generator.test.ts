/** Dogfood proof: code-atlas generates a course about its OWN source, and every
 *  generated Break & Fix is grounded and solvable. */
import assert from "node:assert";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { scanWorkspace, readSource } from "../src/scanner/treeScanner.js";
import { buildGraph } from "../src/scanner/graph.js";
import { generateCourse, assembleBundle, runChecks } from "../src/generator/generator.js";

const sha = (s: string) => "sha256:" + createHash("sha256").update(s).digest("hex");
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const srcRoot = resolve(repoRoot, "src");

const scan = scanWorkspace(srcRoot);
const sources = scan.files.map((f) => ({ path: f.relativePath, code: readSource(f.absolutePath) }));
const graph = buildGraph("code-atlas@self", sources);
const course = generateCourse(graph, sources, { product: "Code Atlas", repoLabel: "code-atlas" });
const bundle = assembleBundle(graph, course, { product: "Code Atlas", repoLabel: "code-atlas" });

assert.ok(sources.length >= 4, "scanned its own source files");
assert.ok(graph.nodes.filter((n) => n.kind === "function").length > 0, "found functions");
assert.ok(course.lessons.length > 0, "generated at least one lesson");
assert.strictEqual(bundle.schemaVersion, "1.0", "assembled a valid bundle");

for (const l of course.lessons) {
  const bf = l.breakAndFix;
  assert.ok(runChecks(bf.broken, bf.checks).length > 0, l.title + ": broken must FAIL checks");
  assert.strictEqual(runChecks(bf.solution, bf.checks).length, 0, l.title + ": solution must PASS checks");
  assert.strictEqual(bf.provenance.contentHash, sha(bf.solution), l.title + ": provenance hash matches real source");
  assert.notStrictEqual(bf.broken, bf.solution, l.title + ": broken differs from solution");
}

console.log(`generator.test: ${sources.length} files, ${graph.nodes.length} nodes, ` +
  `${graph.edges.filter((e) => e.kind === "calls").length} call edges, ${course.lessons.length} lessons — all grounded & solvable`);
