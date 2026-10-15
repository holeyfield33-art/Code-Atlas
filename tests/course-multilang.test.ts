/**
 * Language-agnostic Break & Fix course (#6): a non-JS (Python) repo now gets
 * grounded broken_call_edge lessons off the tree-sitter graph, with the SAME
 * grounding invariant as the Babel path:
 *   - broken !== solution;
 *   - solution === the REAL function body (contentHash matches sha256(solution));
 *   - the checks PASS on the solution and FAIL on the broken variant;
 *   - word-boundary matching: `run(` is not mutated inside `prerun(`.
 */
import assert from "node:assert";
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildAtlas } from "../src/build.js";
import { parseBundle } from "../src/schema.js";
import { runChecks } from "../src/generator/generator.js";

const sha256 = (s: string) => "sha256:" + createHash("sha256").update(s).digest("hex");

const root = mkdtempSync(join(tmpdir(), "atlas-course-"));
mkdirSync(join(root, "pkg"), { recursive: true });
// main() calls run() (a real, known function). It also calls prerun() — an
// EXTERNAL function (not defined in the repo), present so we can prove the
// word-boundary: breaking `run(` must not touch `run` inside `prerun(`.
writeFileSync(join(root, "pkg", "app.py"),
  "from helper import run\n" +
  "\n" +
  "def main(x):\n" +
  "    prerun(x)\n" +
  "    return run(x)\n"
);
writeFileSync(join(root, "pkg", "helper.py"), "def run(y):\n    return y + 1\n");

const { bundle } = await buildAtlas(root, { product: "Code Atlas", security: false });
assert.doesNotThrow(() => parseBundle(bundle), "bundle validates");

const lessons = bundle.course?.lessons ?? [];
// find the lesson whose caller node is the Python `main`
const mainNode = bundle.graph.nodes.find((n) => n.kind === "function" && n.label === "main" && n.evidence.path.endsWith("app.py"));
assert.ok(mainNode, "python main() is a graph node");
const lesson = lessons.find((l) => l.breakAndFix.nodeRef === mainNode!.id);
assert.ok(lesson, "a Break & Fix lesson was generated for a Python function");

const bf = lesson!.breakAndFix;
assert.strictEqual(bf.defectKind, "broken_call_edge", "it is a broken_call_edge defect");
assert.ok(bf.file.endsWith("app.py"), "lesson is grounded in the real .py file");

// grounding invariant
assert.notStrictEqual(bf.broken, bf.solution, "broken differs from solution");
assert.ok(/def main/.test(bf.solution), "solution is the real function body");
assert.strictEqual(bf.provenance.contentHash, sha256(bf.solution), "contentHash is sha256 of the real solution body");

// word-boundary: only the real run( call was mutated, prerun( left intact
assert.ok(/\brun\(/.test(bf.solution) && /run__removed\(/.test(bf.broken), "the real run( call was broken");
assert.ok(bf.broken.includes("prerun(x)"), "the decoy prerun( call was NOT mutated");

// checks pass on the solution, fail on the broken variant
assert.strictEqual(runChecks(bf.solution, bf.checks).length, 0, "all checks pass on the real solution");
assert.ok(runChecks(bf.broken, bf.checks).length > 0, "at least one check fails on the broken variant");

console.log(`course-multilang.test: grounded broken_call_edge lesson for Python main()->run() — checks pass/fail correctly, prerun( untouched`);
