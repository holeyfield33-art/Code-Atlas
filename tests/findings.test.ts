/** Findings scanner proof: rules map to real nodes, grades stay honest (never
 *  OBSERVED/TESTED from a static scan), blast radius comes from real callers,
 *  and the bundle validates. Runs on a small real fixture + the adapter. */
import assert from "node:assert";
import { buildGraph, type SourceFile } from "../src/scanner/graph.js";
import { scan, ingestReport, ingestVibeExplainer, type ExternalFinding } from "../src/scanner/findings.js";
import { assembleBundle } from "../src/generator/generator.js";
import { parseBundle } from "../src/schema.js";

// Regression (PR #4 / Codex): a vibe-explainer report referencing a NESTED path
// must map to a tree-sitter file node, whose label is only the basename while the
// repo-relative path lives in evidence.path.
{
  const ev = (p: string) => ({ path: p, line: 1, column: 1, revision: "r", contentHash: "sha256:x", method: "tree-sitter-static" as const, status: "static" as const });
  const tsGraph: any = { version: "ts-0.1", revision: "r",
    nodes: [{ id: "file:pkg/app.py", kind: "file", label: "app.py", evidence: ev("pkg/app.py") }], edges: [], diagnostics: [] };
  const ve = { ai_inventory: { categories: { x: [{ id: "F", file: "pkg/app.py" }] } },
    risks: { scenarios: [{ risk_id: "R1", title: "t", category: "x", evidence_strength: "HIGH", related_finding_ids: ["F"], rationale: "r" }] } };
  const res = ingestVibeExplainer(ve, tsGraph);
  assert.strictEqual(res.findings.length, 1, "nested report path maps to a tree-sitter file node via evidence.path");
  assert.strictEqual(res.unmapped.length, 0, "nothing unmapped for the nested path");
}

// A fixture with: a sink-without-validator (weakness), a validator (control),
// and a caller of the sink (for blast radius).
const sources: SourceFile[] = [{
  path: "fix.ts",
  code: [
    "import { execSync } from 'node:child_process';",
    "export function runCommand(cmd) { return execSync(cmd); }",      // weakness: exec, no validator
    "export function validateInput(x) { return parse(x); }",          // control: parse
    "export function handler(req) { return runCommand(req.body); }",  // caller of runCommand
  ].join("\n"),
}];

const graph = buildGraph("fix@test", sources);
const { findings, asiSnapshot } = scan(graph, sources);

const byRule = (p: string) => findings.filter((f) => f.id.startsWith(p));
assert.ok(byRule("r-unguarded-sink").length === 1, "one unguarded-sink weakness on runCommand");
assert.ok(byRule("c-input-validation").length === 1, "one input-validation control on validateInput");

const sink = byRule("r-unguarded-sink")[0];
assert.strictEqual(sink.kind, "weakness");
// A STATIC lead casts NO blast radius — only a verified (OBSERVED/TESTED) finding does.
assert.strictEqual(sink.blastRadius.length, 0, "a static lead propagates no blast radius");

// honesty: NO static finding may claim OBSERVED or TESTED
for (const f of findings) assert.ok(f.grade === "STATIC" || f.grade === "INFERRED", f.id + " grade must be static");
// every finding maps to a real node
const ids = new Set(graph.nodes.map((n) => n.id));
for (const f of findings) for (const r of f.nodeRefs) assert.ok(ids.has(r), f.id + " nodeRef resolves");
assert.ok(asiSnapshot && asiSnapshot.classes.length > 0, "ASI snapshot carries referenced classes");

// bundle with findings validates against the locked schema
const bundle = assembleBundle(graph, { title: "t", summary: "s", modules: [], lessons: [] },
  { product: "Code Atlas", repoLabel: "fix" }, { findings, asiSnapshot });
assert.doesNotThrow(() => parseBundle(bundle), "security bundle validates");

// adapter: external report maps to graph by file+symbol, grade kept as-is
const ext: ExternalFinding[] = [{ id: "EXT-1", kind: "weakness", title: "x", explanation: "y",
  grade: "INFERRED", file: "fix.ts", symbol: "runCommand" }];
const { findings: mapped, unmapped } = ingestReport(ext, graph);
assert.strictEqual(mapped.length, 1, "external finding mapped to a node");
assert.strictEqual(mapped[0].grade, "INFERRED", "adapter keeps the report's grade");
assert.strictEqual(unmapped.length, 0, "nothing unmapped");

console.log(`findings.test: ${findings.length} findings (${byRule("r-").length} weakness-rule, ` +
  `${byRule("c-").length} control), grades honest, static leads cast no blast, adapter maps + bundle valid`);

// Regression: a real-world sink dogfooded against sunwood-ai-labs/github-kanban-mcp-server
// (a documented command-injection advisory) was invisible because the sink is reached only
// through `util.promisify(execFile)` rebound to a locally-named helper (`ghAsync`), not a
// literal `execFile(` call — the exact shape that advisory's own `src/utils/exec.ts` has.
// `r-unguarded-sink` must now follow a one-hop alias through the rebind.
{
  const aliasSources: SourceFile[] = [{
    path: "alias.ts",
    code: [
      "import { execFile } from 'node:child_process';",
      "import { promisify } from 'node:util';",
      "const execFileAsync = promisify(execFile);",
      "export async function ghAsync(args) { return await execFileAsync('gh', args); }", // weakness: aliased sink
      "export async function handleListIssues(owner, repo) { return await ghAsync(['issue', 'list', '--repo', owner + '/' + repo]); }",
    ].join("\n"),
  }];
  const aliasGraph = buildGraph("alias@test", aliasSources);
  const { findings: aliasFindings } = scan(aliasGraph, aliasSources);
  const aliasHit = aliasFindings.filter((f) => f.id.startsWith("r-unguarded-sink") && f.id.endsWith(":" + aliasGraph.nodes.find((n) => n.label === "ghAsync")!.id));
  assert.strictEqual(aliasHit.length, 1, "r-unguarded-sink follows the promisify(execFile) alias into ghAsync");
}

console.log("findings.test: sink-alias regression (promisify(execFile) -> ghAsync) passes");
