/**
 * Security regression suite — one assertion per confirmed red-team finding.
 * Each test re-runs the ORIGINAL attack against the fixed pipeline and proves the
 * breakout no longer happens. Dependency-free (node:assert), runs in the suite.
 *
 *   F1 stored XSS      F2 $-sequence inject   F3 symlink escape   F4 ReDoS
 *   F5 secret exposure F6 grade overclaim     F7 javascript: url
 */
import assert from "node:assert";
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { scanWorkspace, readSource } from "../src/scanner/treeScanner.js";
import { buildGraph } from "../src/scanner/graph.js";
import { scan, ingestReport, type ExternalFinding } from "../src/scanner/findings.js";
import { DEFAULT_RULES } from "../src/scanner/rules.js";
import { generateCourse, assembleBundle, runChecks, safeRegex } from "../src/generator/generator.js";
import { redactSecrets } from "../src/scanner/redact.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const viewerTemplate = readFileSync(resolve(repoRoot, "viewer/viewer.html"), "utf8");

/** Run the real build pipeline over an in-memory set of files and return the
 *  generated viewer string + the parsed bundle (as a browser would read it). */
function buildFixture(files: Record<string, string>) {
  const root = mkdtempSync(join(tmpdir(), "atlas-rt-"));
  for (const [rel, code] of Object.entries(files)) {
    const abs = join(root, rel); mkdirSync(dirname(abs), { recursive: true }); writeFileSync(abs, code);
  }
  const scanned = scanWorkspace(root);
  const sources = scanned.files.map((f) => ({ path: f.relativePath, code: readSource(f.absolutePath) }));
  const graph = buildGraph("fixture@test", sources);
  const course = generateCourse(graph, sources, { product: "Code Atlas", repoLabel: "fixture" });
  const security = scan(graph, sources, DEFAULT_RULES);
  const inlined = sources.map((s) => ({ path: s.path, code: redactSecrets(s.code).code }));
  const bundle = assembleBundle(graph, course, { product: "Code Atlas", repoLabel: "fixture" }, security, inlined);
  const bundleJson = JSON.stringify(bundle).replace(/</g, "\\u003c");
  const viewer = viewerTemplate.replace("/*__ATLAS_BUNDLE_JSON__*/", () => bundleJson);
  return { viewer, bundle, root };
}

/** Pull the JSON out of the injected <script type="application/json"> block the
 *  same way the viewer does, and parse it. */
function readInjected(viewer: string) {
  const marker = 'id="atlas-bundle">';
  const start = viewer.indexOf(marker) + marker.length;
  const end = viewer.indexOf("</script>", start);      // escaping guarantees this is the block close
  return JSON.parse(viewer.slice(start, end));
}

let n = 0;
const ok = (msg: string) => { n++; console.log("  ok " + msg); };

// ---- F1: stored XSS via </script> breakout -------------------------------
{
  const PAYLOAD = "</script><script>window.__ATLAS_XSS__=1;document.title='PWNED'</script>";
  const { viewer } = buildFixture({ "src/evil.ts": `export const note = ${JSON.stringify(PAYLOAD)};\nexport function f(){ return note; }` });
  assert.ok(!viewer.includes(PAYLOAD), "F1: raw </script> breakout sequence must NOT appear in the viewer");
  assert.ok(!viewer.includes("<script>window.__ATLAS_XSS__"), "F1: injected <script> must not appear unescaped");
  assert.ok(viewer.includes("\\u003c/script>"), "F1: the payload's < was escaped to \\u003c inside the JSON block");
  const parsed = readInjected(viewer);
  const evil = parsed.sources.find((s: any) => s.path.endsWith("evil.ts"));
  assert.ok(evil && evil.code.includes(PAYLOAD), "F1: source is preserved as data (round-trips through JSON.parse)");
  ok("F1 stored XSS — source inlined as inert JSON, no breakout");
}

// ---- F2: String.replace $-sequence corruption/injection ------------------
{
  const DOLLARS = "const a = \"$&\"; const b = \"$`\"; const c = \"$'\"; const d = \"$1$$\";";
  const { viewer } = buildFixture({ "src/d.ts": `${DOLLARS}\nexport function g(){ return a+b+c+d; }` });
  const parsed = readInjected(viewer);           // must parse at all => not corrupted
  const f = parsed.sources.find((s: any) => s.path.endsWith("d.ts"));
  assert.ok(f && f.code.includes("$&") && f.code.includes("$`") && f.code.includes("$'") && f.code.includes("$1$$"),
    "F2: $-sequences inserted literally (function replacer), bundle not corrupted");
  ok("F2 $-sequence — function replacer preserves source, JSON still parses");
}

// ---- F3: symlink escape --------------------------------------------------
{
  const outside = mkdtempSync(join(tmpdir(), "atlas-host-"));
  const hostSecret = join(outside, "hostfile.txt");
  writeFileSync(hostSecret, "TOP-SECRET-HOST-CONTENT");
  const repo = mkdtempSync(join(tmpdir(), "atlas-sym-"));
  mkdirSync(join(repo, "src"));
  writeFileSync(join(repo, "src", "app.ts"), "export const a = 1;");
  symlinkSync(hostSecret, join(repo, "src", "leak.ts"));   // *.ts symlink pointing outside the repo
  const { files } = scanWorkspace(repo);
  assert.ok(!files.some((f) => f.relativePath.endsWith("leak.ts")), "F3: symlinked file must not be scanned");
  assert.ok(files.some((f) => f.relativePath.endsWith("app.ts")), "F3: real files are still scanned");
  ok("F3 symlink escape — links are not followed, host file not read");
}

// ---- F4: ReDoS -----------------------------------------------------------
{
  const t0 = Date.now();
  const fails = runChecks("a".repeat(50) + "!", [{ kind: "regex", value: "(a+)+$", message: "redos" }]);
  const dt = Date.now() - t0;
  assert.ok(dt < 1000, `F4: catastrophic regex must return fast (took ${dt}ms)`);
  assert.strictEqual(fails.length, 1, "F4: unsafe pattern is rejected and the check fails closed");
  assert.strictEqual(safeRegex("(a+)+$"), null, "F4: safeRegex refuses the nested-quantifier shape");
  assert.ok(safeRegex("foo\\(") instanceof RegExp, "F4: ordinary patterns still compile");
  ok("F4 ReDoS — nested-quantifier patterns refused, input bounded");
}

// ---- F5: secret exposure -------------------------------------------------
{
  const r = redactSecrets('const KEY = "sk-live-ABCDEFGHIJKLMNOP1234567";\nconst password = "hunter2hunter2";');
  assert.ok(!r.code.includes("sk-live-ABCDEFGHIJKLMNOP1234567"), "F5: API key redacted");
  assert.ok(!r.code.includes("hunter2hunter2"), "F5: assigned password redacted");
  assert.ok(r.redactions >= 2, "F5: both secrets counted");
  const { viewer, bundle } = buildFixture({ "src/cfg.ts": 'export const KEY = "sk-live-ZYXWVUTSRQPONMLK987";\nexport function get(){ return KEY; }' });
  assert.ok(!viewer.includes("sk-live-ZYXWVUTSRQPONMLK987"), "F5: secret absent from built viewer");
  assert.ok(!JSON.stringify(bundle).includes("sk-live-ZYXWVUTSRQPONMLK987"), "F5: secret absent from bundle");
  ok("F5 secret exposure — secrets redacted before inlining");
}

// ---- F6 + F7: grade cap + url allowlist in ingestReport ------------------
{
  const graph = buildGraph("r@t", [{ path: "a.ts", code: "export function foo(){ return 1; }" }]);
  const base: ExternalFinding = { id: "X", kind: "weakness", title: "t", explanation: "e", grade: "OBSERVED", file: "a.ts" };
  const capped = ingestReport([base], graph).findings[0];
  assert.strictEqual(capped.grade, "INFERRED", "F6: external OBSERVED is capped to INFERRED");

  const jsUrl = ingestReport([{ ...base, grade: "STATIC", asiRef: { id: "A", url: "javascript:alert(1)", label: "l", asOf: "d" } }], graph).findings[0];
  assert.ok(!("asiRef" in jsUrl), "F7: javascript: asiRef is dropped at ingest");
  const httpUrl = ingestReport([{ ...base, grade: "STATIC", asiRef: { id: "A", url: "https://index.aletheia-core.com/#A", label: "l", asOf: "d" } }], graph).findings[0];
  assert.ok(httpUrl.asiRef && httpUrl.asiRef.url.startsWith("https://"), "F7: http(s) asiRef is kept");
  ok("F6 grade cap + F7 url allowlist — external claims constrained");
}

console.log(`security.test: ${n} finding regressions pass (F1–F7) — every confirmed breakout re-attacked and blocked`);
