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
import { generateCourse, assembleBundle, runChecks } from "../src/generator/generator.js";
import { redactSecrets } from "../src/scanner/redact.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const viewerTemplate = readFileSync(resolve(repoRoot, "viewer/viewer.html"), "utf8");
const renderer = readFileSync(resolve(repoRoot, "viewer/vendor/3d-force-graph.min.js"), "utf8").replace(/<\/script/gi, "<\\/script");

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
  const viewer = viewerTemplate
    .replace("/*__ATLAS_RENDERER__*/", () => renderer)
    .replace("/*__ATLAS_BUNDLE_JSON__*/", () => bundleJson);
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

// ---- F4: ReDoS (regex checks are not executed at all) --------------------
// Includes the alternation case Sol/Codex reproduced that a shape heuristic misses.
{
  const PATHOLOGICAL = ["(a+)+$", "(a|aa)+$", "(a|a?)+$", "([a-zA-Z]+)*$", "(.*a){25}$"];
  const input = "a".repeat(60) + "!";
  for (const p of PATHOLOGICAL) {
    const t0 = Date.now();
    const fails = runChecks(input, [{ kind: "regex", value: p, message: "x" }]);
    const dt = Date.now() - t0;
    assert.ok(dt < 100, `F4: regex check must not execute/backtrack for ${p} (took ${dt}ms)`);
    assert.strictEqual(fails.length, 1, `F4: regex check ${p} is disabled (reported unmet, not run)`);
  }
  assert.strictEqual(runChecks("return x;", [{ kind: "includes", value: "return", message: "m" }]).length, 0,
    "F4: includes/excludes still work");
  ok("F4 ReDoS — regex checks not executed (alternation/overlap/nested all safe)");
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

// ---- P1 (Codex): secret inside a lesson-eligible function must not serialize --
{
  const SECRET = "sk-live-LESSONLEAK-SECRET-9988776655";
  // auth() has a guard with code after it (removed_guard-eligible) AND holds a secret.
  const { viewer, bundle } = buildFixture({
    "src/auth.ts": `export function auth(user){\n  if(!user) return null;\n  const token = "${SECRET}";\n  return token + user;\n}\n`,
  });
  assert.ok(!JSON.stringify(bundle).includes(SECRET), "P1: secret absent from bundle (lesson source included)");
  assert.ok(!viewer.includes(SECRET), "P1: secret absent from viewer");
  const leaked = (bundle.course?.lessons ?? []).some((l: any) =>
    (l.breakAndFix?.broken || "").includes(SECRET) || (l.breakAndFix?.solution || "").includes(SECRET));
  assert.ok(!leaked, "P1: no lesson embeds the secret-bearing function");
  ok("P1 lesson leak — secret-bearing functions get no lesson, nothing serialized");
}

// ---- P2a (Codex): input cap must bind regex only, not includes/excludes ------
{
  const big = "x".repeat(20001) + "NEEDLE";
  assert.strictEqual(runChecks(big, [{ kind: "includes", value: "NEEDLE", message: "m" }]).length, 0,
    "P2a: includes sees a token past the 20k cap");
  assert.strictEqual(runChecks(big, [{ kind: "excludes", value: "NEEDLE", message: "m" }]).length, 1,
    "P2a: excludes sees a forbidden token past the 20k cap");
  ok("P2a input cap — includes/excludes run over the full answer, cap bounds regex only");
}

// ---- F8 (review): viewer is self-contained — renderer bundled, no remote code --
{
  const { viewer } = buildFixture({ "src/app.ts": "export function f(){ return 1; }" });
  assert.ok(!/cdn\.jsdelivr|3d-force-graph@/.test(viewer), "F8: no CDN reference for the renderer");
  assert.ok(!/<script\s+src=["']https?:/i.test(viewer), "F8: no external <script src> in the generated viewer");
  assert.ok(viewer.includes("ForceGraph3D"), "F8: renderer is inlined (ForceGraph3D present in-file)");
  assert.ok(!viewer.includes("__ATLAS_RENDERER__"), "F8: renderer placeholder was filled");
  ok("F8 self-contained — renderer bundled in, no remote script execution");
}

// ---- #3: sink matching ignores method calls (RegExp.exec false positive) -----
{
  const src = [{ path: "x.ts", code:
    "export function a(s){ return /foo(bar)?/.exec(s); }\n" +   // RegExp.exec -> must NOT flag
    "export function b(cmd){ return eval(cmd); }\n" }];          // free eval -> must flag
  const g = buildGraph("x@t", src);
  const { findings } = scan(g, src, DEFAULT_RULES);
  const labelOf = (f: any) => g.nodes.find((nn) => nn.id === f.nodeRefs[0])?.label;
  const flagged = new Set(findings.filter((f) => f.id.startsWith("r-unguarded-sink")).map(labelOf));
  assert.ok(!flagged.has("a"), "#3: RegExp .exec() is not flagged as a high-impact sink");
  assert.ok(flagged.has("b"), "#3: a free eval() call is still flagged");
  // Control rules must STILL match method-form validators (freeOnly is weakness-only).
  const ctl = [{ path: "c.ts", code: "export function h(x){ return schema.parse(x); }\n" }];
  const gc = buildGraph("c@t", ctl);
  const cf = scan(gc, ctl, DEFAULT_RULES).findings;
  assert.ok(cf.some((f) => f.id.startsWith("c-input-validation")), "#3: method-form validator (schema.parse) still detected as a control");
  ok("#3 sink precision — method sinks dropped, method validators still counted");
}

// ---- #1: a STATIC lead casts no blast radius -----------------------------
{
  const src = [{ path: "y.ts", code:
    "export function sink(cmd){ return eval(cmd); }\n" +
    "export function caller(x){ return sink(x); }\n" }];
  const g = buildGraph("y@t", src);
  const { findings } = scan(g, src, DEFAULT_RULES);
  const w = findings.find((f) => f.id.startsWith("r-unguarded-sink"));
  assert.ok(w, "#1: the weakness lead exists");
  assert.strictEqual(w!.grade, "STATIC", "#1: a native lead is STATIC");
  assert.strictEqual(w!.blastRadius.length, 0, "#1: a STATIC lead propagates no blast radius");
  // but a verified (OBSERVED) external finding still casts one
  const obs = ingestReport([{ id: "O", kind: "weakness", title: "t", explanation: "e", grade: "OBSERVED", file: "y.ts", symbol: "sink" }], g).findings[0];
  // (external OBSERVED is capped to INFERRED by design, so it too casts none — the gate is grade-based)
  assert.strictEqual(obs.blastRadius.length, 0, "#1: an external claim (capped to INFERRED) casts no blast either");
  ok("#1 blast gate — only verified findings propagate; static/inferred leads do not");
}

console.log(`security.test: ${n} finding regressions pass (F1–F7 + P1/P2a + F8 + #1/#3) — every confirmed breakout re-attacked and blocked`);
