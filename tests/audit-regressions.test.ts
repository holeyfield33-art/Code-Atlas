/**
 * Regressions for the GDK end-to-end audit (docs/audits/2026-10-15-gdk-code-atlas.md),
 * findings #3–#7. (#1/#2 live in ruby-precision.test.ts.)
 *  #3 a STATIC control is shown as "seen (unverified)", never as hardened/evaluated;
 *  #4 generated lessons attach in the viewer via nodeRefs / breakAndFix.nodeRef;
 *  #5 a comments-only answer fails every generated exercise, and a generic lesson
 *     only names a caller→callee pair that is a real `calls` edge;
 *  #6 a node past a truncated file's inlined prefix reports "unavailable", with a
 *     valid range or none — never empty text with an inverted range;
 *  #7 context_pack bounds the WHOLE serialized response by budgetTokens.
 */
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import vm from "node:vm";
import { buildAtlas } from "../src/build.js";
import { runChecks } from "../src/generator/generator.js";
import { AtlasTools } from "../src/mcp/tools.js";

// ---------- a Ruby + Python repo with real calls, one oversized file ----------
const root = mkdtempSync(join(tmpdir(), "atlas-audit-"));
mkdirSync(join(root, "app"), { recursive: true });
writeFileSync(join(root, "app", "report.rb"),
  "class ReportService\n" +
  "  def create(params)\n" +
  "    record = build(params) # keep the record\n" +
  "    notify(record)\n" +
  "  end\n\n" +
  "  def build(params)\n" +
  "    params\n" +
  "  end\n\n" +
  "  def notify(record)\n" +
  "    record\n" +
  "  end\n" +
  "end\n");
writeFileSync(join(root, "app", "jobs.py"),
  "def helper(x):\n    return x\n\n" +
  "def run(x):\n    y = helper(x)  # call the helper\n    return y\n");
// > 40k chars: `late_method` lies past the inlined prefix
const filler = Array.from({ length: 2000 }, (_, i) => `  def m${i}\n    ${i}\n  end\n`).join("");
writeFileSync(join(root, "app", "huge.rb"), "class Huge\n" + filler + "  def late_method\n    m1\n  end\nend\n");

const { bundle } = await buildAtlas(root, { product: "Code Atlas" });
const nodeById = new Map(bundle.graph.nodes.map((n) => [n.id, n]));
const edgeSet = new Set(bundle.graph.edges.filter((e) => e.kind === "calls").map((e) => e.from + ">" + e.to));
const lessons = bundle.course?.lessons ?? [];
assert.ok(lessons.length >= 2, "Ruby and Python lessons are generated");

// ---------- #5: grading over code, not comments; lessons agree with the graph ----------
const commentOut = (code: string, file: string) =>
  code.split("\n").map((l) => (/\.(rb|py)$/.test(file) ? "# " : "// ") + l).join("\n");
for (const l of lessons) {
  const bf = l.breakAndFix;
  assert.equal(runChecks(bf.solution, bf.checks, bf.file).length, 0, `${l.title}: solution passes`);
  assert.ok(runChecks(bf.broken, bf.checks, bf.file).length > 0, `${l.title}: broken fails`);
  assert.ok(runChecks(commentOut(bf.solution, bf.file), bf.checks, bf.file).length > 0,
    `${l.title}: a comments-only answer containing the solution text fails`);
  assert.ok(runChecks(bf.broken + "\n# " + bf.solution.split("\n").join(" "), bf.checks, bf.file).length > 0,
    `${l.title}: the broken code plus the fix pasted in a comment fails`);
  if (l.nodeRefs.length === 2)
    assert.ok(edgeSet.has(l.nodeRefs[0] + ">" + l.nodeRefs[1]),
      `${l.title}: the taught caller→callee pair is a real calls edge`);
}
// trailing comments on the call line don't break the real solution
const rbLesson = lessons.find((l) => l.breakAndFix.file.endsWith("report.rb"));
assert.ok(rbLesson, "a Ruby lesson exists");

// ---------- #4 + #3 + #5: the viewer's own script ----------
const html = readFileSync(new URL("../viewer/viewer.html", import.meta.url), "utf8");
const script = html.slice(html.lastIndexOf("<script>") + 8, html.lastIndexOf("</script>"));
const el = new Map<string, any>();
const element = (id: string) => {
  if (!el.has(id)) el.set(id, { hidden: false, textContent: "", innerHTML: "", style: {}, classList: { remove() {}, add() {} },
    addEventListener() {}, querySelectorAll: () => [], setAttribute() {},
    // loadGraph calling updateLegend() exercises document.getElementById("tmPanel")?.remove()
    // on every load now, not just a mode switch — see tests/viewer-loading.test.ts for the same fix.
    remove() {}, parentNode: { appendChild() {} } });
  return el.get(id);
};
const ctx = vm.createContext({
  document: { getElementById: element, documentElement: {}, createElement: () => ({ innerHTML: "", querySelectorAll: () => [] }) },
  getComputedStyle: () => ({ getPropertyValue: () => "" }),
  window: { matchMedia: () => ({ matches: false }), addEventListener() {} },
  setTimeout() {}, console, localStorage: { getItem: () => null, setItem() {} },
});
vm.runInContext(script, ctx);
const fg: any = { graphData() { return fg; }, nodeColor() { return fg; }, linkColor() { return fg; } };
ctx.testFG = fg;
ctx.testBundle = bundle;
vm.runInContext("FG = testFG; loadGraph(testBundle);", ctx);

const referenced = [...new Set(lessons.flatMap((l) => [...l.nodeRefs, l.breakAndFix.nodeRef]))];
const attached = referenced.filter((id) => vm.runInContext(`state.lessons.has(${JSON.stringify(id)})`, ctx));
assert.deepEqual(attached, referenced, "#4: every node a lesson references has that lesson in the viewer");
for (const l of lessons) {
  const bf = l.breakAndFix;
  ctx.t = { code: commentOut(bf.solution, bf.file), checks: bf.checks, file: bf.file, solution: bf.solution };
  assert.ok(vm.runInContext("runChecks(t.code, t.checks, t.file).length", ctx) > 0, `viewer: comments-only answer fails (${l.title})`);
  assert.equal(vm.runInContext("runChecks(t.solution, t.checks, t.file).length", ctx), 0, `viewer: real solution passes (${l.title})`);
}

ctx.f = { id: "c", nodeRefs: [bundle.graph.nodes[0].id], kind: "control", grade: "STATIC", title: "Input validation present",
  explanation: "x", evidence: [], blastRadius: [] };
vm.runInContext("buildFindings([f]); state.mode='security';", ctx);
const g = vm.runInContext("gradeOf(f.nodeRefs[0])", ctx);
assert.equal(g, "control", "#3: a STATIC control is not graded green");
const panel = vm.runInContext("securitySection(state.byId.get(f.nodeRefs[0]))", ctx);
assert.ok(!/HARDENED|was evaluated against/i.test(panel), "#3: a STATIC control is never called hardened/evaluated");
assert.ok(panel.includes("<b>present but unverified</b>"), "#3: the panel says the control is unverified");
assert.match(panel, /UNVERIFIED/, "#3: a STATIC control is labelled unverified");
vm.runInContext("f.grade='TESTED'; buildFindings([f]);", ctx);
assert.equal(vm.runInContext("gradeOf(f.nodeRefs[0])", ctx), "green", "a TESTED control is still green");

// ---------- #6: truncated source is reported, not returned empty ----------
const huge = bundle.sources?.find((s) => s.path.endsWith("huge.rb"));
assert.equal(huge?.truncated, true, "the oversized file is marked truncated in the bundle");
const tools = new AtlasTools(bundle);
const late = bundle.graph.nodes.find((n) => n.label === "late_method")!;
const lateSrc: any = tools.getSource(late.id);
assert.ok(!("source" in lateSrc) && /truncated/.test(lateSrc.reason), "#6: past-cap node returns a reason, not empty source");
assert.equal((tools.getNode(late.id) as any).hasSource, false, "#6: hasSource is per node");
const early = bundle.graph.nodes.find((n) => n.label === "m1" && n.evidence.path.endsWith("huge.rb"))!;
const earlySrc: any = tools.getSource(early.id);
assert.ok(earlySrc.source.includes("def m1") && earlySrc.from <= earlySrc.to, "an in-prefix node still returns a valid range");
for (const n of bundle.graph.nodes) {
  const r: any = tools.getSource(n.id);
  if ("source" in r) assert.ok(r.from <= r.to && r.source.length > 0, `valid non-empty range for ${n.label}`);
}

// ---------- #7: the whole context pack fits the budget ----------
for (const budget of [200, 500, 2000]) {
  const pack: any = tools.contextPack("create report notify build helper run huge", budget);
  const size = JSON.stringify(pack).length;
  assert.ok(size <= budget * 4, `#7: serialized pack (${size} chars) fits budget ${budget} tokens (${budget * 4} chars)`);
  assert.equal(pack.selected.length + pack.omitted, pack.receipt.candidates, "selected + omitted = candidates");
  assert.ok(!("selected" in pack.receipt), "the receipt carries a selection hash, not a second copy of the list");
}
const small: any = tools.contextPack("huge", 200);
assert.ok(small.omitted > 0, "a large match set is truncated and counted, not dumped");
const a: any = tools.contextPack("create report", 1000), b: any = tools.contextPack("create report", 1000);
assert.equal(a.receipt.hash, b.receipt.hash, "context pack stays replayable");
void nodeById;

console.log(`audit-regressions.test: ${lessons.length} lessons reject comment-only answers and attach in the viewer; ` +
  `static controls unverified; truncated source reported; context pack within budget`);
