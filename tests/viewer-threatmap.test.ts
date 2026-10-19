/**
 * Threat Map view contract (source-contract + pure-function, like viewer-security):
 *  - the 4th mode exists and is wired through the same applyMode as the others;
 *  - overlay leads never feed the Security grades (gradeOf does not read them);
 *  - lead text is escaped and link schemes are http(s) only;
 *  - with no overlay the view says "not assessed", and with an overlay but no lead on a
 *    node it does not claim the node is safe;
 *  - a collapsed file stands in for the leads on the functions it hides.
 */
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const html = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../viewer/viewer.html"), "utf8");
const grab = (re: RegExp) => { const m = re.exec(html); assert.ok(m, "found " + re.source.slice(0, 40)); return m![0]; };

assert.ok(/data-mode="threatmap"[^>]*>[\s\S]*?Threat Map/.test(html), "a Threat Map mode button exists");
assert.ok(html.includes('document.querySelectorAll(".modes button").forEach(b=>b.addEventListener("click",()=>applyMode(b.dataset.mode)))'), "mode buttons share one handler");

// Overlay leads cannot colour Security: gradeOf never reads overlay state.
const gradeSrc = grab(/function gradeOf\(nodeId\)\{[\s\S]*?\n\}/);
assert.ok(!/leadsByNode|overlay|leadFiles|leadOn/.test(gradeSrc), "gradeOf ignores overlay leads");

const esc = new Function(grab(/function esc\(s\)\{[^\n]*\}/) + "; return esc;")() as (s: string) => string;
const safeHref = new Function(grab(/function safeHref\(u\)\{[^\n]*\}/) + "; return safeHref;")() as (u: string) => string | null;
assert.strictEqual(safeHref("javascript:alert(1)"), null, "javascript: links are refused");
assert.strictEqual(safeHref("data:text/html,x"), null, "data: links are refused");
assert.strictEqual(safeHref(""), null);
assert.strictEqual(safeHref("https://example.test/a b"), "https://example.test/a%20b");

const LEAD_LABEL = grab(/const LEAD_LABEL = \{[^\n]*\}/);
const EVIDENCE_ROWS_SHOWN_SRC = grab(/const EVIDENCE_ROWS_SHOWN\s*=\s*\d+;/);
const leadCardSrc = grab(/function leadCard\(l\)\{[\s\S]*?\n\}/);
const leadCard = new Function("esc", "safeHref", LEAD_LABEL + ";" + EVIDENCE_ROWS_SHOWN_SRC + ";" + leadCardSrc + "; return leadCard;")(esc, safeHref) as (l: any) => string;
const card = leadCard({ id: "L", attackClassId: "A<1>", label: "x", status: "hypothetical", confidence: "low", note: '<img src=x onerror="alert(1)">', url: "javascript:alert(1)", evidence: [] });
assert.ok(!/<img/.test(card), "lead note is escaped");
assert.ok(!/href=/.test(card), "an unsafe url yields no link");
assert.match(card, /HYPOTHETICAL LEAD/);
assert.match(card, /Still needs testing/, "an untested lead says what is missing");
assert.doesNotMatch(leadCard({ id: "R", attackClassId: "A", label: "x", status: "refuted", confidence: "low", note: "n", evidence: [] }), /Still needs testing/, "a refuted lead is not asked to be tested");

// a valid sub-5MB overlay can still put tens of thousands of evidence records on ONE lead — the
// inspector must not map them all into <li>s synchronously (freeze risk), so this is bounded too.
const manyEvidence = Array.from({ length: 5000 }, (_, i) => ({ source: "s" + i, detail: "d" + i }));
const bigCard = leadCard({ id: "L2", attackClassId: "A", label: "x", status: "hypothetical", confidence: "low", note: "n", evidence: manyEvidence });
assert.strictEqual((bigCard.match(/<li>/g) || []).length, 21, "evidence rows are capped (20 shown + 1 'more' row), not all 5000 rendered");
assert.match(bigCard, /4980 more evidence/, "the omitted count is stated");

const secSrc = grab(/function threatMapSection\(n\)\{[\s\S]*?\n\}/);
const mk = (state: any) => new Function("state", "esc", "leadCard", "labelFor", secSrc + "; return threatMapSection;")(state, esc, leadCard, (id: string) => id) as (n: any) => string;
assert.match(mk({ overlay: null })({ id: "n", kind: "function" }), /No threat overlay attached/, "no overlay => not assessed");
const overlay = { source: { identity: "src", ref: "r1", asOf: "2026-10-17" }, leads: [], unresolved: [] };
const none = mk({ overlay, leadsByNode: new Map(), nbr: new Map() })({ id: "n", kind: "function" });
assert.match(none, /Absence of a lead is not proof of safety/);
assert.doesNotMatch(none, /no vulnerabilit|is safe|not vulnerable/i, "an empty node is never declared safe");

// A collapsed file stands in for the leads on its hidden functions.
const leadOnSrc = grab(/function leadOn\(id\)\{[\s\S]*?\n\}/);
const leadOn = (state: any) => new Function("state", leadOnSrc + "; return leadOn;")(state) as (id: string) => boolean;
const base = { leadsByNode: new Map([["fn", [{}]]]), leadFiles: new Set(["file"]), byId: new Map([["file", { kind: "file" }], ["fn", { kind: "function" }]]), expanded: new Set<string>() };
assert.ok(leadOn({ ...base, detail: "files" })("file"), "collapsed file shows its hidden functions' leads");
assert.ok(!leadOn({ ...base, detail: "full" })("file"), "in the full view the file itself carries no lead");
assert.ok(!leadOn({ ...base, detail: "files", expanded: new Set(["file"]) })("file"), "an expanded file no longer stands in for its functions");
assert.ok(leadOn({ ...base, detail: "files" })("fn"), "the function itself is marked");

// pinnedIds() must keep a resolved lead's node AND its containing file drawn under the render
// cap in Threat Map mode — otherwise collapseForDetail's degree ranking can silently drop it on
// a large repo, with no list view through which it could be found afterward.
const pinnedIdsSrc = grab(/function pinnedIds\(\)\{[\s\S]*?\n\}/);
const pinnedIds = (state: any, explore: any) => new Function("state", "explore", pinnedIdsSrc + "; return pinnedIds;")(state, explore)();
const leadState = { mode: "threatmap", leadsByNode: new Map([["fn1", [{}]]]), leadFiles: new Set(["file1"]), byExploreKey: new Map() };
const noExplore = { items: {}, recent: [] };
assert.ok(pinnedIds(leadState, noExplore).has("fn1"), "a lead's own node is pinned in Threat Map mode");
assert.ok(pinnedIds(leadState, noExplore).has("file1"), "a lead's containing file is pinned too");
assert.ok(!pinnedIds({ ...leadState, mode: "security" }, noExplore).has("fn1"), "leads are not force-pinned outside Threat Map mode");

// loadGraph must refresh the legend itself: if it only relied on applyMode/the unresolved-chip
// handler, a bundle loaded while already in Threat Map mode would leave the legend (and an open
// unresolved panel) showing the PREVIOUS bundle's overlay until the user toggled something.
const loadGraphSrc = grab(/function loadGraph\(raw[\s\S]*?\n\}/);
const buildOverlayCall = loadGraphSrc.indexOf("buildOverlay(");
const renderCall = loadGraphSrc.indexOf("render();");
const updateLegendCall = loadGraphSrc.lastIndexOf("updateLegend()");
assert.ok(buildOverlayCall !== -1 && updateLegendCall !== -1 && updateLegendCall > buildOverlayCall,
  "loadGraph calls updateLegend() after buildOverlay(), so the legend/unresolved panel never shows a stale overlay");
assert.ok(renderCall !== -1 && updateLegendCall > renderCall,
  "loadGraph's updateLegend() call comes AFTER render(): its Threat Map branch reads state.drawn (set by render()/fgData()) to list capped leads, and calling it any earlier would read the PREVIOUS graph's drawn set");

// capped leads must stay DISCOVERABLE: a lead the render cap (and its own PIN_OVERFLOW budget)
// dropped needs a way to find it, or the earlier pin-overflow fix just reintroduces the original
// "lead silently absent" bug it was meant to avoid.
const cappedLeadIdsSrc = grab(/function cappedLeadIds\(\)\{[\s\S]*?\n\}/);
const cappedLeadIds = (state: any) => new Function("state", cappedLeadIdsSrc + "; return cappedLeadIds;")(state)();
const drawnState = {
  leadsByNode: new Map([["drawn-fn", [{}]], ["hidden-fn", [{}]], ["stand-in-fn", [{}]]]),
  leadFileOf: new Map([["drawn-fn", "f1"], ["hidden-fn", "f2"], ["stand-in-fn", "f3"]]),
  drawn: new Set(["drawn-fn", "f3"]),   // drawn-fn is drawn directly; stand-in-fn's FILE (f3) is drawn instead; hidden-fn is neither
};
assert.deepStrictEqual(cappedLeadIds(drawnState), ["hidden-fn"], "only a lead whose node AND containing file are both undrawn counts as capped");

console.log("viewer-threatmap.test: 4th mode wired, overlay cannot grade Security, text escaped, links http(s) only, honest empty states, legend refreshes on load, capped leads stay discoverable");
