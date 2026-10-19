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
// A lead's url is untrusted overlay text and can contain an unpaired UTF-16 surrogate (a valid JS
// string, since JS strings are UTF-16 code units, not valid UTF-8/16 text) — encodeURI() THROWS on
// one (URIError: URI malformed). The scheme check alone passes first, so without a try/catch this
// crashes whatever calls safeHref() instead of just refusing the one bad link.
assert.strictEqual(safeHref("https://example.test/\ud800"), null, "an unpaired surrogate in an otherwise valid https url is refused, not thrown");

const LEAD_LABEL = grab(/const LEAD_LABEL = \{[^\n]*\}/);
const EVIDENCE_ROWS_SHOWN_SRC = grab(/const EVIDENCE_ROWS_SHOWN\s*=\s*\d+;/);
const LEAD_TEXT_CAP_SRC = grab(/const LEAD_TEXT_CAP\s*=\s*\d+;/);
const clipSrcForCard = grab(/function clip\(s, n\)\{[^\n]*\}/);
const leadCardSrc = grab(/function leadCard\(l\)\{[\s\S]*?\n\}/);
const leadCard = new Function("esc", "safeHref", EVIDENCE_ROWS_SHOWN_SRC + ";" + LEAD_TEXT_CAP_SRC + ";" + clipSrcForCard + ";" + LEAD_LABEL + ";" + leadCardSrc + "; return leadCard;")(esc, safeHref) as (l: any) => string;
const card = leadCard({ id: "L", attackClassId: "A<1>", label: "x", status: "hypothetical", confidence: "low", note: '<img src=x onerror="alert(1)">', url: "javascript:alert(1)", evidence: [] });
assert.ok(!/<img/.test(card), "lead note is escaped");
assert.ok(!/href=/.test(card), "an unsafe url yields no link");
assert.match(card, /HYPOTHETICAL LEAD/);
assert.match(card, /Still needs testing/, "an untested lead says what is missing");
assert.doesNotMatch(leadCard({ id: "R", attackClassId: "A", label: "x", status: "refuted", confidence: "low", note: "n", evidence: [] }), /Still needs testing/, "a refuted lead is not asked to be tested");

// Row/card caps bound how many things render, not how long any ONE field is — a valid overlay
// can still put most of its 5MB budget into a single lead's note/label/rule, or one evidence
// item's source/detail. Every displayed text field must be clipped too.
const hugeField = "y".repeat(10_000);
const hugeFieldCard = leadCard({ id: "L3", attackClassId: hugeField, label: hugeField, status: "hypothetical", confidence: "low", note: hugeField, rule: hugeField, evidence: [{ source: hugeField, detail: hugeField }] });
assert.ok(hugeFieldCard.length < 5_000, "a lead with 10,000-char fields produces a bounded card, not a multi-KB one");
assert.ok(!hugeFieldCard.includes(hugeField), "the oversized field is clipped, not emitted in full");

// safeHref() only checks the scheme before running the WHOLE url through encodeURI() into the
// href attribute — every OTHER field here is clipped, but an unclipped url would still produce
// multi-megabyte markup (and, pre-fix, run a multi-MB string through encodeURI on every open).
// Clipping the url itself (append "…" to a prefix, like every other field) was tried first and
// rejected: a truncated url navigates somewhere ELSE entirely while still looking like the
// source's own link, which is worse than no link — so an oversized url is OMITTED, not truncated.
const hugeUrl = "https://example.test/" + "z".repeat(50_000);
const hugeUrlCard = leadCard({ id: "L4", attackClassId: "A", label: "x", status: "hypothetical", confidence: "low", note: "n", url: hugeUrl, evidence: [] });
assert.ok(hugeUrlCard.length < 5_000, "a lead with a 50,000-char url still produces a bounded card");
assert.ok(!hugeUrlCard.includes("z".repeat(1000)), "the url itself never appears in full");
assert.ok(!/href=/.test(hugeUrlCard), "an oversized url yields no link at all, not a link to a truncated (different) address");
const okUrl = "https://example.test/short";
const okUrlCard = leadCard({ id: "L5", attackClassId: "A", label: "x", status: "hypothetical", confidence: "low", note: "n", url: okUrl, evidence: [] });
assert.match(okUrlCard, /href="https:\/\/example\.test\/short"/, "a url within the safe bound still yields a real, unaltered link");

// a valid sub-5MB overlay can still put tens of thousands of evidence records on ONE lead — the
// inspector must not map them all into <li>s synchronously (freeze risk), so this is bounded too.
const manyEvidence = Array.from({ length: 5000 }, (_, i) => ({ source: "s" + i, detail: "d" + i }));
const bigCard = leadCard({ id: "L2", attackClassId: "A", label: "x", status: "hypothetical", confidence: "low", note: "n", evidence: manyEvidence });
assert.strictEqual((bigCard.match(/<li>/g) || []).length, 21, "evidence rows are capped (20 shown + 1 'more' row), not all 5000 rendered");
assert.match(bigCard, /4980 more evidence/, "the omitted count is stated");

const LEAD_CARDS_SHOWN_SRC = grab(/const LEAD_CARDS_SHOWN\s*=\s*\d+;/);
const MEMBER_LEADS_SHOWN_SRC = grab(/const MEMBER_LEADS_SHOWN\s*=\s*\d+;/);
const secSrc = grab(/function threatMapSection\(n\)\{[\s\S]*?\n\}/);
const mk = (state: any) => new Function("state", "esc", "leadCard", "labelFor", LEAD_CARDS_SHOWN_SRC + ";" + MEMBER_LEADS_SHOWN_SRC + ";" + LEAD_TEXT_CAP_SRC + ";" + clipSrcForCard + ";" + secSrc + "; return threatMapSection;")(state, esc, leadCard, (id: string) => id) as (n: any) => string;
assert.match(mk({ overlay: null })({ id: "n", kind: "function" }), /No threat overlay attached/, "no overlay => not assessed");
const overlay = { source: { identity: "src", ref: "r1", asOf: "2026-10-17" }, leads: [], unresolved: [] };
const none = mk({ overlay, leadsByNode: new Map(), nbr: new Map() })({ id: "n", kind: "function" });
assert.match(none, /Absence of a lead is not proof of safety/);
assert.doesNotMatch(none, /no vulnerabilit|is safe|not vulnerable/i, "an empty node is never declared safe");

// The overlay schema permits up to 5,000 leads total with nothing stopping them all landing on
// one node — opening that node must not synchronously build thousands of lead cards.
const manyLeads = Array.from({ length: 200 }, (_, i) => ({ id: "L" + i, attackClassId: "A", label: "x" + i, status: "hypothetical", confidence: "low", note: "n", evidence: [] }));
const manySec = mk({ overlay, leadsByNode: new Map([["n", manyLeads]]), nbr: new Map() })({ id: "n", kind: "function" });
assert.strictEqual((manySec.match(/class="lead-card/g) || []).length, 30, "only LEAD_CARDS_SHOWN lead cards render for one component");
assert.match(manySec, /170 more lead/, "the omitted lead count is stated");

// A file's leads-in-this-file list is a SEPARATE unbounded surface from the own-lead cards above:
// a file with leads on hundreds of distinct functions must still render a bounded member list.
const manyMembers = new Map<string, any[]>();
const nbr = new Map<string, any>();
for (let i = 0; i < 200; i++) { manyMembers.set("fn" + i, [{}]); nbr.set("fn" + i, { container: "file1" }); }
const fileSec = mk({ overlay, leadsByNode: manyMembers, nbr })({ id: "file1", kind: "file" });
assert.strictEqual((fileSec.match(/data-goto=/g) || []).length, 30, "only MEMBER_LEADS_SHOWN member functions are listed");
assert.match(fileSec, /170 more function/, "the omitted member-function count is stated");

// The "Source: ..." stamp renders on EVERY component in Threat Map mode, including one with no
// leads at all — it carries the same untrusted overlay text as a lead's own fields, so it needs
// the same clip, not just the per-lead-card one.
const hugeSourceOverlay = { source: { identity: "i".repeat(10_000), ref: "r".repeat(10_000), asOf: "a".repeat(10_000) }, leads: [], unresolved: [] };
const hugeSourceSec = mk({ overlay: hugeSourceOverlay, leadsByNode: new Map(), nbr: new Map() })({ id: "n", kind: "function" });
assert.ok(hugeSourceSec.length < 5_000, "a component with no leads still produces a bounded panel, even with a 30,000-char source stamp");
assert.ok(!hugeSourceSec.includes("i".repeat(10_000)), "the oversized source.identity is clipped, not emitted in full");

// unresolvedPanel() renders straight from the raw bundle (not an MCP response), so neither the
// row count nor any one entry's text is bounded by the server-side field caps — both need their
// own client-side cap here, or a valid overlay near its 5,000-entry/5MB limits can freeze the panel.
const clipSrc = grab(/function clip\(s, n\)\{[^\n]*\}/);
const unresolvedRowsSrc = grab(/const UNRESOLVED_ROWS_SHOWN\s*=\s*\d+;/);
const unresolvedTextCapSrc = grab(/const UNRESOLVED_TEXT_CAP\s*=\s*\d+;/);
const unresolvedPanelSrc = grab(/function unresolvedPanel\(\)\{[\s\S]*?\n\}/);
const unresolvedPanel = (state: any) => new Function("state", "esc", unresolvedRowsSrc + ";" + unresolvedTextCapSrc + ";" + clipSrc + ";" + unresolvedPanelSrc + "; return unresolvedPanel;")(state, esc)();
assert.strictEqual(unresolvedPanel({ overlay, showUnresolved: false }), "", "hidden unless showUnresolved is on");
const manyUnresolved = Array.from({ length: 200 }, (_, i) => ({ attackClassId: "A", description: "d" + i, reason: "r" + i }));
const panel = unresolvedPanel({ overlay: { ...overlay, unresolved: manyUnresolved }, showUnresolved: true });
assert.strictEqual((panel.match(/class="row"/g) || []).length, 50, "only UNRESOLVED_ROWS_SHOWN rows render, not all 200");
assert.match(panel, /150 more unresolved/, "the omitted row count is stated");
const hugeDesc = [{ attackClassId: "A", description: "x".repeat(10_000), reason: "r" }];
const hugePanel = unresolvedPanel({ overlay: { ...overlay, unresolved: hugeDesc }, showUnresolved: true });
assert.ok(hugePanel.length < 5_000, "one oversized entry's description is clipped, not emitted in full");
// attackClassId was rendered with a bare esc(), unlike description/target/reason which were
// already clip()'d — an overlay putting its allowance there alone would still blow up the panel.
const hugeClass = [{ attackClassId: "C".repeat(10_000), description: "d", reason: "r" }];
const hugeClassPanel = unresolvedPanel({ overlay: { ...overlay, unresolved: hugeClass }, showUnresolved: true });
assert.ok(hugeClassPanel.length < 5_000, "one oversized attackClassId is clipped too, not emitted in full");

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

// applyMode() (switching modes, e.g. into Threat Map, without loading a new bundle) has the
// same ordering requirement: calling updateLegend() before the render()/openInspector() that
// re-pins Threat Map leads would label freshly-rescued nodes as still capped.
const applyModeSrc = grab(/function applyMode\(m\)\{[\s\S]*?\n\}/);
const amRenderCall = applyModeSrc.indexOf("render()");
const amOpenInspectorCall = applyModeSrc.indexOf("openInspector(");
const amUpdateLegendCall = applyModeSrc.lastIndexOf("updateLegend()");
assert.ok(amUpdateLegendCall > amRenderCall && amUpdateLegendCall > amOpenInspectorCall,
  "applyMode calls updateLegend() after render()/openInspector(), not before");
// render() must run UNCONDITIONALLY on every mode switch, not only when nothing is selected:
// openInspector()'s own wasDrawn-branch shortcut (recolor only, no render) is for a plain
// selection change within the SAME mode, and reusing that shortcut on a mode switch would skip
// recomputing pinnedIds() for the new mode, leaving Threat Map's lead-node pin rescue stale.
assert.ok(amRenderCall !== -1 && amRenderCall < amOpenInspectorCall,
  "applyMode calls render() before openInspector(), and not merely inside its branch");
assert.doesNotMatch(applyModeSrc.slice(0, amRenderCall), /if\(/, "applyMode's render() call is unconditional");

// capped leads must stay DISCOVERABLE: a lead the render cap (and its own PIN_OVERFLOW budget)
// dropped needs a way to find it, or the earlier pin-overflow fix just reintroduces the original
// "lead silently absent" bug it was meant to avoid.
const cappedLeadIdsSrc = grab(/function cappedLeadIds\(\)\{[\s\S]*?\n\}/);
const cappedLeadIds = (state: any) => new Function("state", cappedLeadIdsSrc + "; return cappedLeadIds;")(state)();
const drawnState = {
  leadsByNode: new Map([["drawn-fn", [{}]], ["hidden-fn", [{}]], ["stand-in-fn", [{}]]]),
  leadFileOf: new Map([["drawn-fn", "f1"], ["hidden-fn", "f2"], ["stand-in-fn", "f3"]]),
  drawn: new Set(["drawn-fn", "f3"]),   // drawn-fn is drawn directly; stand-in-fn's FILE (f3) is drawn instead; hidden-fn is neither
  detail: "files", expanded: new Set(),   // f3 is COLLAPSED, so it validly stands in for stand-in-fn (same condition as leadOn())
};
assert.deepStrictEqual(cappedLeadIds(drawnState), ["hidden-fn"], "only a lead whose node AND containing file are both undrawn counts as capped");

// A drawn file only stands in for its hidden functions' leads under leadOn()'s OWN condition —
// "files" detail and not individually expanded. In Full detail, or once the file is expanded, a
// drawn file is no longer a visual stand-in (same file content as above, different detail state).
assert.deepStrictEqual(cappedLeadIds({ ...drawnState, detail: "full" }), ["hidden-fn", "stand-in-fn"],
  "in Full detail a drawn file no longer stands in for its functions' leads, so they count as capped too");
assert.deepStrictEqual(cappedLeadIds({ ...drawnState, expanded: new Set(["f3"]) }), ["hidden-fn", "stand-in-fn"],
  "once the file is individually expanded it no longer stands in either");

// The "not drawn" panel used to hard-cap itself at CAPPED_LEADS_SHOWN with a dead-end note
// ("zoom in, select a nearby file, or search by name") — but zooming/selecting doesn't change the
// capped SET, and searching needs the omitted node's name, which is exactly what's missing. A list
// beyond the first page must be reachable via Prev/Next pagination, not left permanently hidden.
const CAPPED_LEADS_SHOWN_SRC = grab(/const CAPPED_LEADS_SHOWN\s*=\s*\d+;/);
const cappedLeadsPanelSrc = grab(/function cappedLeadsPanel\(\)\{[\s\S]*?\n\}/);
const cappedLeadsPanel = (state: any) => new Function(
  "state", "esc",
  CAPPED_LEADS_SHOWN_SRC + ";" + cappedLeadIdsSrc + ";" + cappedLeadsPanelSrc + "; return cappedLeadsPanel;",
)(state, esc)();
const manyUndrawnLeads = Array.from({ length: 75 }, (_, i) => [`n${i}`, [{}]] as const);
const pagedState: any = {
  leadsByNode: new Map(manyUndrawnLeads),
  leadFileOf: new Map(), drawn: new Set(), detail: "files", expanded: new Set(),
  byId: new Map(manyUndrawnLeads.map(([id]) => [id, { label: id, evidence: { path: "src/x.js" } }])),
  showCappedLeads: true, cappedLeadsPage: 0,
};
const page1Panel = cappedLeadsPanel(pagedState);
assert.strictEqual((page1Panel.match(/data-goto="n\d+"/g) || []).length, 30, "the first page shows CAPPED_LEADS_SHOWN rows, not all 75");
assert.match(page1Panel, /page 1 \/ 3/, "page count reflects ceil(75\\/30)");
assert.match(page1Panel, /data-page-delta="-1" disabled/, "Prev is disabled on the first page");
assert.match(page1Panel, /data-page-delta="1"(?! disabled)/, "Next is enabled when a later page exists");
pagedState.cappedLeadsPage = 2;
const page3Panel = cappedLeadsPanel(pagedState);
assert.strictEqual((page3Panel.match(/data-goto="n\d+"/g) || []).length, 15, "the last page shows the remainder (75 - 2*30), not a full page of 30");
assert.match(page3Panel, /data-page-delta="1" disabled/, "Next is disabled on the last page");
assert.doesNotMatch(page3Panel, /data-page-delta="-1" disabled/, "Prev is enabled once off the first page");
// a page number past the end (e.g. a re-render after the overlay shrank) must clamp, not go blank
pagedState.cappedLeadsPage = 99;
const clampedPanel = cappedLeadsPanel(pagedState);
assert.strictEqual((clampedPanel.match(/data-goto="n\d+"/g) || []).length, 15, "an out-of-range page clamps back to the last real page");
assert.strictEqual(pagedState.cappedLeadsPage, 2, "the clamp is written back to state so the legend's page indicator agrees with what's shown");
// updateLegend() must actually wire the Prev/Next buttons it renders, or they're dead controls
const updateLegendSrcForPaging = grab(/function updateLegend\(\)\{[\s\S]*?\n\}/);
assert.match(updateLegendSrcForPaging, /data-page-delta/, "updateLegend's panel-wiring includes the pagination buttons");

// Clicking a row in the "not drawn" panel pin-rescues that node via openInspector()'s render()
// branch (wasDrawn was false going in), which changes state.drawn — goTo() must refresh the
// legend afterward, or the panel keeps listing the now-visible node and its stale count until
// some unrelated action rebuilds it.
const goToSrc = grab(/function goTo\(id\)\{[\s\S]*?\n\}/);
const goToOpenInspectorCall = goToSrc.indexOf("openInspector(");
const goToUpdateLegendCall = goToSrc.indexOf("updateLegend()");
assert.ok(goToOpenInspectorCall !== -1 && goToUpdateLegendCall !== -1 && goToUpdateLegendCall > goToOpenInspectorCall,
  "goTo() calls updateLegend() after openInspector(), so a newly-rescued node drops out of the not-drawn panel immediately");

// The unresolved panel and the not-drawn-leads panel can both be open at once; they used to be
// two position:absolute elements at the same left/bottom, so the later one painted directly over
// the earlier one. #tmPanel (their host) must be the one positioned+stacking container now, and
// .tm-panel itself must no longer carry its own position:absolute.
const tmPanelHostCss = grab(/#tmPanel\{[^}]*\}/);
assert.match(tmPanelHostCss, /position:absolute/, "#tmPanel is the positioned container");
assert.match(tmPanelHostCss, /display:flex/, "#tmPanel stacks its panel children instead of letting them overlap");
const tmPanelCss = grab(/\n\s*\.tm-panel\{[^}]*\}/);
assert.doesNotMatch(tmPanelCss, /position:absolute/, ".tm-panel no longer positions itself (its host does), so two open panels stack instead of overlapping");

// Threat Map's unresolved/not-drawn-leads buttons are the only way to reach leads the render cap
// hid, on any screen size — the mobile media query hides the whole #legend they live in, so it
// must have an escape hatch that keeps them reachable there too.
const mobileCss = grab(/@media \(max-width:560px\)\{[\s\S]*?\n\s*\}/);
assert.match(mobileCss, /\.legend\.has-controls\{[^}]*display:flex/, "a has-controls legend stays visible on mobile");
const updateLegendSrc = grab(/function updateLegend\(\)\{[\s\S]*?\n\}/);
assert.match(updateLegendSrc, /classList\.remove\("has-controls"\)/, "updateLegend resets the class before deciding whether to re-add it");
assert.match(updateLegendSrc, /if\(btn \|\| cappedBtn\) el\.classList\.add\("has-controls"\)/, "updateLegend adds has-controls only when it actually put a button in the legend");

// Toggling Files<->Full detail re-renders (changing state.drawn) and also changes what
// cappedLeadIds()/leadOn() consider a valid file stand-in (see the fix above) — the legend's
// capped-lead count and any open panel must refresh here too, like every other render path that
// can change what counts as "drawn" (loadGraph, applyMode, goTo).
const toggleDetailSrc = grab(/function toggleDetail\(\)\{[\s\S]*?\n\}/);
const tdRenderCall = toggleDetailSrc.indexOf("render()");
const tdUpdateLegendCall = toggleDetailSrc.indexOf("updateLegend()");
assert.ok(tdRenderCall !== -1 && tdUpdateLegendCall !== -1 && tdUpdateLegendCall > tdRenderCall,
  "toggleDetail() calls updateLegend() after render()");

console.log("viewer-threatmap.test: 4th mode wired, overlay cannot grade Security, text escaped, links http(s) only, honest empty states, legend refreshes on load, capped leads stay discoverable and paginated, lead text bounded, panels don't overlap, mobile controls reachable, detail toggle refreshes legend");
