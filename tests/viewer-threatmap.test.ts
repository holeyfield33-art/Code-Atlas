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
const leadCardSrc = grab(/function leadCard\(l\)\{[\s\S]*?\n\}/);
const leadCard = new Function("esc", "safeHref", LEAD_LABEL + ";" + leadCardSrc + "; return leadCard;")(esc, safeHref) as (l: any) => string;
const card = leadCard({ id: "L", attackClassId: "A<1>", label: "x", status: "hypothetical", confidence: "low", note: '<img src=x onerror="alert(1)">', url: "javascript:alert(1)", evidence: [] });
assert.ok(!/<img/.test(card), "lead note is escaped");
assert.ok(!/href=/.test(card), "an unsafe url yields no link");
assert.match(card, /HYPOTHETICAL LEAD/);
assert.match(card, /Still needs testing/, "an untested lead says what is missing");
assert.doesNotMatch(leadCard({ id: "R", attackClassId: "A", label: "x", status: "refuted", confidence: "low", note: "n", evidence: [] }), /Still needs testing/, "a refuted lead is not asked to be tested");

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

console.log("viewer-threatmap.test: 4th mode wired, overlay cannot grade Security, text escaped, links http(s) only, honest empty states");
