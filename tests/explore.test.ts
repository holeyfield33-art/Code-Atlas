/**
 * Exploration state in the viewer (UI state, never evidence). Pure helpers are extracted from the page and run here:
 *  - a record is keyed by path + kind + name, so it survives a rebuild that shifts line numbers;
 *  - opened vs reviewed vs unvisited, and a component whose content changed counts as unexplored again;
 *  - "next unexplored" finds the nearest unexplored neighbour (breadth-first);
 *  - the render cap never withholds a pinned node (selected / bookmarked / recent);
 *  - source contract: dimming is skipped in the Security view, and exploration code never touches findings or grades.
 */
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(resolve(here, "../viewer/viewer.html"), "utf8");
const grab = (re: RegExp) => { const m = re.exec(html)?.[0]; assert.ok(m, "found in viewer: " + re); return m; };

const exploreKey = new Function(grab(/function exploreKey\(n\)\{[^\n]*\}/) + "; return exploreKey;")() as any;
const exploreStatus = new Function(grab(/function exploreStatus\(rec, n\)\{[\s\S]*?\n\}/) + "; return exploreStatus;")() as any;
const nextUnexplored = new Function(grab(/function nextUnexplored\([\s\S]*?\n\}/) + "; return nextUnexplored;")() as any;
const mixHex = new Function(grab(/function mixHex\([\s\S]*?\n\}/) + "; return mixHex;")() as any;
const collapseForDetail = new Function(grab(/function collapseForDetail\(nodes, edges, opts\)\{[\s\S]*?\n\}/) + "; return collapseForDetail;")() as any;

const n = (label: string, line: number, hash = "h1") => ({ id: label + line, kind: "function", label, evidence: { path: "a/b.rb", line, contentHash: hash } });
assert.equal(exploreKey(n("run", 10)), exploreKey(n("run", 99)), "the key ignores the line, so a rebuild that shifts lines keeps the record");
assert.notEqual(exploreKey(n("run", 10)), exploreKey({ ...n("run", 10), kind: "file" }), "kind is part of the key");

assert.equal(exploreStatus(undefined, n("x", 1)), "unvisited");
assert.equal(exploreStatus({ t: 5, h: "h1" }, n("x", 1)), "visited");
assert.equal(exploreStatus({ t: 5, h: "h1", r: 6 }, n("x", 1)), "reviewed");
assert.equal(exploreStatus({ t: 5, h: "h1", r: 6 }, n("x", 1, "h2")), "changed", "changed content is not shown as explored (or reviewed)");
assert.equal(exploreStatus({ t: 5, r: 6 }, n("x", 1)), "reviewed", "a record without a hash still works");

// graph: a - b - c - d (a chain); a, b opened
const adj: Record<string, string[]> = { a: ["b"], b: ["a", "c"], c: ["b", "d"], d: ["c"] };
const opened = new Set(["a", "b"]);
assert.equal(nextUnexplored("a", (id: string) => adj[id], (id: string) => !opened.has(id)), "c", "nearest unexplored by hops");
assert.equal(nextUnexplored("a", (id: string) => adj[id], () => false), null, "nothing left -> null");

assert.equal(mixHex("#ffffff", "#000000", 0.5), "#808080");
assert.equal(mixHex("rgb(1,2,3)", "#000000", 0.5), "rgb(1,2,3)", "non-hex input is returned unchanged, never corrupted");

// the cap keeps pinned nodes
const nodes = Array.from({ length: 10 }, (_, i) => ({ id: "f" + i, kind: "file", label: "f" + i }));
const edges = [{ from: "f0", to: "f1", kind: "imports" }, { from: "f0", to: "f2", kind: "imports" }];
const capped = collapseForDetail(nodes, edges, { detail: "files", expanded: new Set(), containerOf: new Map(), filters: {}, cap: 3 });
assert.equal(capped.nodes.length, 3);
assert.ok(!capped.nodes.some((x: any) => x.id === "f9"), "an unconnected node is withheld by the cap");
const pinned = collapseForDetail(nodes, edges, { detail: "files", expanded: new Set(), containerOf: new Map(), filters: {}, cap: 3, pinned: new Set(["f9"]) });
assert.ok(pinned.nodes.some((x: any) => x.id === "f9"), "a pinned node is drawn although the cap would withhold it");
assert.equal(pinned.capped, 6, "the withheld count excludes the pinned node");

// source contract: exploration never alters evidence, and the Security view keeps grade colours exact
const nodeColorSrc = grab(/function nodeColor\(node\)\{[\s\S]*?\n\}/);
assert.ok(nodeColorSrc.indexOf('state.mode==="security"') < nodeColorSrc.indexOf("fogged("), "the Security branch returns before any dimming");
const exploreSrc = html.slice(html.indexOf("/* ---- Exploration"), html.indexOf("let FG = null;"));
assert.ok(!/findingByNode|state\.findings|\.grade\b|blast/.test(exploreSrc), "exploration code does not read or write findings, grades or blast radius");
assert.ok(!/--grade-/.test(exploreSrc), "exploration code does not touch grade colours");
assert.ok(!/--grade-/.test(html.slice(html.indexOf(':root[data-theme="electric"]'), html.indexOf(":root[data-theme=\"electric\"]") + 400).split("}")[0]), "the Electric theme does not redefine grade colours");

console.log("explore.test: opened/reviewed/changed states, nearest-unexplored, pinned nodes survive the cap, Security colours untouched");
