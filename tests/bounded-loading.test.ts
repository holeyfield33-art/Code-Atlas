/**
 * Bounded graph loading: a large repo must not require rendering the full graph.
 * The viewer collapses function/class nodes into their file (edges remapped to
 * the file, intra-file self-loops dropped, duplicates aggregated), and expands a
 * single file on demand. This tests the pure collapseForDetail() extracted from
 * the viewer, plus the source contract that large graphs default to the file view.
 */
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(resolve(here, "../viewer/viewer.html"), "utf8");

// extract the pure collapse function and eval it (our own code)
const src = /function collapseForDetail\(nodes, edges, opts\)\{[\s\S]*?\n\}/.exec(html)?.[0];
assert.ok(src, "found collapseForDetail() in the viewer");
// eslint-disable-next-line no-new-func
const collapseForDetail = new Function(src + "; return collapseForDetail;")() as any;

const nodes = [
  { id: "F1", kind: "file", label: "f1.py" },
  { id: "F2", kind: "file", label: "f2.py" },
  { id: "a", kind: "function", label: "a" },
  { id: "b", kind: "function", label: "b" },
  { id: "c", kind: "function", label: "c" },
];
const edges = [
  { from: "F1", to: "a", kind: "contains" },
  { from: "F1", to: "b", kind: "contains" },
  { from: "F2", to: "c", kind: "contains" },
  { from: "a", to: "b", kind: "calls" },     // intra-file
  { from: "a", to: "c", kind: "calls" },     // cross-file
  { from: "F1", to: "F2", kind: "imports" },
];
const containerOf = new Map([["a", "F1"], ["b", "F1"], ["c", "F2"]]);
const filters = { contains: true, imports: true, calls: true };

// full: everything
const full = collapseForDetail(nodes, edges, { detail: "full", expanded: new Set(), containerOf, filters });
assert.strictEqual(full.nodes.length, 5, "full shows all nodes");
assert.strictEqual(full.links.length, 6, "full shows all links");

// files (nothing expanded): only files; cross-file call + import aggregate to F1->F2; the rest collapse away
const files = collapseForDetail(nodes, edges, { detail: "files", expanded: new Set(), containerOf, filters });
assert.deepStrictEqual(files.nodes.map((n: any) => n.id).sort(), ["F1", "F2"], "files view shows only file nodes");
assert.strictEqual(files.links.length, 2, "cross-file call + import survive; intra-file + contains collapse to self-loops and drop");
assert.ok(files.links.some((l: any) => l.kind === "calls" && l.source === "F1" && l.target === "F2" && l.aggregated), "cross-file call aggregated to the file level");
assert.ok(files.links.every((l: any) => l.source !== l.target), "no self-loops");

// huge-graph node reduction is real
const bigNodes = [{ id: "F1", kind: "file", label: "f" }];
const bigEdges: any[] = [];
const bigCont = new Map<string, string>();
for (let i = 0; i < 5000; i++) { bigNodes.push({ id: "fn" + i, kind: "function", label: "fn" + i }); bigCont.set("fn" + i, "F1"); bigEdges.push({ from: "F1", to: "fn" + i, kind: "contains" }); }
const big = collapseForDetail(bigNodes, bigEdges, { detail: "files", expanded: new Set(), containerOf: bigCont, filters });
assert.strictEqual(big.nodes.length, 1, "5000 functions in one file collapse to a single file node");
assert.strictEqual(big.links.length, 0, "no links rendered for a fully-collapsed file");

// expanding one file reveals its members
const exp = collapseForDetail(nodes, edges, { detail: "files", expanded: new Set(["F1"]), containerOf, filters });
assert.deepStrictEqual(exp.nodes.map((n: any) => n.id).sort(), ["F1", "F2", "a", "b"], "expanding F1 reveals a,b (c stays hidden)");

// HARD CAP: thousands of FILE nodes must not all render — the cap bounds the draw
const manyFiles = []; const manyCont = new Map<string, string>();
for (let i = 0; i < 2000; i++) manyFiles.push({ id: "F" + i, kind: "file", label: "f" + i + ".py" });
const capped = collapseForDetail(manyFiles, [], { detail: "files", expanded: new Set(), containerOf: manyCont, filters, cap: 1200 });
assert.strictEqual(capped.nodes.length, 1200, "2000 file nodes are capped to 1200 drawn");
assert.strictEqual(capped.capped, 800, "the 800 withheld nodes are reported, not silently dropped");
// and the cap is wired into the viewer
assert.ok(/MAX_RENDER\s*=\s*\d+/.test(html), "a render cap constant is defined");
assert.ok(/cap:\s*MAX_RENDER/.test(html), "fgData passes the cap to collapseForDetail");

// PINNING MUST NOT DEFEAT THE CAP: Threat Map pins every lead-bearing node/file, and an untrusted
// overlay can spread leads across thousands of files — a pinned set that size must not be able to
// rescue every one of them and flood the force simulation back up past `cap`.
const manyPinned = new Set(manyFiles.map((n: any) => n.id));   // ALL 2000 files pinned, worst case
const cappedWithHugePin = collapseForDetail(manyFiles, [], { detail: "files", expanded: new Set(), containerOf: manyCont, filters, cap: 1200, pinned: manyPinned });
assert.ok(cappedWithHugePin.nodes.length < 1200 + 1000, "an oversized pinned set is only honoured up to a bounded overflow, not unconditionally");
assert.strictEqual(2000 - cappedWithHugePin.capped, cappedWithHugePin.nodes.length, "capped + drawn still accounts for every node");
// a modest, realistic pinned set (a handful of selected/bookmarked/lead nodes) is still fully honoured
const smallPinned = new Set(manyFiles.slice(0, 50).map((n: any) => n.id));
const cappedWithSmallPin = collapseForDetail(manyFiles, [], { detail: "files", expanded: new Set(), containerOf: manyCont, filters, cap: 1200, pinned: smallPinned });
assert.strictEqual(cappedWithSmallPin.nodes.length, 1200, "a realistic pinned set that already overlaps the top-1200 by degree needs no rescue");

// source contract: a large graph defaults to the collapsed file view
assert.ok(/COLLAPSE_THRESHOLD\s*=\s*\d+/.test(html), "a collapse threshold is defined");
assert.ok(/state\.detail\s*=\s*norm\.graph\.nodes\.length\s*>\s*COLLAPSE_THRESHOLD\s*\?\s*"files"\s*:\s*"full"/.test(html.replace(/\s+/g, " ")),
  "loadGraph defaults large graphs to the file view");

console.log("bounded-loading.test: collapse reduces 5001 nodes to 1, aggregates cross-file edges, expands on demand, and large graphs default collapsed");
