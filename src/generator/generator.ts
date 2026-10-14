/**
 * Code Atlas — course generator (v1).
 *
 * Input:  an AtlasGraph (from the graph builder) + the real source of each file.
 * Output: a conforming AtlasBundle whose course layer carries GROUNDED Break & Fix
 *         exercises — each a reversible mutation of real code, never invented.
 *
 * v1 defect kinds: removed_guard, broken_call_edge. The structure takes more.
 */

import { createHash } from "node:crypto";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import type { AtlasGraph, AtlasBundle, Course, Lesson, BreakAndFix, Check, Finding, AsiSnapshot } from "../schema.js";
import { parseBundle } from "../schema.js";
import { redactSecrets } from "../scanner/redact.js";

const traverse: any =
  (typeof _traverse === "function" ? _traverse : (_traverse as any).default);

export interface SourceFile { path: string; code: string; }
export interface GenOptions {
  product: string;
  repoLabel: string;
  defectKinds?: Array<"removed_guard" | "broken_call_edge">;
  maxLessons?: number;
}

const sha256 = (s: string) => "sha256:" + createHash("sha256").update(s).digest("hex");

function parseTs(code: string) {
  return parse(code, { sourceType: "unambiguous", plugins: ["typescript", "jsx", "decorators-legacy"], ranges: true });
}

/** All named function-ish declarations in a file, with their char offsets. */
interface FnSite { name: string; start: number; end: number; node: any; }
function functionsIn(code: string): FnSite[] {
  const out: FnSite[] = [];
  const ast = parseTs(code);
  traverse(ast, {
    FunctionDeclaration(p: any) { if (p.node.id) out.push({ name: p.node.id.name, start: p.node.start, end: p.node.end, node: p.node }); },
    VariableDeclarator(p: any) {
      if (p.node.id?.type === "Identifier" &&
          (p.node.init?.type === "ArrowFunctionExpression" || p.node.init?.type === "FunctionExpression"))
        out.push({ name: p.node.id.name, start: p.node.start, end: p.node.end, node: p.node.init });
    },
  });
  return out;
}

/* ---- defect 1: removed_guard --------------------------------------------- *
 * Find the first top-level `if (test) { return/throw/... }` guard inside a
 * function that has code AFTER it (so removing it is a real behaviour change,
 * and the body is not just the guard). The break removes the guard; the fix is
 * the untouched function. */
function detectRemovedGuard(fn: FnSite, code: string): BreakAndFix | null {
  const body = fn.node.body;
  if (!body || body.type !== "BlockStatement") return null;
  const stmts = body.body;
  for (let i = 0; i < stmts.length - 1; i++) {        // -1: must be code after it
    const s = stmts[i];
    if (s.type !== "IfStatement" || s.alternate) continue;
    const cons = s.consequent;
    const guards = cons.type === "BlockStatement" ? cons.body : [cons];
    const isGuard = guards.length >= 1 && guards.every((g: any) =>
      g.type === "ReturnStatement" || g.type === "ThrowStatement" || g.type === "ContinueStatement");
    if (!isGuard) continue;

    const solution = code.slice(fn.start, fn.end);
    const guardText = code.slice(s.start, s.end);
    // Remove the guard statement (unique within the function) plus a trailing newline.
    const broken = solution.replace(guardText, "").replace(/\n[ \t]*\n/, "\n");
    if (broken === solution) return null;
    const condText = code.slice(s.test.start, s.test.end).replace(/\s+/g, " ").trim();
    const checks: Check[] = [
      { kind: "includes", value: "if (" + condText.slice(0, 40), message: "Restore the `if (" + condText + ")` guard." },
      { kind: "includes", value: guards[0].type === "ThrowStatement" ? "throw" : "return",
        message: "The guard must " + (guards[0].type === "ThrowStatement" ? "throw" : "return") + " when the condition holds." },
    ];
    return {
      nodeRef: "",                                     // filled by caller
      file: fn.name === "" ? "" : "",                  // filled by caller
      defectKind: "removed_guard",
      task: "This version of `" + fn.name + "` is missing a guard clause, so bad input flows straight through. Restore the guard that checks `" + condText + "` and " + (guards[0].type === "ThrowStatement" ? "throws" : "returns") + " early.",
      broken, solution, checks,
      provenance: { revision: "", contentHash: sha256(solution), derivedFrom: "guard", method: "atlas-graph" },
    } as BreakAndFix;
  }
  return null;
}

/* ---- defect 2: broken_call_edge ------------------------------------------ *
 * Given a real `calls` edge, find the call to the callee in the caller's source
 * and rename it so the edge disappears. The fix restores the real call. */
function detectBrokenCallEdge(caller: FnSite, code: string, calleeName: string): BreakAndFix | null {
  const solution = code.slice(caller.start, caller.end);
  const callPattern = calleeName + "(";
  if (!solution.includes(callPattern)) return null;
  const broken = solution.replace(callPattern, calleeName + "__removed(");
  if (broken === solution) return null;
  const checks: Check[] = [
    { kind: "includes", value: callPattern, message: "Call `" + calleeName + "(...)` — the real function." },
    { kind: "excludes", value: calleeName + "__removed(", message: "Remove the bogus `" + calleeName + "__removed` call." },
  ];
  return {
    nodeRef: "",
    file: "",
    defectKind: "broken_call_edge",
    task: "`" + caller.name + "` is supposed to call `" + calleeName + "`, but the call has been renamed to a function that does not exist. Restore the real call to `" + calleeName + "`.",
    broken, solution, checks,
    provenance: { revision: "", contentHash: sha256(solution), derivedFrom: "edge", method: "atlas-graph" },
  } as BreakAndFix;
}

/** Plain-language teach line, grounded in the node's real neighbours. */
function teachFor(nodeId: string, graph: AtlasGraph): string {
  const n = graph.nodes.find((x) => x.id === nodeId)!;
  const callers = graph.edges.filter((e) => e.kind === "calls" && e.to === nodeId).length;
  const callees = graph.edges.filter((e) => e.kind === "calls" && e.from === nodeId).length;
  let s = "`" + n.label + "` is a " + n.kind + " in " + n.evidence.path + ".";
  if (callers || callees) s += " It is called by " + callers + " place" + (callers === 1 ? "" : "s") + " and calls " + callees + " other function" + (callees === 1 ? "" : "s") + ".";
  return s;
}

export function generateCourse(graph: AtlasGraph, sources: SourceFile[], opts: GenOptions): Course {
  const wanted = new Set(opts.defectKinds ?? ["removed_guard", "broken_call_edge"]);
  const srcByPath = new Map(sources.map((s) => [s.path, s.code]));
  const funcNodes = graph.nodes.filter((n) => n.kind === "function");
  const lessons: Lesson[] = [];
  const max = opts.maxLessons ?? 8;

  // removed_guard: scan each function node's own source
  if (wanted.has("removed_guard")) {
    for (const node of funcNodes) {
      if (lessons.length >= max) break;
      const code = srcByPath.get(node.evidence.path);
      if (!code) continue;
      const fn = functionsIn(code).find((f) => f.name === node.label);
      if (!fn) continue;
      const bf = detectRemovedGuard(fn, code);
      if (!bf) continue;
      // A lesson embeds the REAL function (broken + solution) in the bundle/viewer.
      // If that source carries a secret, skip it — redacting the snippet would break
      // the exercise's grounding, so a secret-bearing function gets no lesson.
      if (redactSecrets(bf.solution).redactions > 0) continue;
      bf.nodeRef = node.id; bf.file = node.evidence.path; bf.provenance.revision = node.evidence.revision;
      lessons.push({
        id: "l_guard_" + node.id, moduleId: "mod-01", title: "Restore the guard in " + node.label,
        nodeRefs: [node.id], teach: teachFor(node.id, graph), concepts: ["validation", "fail-closed"], breakAndFix: bf,
      });
    }
  }

  // broken_call_edge: one per real calls edge whose caller+callee are known functions
  if (wanted.has("broken_call_edge")) {
    for (const edge of graph.edges) {
      if (lessons.length >= max || edge.kind !== "calls") continue;
      const caller = graph.nodes.find((n) => n.id === edge.from && n.kind === "function");
      const callee = graph.nodes.find((n) => n.id === edge.to && n.kind === "function");
      if (!caller || !callee) continue;
      const code = srcByPath.get(caller.evidence.path);
      if (!code) continue;
      const fn = functionsIn(code).find((f) => f.name === caller.label);
      if (!fn) continue;
      const bf = detectBrokenCallEdge(fn, code, callee.label);
      if (!bf) continue;
      if (redactSecrets(bf.solution).redactions > 0) continue; // never serialize a lesson built from secret-bearing source
      bf.nodeRef = caller.id; bf.file = caller.evidence.path; bf.provenance.revision = caller.evidence.revision;
      lessons.push({
        id: "l_call_" + edge.id.replace(/[^a-z0-9]/gi, "_"), moduleId: "mod-01",
        title: caller.label + " → " + callee.label, nodeRefs: [caller.id, callee.id],
        teach: teachFor(caller.id, graph), concepts: ["call graph"], breakAndFix: bf,
      });
    }
  }

  return {
    title: opts.repoLabel + " — learn by fixing",
    summary: "Grounded Break & Fix exercises generated from the real call graph.",
    modules: [{ id: "mod-01", title: "Core logic", summary: "Fix real defects in real functions.",
      lessonIds: lessons.map((l) => l.id), nodeRefs: [...new Set(lessons.flatMap((l) => l.nodeRefs))] }],
    lessons,
  };
}

export interface SecurityLayer { findings?: Finding[]; asiSnapshot?: AsiSnapshot; }

export function assembleBundle(graph: AtlasGraph, course: Course, opts: GenOptions, security?: SecurityLayer, sources?: SourceFile[]): AtlasBundle {
  const bundle: AtlasBundle = {
    schemaVersion: "1.0",
    product: { name: opts.product },
    repository: { label: opts.repoLabel, revision: graph.revision },
    generatedAt: new Date().toISOString(),
    graph, course, diagnostics: [],
    ...(security?.findings && security.findings.length ? { findings: security.findings } : {}),
    ...(security?.asiSnapshot ? { asiSnapshot: security.asiSnapshot } : {}),
    ...(sources && sources.length ? { sources } : {}),
    integrity: { graphHash: sha256(JSON.stringify(graph)), bundleHash: "" },
  };
  bundle.integrity!.bundleHash = sha256(JSON.stringify({ ...bundle, integrity: undefined }));
  return parseBundle(bundle);   // self-validate against the locked contract
}

/** A learner answer is bounded, and a check pattern is a short literal. Cap both
 *  so a hostile `regex` check (from an externally-authored bundle/rule pack)
 *  cannot drive catastrophic backtracking. Patterns with the classic nested-
 *  quantifier ReDoS shape — e.g. `(a+)+` — are refused outright (fail-closed). */
const MAX_CHECK_INPUT = 20_000;
const NESTED_QUANTIFIER = /\([^()]*[+*][^()]*\)[+*]/;
export function safeRegex(value: string): RegExp | null {
  if (value.length > 1000) return null;
  if (NESTED_QUANTIFIER.test(value)) return null;
  try { return new RegExp(value); } catch { return null; }
}

/** Shared check runner (same semantics as the viewer). The input cap applies
 *  ONLY to regex evaluation (the backtracking surface). includes/excludes run
 *  over the full answer so a required/forbidden token past the cap is not missed. */
export function runChecks(code: string, checks: Check[]): string[] {
  const fails: string[] = [];
  for (const c of checks) {
    let ok = true;
    if (c.kind === "includes") ok = code.includes(c.value);
    else if (c.kind === "excludes") ok = !code.includes(c.value);
    else if (c.kind === "regex") {
      const re = safeRegex(c.value);
      const bounded = code.length > MAX_CHECK_INPUT ? code.slice(0, MAX_CHECK_INPUT) : code;
      ok = re ? re.test(bounded) : false;
    }
    else if (c.kind === "structure") ok = true; // delegated to Block-Wise conformance in full build
    if (!ok) fails.push(c.message);
  }
  return fails;
}
