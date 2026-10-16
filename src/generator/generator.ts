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
  /** function node id -> real body source for NON-JS (tree-sitter) functions.
   *  When present, the generator also emits language-agnostic broken_call_edge
   *  lessons for those functions — same grounding as the Babel path, no AST. */
  genericBodies?: Map<string, string>;
  /** function node id -> qualified callee tokens PARSED from its body (real call
   *  nodes). A generic lesson's callee must appear here, so a function name that
   *  only shows up in a string/comment never produces a (false) lesson. */
  genericCalls?: Map<string, string[]>;
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
 * and rename it so the edge disappears. The fix restores the real call.
 *
 * This defect is LANGUAGE-AGNOSTIC: it needs only the caller's function-body
 * source and the callee's name — no AST. The Babel path passes a Babel-sliced
 * body; the tree-sitter path passes a tree-sitter-sliced body (same contract). */
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
/** A real call site `name(` with a word boundary before the name, so `run(` does
 *  NOT match inside `prerun(`. Global: a broken variant removes EVERY call site,
 *  so the `includes` check reliably fails on the broken answer. */
const callSiteRe = (name: string) => new RegExp("(?<![\\w.$])" + escapeRe(name) + "\\(", "g");

function makeBrokenCallEdge(callerName: string, body: string, calleeName: string): BreakAndFix | null {
  const solution = body;
  const callPattern = calleeName + "(";
  const m = callSiteRe(calleeName).exec(solution);
  if (!m) return null;                                  // no real (boundary-delimited) call site → not groundable
  const broken = solution.replace(callSiteRe(calleeName), calleeName + "__removed(");
  if (broken === solution) return null;
  // Grade with the SAME call-site boundary the mutation used: include the char
  // that precedes the real call (a space/newline/`(`), so the `includes` check
  // can't be satisfied by a longer identifier that merely ends in the callee
  // name (e.g. `prerun(` passing a bare `run(` check). Empty lead => call is at
  // the body start, where no such ambiguity exists.
  const lead = m.index > 0 ? body[m.index - 1] : "";
  const includeVal = lead + callPattern;
  const checks: Check[] = [
    { kind: "includes", value: includeVal, message: "Call `" + calleeName + "(...)` — the real function." },
    { kind: "excludes", value: calleeName + "__removed(", message: "Remove the bogus `" + calleeName + "__removed` call." },
  ];
  return {
    nodeRef: "",
    file: "",
    defectKind: "broken_call_edge",
    task: "`" + callerName + "` is supposed to call `" + calleeName + "`, but the call has been renamed to a function that does not exist. Restore the real call to `" + calleeName + "`.",
    broken, solution, checks,
    provenance: { revision: "", contentHash: sha256(solution), derivedFrom: "edge", method: "atlas-graph" },
  } as BreakAndFix;
}

function detectBrokenCallEdge(caller: FnSite, code: string, calleeName: string): BreakAndFix | null {
  return makeBrokenCallEdge(caller.name, code.slice(caller.start, caller.end), calleeName);
}

/** Plain-language teach line, grounded in the node's real neighbours. */
function teachFor(nodeId: string, graph: AtlasGraph): string {
  const n = graph.nodes.find((x) => x.id === nodeId)!;
  const touching = graph.edges.filter((e) => e.kind === "calls" && (e.to === nodeId || e.from === nodeId));
  const callers = touching.filter((e) => e.to === nodeId).length;
  const callees = touching.filter((e) => e.from === nodeId).length;
  const inferred = touching.filter((e) => e.confidence === "inferred").length;
  let s = "`" + n.label + "` is a " + n.kind + " in " + n.evidence.path + ".";
  if (callers || callees) s += " It is called by " + callers + " place" + (callers === 1 ? "" : "s") + " and calls " + callees + " other function" + (callees === 1 ? "" : "s") + ".";
  // Name-inferred calls (Python/Ruby) are counted, but never stated as proven.
  if (inferred) s += inferred === touching.length
    ? " These calls are matched by name only, not proven."
    : " " + inferred + " of these calls are matched by name only, not proven.";
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

  // broken_call_edge for NON-JS functions, from tree-sitter body slices (no AST).
  // A lesson's callee must be (a) PARSED as a real call in the caller's body
  // (genericCalls — so a name in a string/comment never qualifies) AND (b) present
  // as a literal `callee(` call site so the text can be mutated. We do not rely on
  // the calls edge's origin, which some tree-sitter backends attribute to the file.
  // Same grounding as the Babel path: solution is the real body, the break renames
  // a real callee, checks fail on broken / pass on solution.
  if (wanted.has("broken_call_edge") && opts.genericBodies && opts.genericBodies.size) {
    const fnById = new Map(funcNodes.map((n) => [n.id, n]));
    const calleeNames = [...new Set(funcNodes.map((n) => n.label))];
    const lastSeg = (t: string) => t.split(".").pop() || t;
    for (const [callerId, body] of opts.genericBodies) {
      if (lessons.length >= max) break;
      const caller = fnById.get(callerId);
      if (!caller) continue;
      // parsed call tokens for this caller (last segment = bare callee name)
      const parsed = new Set((opts.genericCalls?.get(callerId) ?? []).map(lastSeg));
      // a known function (not the caller itself) that is BOTH really called (parsed)
      // and present as a literal `callee(` site we can mutate.
      const calleeName = calleeNames.find((lbl) => lbl !== caller.label && parsed.has(lbl) && callSiteRe(lbl).test(body));
      if (!calleeName) continue;
      // Resolve the callee NODE within the caller's own file; only fall back to a
      // repo-wide match when it is unambiguous. Otherwise attach just the caller,
      // so we never teach a cross-file/cross-language edge that does not exist.
      const all = funcNodes.filter((n) => n.label === calleeName);
      const callee = all.find((n) => n.evidence.path === caller.evidence.path) ?? (all.length === 1 ? all[0] : undefined);
      const bf = makeBrokenCallEdge(caller.label, body, calleeName);
      if (!bf) continue;
      if (redactSecrets(bf.solution).redactions > 0) continue;  // never serialize a lesson built from secret-bearing source
      bf.nodeRef = caller.id; bf.file = caller.evidence.path; bf.provenance.revision = caller.evidence.revision;
      const id = "l_callg_" + callerId.replace(/[^a-z0-9]/gi, "_");
      if (lessons.some((l) => l.id === id)) continue;           // dedup
      lessons.push({
        id, moduleId: "mod-01", title: caller.label + " → " + calleeName,
        nodeRefs: callee ? [caller.id, callee.id] : [caller.id],
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

export function assembleBundle(graph: AtlasGraph, course: Course, opts: GenOptions, security?: SecurityLayer, sources?: SourceFile[], coverage?: AtlasBundle["coverage"]): AtlasBundle {
  const bundle: AtlasBundle = {
    schemaVersion: "1.0",
    product: { name: opts.product },
    repository: { label: opts.repoLabel, revision: graph.revision },
    generatedAt: new Date().toISOString(),
    graph, course, diagnostics: [],
    ...(security?.findings && security.findings.length ? { findings: security.findings } : {}),
    ...(security?.asiSnapshot ? { asiSnapshot: security.asiSnapshot } : {}),
    ...(sources && sources.length ? { sources } : {}),
    ...(coverage ? { coverage } : {}),
    integrity: { graphHash: sha256(JSON.stringify(graph)), bundleHash: "" },
  };
  bundle.integrity!.bundleHash = sha256(JSON.stringify({ ...bundle, integrity: undefined }));
  return parseBundle(bundle);   // self-validate against the locked contract
}

/** Shared check runner (same semantics as the viewer).
 *
 *  `regex` checks are NOT executed. Running a caller-supplied pattern on a
 *  learner answer is an unbounded backtracking (ReDoS) surface, and there is no
 *  safe way to bound it in a standalone HTML page without a non-backtracking
 *  engine — heuristic pattern-shape filters are provably incomplete (e.g.
 *  `(a|aa)+$` is catastrophic yet has no quantified token inside the group).
 *  The generator only ever emits `includes`/`excludes` checks, so disabling the
 *  `regex` kind at runtime costs no generated content and removes the surface
 *  entirely. A regex check reports as unmet with a clear message rather than run.
 *  includes/excludes evaluate over the FULL answer. */
export function runChecks(code: string, checks: Check[]): string[] {
  const fails: string[] = [];
  for (const c of checks) {
    if (c.kind === "regex") { fails.push("Regex checks are disabled in this build for safety."); continue; }
    let ok = true;
    if (c.kind === "includes") ok = code.includes(c.value);
    else if (c.kind === "excludes") ok = !code.includes(c.value);
    else if (c.kind === "structure") ok = true; // delegated to Block-Wise conformance in full build
    if (!ok) fails.push(c.message);
  }
  return fails;
}
