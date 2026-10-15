/**
 * Native findings scanner + external-report adapter.
 *
 *  scan(graph, sources, rules)  — runs the rule pack over the graph's functions,
 *      maps each hit to a real node, grades it (STATIC/INFERRED only), and draws
 *      blast radius from the REAL call graph. Produces schema Findings + the ASI
 *      snapshot referenced by those findings.
 *
 *  ingestReport(report, graph) — adapter that maps an EXTERNAL evidence report
 *      (e.g. vibe-explainer's JSON) onto graph nodes. The report supplies the
 *      finding + its ASI ref + a confidence; the grade is taken from that
 *      confidence and NEVER upgraded. Blast radius still comes from our graph.
 */
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import type { AtlasGraph, Finding, AsiSnapshot } from "../schema.js";
import { DEFAULT_RULES, type Rule } from "./rules.js";
import { ASI_BASE, CATEGORY_TO_AAC, asiRefFor, asiClassFor } from "./asi.js";
import type { SourceFile } from "./graph.js";

const traverse: any = (typeof _traverse === "function" ? _traverse : (_traverse as any).default);

/** name -> source slice, for the functions in one file. */
function functionSources(code: string): Map<string, string> {
  const out = new Map<string, string>();
  let ast;
  try { ast = parse(code, { sourceType: "unambiguous", plugins: ["typescript", "jsx", "decorators-legacy"], ranges: true }); }
  catch { return out; }
  const add = (name: string, start: number, end: number) => { if (!out.has(name)) out.set(name, code.slice(start, end)); };
  traverse(ast, {
    FunctionDeclaration(p: any) { if (p.node.id) add(p.node.id.name, p.node.start, p.node.end); },
    VariableDeclarator(p: any) {
      if (p.node.id?.type === "Identifier" && (p.node.init?.type === "ArrowFunctionExpression" || p.node.init?.type === "FunctionExpression"))
        add(p.node.id.name, p.node.start, p.node.end);
    },
  });
  return out;
}

// freeOnly: match a FREE/imported call `name(` but not a method call `x.name(`.
const callsName = (src: string, name: string, freeOnly = false) =>
  new RegExp((freeOnly ? "(?<!\\.)" : "") + "\\b" + name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\s*\\(").test(src);

/** A blast radius is drawn only for a VERIFIED finding. A static/inferred lead
 *  propagates nothing: painting neighbours "possibly affected" from an unverified
 *  pattern match is itself a fabrication, which the grounding invariant forbids. */
const castsBlast = (g: string) => g === "OBSERVED" || g === "TESTED";

function matches(when: Rule["when"], fnName: string, src: string, kind: Rule["kind"]): boolean {
  // A WEAKNESS rule's positive calls are SINKS: match free/imported calls only, so a
  // method like `re.exec(...)` / `arr.query(...)` can't masquerade as a sink. A CONTROL
  // rule's positive calls are VALIDATORS, which are usually methods (`schema.parse(...)`,
  // `z.safeParse(...)`), so those must still match method calls.
  const freeOnly = kind === "weakness";
  if (when.nameMatches && !new RegExp(when.nameMatches, "i").test(fnName)) return false;
  if (when.callsAny && !when.callsAny.some((n) => callsName(src, n, freeOnly))) return false;
  if (when.callsNoneOf && when.callsNoneOf.some((n) => callsName(src, n))) return false;        // guards: any call form
  if (when.guardText && when.guardText.some((t) => src.includes(t))) return false;              // keyword-arg guards
  // a rule with only callsNoneOf would match everything — require at least one positive signal
  if (!when.nameMatches && !when.callsAny) return false;
  return true;
}

/** Does a tree-sitter-captured qualified call token match a rule token?
 *  - a QUALIFIED rule token (`os.system`, `Marshal.load`) matches the same token
 *    or a deeper-receiver form ending in `.os.system`, but NOT an unrelated
 *    `foo.run` for `subprocess.run` — precision is kept.
 *  - a BARE rule token (`eval`, `system`) matches by LAST SEGMENT, so it matches
 *    both `eval` and `Kernel.system`. */
function callTokenMatches(callToken: string, ruleToken: string): boolean {
  if (ruleToken.includes(".")) return callToken === ruleToken || callToken.endsWith("." + ruleToken);
  return (callToken.split(".").pop() || callToken) === ruleToken;
}
const anyCall = (tokens: string[], ruleTokens: string[]) =>
  ruleTokens.some((rt) => tokens.some((ct) => callTokenMatches(ct, rt)));

/** Non-JS matcher: SINKS/validators are matched against REAL parsed call tokens
 *  (no regex over source — so comments/strings never match and paren-less calls
 *  do). `guardText` still checks the body text, but it only ever SUPPRESSES a
 *  finding (e.g. an explicit `SafeLoader=`), so a lenient check is conservative. */
function matchesGeneric(when: Rule["when"], fnName: string, callTokens: string[], bodySrc: string): boolean {
  if (when.nameMatches && !new RegExp(when.nameMatches, "i").test(fnName)) return false;
  if (when.callsAny && !anyCall(callTokens, when.callsAny)) return false;
  if (when.callsNoneOf && anyCall(callTokens, when.callsNoneOf)) return false;                  // guard CALLS
  if (when.guardText && when.guardText.some((t) => bodySrc.includes(t))) return false;          // keyword-arg guards
  if (!when.nameMatches && !when.callsAny) return false;
  return true;
}

/** Core rule evaluation shared by both backends. `srcForNode` returns the real
 *  source slice of a function node's body (Babel-sliced for JS/TS; tree-sitter-
 *  sliced for Python/Ruby), or undefined when no slice is available. Everything
 *  else — grounding, grade-gated blast radius, ASI linking — is identical, so a
 *  non-JS finding carries exactly the same honesty rails as a JS one. */
function evalRules(
  graph: AtlasGraph,
  fnNodes: AtlasGraph["nodes"],
  rules: Rule[],
  matchNode: (node: AtlasGraph["nodes"][number], rule: Rule) => boolean,
): { findings: Finding[]; usedClasses: Map<string, { id: string; label: string; mitigation: string; url: string }> } {
  const callersOf = (nodeId: string) =>
    graph.edges.filter((e) => e.kind === "calls" && e.to === nodeId).map((e) => e.from);
  const findings: Finding[] = [];
  const usedClasses = new Map<string, { id: string; label: string; mitigation: string; url: string }>();

  for (const node of fnNodes) {
    for (const rule of rules) {
      if (!matchNode(node, rule)) continue;
      const blast = (rule.kind === "weakness" && rule.blast === "callers" && castsBlast(rule.grade)) ? callersOf(node.id) : [];
      const f: Finding = {
        id: rule.id + ":" + node.id,
        nodeRefs: [node.id],
        kind: rule.kind,
        title: rule.title,
        explanation: rule.explanation,
        grade: rule.grade,
        evidence: [{ source: "code-atlas/rule:" + rule.id, detail: "structural match in " + node.evidence.path }],
        blastRadius: blast,
      };
      if (rule.asi) { f.asiRef = { id: rule.asi.id, url: rule.asi.url, label: rule.asi.label, asOf: today() }; usedClasses.set(rule.asi.id, rule.asi); }
      findings.push(f);
    }
  }
  return { findings, usedClasses };
}

function asiSnapshotFrom(usedClasses: Map<string, { id: string; label: string; mitigation: string; url: string }>): AsiSnapshot | undefined {
  return usedClasses.size
    ? { source: "Agent Security Index (bridge)", revision: "draft-local", asOf: today(),
        baseUrl: "https://index.aletheia-core.com", classes: [...usedClasses.values()] }
    : undefined;
}

/** Native scan over the JS/TS slice (Babel-sliced function bodies). */
export function scan(graph: AtlasGraph, sources: SourceFile[], rules: Rule[] = DEFAULT_RULES):
  { findings: Finding[]; asiSnapshot?: AsiSnapshot } {
  const srcByPath = new Map(sources.map((s) => [s.path, s.code]));
  const fnSrcCache = new Map<string, Map<string, string>>();
  const fnSrc = (path: string) => {
    if (!fnSrcCache.has(path)) fnSrcCache.set(path, functionSources(srcByPath.get(path) ?? ""));
    return fnSrcCache.get(path)!;
  };
  const fnNodes = graph.nodes.filter((n) => n.kind === "function");
  const { findings, usedClasses } = evalRules(graph, fnNodes, rules, (node, rule) => {
    const src = fnSrc(node.evidence.path).get(node.label);
    return src ? matches(rule.when, node.label, src, rule.kind) : false;
  });
  return { findings, asiSnapshot: asiSnapshotFrom(usedClasses) };
}

/** Native scan over a non-JS (tree-sitter) slice. Sinks/validators are matched
 *  against REAL parsed call tokens (`functionCalls`), not regex over source, so
 *  paren-less calls are covered and comments/strings never match. `functionSrc`
 *  (the body text) is used only for name-based rules and `guardText` suppression.
 *  Only function nodes with a body slice are scanned; same grounding + grade rules. */
export function scanGeneric(
  graph: AtlasGraph,
  functionSrc: Map<string, string>,
  functionCalls: Map<string, string[]>,
  rules: Rule[],
): { findings: Finding[]; asiSnapshot?: AsiSnapshot } {
  const ids = new Set(functionSrc.keys());
  const fnNodes = graph.nodes.filter((n) => n.kind === "function" && ids.has(n.id));
  const { findings, usedClasses } = evalRules(graph, fnNodes, rules, (node, rule) =>
    matchesGeneric(rule.when, node.label, functionCalls.get(node.id) ?? [], functionSrc.get(node.id) ?? ""));
  return { findings, asiSnapshot: asiSnapshotFrom(usedClasses) };
}

function today() { return new Date().toISOString().slice(0, 10); }

/* ---- adapter for an external evidence report (e.g. vibe-explainer JSON) ---- *
 * Documented shape the adapter accepts. The grade comes from the report's own
 * confidence and is never upgraded; nodes are matched by file path (+ optional
 * symbol). Unmatched entries are returned as `unmapped` rather than dropped. */
export interface ExternalFinding {
  id: string;
  kind: "weakness" | "control";
  title: string;
  explanation: string;
  grade: "OBSERVED" | "STATIC" | "TESTED" | "INFERRED" | "UNKNOWN";
  file: string;                 // repo-relative path the report points at
  symbol?: string;              // optional function/symbol name
  asiRef?: { id: string; url: string; label: string; asOf: string };
}

/* ---- vibe-explainer adapter ---------------------------------------------- *
 * Maps a real vibe-explainer --json report onto graph nodes. vibe-explainer
 * states its reachability is statically inferred and effectiveness untested, so
 * grades are CAPPED at STATIC/INFERRED here — never OBSERVED/TESTED. Risk
 * scenarios -> weaknesses, present controls -> hardened controls. Nodes are
 * matched by file path; blast radius comes from our call graph. */
function fileNode(graph: AtlasGraph, file: string) {
  // Match on evidence.path (the reliable repo-relative path) as well as label.
  // Babel file nodes label by path, but tree-sitter file nodes label by basename
  // and keep the full path only in evidence.path — matching both maps a report's
  // nested path (pkg/app.py) to the right node regardless of backend.
  return graph.nodes.find((n) => n.kind === "file" &&
    (n.label === file || n.label.endsWith("/" + file) ||
     n.evidence.path === file || n.evidence.path.endsWith("/" + file)));
}
function veGrade(strength: string | undefined): "STATIC" | "INFERRED" {
  return (strength || "").toUpperCase() === "HIGH" ? "STATIC" : "INFERRED";
}

export function ingestVibeExplainer(ve: any, graph: AtlasGraph):
  { findings: Finding[]; asiSnapshot?: AsiSnapshot; unmapped: string[] } {
  const findings: Finding[] = []; const unmapped: string[] = [];
  const usedClasses = new Set<string>();
  const callersOf = (id: string) => graph.edges.filter((e) => e.kind === "calls" && e.to === id).map((e) => e.from);

  // finding id -> file, from the AI inventory + attack surface buckets
  const fileOf = new Map<string, string>();
  const collect = (bucket: any) => {
    if (!bucket || typeof bucket !== "object") return;
    for (const v of Object.values(bucket)) if (Array.isArray(v))
      for (const it of v) if (it && typeof it === "object" && it.id && it.file) fileOf.set(it.id, it.file);
  };
  collect(ve?.ai_inventory?.categories);
  collect(ve?.attack_surface);

  // weaknesses from risk scenarios
  for (const s of (ve?.risks?.scenarios ?? [])) {
    const files = [...new Set((s.related_finding_ids ?? []).map((id: string) => fileOf.get(id)).filter(Boolean))] as string[];
    const asiId = CATEGORY_TO_AAC[s.category];
    if (asiId) usedClasses.add(asiId);
    const grade = veGrade(s.evidence_strength);
    const explanation = [s.rationale, ...(s.unresolved_assumptions ?? [])].filter(Boolean).join(" ");
    let mappedAny = false;
    for (const f of files) {
      const node = fileNode(graph, f);
      if (!node) continue;
      mappedAny = true;
      findings.push({
        id: s.risk_id + ":" + node.id, nodeRefs: [node.id], kind: "weakness",
        title: s.title, explanation, grade,
        evidence: [{ source: "vibe-explainer", detail: s.risk_id + " (" + (s.reachability_status || "static") + ")" }],
        blastRadius: castsBlast(grade) ? callersOf(node.id) : [],
        ...(asiId && asiRefFor(asiId, today()) ? { asiRef: asiRefFor(asiId, today())! } : {}),
      });
    }
    if (!mappedAny) unmapped.push(s.risk_id);
  }

  // present controls -> hardened (green)
  const present = [...(ve?.controls?.by_status?.EVIDENCE_FOUND ?? []), ...(ve?.controls?.by_status?.PARTIAL ?? [])];
  for (const c of present) {
    const files = new Set<string>();
    for (const id of (c.related_finding_ids ?? [])) { const f = fileOf.get(id); if (f) files.add(f); }
    for (const e of (c.evidence ?? [])) {
      const m = /([\w./-]+\.(?:ts|tsx|js|jsx)):\d+/.exec(e?.description ?? "");
      if (m) files.add(m[1]);
    }
    for (const f of files) {
      const node = fileNode(graph, f);
      if (!node) continue;
      findings.push({
        id: c.control_id + ":" + node.id, nodeRefs: [node.id], kind: "control",
        title: c.name + " present", grade: "STATIC",
        explanation: (c.rationale || "A control artifact is present.") + " Present does not mean effective; a reviewer must confirm it guards the relevant surface.",
        evidence: [{ source: "vibe-explainer", detail: c.control_id + " / " + (c.artifact_status || "found") }],
        blastRadius: [],
      });
    }
  }

  const asiSnapshot: AsiSnapshot | undefined = usedClasses.size
    ? { source: "Agent Security Index (vibe-explainer bridge)", revision: "draft-local", asOf: today(),
        baseUrl: ASI_BASE, classes: [...usedClasses].map((id) => asiClassFor(id)!).filter(Boolean) }
    : undefined;
  return { findings, asiSnapshot, unmapped };
}

/** An external report's grade is a CLAIM, not our verification. Runtime grades
 *  (OBSERVED/TESTED) require evidence we did not produce, so cap them to INFERRED. */
function capExternalGrade(g: ExternalFinding["grade"]): Finding["grade"] {
  return (g === "OBSERVED" || g === "TESTED") ? "INFERRED" : g;
}
/** Only http(s) ASI links are kept; a `javascript:`/`data:` url is dropped so it
 *  can never reach an href sink in the viewer (defense in depth with the viewer). */
function isHttpUrl(u: string | undefined): boolean {
  if (!u) return false;
  try { const p = new URL(u); return p.protocol === "http:" || p.protocol === "https:"; } catch { return false; }
}

export function ingestReport(report: ExternalFinding[], graph: AtlasGraph):
  { findings: Finding[]; unmapped: ExternalFinding[] } {
  const findings: Finding[] = []; const unmapped: ExternalFinding[] = [];
  const callersOf = (nodeId: string) => graph.edges.filter((e) => e.kind === "calls" && e.to === nodeId).map((e) => e.from);
  for (const r of report) {
    // prefer a function node matching file+symbol, else the file node
    let node = r.symbol
      ? graph.nodes.find((n) => n.kind === "function" && n.label === r.symbol && n.evidence.path === r.file)
      : undefined;
    if (!node) node = graph.nodes.find((n) => n.kind === "file" && n.label === r.file);
    if (!node) { unmapped.push(r); continue; }
    const grade = capExternalGrade(r.grade);
    findings.push({
      id: r.id, nodeRefs: [node.id], kind: r.kind, title: r.title, explanation: r.explanation,
      grade,                                            // external claim, capped — never OBSERVED/TESTED
      evidence: [{ source: "external-report", detail: "mapped from " + r.file + (r.symbol ? "#" + r.symbol : "") + (grade !== r.grade ? ` (claimed ${r.grade}, capped to ${grade})` : "") }],
      blastRadius: (r.kind === "weakness" && castsBlast(grade)) ? callersOf(node.id) : [],
      ...(isHttpUrl(r.asiRef?.url) ? { asiRef: r.asiRef } : {}),
    });
  }
  return { findings, unmapped };
}
