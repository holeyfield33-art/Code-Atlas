/**
 * Code Atlas MCP tool logic (pure, over a loaded bundle).
 *
 * The point, per Horos: let an agent pull the MINIMAL slice it needs instead of
 * loading whole files. Most tools return ids + summaries (cheap); source is
 * fetched only on demand; context_pack does Horos-style budgeted selection with
 * a replayable receipt.
 */
import { createHash } from "node:crypto";
import type { AtlasBundle, AtlasNode } from "../schema.js";
import { castsBlastAfterTriage } from "../triage.js";

const sha = (s: string) => "sha256:" + createHash("sha256").update(s).digest("hex").slice(0, 16);

/** Deterministic hash of ALL state a read tool can surface — not the (optional,
 *  generation-time, and after triage stale) `integrity` field. Receipts (context
 *  pack, atlas_exec) must change whenever any read could change: different sources,
 *  edges, diagnostics, findings, course, or identity fields all move the hash, and
 *  it is recomputed when atlas_triage commits a new bundle. Same bundle => same
 *  hash, so replay still holds. */
export function bundleId(bundle: AtlasBundle): string {
  const visible = {
    product: bundle.product,
    repository: bundle.repository,
    graph: bundle.graph,                 // nodes + edges + diagnostics
    coverage: bundle.coverage ?? null,   // overview() exposes scan coverage
    sources: bundle.sources ?? null,
    findings: bundle.findings ?? null,
    course: bundle.course ?? null,
  };
  return "sha256:" + createHash("sha256").update(JSON.stringify(visible)).digest("hex").slice(0, 16);
}

export class AtlasTools {
  private byId = new Map<string, AtlasNode>();
  private byPath = new Map<string, string>();                 // file path -> code
  private truncatedPaths = new Set<string>();                 // files only partially inlined
  private callers = new Map<string, string[]>();
  private callees = new Map<string, string[]>();
  private importsOut = new Map<string, string[]>();
  private containerOf = new Map<string, string>();
  private findingsByNode = new Map<string, any[]>();
  private lessonByNode = new Map<string, any>();
  private inferredCall = new Set<string>();                    // `${from}->${to}` for name-inferred calls

  private cachedId: string | null = null;
  /** Content identity of the bundle these tools serve (computed once, lazily). */
  get bundleHash(): string { return (this.cachedId ??= bundleId(this.bundle)); }

  constructor(private bundle: AtlasBundle) {
    for (const n of bundle.graph.nodes) this.byId.set(n.id, n);
    for (const s of bundle.sources ?? []) { this.byPath.set(s.path, s.code); if (s.truncated) this.truncatedPaths.add(s.path); }
    for (const e of bundle.graph.edges) {
      if (e.kind === "calls") {
        push(this.callees, e.from, e.to); push(this.callers, e.to, e.from);
        if (e.confidence === "inferred") this.inferredCall.add(e.from + "->" + e.to);
      }
      else if (e.kind === "imports") push(this.importsOut, e.from, e.to);
      else if (e.kind === "contains") this.containerOf.set(e.to, e.from);
    }
    for (const f of bundle.findings ?? []) for (const ref of f.nodeRefs) push(this.findingsByNode, ref, f);
    // Same join as the viewer: the defect's own node first, then every taught node.
    const lessons = bundle.course?.lessons ?? [];
    for (const l of lessons) if (!this.lessonByNode.has(l.breakAndFix.nodeRef)) this.lessonByNode.set(l.breakAndFix.nodeRef, l);
    for (const l of lessons) for (const ref of l.nodeRefs) if (!this.lessonByNode.has(ref)) this.lessonByNode.set(ref, l);
  }

  /** The inlined source window for a node, or why there is none. Never returns
   *  an empty/inverted range as if it were source. */
  private sourceWindow(n: AtlasNode):
    | { available: true; from: number; to: number; source: string; truncated: boolean; fileTruncated: boolean }
    | { available: false; reason: string } {
    const code = this.byPath.get(n.evidence.path);
    if (code === undefined) return { available: false, reason: "source not inlined in this bundle" };
    const lines = code.split("\n");
    const fileTruncated = this.truncatedPaths.has(n.evidence.path);
    const target = n.evidence.line || 1;
    if (target > lines.length) return { available: false,
      reason: fileTruncated
        ? `line ${target} is past the inlined prefix of ${n.evidence.path} (${lines.length} lines inlined; the file was truncated at build time)`
        : `line ${target} is outside the inlined source of ${n.evidence.path} (${lines.length} lines)` };
    const [from, to] = n.kind === "function" ? [Math.max(1, target - 1), Math.min(lines.length, target + 60)] : [1, Math.min(lines.length, 400)];
    return { available: true, from, to, source: lines.slice(from - 1, to).join("\n"), truncated: to < lines.length || fileTruncated, fileTruncated };
  }

  private label = (id: string) => this.byId.get(id)?.label ?? id;
  private brief = (id: string) => { const n = this.byId.get(id); return n ? { id, label: n.label, kind: n.kind, path: n.evidence.path, line: n.evidence.line } : { id }; };
  // A call brief that flags a name-INFERRED edge (from -> to), so an agent never
  // treats a name-based match as a proven call.
  // `show` is the NEIGHBOUR node to describe; `from`->`to` is the directed call
  // edge whose confidence we check. For calls: show=callee, edge id->callee. For
  // calledBy: show=caller, edge caller->id. (Returning brief(to) unconditionally
  // made calledBy describe the selected node instead of its caller.)
  private callBrief = (show: string, from: string, to: string) =>
    this.inferredCall.has(from + "->" + to) ? { ...this.brief(show), inferred: true } : this.brief(show);

  overview() {
    const g = this.bundle.graph;
    const fns = g.nodes.filter((n) => n.kind === "function");
    const files = g.nodes.filter((n) => n.kind === "file");
    const entryPoints = fns.filter((n) => (this.callers.get(n.id)?.length ?? 0) === 0).slice(0, 15).map((n) => this.brief(n.id));
    const findings = this.bundle.findings ?? [];
    return {
      product: this.bundle.product.name, repository: this.bundle.repository,
      counts: { files: files.length, functions: fns.length, edges: g.edges.length, diagnostics: g.diagnostics.length, lessons: this.bundle.course?.lessons.length ?? 0, findings: findings.length },
      findingsByKind: tally(findings.map((f) => f.kind)),
      findingsByGrade: tally(findings.map((f) => f.grade)),
      findingsByDisposition: tally(findings.map((f) => f.disposition?.status ?? "untriaged")),
      coverage: this.bundle.coverage ?? null,   // what the scan omitted, counted by reason (null on older bundles)
      entryPoints,
      note: "Every edge is source-backed; unresolved relationships are diagnostics, never fabricated. `coverage` reports what the scan omitted (unsupported / too large / over the file cap), so absence of a node is not absence from the repo. Use atlas_get_source to read code only when needed.",
    };
  }

  search(query: string, limit = 10) {
    const words = query.toLowerCase().split(/\s+/).filter(Boolean);
    const scored = this.bundle.graph.nodes.map((n) => {
      const hay = (n.label + " " + n.evidence.path).toLowerCase();
      const score = words.reduce((s, w) => s + (hay.includes(w) ? 1 : 0) + (n.label.toLowerCase() === w ? 2 : 0), 0);
      return { n, score };
    }).filter((x) => x.score > 0).sort((a, b) => b.score - a.score).slice(0, limit);
    return { query, results: scored.map((x) => this.brief(x.n.id)) };
  }

  getNode(id: string) {
    const n = this.byId.get(id);
    if (!n) return { error: "unknown node id", id, hint: "use atlas_search to find an id" };
    return {
      ...this.brief(id),
      container: this.containerOf.get(id) ? this.brief(this.containerOf.get(id)!) : null,
      calls: (this.callees.get(id) ?? []).map((x) => this.callBrief(x, id, x)),
      calledBy: (this.callers.get(id) ?? []).map((x) => this.callBrief(x, x, id)),
      imports: (this.importsOut.get(id) ?? []).map((x) => this.brief(x)),
      hasSource: this.sourceWindow(n).available,                 // per node: false past a truncated prefix
      hasThreats: (this.findingsByNode.get(id)?.length ?? 0) > 0,
      hasLesson: this.lessonByNode.has(id),
      evidence: n.evidence,
    };
  }

  getSource(id: string) {
    const n = this.byId.get(id);
    if (!n) return { error: "unknown node id", id };
    const w = this.sourceWindow(n);
    if (!w.available) return { ...this.brief(id), error: "source unavailable", reason: w.reason, path: n.evidence.path };
    return { ...this.brief(id), from: w.from, to: w.to, source: w.source, truncated: w.truncated, ...(w.fileTruncated ? { fileTruncated: true } : {}) };
  }

  neighbors(id: string, kinds?: string[]) {
    const n = this.byId.get(id);
    if (!n) return { error: "unknown node id", id };
    const want = (k: string) => !kinds || kinds.includes(k);
    return {
      ...this.brief(id),
      ...(want("calls") ? { calls: (this.callees.get(id) ?? []).map((x) => this.callBrief(x, id, x)) } : {}),
      ...(want("calledBy") ? { calledBy: (this.callers.get(id) ?? []).map((x) => this.callBrief(x, x, id)) } : {}),
      ...(want("imports") ? { imports: (this.importsOut.get(id) ?? []).map((x) => this.brief(x)) } : {}),
    };
  }

  threats(ref: string) {
    // ref is a node id or a file path
    const ids = this.byId.has(ref) ? [ref]
      : this.bundle.graph.nodes.filter((n) => n.evidence.path === ref).map((n) => n.id);
    const found: any[] = [];
    for (const id of ids) for (const f of (this.findingsByNode.get(id) ?? [])) found.push({
      id: f.id, kind: f.kind, grade: f.grade, title: f.title, explanation: f.explanation,
      node: this.brief(id),
      // blast radius reflects triage: a dismissed/accepted finding propagates nothing.
      blastRadius: (castsBlastAfterTriage(f) ? f.blastRadius ?? [] : []).map((x: string) => this.label(x)),
      asiRef: f.asiRef ?? null,
      disposition: f.disposition ?? null,
    });
    return { ref, findings: found, note: "Grade reflects how this was verified; a dependency link alone does not establish exploitability. A disposition is a human/agent triage decision and never upgrades the grade." };
  }

  /** List findings without knowing a node id or path first (threats() needs one). Compact rows;
   *  filter by kind, grade, rule id, a path fragment or disposition. Read-only. */
  findings(filter: { kind?: string; grade?: string; rule?: string; path?: string; triaged?: boolean; limit?: number } = {}) {
    const limit = Math.min(Math.max(Math.floor(Number(filter.limit) || 200), 1), 1000);
    const rows: any[] = []; let total = 0;
    for (const f of this.bundle.findings ?? []) {
      const rule = (f.evidence[0]?.source ?? "").replace("code-atlas/rule:", "");
      const node = this.byId.get(f.nodeRefs[0]);
      if (filter.kind && f.kind !== filter.kind) continue;
      if (filter.grade && f.grade !== filter.grade) continue;
      if (filter.rule && !rule.includes(filter.rule)) continue;
      if (filter.path && !(node?.evidence.path ?? "").includes(filter.path)) continue;
      if (filter.triaged !== undefined && Boolean(f.disposition) !== filter.triaged) continue;
      total++;
      if (rows.length < limit) rows.push({ id: f.id, kind: f.kind, grade: f.grade, rule, title: f.title, node: node ? this.brief(node.id) : null, disposition: f.disposition?.status ?? null });
    }
    return { total, returned: rows.length, findings: rows, note: "Static leads unless graded OBSERVED/TESTED. Use atlas_threats(id) for the explanation and blast radius." };
  }

  course(id: string) {
    const l = this.lessonByNode.get(id);
    if (!l) return { id, lesson: null, note: "no lesson attached to this node" };
    return { id, title: l.title, teach: l.teach, breakAndFix: { task: l.breakAndFix.task, defectKind: l.breakAndFix.defectKind, broken: l.breakAndFix.broken, solution: l.breakAndFix.solution, checks: l.breakAndFix.checks } };
  }

  /** Horos-style: task -> entrypoint token match -> bounded BFS -> budget fill.
   *  Returns the minimal pack an agent needs, plus a replayable receipt. */
  contextPack(task: string, budgetTokens = 2000) {
    const words = task.toLowerCase().split(/\s+/).filter(Boolean);
    const score = new Map<string, number>();
    const evidence = new Map<string, string>();
    for (const n of this.bundle.graph.nodes) {
      const hay = (n.label + " " + n.evidence.path).toLowerCase();
      let s = 0; for (const w of words) { if (n.label.toLowerCase() === w) s += 3; else if (hay.includes(w)) s += 1; }
      if (s > 0) { score.set(n.id, s); evidence.set(n.id, "task-match"); }
    }
    // bounded BFS over calls+imports, depth 2, decaying
    let frontier = [...score.keys()];
    for (let depth = 1; depth <= 2 && frontier.length; depth++) {
      const next: string[] = [];
      for (const id of frontier) {
        const nb = [...(this.callees.get(id) ?? []), ...(this.callers.get(id) ?? []), ...(this.importsOut.get(id) ?? [])];
        for (const m of nb) if (!score.has(m)) { score.set(m, Math.max(0.1, 2 - depth)); evidence.set(m, `${depth}-hop from ${this.label(id)}`); next.push(m); }
      }
      frontier = next;
    }
    const ranked = [...score.entries()].sort((a, b) => b[1] - a[1]).map(([id]) => id);
    // Budget the WHOLE serialized response (approx tokens = chars/4): the envelope
    // (task, note, receipt) is charged first, then node metadata and source slices
    // draw from the same pool in rank order. Selection stops at the first node whose
    // metadata no longer fits; the rest are counted in `omitted`, not returned.
    const NOTE = "Budgeted, source-backed pack for this task: the whole response fits budgetTokens (~4 chars/token). " +
      "`omitted` counts lower-ranked matches left out; raise the budget or narrow the task to see them. " +
      "Replayable: same bundle + task + selector + budget => same receipt hash.";
    const cap = Math.max(0, budgetTokens) * 4;
    const cost = (x: unknown) => JSON.stringify(x).length + 1;
    let used = cost({ task, note: NOTE, omitted: ranked.length, budget: { tokens: budgetTokens, approxTokensUsed: budgetTokens },
      receipt: { task, selector: "atlas-ctx-v2", budgetTokens, candidates: ranked.length, selectedCount: ranked.length,
        selectionHash: sha(""), bundleHash: sha(""), sourceHash: sha(""), sourceIncluded: [], hash: sha("") }, selected: [], sourceIncluded: [] });
    const selected: any[] = []; const included: any[] = [];
    for (const id of ranked) {
      const n = this.byId.get(id)!;
      const entry = { ...this.brief(id), why: evidence.get(id), grade: (this.findingsByNode.get(id)?.[0]?.grade) ?? null };
      const entryCost = cost(entry);
      if (used + entryCost > cap) break;
      selected.push(entry); used += entryCost;
      if (n.kind !== "function") continue;
      const w = this.sourceWindow(n);
      if (!w.available) continue;
      const item = { id, label: n.label, path: n.evidence.path, from: w.from, to: w.to, source: w.source };
      const itemCost = cost(item) + id.length + 3;                     // + its id in the receipt
      if (used + itemCost <= cap) { included.push(item); used += itemCost; }
    }
    // v2: the receipt binds the pack to the CONTENT it returned. bundleHash covers every
    // query-visible byte; sourceHash covers the exact slices handed out; selectionHash the
    // ranked selection (the list itself is not repeated, to keep the response bounded).
    const receipt = { task, selector: "atlas-ctx-v2", budgetTokens, bundleHash: this.bundleHash,
      candidates: ranked.length, selectedCount: selected.length,
      selectionHash: sha(selected.map((s) => s.id).join("\n")), sourceIncluded: included.map((i) => i.id),
      sourceHash: sha(JSON.stringify(included.map((i) => [i.id, i.source]))) };
    return { task, selected, sourceIncluded: included, omitted: ranked.length - selected.length,
      budget: { tokens: budgetTokens, approxTokensUsed: Math.ceil(used / 4) },
      receipt: { ...receipt, hash: sha(JSON.stringify(receipt)) }, note: NOTE };
  }
}

function push<T>(m: Map<string, T[]>, k: string, v: T) { const a = m.get(k) ?? []; a.push(v); m.set(k, a); }
function tally(xs: string[]) { const o: Record<string, number> = {}; for (const x of xs) o[x] = (o[x] ?? 0) + 1; return o; }
