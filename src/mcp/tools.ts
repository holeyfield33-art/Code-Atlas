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

const sha = (s: string) => "sha256:" + createHash("sha256").update(s).digest("hex").slice(0, 16);

export class AtlasTools {
  private byId = new Map<string, AtlasNode>();
  private byPath = new Map<string, string>();                 // file path -> code
  private callers = new Map<string, string[]>();
  private callees = new Map<string, string[]>();
  private importsOut = new Map<string, string[]>();
  private containerOf = new Map<string, string>();
  private findingsByNode = new Map<string, any[]>();
  private lessonByNode = new Map<string, any>();

  constructor(private bundle: AtlasBundle) {
    for (const n of bundle.graph.nodes) this.byId.set(n.id, n);
    for (const s of bundle.sources ?? []) this.byPath.set(s.path, s.code);
    for (const e of bundle.graph.edges) {
      if (e.kind === "calls") { push(this.callees, e.from, e.to); push(this.callers, e.to, e.from); }
      else if (e.kind === "imports") push(this.importsOut, e.from, e.to);
      else if (e.kind === "contains") this.containerOf.set(e.to, e.from);
    }
    for (const f of bundle.findings ?? []) for (const ref of f.nodeRefs) push(this.findingsByNode, ref, f);
    for (const l of bundle.course?.lessons ?? []) for (const ref of l.nodeRefs) if (!this.lessonByNode.has(ref)) this.lessonByNode.set(ref, l);
  }

  private label = (id: string) => this.byId.get(id)?.label ?? id;
  private brief = (id: string) => { const n = this.byId.get(id); return n ? { id, label: n.label, kind: n.kind, path: n.evidence.path, line: n.evidence.line } : { id }; };

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
      entryPoints,
      note: "Every edge is source-backed; unresolved relationships are diagnostics, never fabricated. Use atlas_get_source to read code only when needed.",
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
      calls: (this.callees.get(id) ?? []).map((x) => this.brief(x)),
      calledBy: (this.callers.get(id) ?? []).map((x) => this.brief(x)),
      imports: (this.importsOut.get(id) ?? []).map((x) => this.brief(x)),
      hasSource: this.byPath.has(n.evidence.path),
      hasThreats: (this.findingsByNode.get(id)?.length ?? 0) > 0,
      hasLesson: this.lessonByNode.has(id),
      evidence: n.evidence,
    };
  }

  getSource(id: string) {
    const n = this.byId.get(id);
    if (!n) return { error: "unknown node id", id };
    const code = this.byPath.get(n.evidence.path);
    if (code === undefined) return { error: "source not inlined in this bundle", path: n.evidence.path };
    const lines = code.split("\n");
    const target = n.evidence.line || 1;
    const [start, end] = n.kind === "function" ? [Math.max(1, target - 1), Math.min(lines.length, target + 60)] : [1, Math.min(lines.length, 400)];
    return { ...this.brief(id), from: start, to: end, source: lines.slice(start - 1, end).join("\n"), truncated: end < lines.length };
  }

  neighbors(id: string, kinds?: string[]) {
    const n = this.byId.get(id);
    if (!n) return { error: "unknown node id", id };
    const want = (k: string) => !kinds || kinds.includes(k);
    return {
      ...this.brief(id),
      ...(want("calls") ? { calls: (this.callees.get(id) ?? []).map((x) => this.brief(x)) } : {}),
      ...(want("calledBy") ? { calledBy: (this.callers.get(id) ?? []).map((x) => this.brief(x)) } : {}),
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
      node: this.brief(id), blastRadius: (f.blastRadius ?? []).map((x: string) => this.label(x)), asiRef: f.asiRef ?? null,
    });
    return { ref, findings: found, note: "Grade reflects how this was verified; a dependency link alone does not establish exploitability." };
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
    // budget fill: include source for the top nodes until budget (approx tokens = chars/4)
    const selected: any[] = []; const included: any[] = []; let used = 0; const cap = budgetTokens * 4;
    for (const id of ranked) {
      const b = this.brief(id); const why = evidence.get(id);
      const n = this.byId.get(id)!; const src = this.getSource(id);
      const cost = ("source" in src ? src.source.length : 0) + 80;
      selected.push({ ...b, why, grade: (this.findingsByNode.get(id)?.[0]?.grade) ?? null });
      if (n.kind === "function" && "source" in src && used + cost <= cap) { included.push({ id, label: n.label, path: n.evidence.path, source: src.source }); used += cost; }
    }
    const receipt = { task, selector: "atlas-ctx-v1", budgetTokens, selected: selected.map((s) => s.id), sourceIncluded: included.map((i) => i.id) };
    return { task, selected, sourceIncluded: included, receipt: { ...receipt, hash: sha(JSON.stringify(receipt)) },
      note: "Minimal source-backed pack for this task. Replayable: same bundle + task + selector => same receipt hash." };
  }
}

function push<T>(m: Map<string, T[]>, k: string, v: T) { const a = m.get(k) ?? []; a.push(v); m.set(k, a); }
function tally(xs: string[]) { const o: Record<string, number> = {}; for (const x of xs) o[x] = (o[x] ?? 0) + 1; return o; }
