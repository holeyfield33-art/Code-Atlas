/**
 * Code Atlas MCP tool logic (pure, over a loaded bundle).
 *
 * The point, per Horos: let an agent pull the MINIMAL slice it needs instead of
 * loading whole files. Most tools return ids + summaries (cheap); source is
 * fetched only on demand; context_pack does Horos-style budgeted selection with
 * a replayable receipt.
 */
import { createHash } from "node:crypto";
import type { AtlasBundle, AtlasNode, ThreatLead } from "../schema.js";
import { castsBlastAfterTriage } from "../triage.js";

const sha = (s: string) => "sha256:" + createHash("sha256").update(s).digest("hex").slice(0, 16);

const OVERLAY_FIELD_CAP = 200;
/** Cap one free-text field from an UNTRUSTED overlay (any of its text fields can run up to the
 *  5 MB document limit) before it leaves this process. Bounding the row/array length alone still
 *  lets one oversized field cross the MCP `ok` wrapper whole. */
const capText = (s: string): string => (s.length > OVERLAY_FIELD_CAP ? s.slice(0, OVERLAY_FIELD_CAP) + "…" : s);
/** Cap the number of evidence rows ONE lead can carry. The 5,000-entry overlay cap bounds how many
 *  leads a bundle holds, not how many evidence records a SINGLE lead carries — an overlay could put
 *  its whole allowance into one lead's evidence array. Each row is itself capText'd, but an unbounded
 *  row COUNT still lets one lead's evidence alone serialize to megabytes. */
const EVIDENCE_CAP = 50;

// Every free-text field on an UnresolvedLead is overlay-controlled and can independently run up to
// the document limit — capping only description/target (the original fix) still lets id/attackClassId/
// reason carry an oversized string through untouched. Cap every string field here.
function boundUnresolvedEntry<T extends { id: string; attackClassId: string; description: string; target?: string; reason: string }>(u: T): T {
  return {
    ...u,
    id: capText(u.id),
    attackClassId: capText(u.attackClassId),
    description: capText(u.description),
    ...(u.target !== undefined ? { target: capText(u.target) } : {}),
    reason: capText(u.reason),
  };
}

/** Bound a resolved lead's free-text fields (id, attackClassId, label, note, rule, url, each
 *  evidence item) before it's surfaced by threats()/threatLeads() — the row count being bounded
 *  does not bound any ONE row, and the evidence array's own length is unbounded on the schema, so
 *  it is capped here too. Fresh evidence after the first field-cap round: id/attackClassId/rule
 *  were still passed through the call sites verbatim, so an overlay could still put its 5MB
 *  allowance into any of those three instead. */
function boundLeadText(l: ThreatLead): Pick<ThreatLead, "id" | "attackClassId" | "label" | "note" | "rule" | "url" | "evidence"> & { evidenceTotal: number } {
  return {
    id: capText(l.id), attackClassId: capText(l.attackClassId),
    label: capText(l.label), note: capText(l.note), rule: l.rule !== undefined ? capText(l.rule) : undefined,
    // A truncated url (capText's slice+"…") is a DIFFERENT address that still looks like the
    // source's own reference — a caller that follows or cites it lands somewhere else entirely.
    // That's worse than omitting it, so an oversized url is dropped outright instead of mutated
    // (same fix as the viewer's leadCard(), which hit the identical problem one field cap earlier).
    url: l.url !== undefined && l.url.length <= OVERLAY_FIELD_CAP ? l.url : undefined,
    evidence: l.evidence.slice(0, EVIDENCE_CAP).map((e) => ({ source: capText(e.source), detail: capText(e.detail) })),
    evidenceTotal: l.evidence.length,
  };
}

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
    threatOverlay: bundle.threatOverlay ?? null,   // overview()/threats() surface it, so receipts must move with it
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
  private findingsById = new Map<string, any>();
  private leadsByNode = new Map<string, ThreatLead[]>();
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
    for (const l of bundle.threatOverlay?.leads ?? []) push(this.leadsByNode, l.nodeId, l);
    for (const f of bundle.findings ?? []) {
      for (const ref of f.nodeRefs) push(this.findingsByNode, ref, f);
      this.findingsById.set(f.id, f);
    }
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
      threatOverlay: this.bundle.threatOverlay
        ? {
            // source.identity/ref/asOf come from the same untrusted overlay document as
            // leads/unresolved (up to the 5MB document limit on any one field) and overview()
            // is the recommended FIRST call — it must stay cheap even when those fields are not.
            source: {
              identity: capText(this.bundle.threatOverlay.source.identity),
              ref: capText(this.bundle.threatOverlay.source.ref),
              asOf: capText(this.bundle.threatOverlay.source.asOf),
            },
            leads: this.bundle.threatOverlay.leads.length,
            unresolved: this.bundle.threatOverlay.unresolved.slice(0, 50).map(boundUnresolvedEntry),
            unresolvedTotal: this.bundle.threatOverlay.unresolved.length,
            // unresolvedTotal alone would read as complete even when resolveOverlay() had to trim
            // the combined (synthesized + explicit) unresolved list to fit the schema's cap —
            // surface the true drop count so that's never silently mistaken for "everything".
            unresolvedDropped: this.bundle.threatOverlay.unresolvedDropped ?? 0,
          }
        : null,   // external leads (e.g. ASI); null when none attached. Leads are hypotheses, never findings. Use atlas.threatLeads() to enumerate resolved leads without knowing a node id first.
      coverage: this.bundle.coverage ?? null,   // what the scan omitted, counted by reason (null on older bundles)
      // build.ts records an overlay attach failure (or an unresolved-entry truncation) as a
      // "threat-overlay"-stage bundle diagnostic — bundle-level, not graph-level, so it was never
      // actually surfaced here despite the comment at that call site claiming otherwise: a malformed
      // or unreachable overlay source left `threatOverlay: null` with no sign of WHY it's missing,
      // visible only in a one-time CLI warning that's gone by the time anyone opens the saved
      // bundle. Capped in count and per-message length like every other untrusted-adjacent field,
      // since `message` can echo text from the overlay source (e.g. a parse error).
      overlayDiagnostics: (this.bundle.diagnostics ?? [])
        .filter((d) => d.stage === "threat-overlay").slice(0, 20)
        .map((d) => ({ stage: d.stage, message: capText(d.message) })),
      entryPoints,
      note: "Every edge is source-backed; unresolved relationships are diagnostics, never fabricated. `coverage` reports what the scan omitted (unsupported / too large / over the file cap), so absence of a node is not absence from the repo. Use atlas_get_source to read code only when needed. threatOverlay.unresolved here is capped at 50 for a cheap first look; use atlas.unresolvedLeads({limit?, offset?}) to page through every entry. `overlayDiagnostics` says why threatOverlay is null (a bad/unreachable source) when it is.",
    };
  }

  /** Find files / functions by identifier-like words or path fragments. A phrase works, but filler words
   *  ("a", "the", "for", "find", ...) are ignored and a node that matches MORE of the distinct words ranks
   *  first, so "personal_access_tokens rotate service" lands on rotate_service.rb, not on every node that contains "a". */
  search(query: string, limit = 10) {
    const FILLER = new Set(["a", "an", "the", "of", "to", "in", "on", "for", "and", "or", "is", "are", "by", "with", "from", "that", "this", "find", "show", "get", "where", "how", "what", "which", "code", "file", "files", "function", "method"]);
    const words = [...new Set(query.toLowerCase().split(/[^a-z0-9_./-]+/).filter((w) => w.length > 1 && !FILLER.has(w)))];
    if (!words.length) return { query, results: [], hint: "use identifier-like words or a path fragment, e.g. 'rotate_service' or 'lib/api/projects'" };
    const scored = this.bundle.graph.nodes.map((n) => {
      const label = n.label.toLowerCase(), path = n.evidence.path.toLowerCase();
      const base = path.slice(path.lastIndexOf("/") + 1);
      let matched = 0, score = 0;
      for (const w of words) {
        let s = 0;
        if (label === w) s = 5; else if (path === w || path.endsWith("/" + w)) s = 5;
        else if (label.includes(w)) s = 3; else if (base.includes(w)) s = 3;
        else if (path.includes(w)) s = 1;
        if (s) { matched++; score += s; }
      }
      return { n, matched, score: score + (n.kind === "file" ? 0.5 : 0) };
    }).filter((x) => x.matched > 0).sort((a, b) => b.matched - a.matched || b.score - a.score).slice(0, limit);
    return { query, matchedWords: words, results: scored.map((x) => this.brief(x.n.id)) };
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
      // Kept as two flags, not merged into one: a finding is graded on THIS repo and verified;
      // an overlay lead is an external, ungrounded hypothesis (see threatOverlay.ts's contract).
      // An agent reading only `hasThreats` for "is this graded as a risk" must not be told false
      // for a node that atlas_threats/atlas_threat_leads would report a lead on.
      hasThreats: (this.findingsByNode.get(id)?.length ?? 0) > 0,
      hasThreatLeads: (this.leadsByNode.get(id)?.length ?? 0) > 0,
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
    // ref is a node id or a file path. `ref` is usually one node (or a handful sharing a file),
    // so findings are inherently bounded in practice — but a lead count is set by the UNTRUSTED
    // overlay, not by this repo's shape, and OverlayInputSchema's 5,000-entry cap is PER BUNDLE,
    // not per node: every one of them could target the same file. Row-cap both, same as findings()
    // and threatLeads(), so one ref can't make the MCP `ok` wrapper serialize an unbounded array.
    const ROW_CAP = 500;
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
    const allLeads = ids.flatMap((id) => (this.leadsByNode.get(id) ?? []).map((l) => {
      const bounded = boundLeadText(l);
      return {
        id: bounded.id, attackClassId: bounded.attackClassId, label: bounded.label, status: l.status, confidence: l.confidence,
        note: bounded.note, rule: bounded.rule ?? null, url: bounded.url ?? null, evidence: bounded.evidence, evidenceTotal: bounded.evidenceTotal, node: this.brief(id),
      };
    }));
    const findingsTotal = found.length, leadsTotal = allLeads.length;
    return {
      ref, findings: found.slice(0, ROW_CAP), findingsTotal, leads: allLeads.slice(0, ROW_CAP), leadsTotal,
      note: "Leads come from an external overlay and are hypotheses to investigate, not findings; only a finding graded OBSERVED/TESTED on this repo is a verified weakness. Grade reflects how this was verified; a dependency link alone does not establish exploitability. A disposition is a human/agent triage decision and never upgrades the grade." +
        // atlas_threat_leads only paginates LEADS; a findings overflow needs findings() (now
        // itself offset-paginated), reachable via atlas_exec since findings() has no standalone
        // MCP tool — pointing BOTH kinds of overflow at atlas_threat_leads left findings past the
        // cap with no actual way to reach them.
        (findingsTotal > ROW_CAP ? ` Findings row-capped at ${ROW_CAP}; via atlas_exec, call atlas.findings({path: ..., offset}) to page through the rest.` : "") +
        (leadsTotal > ROW_CAP ? ` Leads row-capped at ${ROW_CAP}; use atlas_threat_leads with filters to page through the rest.` : ""),
    };
  }

  /** List RESOLVED overlay leads without knowing a node id or path first (threats() needs one) —
   *  e.g. "review all overlay leads". Compact rows with node references; filter by attack class,
   *  status, confidence, or a path fragment. Unresolved leads stay out of this list (overview()
   *  already summarizes those, bounded) since they have no node to reference. Read-only. */
  threatLeads(filter: { attackClassId?: string; status?: string; confidence?: string; path?: string; limit?: number; offset?: number } = {}) {
    const limit = Math.min(Math.max(Math.floor(Number(filter.limit) || 200), 1), 1000);
    // `offset` pages through matches beyond `limit` — without it, more matches than `limit` (the
    // overlay document cap is 5,000, well past limit's 1,000 ceiling) could never be enumerated;
    // every call would return the same leading page forever.
    const offset = Math.max(Math.floor(Number(filter.offset) || 0), 0);
    const rows: any[] = []; let matched = 0;
    for (const l of this.bundle.threatOverlay?.leads ?? []) {
      const node = this.byId.get(l.nodeId);
      if (filter.attackClassId && l.attackClassId !== filter.attackClassId) continue;
      if (filter.status && l.status !== filter.status) continue;
      if (filter.confidence && l.confidence !== filter.confidence) continue;
      if (filter.path && !(node?.evidence.path ?? "").includes(filter.path)) continue;
      const i = matched++;
      if (i < offset || rows.length >= limit) continue;
      const bounded = boundLeadText(l);
      rows.push({
        id: bounded.id, attackClassId: bounded.attackClassId, label: bounded.label, status: l.status, confidence: l.confidence,
        note: bounded.note, rule: bounded.rule ?? null, url: bounded.url ?? null, evidence: bounded.evidence, evidenceTotal: bounded.evidenceTotal, node: node ? this.brief(l.nodeId) : { id: l.nodeId },
      });
    }
    const nextOffset = offset + rows.length < matched ? offset + rows.length : null;
    return {
      total: matched, returned: rows.length, offset, nextOffset, leads: rows,
      note: "Leads are hypotheses from an external overlay, never findings; only a finding graded OBSERVED/TESTED on this repo is a verified weakness. Use atlas_threats(id) for a node's leads plus its real findings together." +
        (nextOffset !== null ? ` More match than fit in this page; call again with offset=${nextOffset} for the rest.` : ""),
    };
  }

  /** List UNRESOLVED overlay entries, paginated — overview()'s summary hard-stops at 50 so the
   *  recommended first call stays cheap, but an overlay can carry up to 5,000; threatLeads() also
   *  excludes unresolved entries outright (they have no node to reference). Without this, anything
   *  past the first 50 was unreachable through either the agent API or the viewer. Read-only. */
  unresolvedLeads(filter: { limit?: number; offset?: number } = {}) {
    const limit = Math.min(Math.max(Math.floor(Number(filter.limit) || 50), 1), 1000);
    const offset = Math.max(Math.floor(Number(filter.offset) || 0), 0);
    const all = this.bundle.threatOverlay?.unresolved ?? [];
    const dropped = this.bundle.threatOverlay?.unresolvedDropped ?? 0;
    const rows = all.slice(offset, offset + limit).map(boundUnresolvedEntry);
    const nextOffset = offset + rows.length < all.length ? offset + rows.length : null;
    return {
      total: all.length, unresolvedDropped: dropped, returned: rows.length, offset, nextOffset, unresolved: rows,
      note: "These could not be matched to exactly one component of this graph — unknown, not cleared." +
        (nextOffset !== null ? ` More entries than fit in this page; call again with offset=${nextOffset} for the rest.` : "") +
        // Paging to the end of `total` is NOT "everything": resolveOverlay() may have already
        // trimmed entries that never made it into the saved bundle at all, past this cap.
        (dropped > 0 ? ` ${dropped} additional entries were dropped at build time (the combined unresolved list exceeded the overlay's entry cap) and are not retrievable here.` : ""),
    };
  }

  /** List findings without knowing a node id or path first (threats() needs one). Compact rows;
   *  filter by kind, grade, rule id, a path fragment or disposition; page with offset/nextOffset —
   *  threats() directs callers with more than ROW_CAP findings on one ref here (filtered by
   *  `path`), so it needs the same offset pagination atlas_threat_leads/atlas_unresolved_leads
   *  already have, not just a `limit`. Read-only. */
  findings(filter: { kind?: string; grade?: string; rule?: string; path?: string; triaged?: boolean; limit?: number; offset?: number } = {}) {
    const limit = Math.min(Math.max(Math.floor(Number(filter.limit) || 200), 1), 1000);
    const offset = Math.max(Math.floor(Number(filter.offset) || 0), 0);
    const rows: any[] = []; let total = 0;
    for (const f of this.bundle.findings ?? []) {
      const rule = (f.evidence[0]?.source ?? "").replace("code-atlas/rule:", "");
      const node = this.byId.get(f.nodeRefs[0]);
      if (filter.kind && f.kind !== filter.kind) continue;
      if (filter.grade && f.grade !== filter.grade) continue;
      if (filter.rule && !rule.includes(filter.rule)) continue;
      if (filter.path && !(node?.evidence.path ?? "").includes(filter.path)) continue;
      if (filter.triaged !== undefined && Boolean(f.disposition) !== filter.triaged) continue;
      const i = total++;
      if (i < offset || rows.length >= limit) continue;
      rows.push({ id: f.id, kind: f.kind, grade: f.grade, rule, title: f.title, node: node ? this.brief(node.id) : null, disposition: f.disposition?.status ?? null });
    }
    const nextOffset = offset + rows.length < total ? offset + rows.length : null;
    return {
      total, returned: rows.length, offset, nextOffset, findings: rows,
      // Each row here is compact (same shape threats() also row-caps at 500 per ref), so a finding
      // beyond that cap on a busy ref had its full detail (explanation/evidence/blastRadius/asiRef/
      // disposition) permanently unreachable — findings()/threats() both only ever return the first
      // ROW_CAP in full. finding(id) is the lookup that works at any offset, by id rather than by ref.
      note: "Static leads unless graded OBSERVED/TESTED. Use atlas_threats(id) for a node's findings with full detail, or atlas.finding(id) via atlas_exec to look up one finding's full detail directly by id (e.g. for a row returned here past atlas_threats' row cap)." +
        (nextOffset !== null ? ` More match than fit in this page; call again with offset=${nextOffset} for the rest.` : ""),
    };
  }

  /** One finding's full detail by id — the lookup findings()/threats() can't provide once a busy
   *  ref has more findings than ROW_CAP: both only return compact or detailed rows for the first
   *  ROW_CAP, so anything past that is otherwise unreachable in full. Read-only. */
  finding(id: string) {
    const f = this.findingsById.get(id);
    if (!f) return { error: "unknown finding id", id, hint: "use atlas_exec's atlas.findings({...}) to find an id" };
    const node = this.byId.get(f.nodeRefs[0]);
    return {
      id: f.id, kind: f.kind, grade: f.grade, title: f.title, explanation: f.explanation,
      node: node ? this.brief(node.id) : null,
      nodeRefs: f.nodeRefs.map((r: string) => this.byId.has(r) ? this.brief(r) : { id: r }),
      evidence: f.evidence,
      blastRadius: (castsBlastAfterTriage(f) ? f.blastRadius ?? [] : []).map((x: string) => this.label(x)),
      asiRef: f.asiRef ?? null,
      disposition: f.disposition ?? null,
      note: "A disposition is a human/agent triage decision and never upgrades the grade; blast radius reflects triage (a dismissed/accepted finding propagates nothing).",
    };
  }

  /** HTTP routes found in code (method, path template, handler), optionally filtered. A static reading: see routes.ts. */
  routes(filter: { method?: string; path?: string; file?: string; limit?: number } = {}) {
    const limit = Math.min(Math.max(Math.floor(Number(filter.limit) || 200), 1), 1000);
    const rows: any[] = []; let total = 0;
    for (const r of this.bundle.routes ?? []) {
      if (filter.method && r.method !== String(filter.method).toUpperCase()) continue;
      if (filter.path && !r.path.includes(filter.path) && !r.template.includes(filter.path)) continue;
      if (filter.file && !r.evidence.path.includes(filter.file)) continue;
      total++;
      if (rows.length < limit) rows.push({
        method: r.method, path: r.path, template: r.template, handler: r.handler ?? null, inline: r.inline ?? false,
        file: r.evidence.path, line: r.evidence.line, node: r.nodeRef ? this.brief(r.nodeRef) : null,
        findings: r.nodeRef ? (this.findingsByNode.get(r.nodeRef) ?? []).map((f: any) => ({ id: f.id, kind: f.kind, grade: f.grade, title: f.title })) : [], note: r.note ?? null,
      });
    }
    return { total, returned: rows.length, routes: rows, note: "Routes are read from code (JS/TS). A mount prefix is not applied and a run-time path is not seen; a route is not evidence that an endpoint is reachable." };
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
