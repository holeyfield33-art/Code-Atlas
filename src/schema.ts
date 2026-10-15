/**
 * Code Atlas — Bundle & Course Schema  (schemaVersion "1.0")
 * -----------------------------------------------------------------------------
 * The single contract the generator EMITS, the viewer CONSUMES, and the
 * verifier CHECKS against. Language backend (Babel now, tree-sitter at hosting)
 * is replaceable; this shape is the fixed seam.
 *
 * Canonical form: Zod (runtime validation) + inferred TypeScript types.
 * JSON Schema can be generated from these with zod-to-json-schema if needed.
 *
 * Status of each section:
 *   graph    — LOCKED. Verified against the real graph builder (atlas/graph.ts).
 *   course   — LOCKED (v1). The grounded Break & Fix contract.
 *   blurbs   — RESERVED. Plain-language layer; optional, may be absent.
 *   findings — RESERVED. Security layer; optional, absent => all components GRAY.
 */

import { z } from "zod";

/* ========================================================================== *
 * 1. GRAPH  (LOCKED — mirrors the real AtlasGraph)
 * ========================================================================== */

/** Where a node/edge physically comes from. Every graph element carries this;
 *  there is no such thing as an unsourced element. */
export const EvidenceSchema = z.object({
  path: z.string(),
  line: z.number().int().nonnegative(),
  column: z.number().int().nonnegative(),
  revision: z.string(),
  contentHash: z.string(),                 // sha256 of the source the element came from
  method: z.enum(["babel-static", "tree-sitter-static"]), // which backend produced this element
  status: z.literal("static"),
});

export const AtlasNodeSchema = z.object({
  id: z.string(),                          // hash-derived, unique within a bundle
  stableKey: z.string().optional(),        // RESERVED: offset-independent id (e.g. "file:path#scope/name")
  // file/function from the Babel backend; class/constant/module from tree-sitter
  // backends (methods are normalized to function). "package" reserved for monorepos (D-5).
  kind: z.enum(["file", "function", "class", "constant", "module"]),
  label: z.string(),
  evidence: EvidenceSchema,
});

export const AtlasEdgeSchema = z.object({
  id: z.string(),
  from: z.string(),                        // node id
  to: z.string(),                          // node id
  kind: z.enum(["contains", "imports", "calls"]),
  evidence: EvidenceSchema,
});

/** A relationship the analyzer could NOT resolve becomes a diagnostic, never a
 *  fabricated edge. Security credibility rests on this. */
export const GraphDiagnosticSchema = z.object({
  path: z.string(),
  message: z.string(),
});

export const AtlasGraphSchema = z.object({
  version: z.string(),                     // graph-builder format version (e.g. "0.1")
  revision: z.string(),
  nodes: z.array(AtlasNodeSchema),
  edges: z.array(AtlasEdgeSchema),
  diagnostics: z.array(GraphDiagnosticSchema),
});

/* ========================================================================== *
 * 2. COURSE  (LOCKED v1 — the grounded Break & Fix contract)
 * ========================================================================== */

/** A structural check on the learner's edited code. Not a behaviour proof.
 *  - includes/excludes/regex: lightweight string/pattern checks (viewer-runnable).
 *  - structure: run the Block-Wise conformance checker against `value` (a plan id),
 *    the strong verifier used in the full build. */
export const CheckSchema = z.object({
  kind: z.enum(["includes", "excludes", "regex", "structure"]),
  value: z.string(),
  message: z.string(),                     // shown when the check fails — tells the learner what's missing
});

/** The defect taxonomy. Each kind is MECHANICALLY derivable from the real graph
 *  + source, so a defect is never invented — it is a reversible mutation of real
 *  code. The comment on each names how it is derived and how the fix is checked. */
export const DefectKindSchema = z.enum([
  "removed_guard",       // delete a validation/guard clause        → check: guard restored
  "broken_call_edge",    // remove/rename a real `calls` edge target → check: call restored
  "swapped_condition",   // invert/weaken a boolean or comparison    → check: condition corrected
  "missing_import",      // remove a needed `imports` edge's symbol  → check: import restored
  "wrong_target",        // point a call/assign at the wrong symbol  → check: correct target
  "order_violation",     // reorder statements/passes (e.g. resolve-before-index) → check: order restored
]);

/** Ties the defect to the exact real source it was derived from. This is the
 *  anti-fabrication guarantee: `solution` must equal the original source whose
 *  sha256 is `contentHash`; `broken` is that source with the `defectKind`
 *  mutation applied. A generator MUST NOT emit a Break & Fix whose solution is
 *  not real source. */
export const BreakFixProvenanceSchema = z.object({
  revision: z.string(),
  contentHash: z.string(),                 // sha256 of the real source `solution` was taken from
  derivedFrom: z.enum(["node", "edge", "guard", "signature"]),
  method: z.enum(["atlas-graph", "block-wise-conformance"]),
});

export const BreakAndFixSchema = z.object({
  nodeRef: z.string(),                     // the graph node (id or stableKey) the defect lives in
  file: z.string(),                        // source path, from the node's evidence
  anchor: z.object({ line: z.number().int(), column: z.number().int() }).optional(),
  defectKind: DefectKindSchema,
  task: z.string(),                        // plain-language: what the learner must do
  broken: z.string(),                      // real source WITH the defect applied
  solution: z.string(),                    // the original real source (the correct answer)
  checks: z.array(CheckSchema).min(1),     // at least one — "press done" is never a pass
  provenance: BreakFixProvenanceSchema,
});

/** Optional per-lesson quiz. Secondary to Break & Fix; kept optional so the
 *  course never depends on it. */
export const CheckpointSchema = z.object({
  questions: z.array(z.object({
    id: z.string(),
    prompt: z.string(),
    options: z.array(z.string()).min(2).max(4),
    correctIndex: z.number().int().nonnegative(),
    explanation: z.string(),
  })),
}).optional();

export const LessonSchema = z.object({
  id: z.string(),
  moduleId: z.string(),
  title: z.string(),
  nodeRefs: z.array(z.string()),           // THE JOIN: graph nodes this lesson teaches
  teach: z.string(),                       // plain-language, describes only real edges/structure
  concepts: z.array(z.string()).default([]),
  breakAndFix: BreakAndFixSchema,
  checkpoint: CheckpointSchema,
});

export const CourseModuleSchema = z.object({
  id: z.string(),
  title: z.string(),
  summary: z.string(),
  lessonIds: z.array(z.string()),
  nodeRefs: z.array(z.string()),           // graph nodes this module spans
});

export const CourseSchema = z.object({
  title: z.string(),
  summary: z.string(),
  modules: z.array(CourseModuleSchema),
  lessons: z.array(LessonSchema),
});

/* ========================================================================== *
 * 3. RESERVED LAYERS  (optional; bundle renders without them)
 * ========================================================================== */

/** Plain-language per-node gloss, baked at build time (no runtime LLM). */
export const NodeBlurbSchema = z.object({
  nodeId: z.string(),
  plain: z.string(),
  role: z.string(),
  connects: z.string(),
  checkHints: z.array(z.string()).default([]),
  generator: z.object({ model: z.string(), at: z.string() }),
});

/** A pinned reference to an ASI attack class. `url` is the live link (source of
 *  truth); the rest is the offline snapshot. `url` is DATA, not a hardcoded
 *  scheme — whatever ASI's link structure is, it travels here. */
export const AsiRefSchema = z.object({
  id: z.string(),            // ASI attack-class id
  url: z.string(),           // live link to the authoritative ASI page
  label: z.string(),         // one-line class name (snapshot)
  asOf: z.string(),          // date the snapshot was taken (staleness is visible)
});

/** Security finding, mapped to node(s). `kind` is polarity (weakness ⇒ red,
 *  control ⇒ green); `grade` is evidence strength. Color = f(kind, grade).
 *  The grade comes ONLY from how this was verified on THIS repo — never from
 *  ASI saying the class exists. ASI explains; it cannot colour a node. */
export const FindingSchema = z.object({
  id: z.string(),
  nodeRefs: z.array(z.string()),
  kind: z.enum(["weakness", "control"]),
  title: z.string(),
  explanation: z.string(),
  grade: z.enum(["OBSERVED", "STATIC", "TESTED", "INFERRED", "UNKNOWN"]),
  evidence: z.array(z.object({ source: z.string(), detail: z.string() })),
  blastRadius: z.array(z.string()).default([]),
  asiRef: AsiRefSchema.optional(),
});

/** Pinned snapshot of the ASI attack classes the findings reference. Stamped
 *  with revision + asOf so staleness is visible; the per-finding asiRef.url is
 *  always the authoritative live source. */
export const AsiSnapshotSchema = z.object({
  source: z.string(),
  revision: z.string(),
  asOf: z.string(),
  baseUrl: z.string(),
  classes: z.array(z.object({ id: z.string(), label: z.string(), mitigation: z.string(), url: z.string() })),
});

/* ========================================================================== *
 * 4. BUNDLE  (top-level — assembles everything)
 * ========================================================================== */

export const AtlasBundleSchema = z.object({
  schemaVersion: z.literal("1.0"),
  product: z.object({ name: z.string() }),          // NOT hardcoded; viewer reads it
  repository: z.object({ label: z.string(), revision: z.string() }),
  generatedAt: z.string(),                          // ISO
  graph: AtlasGraphSchema,                          // LOCKED
  course: CourseSchema.optional(),                  // v1 course layer
  blurbs: z.array(NodeBlurbSchema).optional(),      // RESERVED
  findings: z.array(FindingSchema).optional(),      // Security layer (absent => all GRAY)
  asiSnapshot: AsiSnapshotSchema.optional(),        // pinned ASI classes referenced by findings
  sources: z.array(z.object({ path: z.string(), code: z.string() })).optional(), // inlined source for the viewer (offline)
  diagnostics: z.array(z.object({ stage: z.string(), message: z.string() })).default([]),
  integrity: z.object({ graphHash: z.string(), bundleHash: z.string() }).optional(),
});

/* ========================================================================== *
 * 5. Types + validation entry point
 * ========================================================================== */

export type Evidence = z.infer<typeof EvidenceSchema>;
export type AtlasNode = z.infer<typeof AtlasNodeSchema>;
export type AtlasEdge = z.infer<typeof AtlasEdgeSchema>;
export type AtlasGraph = z.infer<typeof AtlasGraphSchema>;
export type Check = z.infer<typeof CheckSchema>;
export type DefectKind = z.infer<typeof DefectKindSchema>;
export type BreakAndFix = z.infer<typeof BreakAndFixSchema>;
export type Lesson = z.infer<typeof LessonSchema>;
export type CourseModule = z.infer<typeof CourseModuleSchema>;
export type Course = z.infer<typeof CourseSchema>;
export type NodeBlurb = z.infer<typeof NodeBlurbSchema>;
export type AsiRef = z.infer<typeof AsiRefSchema>;
export type Finding = z.infer<typeof FindingSchema>;
export type AsiSnapshot = z.infer<typeof AsiSnapshotSchema>;
export type AtlasBundle = z.infer<typeof AtlasBundleSchema>;

/** Parse + validate an unknown value as an AtlasBundle. Throws on failure.
 *  Referential checks beyond shape (every nodeRef resolves, no duplicate ids,
 *  every breakAndFix.nodeRef exists in the graph) are enforced here. */
export function parseBundle(input: unknown): AtlasBundle {
  const bundle = AtlasBundleSchema.parse(input);
  const nodeIds = new Set(bundle.graph.nodes.map((n) => n.id));
  const stableKeys = new Set(
    bundle.graph.nodes.map((n) => n.stableKey).filter((k): k is string => Boolean(k))
  );
  const resolves = (ref: string) => nodeIds.has(ref) || stableKeys.has(ref);

  // unique node / edge ids
  if (nodeIds.size !== bundle.graph.nodes.length) throw new Error("Duplicate node id in graph");

  // every edge endpoint exists
  for (const e of bundle.graph.edges) {
    if (!nodeIds.has(e.from) || !nodeIds.has(e.to)) throw new Error(`Edge ${e.id} references a missing node`);
  }

  if (bundle.course) {
    const lessonIds = new Set(bundle.course.lessons.map((l) => l.id));
    if (lessonIds.size !== bundle.course.lessons.length) throw new Error("Duplicate lesson id");
    for (const l of bundle.course.lessons) {
      for (const ref of l.nodeRefs) if (!resolves(ref)) throw new Error(`Lesson ${l.id} nodeRef '${ref}' not in graph`);
      if (!resolves(l.breakAndFix.nodeRef)) throw new Error(`Lesson ${l.id} breakAndFix.nodeRef not in graph`);
      // Grounding invariant (shape-level): broken must differ from solution.
      if (l.breakAndFix.broken === l.breakAndFix.solution) throw new Error(`Lesson ${l.id} break==fix (no real defect)`);
    }
    for (const m of bundle.course.modules)
      for (const id of m.lessonIds) if (!lessonIds.has(id)) throw new Error(`Module ${m.id} lists unknown lesson ${id}`);
  }

  if (bundle.findings) {
    const classIds = new Set((bundle.asiSnapshot?.classes ?? []).map((c) => c.id));
    for (const f of bundle.findings) {
      for (const ref of f.nodeRefs) if (!resolves(ref)) throw new Error(`Finding ${f.id} nodeRef '${ref}' not in graph`);
      for (const ref of f.blastRadius) if (!resolves(ref)) throw new Error(`Finding ${f.id} blastRadius '${ref}' not in graph`);
      // If an ASI snapshot is present, a referenced class must be in it (snapshot stays consistent).
      if (f.asiRef && classIds.size && !classIds.has(f.asiRef.id))
        throw new Error(`Finding ${f.id} cites ASI class '${f.asiRef.id}' absent from the snapshot`);
    }
  }
  return bundle;
}
