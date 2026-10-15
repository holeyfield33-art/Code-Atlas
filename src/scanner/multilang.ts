/**
 * Multi-language graph backend (tree-sitter), behind the AtlasBundle seam.
 *
 * Reuses the vendored tree-sitter mapper (web-tree-sitter + each grammar's
 * tags.scm) and ADAPTS its generic graph into a conformant AtlasGraph, so the
 * viewer / course / MCP / findings consume it with no downstream change. The
 * grounding invariant holds end to end: an edge is emitted only when both
 * endpoints resolve to real nodes; everything else is a diagnostic.
 *
 * v1 scope + honest limits:
 *  - Languages: Python, Ruby (grow by adding a grammar wasm + tags.scm).
 *  - `calls` edges originate from the FILE node, not the enclosing function
 *    (name-based resolution — coarser than the Babel backend). Tracked as a
 *    follow-up; it never fabricates, it is only less precise.
 *  - contentHash is per file (sha256 of the file source at this revision).
 *  - line/column are derived from character offsets (ASCII-safe; byte-exact
 *    positions for non-ASCII source are a follow-up).
 *  - The Break & Fix course is still JS/TS-only (Babel); a non-JS graph gets a
 *    graph + threat map, not lessons, until a language-agnostic generator lands.
 */
import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import type { AtlasGraph, AtlasNode, AtlasEdge } from "../schema.js";

const require = createRequire(import.meta.url);
interface GenericNode { id: string; kind: string; name?: string; file?: string; range?: { start: number; end: number }; bodyRange?: { start: number; end: number }; meta?: unknown; }
interface GenericEdge { id: string; kind: string; source: string; target: string; meta?: unknown; }
interface GenericDiag { severity?: string; message: string; file?: string; range?: unknown; }
interface GenericGraph { nodes: GenericNode[]; edges: GenericEdge[]; diagnostics: GenericDiag[]; callTokens?: Record<string, string[]>; }
const mapper = require("./treeSitter/mapper.cjs") as {
  buildGraph(lang: string, fileContents: Map<string, string>, projectRoot: string): Promise<GenericGraph>;
};

export const SUPPORTED_LANGUAGES = ["python", "ruby"] as const;
export type MultiLang = (typeof SUPPORTED_LANGUAGES)[number];

const sha256 = (s: string) => "sha256:" + createHash("sha256").update(s).digest("hex");
const ATLAS_KINDS = new Set<AtlasNode["kind"]>(["file", "function", "class", "constant", "module"]);
const EDGE_KINDS = new Set<AtlasEdge["kind"]>(["contains", "imports", "calls"]);

/** 1-based line/column from a character offset — matches the Babel backend
 *  (loc.start.line is 1-based; it stores column as loc.start.column + 1), which
 *  is what the viewer and MCP source slicing expect. */
function lineCol(source: string, offset: number): { line: number; column: number } {
  const n = Math.min(Math.max(offset, 0), source.length);
  let line = 0, lastNewline = -1;
  for (let i = 0; i < n; i++) if (source.charCodeAt(i) === 10) { line++; lastNewline = i; }
  return { line: line + 1, column: n - lastNewline };
}

export function languageOf(path: string): MultiLang | null {
  if (/\.(?:py|pyi)$/.test(path)) return "python";
  if (/\.(?:rb|rake)$/.test(path)) return "ruby";
  return null;
}

/** A built graph plus the real source slice of each function-kind node, keyed by
 *  node id. The slices let the native rule engine (findings.ts) scan non-JS
 *  functions without a JS parser — the slice is the verbatim definition body at
 *  the tree-sitter range, so matches stay source-grounded. */
export interface MultiLangBuild {
  graph: AtlasGraph;
  functionSources: Map<string, string>;
  /** function node id -> qualified callee tokens found in its body, grounded in
   *  real parsed call nodes (paren-less calls included; comments/strings not).
   *  The native rule engine matches sinks/guards against these, not raw text. */
  functionCalls: Map<string, string[]>;
}

/**
 * Build a schema-conformant AtlasGraph for one language, plus per-function source
 * slices for the native rule engine.
 * @param fileContents repo-relative path -> source (one language's files)
 */
export async function buildMultiLangGraph(
  lang: MultiLang,
  fileContents: Map<string, string>,
  revision: string,
  projectRoot = ".",
): Promise<MultiLangBuild> {
  const g = await mapper.buildGraph(lang, fileContents, projectRoot);
  const srcOf = (p?: string) => (p ? fileContents.get(p) ?? "" : "");

  const functionSources = new Map<string, string>();
  const nodes: AtlasNode[] = g.nodes.map((n) => {
    const src = srcOf(n.file);
    const { line, column } = lineCol(src, n.range?.start ?? 0);
    const kind = ATLAS_KINDS.has(n.kind as AtlasNode["kind"]) ? (n.kind as AtlasNode["kind"]) : "function";
    // slice the real definition body for the rule engine (functions only)
    if (kind === "function" && n.bodyRange)
      functionSources.set(n.id, src.slice(n.bodyRange.start, n.bodyRange.end));
    return {
      id: n.id,
      kind,
      label: n.name ?? n.id,
      evidence: {
        path: n.file ?? "",
        line,
        column,
        revision,
        contentHash: sha256(src),
        method: "tree-sitter-static",
        status: "static",
      },
    };
  });

  const byId = new Map(nodes.map((n) => [n.id, n]));
  const seen = new Set<string>();
  const edges: AtlasEdge[] = [];
  for (const e of g.edges) {
    const from = byId.get(e.source);
    const to = byId.get(e.target);
    if (!from || !to) continue;                                  // grounding: no edge to a non-node
    if (!EDGE_KINDS.has(e.kind as AtlasEdge["kind"])) continue;
    if (seen.has(e.id)) continue;                                // unique edge ids
    seen.add(e.id);
    edges.push({ id: e.id, from: e.source, to: e.target, kind: e.kind as AtlasEdge["kind"], evidence: { ...from.evidence } });
  }

  const diagnostics = g.diagnostics.map((d) => ({ path: d.file ?? "", message: d.message }));
  const functionCalls = new Map<string, string[]>(Object.entries(g.callTokens ?? {}));
  return { graph: { version: "ts-0.1", revision, nodes, edges, diagnostics }, functionSources, functionCalls };
}
