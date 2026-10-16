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

/** 1-based line/column from a tree-sitter BYTE offset. tree-sitter indexes by
 *  UTF-8 byte; for ASCII (byte == char) we slice directly, and for any non-ASCII
 *  source we decode the byte prefix so positions are exact in characters — which
 *  is what the Babel backend emits (1-based line, column+1) and what the viewer /
 *  MCP source slicing expect. */
export function lineCol(source: string, byteOffset: number, ascii: boolean): { line: number; column: number } {
  const off = Math.max(byteOffset, 0);
  const text = ascii
    ? source.slice(0, Math.min(off, source.length))
    : Buffer.from(source, "utf8").subarray(0, off).toString("utf8");
  let line = 0, lastNewline = -1;
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) { line++; lastNewline = i; }
  return { line: line + 1, column: text.length - lastNewline };
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
  const asciiOf = new Map<string, boolean>();           // per-file: is the source pure ASCII?
  const isAscii = (p: string, s: string) => {
    let a = asciiOf.get(p);
    if (a === undefined) { a = s.length === Buffer.byteLength(s, "utf8"); asciiOf.set(p, a); }
    return a;
  };

  const functionSources = new Map<string, string>();
  const nodes: AtlasNode[] = g.nodes.map((n) => {
    const src = srcOf(n.file);
    const { line, column } = lineCol(src, n.range?.start ?? 0, isAscii(n.file ?? "", src));
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
    const kind = e.kind as AtlasEdge["kind"];
    // tree-sitter call edges are resolved by NAME only (not by imports), so they
    // are inferred, never proven. contains/imports are structural/path-resolved.
    const confidence: AtlasEdge["confidence"] = kind === "calls" ? "inferred" : "resolved";
    edges.push({ id: e.id, from: e.source, to: e.target, kind, evidence: { ...from.evidence }, confidence });
  }

  const diagnostics = g.diagnostics.map((d) => ({ path: d.file ?? "", message: d.message }));
  const functionCalls = new Map<string, string[]>(Object.entries(g.callTokens ?? {}));
  return { graph: { version: "ts-0.1", revision, nodes, edges, diagnostics }, functionSources, functionCalls };
}
