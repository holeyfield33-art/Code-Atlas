/**
 * The build pipeline (no CLI/IO concerns): scan a repo, route files to the Babel
 * (JS/TS) and tree-sitter (Python/Ruby) backends, merge into one AtlasGraph, run
 * the course + native findings over the JS/TS slice, and assemble a bundle.
 * The CLI wraps this with file writes + the viewer; tests call it directly.
 */
import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { scanWorkspace, readSource } from "./scanner/treeScanner.js";
import { buildGraph, type SourceFile } from "./scanner/graph.js";
import { extractRoutes } from "./scanner/routes.js";
import { scan, scanGeneric, ingestVibeExplainer } from "./scanner/findings.js";
import { DEFAULT_RULES, LANGUAGE_RULES, validateRules } from "./scanner/rules.js";
import { redactSecrets } from "./scanner/redact.js";
import { extractVueScript } from "./scanner/vue.js";
import { buildMultiLangGraph, type MultiLang } from "./scanner/multilang.js";
import { generateCourse, assembleBundle } from "./generator/generator.js";
import type { AtlasGraph, AtlasBundle } from "./schema.js";

export interface BuildOptions { product?: string; rules?: string; findingsReport?: string; security?: boolean; maxFiles?: number; maxBytes?: number; repoLabel?: string; include?: string[]; skip?: string[]; }
export interface BuildResult {
  bundle: AtlasBundle;
  langSummary: string;
  redactionCount: number;
  findingsCount: number;
  unmappedReport: number;
}

/** Concatenate backend graphs into one AtlasGraph (ids are unique per backend). */
export function mergeGraphs(revision: string, graphs: AtlasGraph[]): AtlasGraph {
  const nodes: AtlasGraph["nodes"] = [];
  const edges: AtlasGraph["edges"] = [];
  const diagnostics: AtlasGraph["diagnostics"] = [];
  const seenN = new Set<string>(), seenE = new Set<string>();
  for (const g of graphs) {
    for (const n of g.nodes) if (!seenN.has(n.id)) { seenN.add(n.id); nodes.push(n); }
    for (const e of g.edges) if (!seenE.has(e.id)) { seenE.add(e.id); edges.push(e); }
    diagnostics.push(...g.diagnostics);
  }
  return { version: graphs.length > 1 ? "mixed-0.1" : (graphs[0]?.version ?? "0.1"), revision, nodes, edges, diagnostics };
}

/** Union two ASI snapshots by class id (JS + each language pack may reference
 *  the same AAC class). Metadata (source/baseUrl) comes from the first snapshot. */
function mergeAsi(a: any, b: any): any {
  if (!a) return b;
  if (!b) return a;
  const byId = new Map<string, any>();
  for (const c of [...(a.classes ?? []), ...(b.classes ?? [])]) byId.set(c.id, c);
  return { ...a, classes: [...byId.values()] };
}

export async function buildAtlas(rootInput: string, opts: BuildOptions = {}): Promise<BuildResult> {
  const product = opts.product ?? "Code Atlas";
  const root = resolve(rootInput);
  const label = opts.repoLabel ?? basename(root);
  const revision = label + "@" + new Date().toISOString().slice(0, 10);

  const scanned = scanWorkspace(root, { maxFiles: opts.maxFiles, maxBytes: opts.maxBytes, include: opts.include, skip: opts.skip });
  if (!scanned.files.length) throw new Error("No supported source files (JS/TS, Python, Ruby) found under " + root);

  const byLang = {
    js: [] as typeof scanned.files,
    python: [] as typeof scanned.files,
    ruby: [] as typeof scanned.files,
    vue: [] as typeof scanned.files,
  };
  for (const f of scanned.files) byLang[f.language].push(f);
  const srcMap = (fs: typeof scanned.files) => new Map(fs.map((f) => [f.relativePath, readSource(f.absolutePath)]));

  const jsSources: SourceFile[] = byLang.js.map((f) => ({ path: f.relativePath, code: readSource(f.absolutePath) }));
  // A .vue SFC routes its <script> block to the Babel backend via a position-
  // preserving shim, so node line/columns map to the real .vue (the inlined
  // source below is the real file). A component with no <script> is skipped.
  for (const f of byLang.vue) {
    const real = readSource(f.absolutePath);
    const shim = extractVueScript(real);
    // Parse the shim, but hash the REAL SFC: evidence.path + the inlined source
    // point at the real .vue, so contentHash must identify the real source.
    if (shim) jsSources.push({ path: f.relativePath, code: shim, hashCode: real });
  }
  const graphs: AtlasGraph[] = [];
  if (jsSources.length) graphs.push(buildGraph(revision, jsSources));

  const perLangCounts: Record<string, number> = {};
  // Per-non-JS-language function bodies + parsed call tokens, for the rule engine.
  const langFnSources: Array<{ lang: MultiLang; functionSources: Map<string, string>; functionCalls: Map<string, string[]> }> = [];
  for (const lang of ["python", "ruby"] as MultiLang[]) {
    const files = byLang[lang];
    if (!files.length) continue;
    perLangCounts[lang] = files.length;
    const built = await buildMultiLangGraph(lang, srcMap(files), revision, ".");
    graphs.push(built.graph);
    langFnSources.push({ lang, functionSources: built.functionSources, functionCalls: built.functionCalls });
  }

  const graph = mergeGraphs(revision, graphs);

  // Course: Babel-grounded lessons over the JS/TS slice PLUS language-agnostic
  // broken_call_edge lessons over the non-JS function bodies (same grounding).
  const genericBodies = new Map<string, string>();
  const genericCalls = new Map<string, string[]>();
  for (const { functionSources, functionCalls } of langFnSources) {
    for (const [id, body] of functionSources) genericBodies.set(id, body);
    for (const [id, calls] of functionCalls) genericCalls.set(id, calls);
  }
  const course = generateCourse(graph, jsSources, { product, repoLabel: label, genericBodies, genericCalls });
  // Native findings run over the JS/TS slice AND each non-JS slice via its
  // language rule pack — all STATIC leads, grade-gated blast radius, same grounding.
  let security: { findings?: any[]; asiSnapshot?: any } | undefined;
  let unmappedReport = 0;
  if (opts.security !== false) {
    const rules = opts.rules ? validateRules(JSON.parse(readFileSync(opts.rules, "utf8"))) : DEFAULT_RULES;
    security = scan(graph, jsSources, rules);
    // A custom pack (opts.rules) replaces the JS defaults only; the language
    // packs are built-in and always applied to their backend's nodes.
    for (const { lang, functionSources, functionCalls } of langFnSources) {
      const pack = LANGUAGE_RULES[lang];
      if (!pack || !functionSources.size) continue;
      const r = scanGeneric(graph, functionSources, functionCalls, pack);
      security = {
        findings: [...(security.findings ?? []), ...r.findings],
        asiSnapshot: mergeAsi(security.asiSnapshot, r.asiSnapshot),
      };
    }
    if (opts.findingsReport) {
      const ve = ingestVibeExplainer(JSON.parse(readFileSync(opts.findingsReport, "utf8")), graph);
      security = { findings: [...(security.findings ?? []), ...ve.findings], asiSnapshot: ve.asiSnapshot ?? security.asiSnapshot };
      unmappedReport = ve.unmapped.length;
    }
  }

  // Inline + redact every scanned file's source (all languages) for the viewer.
  const MAX_SRC = 40_000;
  let redactionCount = 0;
  const inlined = scanned.files.map((f) => {
    const raw = readSource(f.absolutePath);
    // Cut at a line boundary so every inlined line is a whole source line; record
    // the truncation so consumers can say "not inlined" instead of returning "".
    const truncated = raw.length > MAX_SRC;
    const cut = raw.lastIndexOf("\n", MAX_SRC);
    const capped = truncated ? raw.slice(0, cut > 0 ? cut : MAX_SRC) : raw;
    const { code, redactions } = redactSecrets(capped);
    redactionCount += redactions;
    return truncated ? { path: f.relativePath, code, truncated } : { path: f.relativePath, code };
  });

  const bundle = assembleBundle(graph, course, { product, repoLabel: label }, security, inlined, scanned.coverage);
  // HTTP routes registered in JS/TS code (not .vue shims): the link from the map to live traffic.
  const routes = extractRoutes(revision, jsSources.filter((s) => !s.hashCode), graph);
  if (routes.length) bundle.routes = routes;
  const langSummary = [
    byLang.js.length ? `${byLang.js.length} js/ts` : "",
    byLang.vue.length ? `${byLang.vue.length} vue` : "",
    ...Object.entries(perLangCounts).map(([l, c]) => `${c} ${l}`),
  ].filter(Boolean).join(", ");

  return { bundle, langSummary, redactionCount, findingsCount: security?.findings?.length ?? 0, unmappedReport };
}
