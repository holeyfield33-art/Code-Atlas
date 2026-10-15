/**
 * The build pipeline (no CLI/IO concerns): scan a repo, route files to the Babel
 * (JS/TS) and tree-sitter (Python/Ruby) backends, merge into one AtlasGraph, run
 * the course + native findings over the JS/TS slice, and assemble a bundle.
 * The CLI wraps this with file writes + the viewer; tests call it directly.
 */
import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { scanWorkspace, readSource } from "./scanner/treeScanner.js";
import { buildGraph } from "./scanner/graph.js";
import { scan, ingestVibeExplainer } from "./scanner/findings.js";
import { DEFAULT_RULES, validateRules } from "./scanner/rules.js";
import { redactSecrets } from "./scanner/redact.js";
import { buildMultiLangGraph, type MultiLang } from "./scanner/multilang.js";
import { generateCourse, assembleBundle } from "./generator/generator.js";
import type { AtlasGraph, AtlasBundle } from "./schema.js";

export interface BuildOptions { product?: string; rules?: string; findingsReport?: string; security?: boolean; }
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

export async function buildAtlas(rootInput: string, opts: BuildOptions = {}): Promise<BuildResult> {
  const product = opts.product ?? "Code Atlas";
  const root = resolve(rootInput);
  const label = basename(root);
  const revision = label + "@" + new Date().toISOString().slice(0, 10);

  const scanned = scanWorkspace(root);
  if (!scanned.files.length) throw new Error("No supported source files (JS/TS, Python, Ruby) found under " + root);

  const byLang = { js: [] as typeof scanned.files, python: [] as typeof scanned.files, ruby: [] as typeof scanned.files };
  for (const f of scanned.files) byLang[f.language].push(f);
  const srcMap = (fs: typeof scanned.files) => new Map(fs.map((f) => [f.relativePath, readSource(f.absolutePath)]));

  const jsSources = byLang.js.map((f) => ({ path: f.relativePath, code: readSource(f.absolutePath) }));
  const graphs: AtlasGraph[] = [];
  if (jsSources.length) graphs.push(buildGraph(revision, jsSources));

  const perLangCounts: Record<string, number> = {};
  for (const lang of ["python", "ruby"] as MultiLang[]) {
    const files = byLang[lang];
    if (!files.length) continue;
    perLangCounts[lang] = files.length;
    graphs.push(await buildMultiLangGraph(lang, srcMap(files), revision, "."));
  }

  const graph = mergeGraphs(revision, graphs);

  // Course + native findings run over the JS/TS slice (Babel-grounded).
  const course = generateCourse(graph, jsSources, { product, repoLabel: label });
  let security: { findings?: any[]; asiSnapshot?: any } | undefined;
  let unmappedReport = 0;
  if (opts.security !== false) {
    const rules = opts.rules ? validateRules(JSON.parse(readFileSync(opts.rules, "utf8"))) : DEFAULT_RULES;
    security = scan(graph, jsSources, rules);
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
    const capped = raw.length > MAX_SRC ? raw.slice(0, MAX_SRC) + "\n/* … truncated … */" : raw;
    const { code, redactions } = redactSecrets(capped);
    redactionCount += redactions;
    return { path: f.relativePath, code };
  });

  const bundle = assembleBundle(graph, course, { product, repoLabel: label }, security, inlined);
  const langSummary = [
    byLang.js.length ? `${byLang.js.length} js/ts` : "",
    ...Object.entries(perLangCounts).map(([l, c]) => `${c} ${l}`),
  ].filter(Boolean).join(", ");

  return { bundle, langSummary, redactionCount, findingsCount: security?.findings?.length ?? 0, unmappedReport };
}
