#!/usr/bin/env node
/**
 * code-atlas CLI.
 *   build [path]   scan a repo -> atlas.bundle.json + a self-contained viewer.html
 * Local, no server. The language backend (Babel) is swappable behind the graph.
 */
import { Command } from "commander";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { scanWorkspace, readSource } from "./scanner/treeScanner.js";
import { buildGraph } from "./scanner/graph.js";
import { scan, ingestVibeExplainer } from "./scanner/findings.js";
import { DEFAULT_RULES, validateRules } from "./scanner/rules.js";
import { generateCourse, assembleBundle } from "./generator/generator.js";

const here = dirname(fileURLToPath(import.meta.url));
const viewerPath = resolve(here, "../viewer/viewer.html");

const program = new Command();
program
  .name("code-atlas")
  .description("Source-grounded 3D code map + grounded Break & Fix course.")
  .version("0.1.0");

program
  .command("build")
  .description("Scan a repo and write atlas.bundle.json + a self-contained viewer.")
  .argument("[path]", "repository path", ".")
  .option("-o, --out <dir>", "output directory", "atlas")
  .option("--product <name>", "product name shown in the viewer", "Code Atlas")
  .option("--rules <file>", "custom rule pack (JSON) for the findings scanner")
  .option("--findings-report <file>", "a vibe-explainer --json report to map onto the graph")
  .option("--no-security", "skip the findings scanner")
  .action((path: string, opts: { out: string; product: string; rules?: string; findingsReport?: string; security: boolean }) => {
    const root = resolve(path);
    const label = basename(root);
    const revision = label + "@" + new Date().toISOString().slice(0, 10);

    const scanned = scanWorkspace(root);
    const sources = scanned.files.map((f) => ({ path: f.relativePath, code: readSource(f.absolutePath) }));
    if (!sources.length) { console.error("No JS/TS files found under " + root); process.exit(1); }

    const graph = buildGraph(revision, sources);
    const course = generateCourse(graph, sources, { product: opts.product, repoLabel: label });
    let security: { findings?: any[]; asiSnapshot?: any } | undefined;
    if (opts.security !== false) {
      const rules = opts.rules ? validateRules(JSON.parse(readFileSync(opts.rules, "utf8"))) : DEFAULT_RULES;
      security = scan(graph, sources, rules);
      if (opts.findingsReport) {
        const ve = ingestVibeExplainer(JSON.parse(readFileSync(opts.findingsReport, "utf8")), graph);
        security = {
          findings: [...(security.findings ?? []), ...ve.findings],
          asiSnapshot: ve.asiSnapshot ?? security.asiSnapshot,
        };
        if (ve.unmapped.length) console.log(`  (${ve.unmapped.length} report scenarios did not map to a graph file)`);
      }
    }
    // Inline source so the local viewer can show code offline (per-file cap keeps the bundle sane).
    const MAX_SRC = 40_000;
    const inlined = sources.map((s) => ({ path: s.path, code: s.code.length > MAX_SRC ? s.code.slice(0, MAX_SRC) + "\n/* … truncated … */" : s.code }));
    const bundle = assembleBundle(graph, course, { product: opts.product, repoLabel: label }, security, inlined);

    mkdirSync(opts.out, { recursive: true });
    writeFileSync(join(opts.out, "atlas.bundle.json"), JSON.stringify(bundle, null, 2));

    let viewer: string;
    try { viewer = readFileSync(viewerPath, "utf8"); }
    catch { console.error("Viewer template not found at " + viewerPath); process.exit(1); }
    viewer = viewer.replace("/*__ATLAS_BUNDLE__*/ null", JSON.stringify(bundle));
    writeFileSync(join(opts.out, "viewer.html"), viewer);

    const fns = graph.nodes.filter((n) => n.kind === "function").length;
    const nf = security?.findings?.length ?? 0;
    console.log(`Wrote ${join(opts.out, "atlas.bundle.json")} and ${join(opts.out, "viewer.html")}`);
    console.log(`  ${graph.nodes.length} nodes (${fns} functions), ${graph.edges.length} edges, ` +
      `${course.lessons.length} lessons, ${nf} findings, ${graph.diagnostics.length} diagnostics`);
    console.log(`  Open ${join(opts.out, "viewer.html")} in a browser.`);
  });

program.parse();
