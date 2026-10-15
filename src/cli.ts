#!/usr/bin/env node
/**
 * code-atlas CLI.
 *   build [path]   scan a repo -> atlas.bundle.json + a self-contained viewer.html
 * Local, no server. Two graph backends sit behind one AtlasGraph seam: Babel for
 * JS/TS, tree-sitter for Python/Ruby. Pipeline lives in build.ts; this adds IO.
 */
import { Command } from "commander";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildAtlas } from "./build.js";

const here = dirname(fileURLToPath(import.meta.url));
const viewerPath = resolve(here, "../viewer/viewer.html");
const rendererPath = resolve(here, "../viewer/vendor/3d-force-graph.min.js");

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
  .action(async (path: string, opts: { out: string; product: string; rules?: string; findingsReport?: string; security: boolean }) => {
    const { bundle, langSummary, redactionCount, findingsCount, unmappedReport } =
      await buildAtlas(path, { product: opts.product, rules: opts.rules, findingsReport: opts.findingsReport, security: opts.security });

    mkdirSync(opts.out, { recursive: true });
    writeFileSync(join(opts.out, "atlas.bundle.json"), JSON.stringify(bundle, null, 2));

    let viewer: string;
    try { viewer = readFileSync(viewerPath, "utf8"); }
    catch { console.error("Viewer template not found at " + viewerPath); process.exit(1); }
    let renderer: string;
    try { renderer = readFileSync(rendererPath, "utf8"); }
    catch { console.error("Vendored renderer not found at " + rendererPath); process.exit(1); }
    // Bundle the renderer in (no CDN) and inject the bundle as inert JSON (escape
    // "</script" and use function replacers so source can't break out or be mangled).
    renderer = renderer.replace(/<\/script/gi, "<\\/script");
    viewer = viewer.replace("/*__ATLAS_RENDERER__*/", () => renderer);
    const bundleJson = JSON.stringify(bundle).replace(/</g, "\\u003c");
    viewer = viewer.replace("/*__ATLAS_BUNDLE_JSON__*/", () => bundleJson);
    writeFileSync(join(opts.out, "viewer.html"), viewer);

    const g = bundle.graph;
    const fns = g.nodes.filter((n) => n.kind === "function").length;
    if (unmappedReport) console.log(`  (${unmappedReport} report scenarios did not map to a graph file)`);
    console.log(`Wrote ${join(opts.out, "atlas.bundle.json")} and ${join(opts.out, "viewer.html")}`);
    console.log(`  files: ${langSummary}`);
    console.log(`  ${g.nodes.length} nodes (${fns} functions), ${g.edges.length} edges, ` +
      `${bundle.course?.lessons.length ?? 0} lessons, ${findingsCount} findings, ${g.diagnostics.length} diagnostics`);
    if (redactionCount) console.log(`  redacted ${redactionCount} secret-like value(s) from inlined source`);
    console.log(`  Open ${join(opts.out, "viewer.html")} in a browser.`);
  });

program.parseAsync().catch((e) => { console.error(String(e?.stack || e)); process.exit(1); });
