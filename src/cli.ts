#!/usr/bin/env node
/**
 * code-atlas CLI.
 *   build [path]   scan a repo -> atlas.bundle.json + a self-contained viewer.html
 *   serve          local browser app (loopback only) with an Open folder button
 * Local-first. Two graph backends sit behind one AtlasGraph seam: Babel for
 * JS/TS, tree-sitter for Python/Ruby. Pipeline lives in build.ts; this adds IO.
 */
import { Command } from "commander";
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { buildAtlas } from "./build.js";
import { renderViewer } from "./viewer.js";
import { serveAtlas } from "./server.js";
import { planShards } from "./scanner/shards.js";

/** Comma-separated CLI list -> trimmed non-empty entries (undefined when absent). */
const csv = (v?: string): string[] | undefined => (v ? v.split(",").map((x) => x.trim()).filter(Boolean) : undefined);

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
  .option("--max-files <n>", "max files to analyze (default 2000); omitted files are counted in coverage", (v) => parseInt(v, 10))
  .option("--max-bytes <n>", "max bytes per file (default 200000)", (v) => parseInt(v, 10))
  .option("--label <name>", "project name shown in the bundle (default: the folder name)")
  .option("--include <dirs>", "scan only these root-relative folders (comma-separated; `dir/.` = that folder's own files only); paths stay root-relative")
  .option("--skip <dirs>", "leave these out (comma-separated; a bare name such as `spec` matches at any depth, `ee/spec` is a root-relative path)")
  .action(async (path: string, opts: { out: string; product: string; rules?: string; findingsReport?: string; security: boolean; maxFiles?: number; maxBytes?: number; label?: string; include?: string; skip?: string }) => {
    const { bundle, langSummary, redactionCount, findingsCount, unmappedReport } =
      await buildAtlas(path, { product: opts.product, rules: opts.rules, findingsReport: opts.findingsReport, security: opts.security, maxFiles: opts.maxFiles, maxBytes: opts.maxBytes, repoLabel: opts.label, include: csv(opts.include), skip: csv(opts.skip) });

    mkdirSync(opts.out, { recursive: true });
    writeFileSync(join(opts.out, "atlas.bundle.json"), JSON.stringify(bundle, null, 2));

    // Renderer bundled in (no CDN); the bundle is injected as inert JSON (see viewer.ts).
    writeFileSync(join(opts.out, "viewer.html"), renderViewer(bundle));

    const g = bundle.graph;
    const fns = g.nodes.filter((n) => n.kind === "function").length;
    if (unmappedReport) console.log(`  (${unmappedReport} report scenarios did not map to a graph file)`);
    console.log(`Wrote ${join(opts.out, "atlas.bundle.json")} and ${join(opts.out, "viewer.html")}`);
    console.log(`  files: ${langSummary}`);
    console.log(`  ${g.nodes.length} nodes (${fns} functions), ${g.edges.length} edges, ` +
      `${bundle.course?.lessons.length ?? 0} lessons, ${findingsCount} findings, ${g.diagnostics.length} diagnostics`);
    if (redactionCount) console.log(`  redacted ${redactionCount} secret-like value(s) from inlined source`);
    const cov = bundle.coverage;
    if (cov) {
      const s = cov.skipped;
      // every skip reason is in the sum + the breakdown, so the line never reads
      // "analyzed N/N" while files were pruned by an ignored dir or an unreadable entry.
      const omitted = s.unsupported + s.tooLarge + s.overCap + s.symlink + s.ignoredDir + s.ignoredDirFiles + s.unreadable + (s.excluded ?? 0);
      const parts = [
        s.unsupported && `${s.unsupported} unsupported`,
        s.tooLarge && `${s.tooLarge} too-large`,
        s.overCap && `${s.overCap} over the ${cov.maxFiles}-file cap`,
        s.symlink && `${s.symlink} symlink`,
        s.ignoredDirFiles && `${s.ignoredDirFiles} in ${s.ignoredDir} ignored dir(s)`,
        s.excluded && `${s.excluded} outside --include / under --skip`,
        s.unreadable && `${s.unreadable} unreadable`,
      ].filter(Boolean).join(", ");
      console.log(`  coverage: analyzed ${cov.scannedFiles}/${cov.totalFilesSeen} walked files` + (omitted ? ` — skipped ${parts}` : ""));
      if (s.overCap) console.log(`  NOTE: ${s.overCap} supported file(s) were omitted by the --max-files cap (${cov.maxFiles}); raise it to include them.`);
    }
    console.log(`  Open ${join(opts.out, "viewer.html")} in a browser.`);
  });

program
  .command("plan")
  .description("Split a repo too large for one bundle into shards (folder groups under a file cap). Prints the plan; builds nothing.")
  .argument("[path]", "repository path", ".")
  .option("--max-files <n>", "files per shard (default 3000)", (v) => parseInt(v, 10), 3000)
  .option("--max-bytes <n>", "max bytes per file (default 200000)", (v) => parseInt(v, 10))
  .option("--skip <dirs>", "leave these out (comma-separated; same rules as build --skip)")
  .option("--json", "machine-readable output")
  .action((path: string, opts: { maxFiles: number; maxBytes?: number; skip?: string; json?: boolean }) => {
    const shards = planShards(path, { maxFiles: opts.maxFiles, maxBytes: opts.maxBytes, skip: csv(opts.skip) });
    if (opts.json) { console.log(JSON.stringify({ maxFiles: opts.maxFiles, skip: csv(opts.skip) ?? [], shards }, null, 2)); return; }
    const total = shards.reduce((n, s) => n + s.files, 0);
    console.log(`${total} analyzable files -> ${shards.length} shard(s) of up to ${opts.maxFiles}`);
    const brief = (inc: string[]) => inc.length === 0 ? "(whole tree)" : inc.length <= 4 ? inc.join(", ") : `${inc.slice(0, 4).join(", ")}  (+${inc.length - 4} more folders)`;
    for (const s of shards) console.log(`  ${String(s.index).padStart(2)}  ${String(s.files).padStart(5)} files${s.oversize ? "  (OVERSIZE: one folder is bigger than the cap)" : ""}  [${s.hint}]  ${brief(s.include)}`);
    console.log("Build one:  code-atlas build <path> --include <its folders> [--skip ...] --label <name>");
  });

program
  .command("serve")
  .description("Start the local app (127.0.0.1 only) with an Open folder button.")
  .option("-p, --port <number>", "port", "4173")
  .option("--host <address>", "interface to bind", "127.0.0.1")
  .option("--allow-remote", "permit a non-loopback bind (containers)")
  .option("--bundle <file>", "open the page on this built bundle instead of the sample (default: $ATLAS_BUNDLE)")
  .action(async (opts: { port: string; host: string; allowRemote?: boolean; bundle?: string }) => {
    const port = Number(opts.port);
    if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error("Invalid port");
    await serveAtlas(port, opts.host, Boolean(opts.allowRemote), opts.bundle ?? process.env.ATLAS_BUNDLE);
  });

// `code-atlas` with no command opens the local app.
program.action(async () => { await serveAtlas(4173, "127.0.0.1", false, process.env.ATLAS_BUNDLE); });

program.parseAsync().catch((e) => { console.error(String(e?.stack || e)); process.exit(1); });
