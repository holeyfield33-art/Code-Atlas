#!/usr/bin/env node
/**
 * Code Atlas MCP server (stdio, or authenticated read-only Streamable HTTP with --http). Serves one bundle to an agent so it can query
 * the graph, threats, course, and pull minimal source — instead of loading the
 * whole repo into context.
 *
 *   code-atlas-mcp --bundle atlas.bundle.json
 *
 * Agent config:
 *   { "mcpServers": { "code-atlas": { "command": "code-atlas-mcp",
 *       "args": ["--bundle", "atlas.bundle.json"] } } }
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { parseBundle, type AtlasBundle } from "../schema.js";
import { AtlasTools, bundleId } from "./tools.js";
import { writeFileAtomic } from "../atomicWrite.js";
import { applyDisposition, DISPOSITION_STATUSES } from "../triage.js";
import { runAtlasExec } from "./sandbox.js";

function bundlePath(argv: string[]): string {
  const i = argv.indexOf("--bundle");
  const path = i >= 0 ? argv[i + 1] : process.env.ATLAS_BUNDLE;
  if (!path) throw new Error("Pass --bundle <atlas.bundle.json> or set ATLAS_BUNDLE");
  return path;
}

const ok = (data: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(data) }] });
const RO = { readOnlyHint: true, openWorldHint: false };

/** Mutable server context: the current tools view, plus a triage op that persists
 *  back to the bundle file and refreshes the view so later reads reflect it. A
 *  `path` of null means in-memory only (tests) — triage still works, just no write. */
export interface AtlasCtx {
  tools: AtlasTools;
  /** Stable id of the loaded bundle, for replayable receipts. */
  bundleHash: string;
  triage(findingId: string, status: string, by: string, note?: string): unknown;
}

// bundleId lives in tools.ts (shared by the context-pack and atlas_exec receipts).
export { bundleId };

export function makeCtx(bundle: AtlasBundle, path: string | null): AtlasCtx {
  const ctx: AtlasCtx = {
    tools: new AtlasTools(bundle),
    bundleHash: bundleId(bundle),
    triage(findingId, status, by, note) {
      const updated = applyDisposition(bundle, findingId, { status: status as any, by, note });
      // Persist FIRST: if the write throws (read-only bundle, full disk), the
      // in-memory state must NOT advance, or a later successful triage could
      // silently commit this failed decision. Commit only after the write.
      if (path) writeFileAtomic(path, JSON.stringify(updated, null, 2));
      bundle = updated;                       // commit the in-memory bundle
      ctx.tools = new AtlasTools(updated);    // refresh reads from the committed value
      ctx.bundleHash = bundleId(updated);     // and the exec receipt id, so replay reflects the new state
      const f = (updated.findings ?? []).find((x) => x.id === findingId)!;
      return { ok: true, persisted: Boolean(path), finding: { id: f.id, title: f.title, grade: f.grade, disposition: f.disposition } };
    },
  };
  return ctx;
}

export interface BuildServerOptions {
  /** Register `atlas_triage` (the only tool that WRITES). Default true for local stdio,
   *  where the user owns the bundle; the HTTP transport passes false unless the operator
   *  opts in with --allow-triage, so a remote credential is read-only by default. */
  allowTriage?: boolean;
}

/** Sent to every client at connect time, so an agent knows how to use the tools without being taught. */
const AGENT_GUIDE = [
  "Code Atlas is a STATIC, source-linked map of one codebase. It reads code; it never runs it or contacts the target.",
  "",
  "Start: atlas_overview. Read `repository` (label, sourceCommit) and `coverage`: the map may be PARTIAL (a file cap, a shard of a large repo, skipped folders). A file that is not found may simply not be in this map, so check coverage before concluding it does not exist. The sourceCommit says which checkout was scanned; compare it with the instance you are testing.",
  "Find things: atlas_search takes identifier-like words or path fragments ('rotate_service', 'lib/api/projects', 'zoekt cache'), not sentences. It returns ids and locations only. Then atlas_get_source for the code, atlas_neighbors for callers / callees / imports.",
  "Many questions at once: atlas_exec runs read-only JavaScript against the map in one call. Beyond search/neighbors it has atlas.findings({kind, rule, path, limit}) to list findings, and atlas.routes({method, path, file}) to list the HTTP routes found in JS/TS code with their handlers. Prefer one atlas_exec join over many tool calls.",
  "",
  "Honesty rules: a finding is a STATIC lead (a risky shape), never proof of a vulnerability. Python and Ruby call edges are matched by name and marked inferred. Unresolved relationships are diagnostics, not edges. Absence of a finding is not evidence of safety. Routes cover JS/TS only, and a mount prefix is not applied.",
  "If the code you need is not in the map, read it from the source checkout instead; do not guess.",
].join("\n");

export function buildServer(ctx: AtlasCtx, opts: BuildServerOptions = {}): McpServer {
  const server = new McpServer({ name: "code-atlas", version: "0.1.0" }, { instructions: AGENT_GUIDE });

  server.registerTool("atlas_overview",
    { title: "Repository overview", description: "Orientation: counts, entry points, and the threat summary. Call this first.", inputSchema: {}, annotations: RO },
    async () => ok(ctx.tools.overview()));

  server.registerTool("atlas_search",
    { title: "Find components", description: "Find files/functions by identifier-like words or path fragments (e.g. 'rotate_service', 'lib/api/projects'); filler words are ignored and nodes matching more of the words rank first. Returns ids + locations only (no source) so you can target a follow-up.", inputSchema: { query: z.string(), limit: z.number().int().min(1).max(50).optional() }, annotations: RO },
    async ({ query, limit }) => ok(ctx.tools.search(query, limit)));

  server.registerTool("atlas_get_node",
    { title: "Inspect a component", description: "One node with its neighbors (ids+labels) and flags. Compact — does NOT include source; use atlas_get_source for that.", inputSchema: { id: z.string() }, annotations: RO },
    async ({ id }) => ok(ctx.tools.getNode(id)));

  server.registerTool("atlas_get_source",
    { title: "Read source", description: "The source of ONE node (a function's body or a file head). Pull this only when you actually need the code. If the node lies past the inlined prefix of a large file, returns error + reason instead of empty text.", inputSchema: { id: z.string() }, annotations: RO },
    async ({ id }) => ok(ctx.tools.getSource(id)));

  server.registerTool("atlas_neighbors",
    { title: "Local subgraph", description: "A node's callers/callees/imports as ids+labels, to traverse the graph without reading source.", inputSchema: { id: z.string(), kinds: z.array(z.enum(["calls", "calledBy", "imports"])).optional() }, annotations: RO },
    async ({ id, kinds }) => ok(ctx.tools.neighbors(id, kinds)));

  server.registerTool("atlas_context_pack",
    { title: "Minimal context for a task", description: "Horos-style: given a task, selects the minimal source-backed set of components (entrypoint match + bounded graph walk) and returns a replayable receipt. budgetTokens bounds the WHOLE response (metadata + source); lower-ranked matches are counted in `omitted`. Use this to load only what a task needs.", inputSchema: { task: z.string(), budgetTokens: z.number().int().min(200).max(20000).optional() }, annotations: RO },
    async ({ task, budgetTokens }) => ok(ctx.tools.contextPack(task, budgetTokens)));

  server.registerTool("atlas_threats",
    { title: "Threats for a component", description: "Findings (with grade, ASI reference, and any triage disposition) on a node id or file path, plus any external overlay `leads` (hypotheses, never findings). Grade reflects how it was verified; absence is not proof of safety.", inputSchema: { ref: z.string() }, annotations: RO },
    async ({ ref }) => ok(ctx.tools.threats(ref)));

  server.registerTool("atlas_threat_leads",
    {
      title: "List overlay leads",
      description: "Resolved external-overlay leads without knowing a node id or path first — e.g. \"review all overlay leads\". Compact rows with node references; filter by attack class, status, confidence, or a path fragment. Leads are hypotheses, never findings.",
      inputSchema: {
        attackClassId: z.string().optional(), status: z.string().optional(), confidence: z.string().optional(),
        path: z.string().optional(), limit: z.number().int().min(1).max(1000).optional(),
      },
      annotations: RO,
    },
    async (filter) => ok(ctx.tools.threatLeads(filter)));

  server.registerTool("atlas_course",
    { title: "Lesson for a component", description: "The grounded lesson + Break & Fix attached to a node, if any.", inputSchema: { id: z.string() }, annotations: RO },
    async ({ id }) => ok(ctx.tools.course(id)));

  if (opts.allowTriage !== false) server.registerTool("atlas_triage",
    {
      title: "Disposition a finding",
      description: "Record a triage decision on a finding: confirmed | false_positive | accepted_risk, with who made the call and an optional note. Persists to the bundle. A disposition NEVER upgrades the grade; false_positive drops the finding's colour + blast, accepted_risk stops it casting a blast.",
      inputSchema: {
        findingId: z.string(),
        status: z.enum(DISPOSITION_STATUSES as unknown as [string, ...string[]]),
        by: z.string().describe("who made the call — a human handle or agent name"),
        note: z.string().optional().describe("rationale for the decision"),
      },
      // NOT idempotent: each call stamps a fresh `at` and rewrites the bundle, so
      // a retry would replace the original decision time. No idempotentHint.
      annotations: { readOnlyHint: false, openWorldHint: false },
    },
    async ({ findingId, status, by, note }) => {
      try { return ok(ctx.triage(findingId, status, by, note)); }
      catch (e) { return ok({ ok: false, error: String(e instanceof Error ? e.message : e) }); }
    });

  server.registerTool("atlas_exec",
    {
      title: "Run a read-only query against the atlas",
      description:
        "ONE programmable read tool. Write JavaScript that calls a frozen, read-only `atlas` API and `return`s a value — filter, join, aggregate, or traverse in a single call instead of chaining fixed tools. " +
        "Available (all read-only): atlas.overview(), atlas.search(query, limit?), atlas.getNode(id), atlas.getSource(id), atlas.neighbors(id, kinds?), atlas.contextPack(task, budgetTokens?), atlas.threats(ref), atlas.findings({kind?, grade?, rule?, path?, triaged?, limit?}) (list findings without knowing an id), atlas.threatLeads({attackClassId?, status?, confidence?, path?, limit?}) (list resolved overlay leads without knowing an id), atlas.routes({method?, path?, file?, limit?}) (HTTP routes found in JS/TS code, with their handlers and leads), atlas.course(id). " +
        "The code runs in an isolate with NO network, filesystem, require, import, process, or timers — only `atlas`. There is no way to write or mutate the bundle from here. A wall-clock timeout and memory cap bound every run, and the response carries a replayable receipt (sha256 of code + bundle). " +
        "Example: `const o = atlas.overview(); return o.entryPoints.map(e => ({ id: e.id, threats: atlas.threats(e.id).findings.length }));`",
      inputSchema: {
        code: z.string().describe("JavaScript body that uses `atlas` and returns a JSON-serializable value. Top-level `return` is supported."),
      },
      annotations: RO,
    },
    async ({ code }) => ok(runAtlasExec(ctx.tools, code, ctx.bundleHash)));

  return server;
}

async function main() {
  const args = process.argv.slice(2);
  const path = bundlePath(args);
  const bundle = parseBundle(JSON.parse(readFileSync(path, "utf8")));
  const ctx = makeCtx(bundle, path);

  if (args.includes("--http")) {
    // Imported lazily: http.ts imports buildServer from this module.
    const { startHttpServer, httpOptionsFromArgs } = await import("./http.js");
    const options = httpOptionsFromArgs(args, process.env);
    const httpServer = await startHttpServer(ctx, options);
    const where = `http://${options.host}:${(httpServer.address() as { port: number }).port}/mcp`;
    console.error(`code-atlas MCP server ready (Streamable HTTP at ${where}; ${options.allowTriage ? "READ+TRIAGE" : "read-only"})`);
    const shutdown = () => { httpServer.close((e) => { if (e) { console.error("MCP HTTP shutdown failed:", e); process.exitCode = 1; } }); };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
    return;
  }

  const server = buildServer(ctx);
  await server.connect(new StdioServerTransport());
  // stderr is safe for logs on stdio transport (stdout is the protocol channel)
  console.error("code-atlas MCP server ready (stdio)");
}

// Run only when invoked directly.
// Compare as file URLs: `file://${argv[1]}` is wrong on Windows (backslashes, drive letter).
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((e) => { console.error(String(e)); process.exit(1); });
}
