#!/usr/bin/env node
/**
 * Code Atlas MCP server (stdio). Serves one bundle to an agent so it can query
 * the graph, threats, course, and pull minimal source — instead of loading the
 * whole repo into context.
 *
 *   code-atlas-mcp --bundle atlas.bundle.json
 *
 * Agent config:
 *   { "mcpServers": { "code-atlas": { "command": "code-atlas-mcp",
 *       "args": ["--bundle", "atlas.bundle.json"] } } }
 */
import { readFileSync, writeFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { parseBundle, type AtlasBundle } from "../schema.js";
import { AtlasTools } from "./tools.js";
import { applyDisposition, DISPOSITION_STATUSES } from "../triage.js";

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
  triage(findingId: string, status: string, by: string, note?: string): unknown;
}

export function makeCtx(bundle: AtlasBundle, path: string | null): AtlasCtx {
  const ctx: AtlasCtx = {
    tools: new AtlasTools(bundle),
    triage(findingId, status, by, note) {
      const updated = applyDisposition(bundle, findingId, { status: status as any, by, note });
      bundle = updated;                       // advance the in-memory bundle
      if (path) writeFileSync(path, JSON.stringify(updated, null, 2));  // persist
      ctx.tools = new AtlasTools(updated);    // refresh reads
      const f = (updated.findings ?? []).find((x) => x.id === findingId)!;
      return { ok: true, persisted: Boolean(path), finding: { id: f.id, title: f.title, grade: f.grade, disposition: f.disposition } };
    },
  };
  return ctx;
}

export function buildServer(ctx: AtlasCtx): McpServer {
  const server = new McpServer({ name: "code-atlas", version: "0.1.0" });

  server.registerTool("atlas_overview",
    { title: "Repository overview", description: "Orientation: counts, entry points, and the threat summary. Call this first.", inputSchema: {}, annotations: RO },
    async () => ok(ctx.tools.overview()));

  server.registerTool("atlas_search",
    { title: "Find components", description: "Find files/functions by words. Returns ids + locations only (no source) so you can target a follow-up.", inputSchema: { query: z.string(), limit: z.number().int().min(1).max(50).optional() }, annotations: RO },
    async ({ query, limit }) => ok(ctx.tools.search(query, limit)));

  server.registerTool("atlas_get_node",
    { title: "Inspect a component", description: "One node with its neighbors (ids+labels) and flags. Compact — does NOT include source; use atlas_get_source for that.", inputSchema: { id: z.string() }, annotations: RO },
    async ({ id }) => ok(ctx.tools.getNode(id)));

  server.registerTool("atlas_get_source",
    { title: "Read source", description: "The source of ONE node (a function's body or a file head). Pull this only when you actually need the code.", inputSchema: { id: z.string() }, annotations: RO },
    async ({ id }) => ok(ctx.tools.getSource(id)));

  server.registerTool("atlas_neighbors",
    { title: "Local subgraph", description: "A node's callers/callees/imports as ids+labels, to traverse the graph without reading source.", inputSchema: { id: z.string(), kinds: z.array(z.enum(["calls", "calledBy", "imports"])).optional() }, annotations: RO },
    async ({ id, kinds }) => ok(ctx.tools.neighbors(id, kinds)));

  server.registerTool("atlas_context_pack",
    { title: "Minimal context for a task", description: "Horos-style: given a task, selects the minimal source-backed set of components (entrypoint match + bounded graph walk + token budget) and returns a replayable receipt. Use this to load only what a task needs.", inputSchema: { task: z.string(), budgetTokens: z.number().int().min(200).max(20000).optional() }, annotations: RO },
    async ({ task, budgetTokens }) => ok(ctx.tools.contextPack(task, budgetTokens)));

  server.registerTool("atlas_threats",
    { title: "Threats for a component", description: "Findings (with grade, ASI reference, and any triage disposition) on a node id or file path. Grade reflects how it was verified; absence is not proof of safety.", inputSchema: { ref: z.string() }, annotations: RO },
    async ({ ref }) => ok(ctx.tools.threats(ref)));

  server.registerTool("atlas_course",
    { title: "Lesson for a component", description: "The grounded lesson + Break & Fix attached to a node, if any.", inputSchema: { id: z.string() }, annotations: RO },
    async ({ id }) => ok(ctx.tools.course(id)));

  server.registerTool("atlas_triage",
    {
      title: "Disposition a finding",
      description: "Record a triage decision on a finding: confirmed | false_positive | accepted_risk, with who made the call and an optional note. Persists to the bundle. A disposition NEVER upgrades the grade; false_positive drops the finding's colour + blast, accepted_risk stops it casting a blast.",
      inputSchema: {
        findingId: z.string(),
        status: z.enum(DISPOSITION_STATUSES as unknown as [string, ...string[]]),
        by: z.string().describe("who made the call — a human handle or agent name"),
        note: z.string().optional().describe("rationale for the decision"),
      },
      annotations: { readOnlyHint: false, openWorldHint: false, idempotentHint: true },
    },
    async ({ findingId, status, by, note }) => {
      try { return ok(ctx.triage(findingId, status, by, note)); }
      catch (e) { return ok({ ok: false, error: String(e instanceof Error ? e.message : e) }); }
    });

  return server;
}

async function main() {
  const path = bundlePath(process.argv.slice(2));
  const bundle = parseBundle(JSON.parse(readFileSync(path, "utf8")));
  const server = buildServer(makeCtx(bundle, path));
  await server.connect(new StdioServerTransport());
  // stderr is safe for logs on stdio transport (stdout is the protocol channel)
  console.error("code-atlas MCP server ready (stdio)");
}

// Run only when invoked directly.
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { console.error(String(e)); process.exit(1); });
}
