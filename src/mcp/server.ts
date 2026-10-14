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
import { readFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { parseBundle } from "../schema.js";
import { AtlasTools } from "./tools.js";

function loadBundle(argv: string[]) {
  const i = argv.indexOf("--bundle");
  const path = i >= 0 ? argv[i + 1] : process.env.ATLAS_BUNDLE;
  if (!path) throw new Error("Pass --bundle <atlas.bundle.json> or set ATLAS_BUNDLE");
  return parseBundle(JSON.parse(readFileSync(path, "utf8")));
}

const ok = (data: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(data) }] });
const RO = { readOnlyHint: true, openWorldHint: false };

export function buildServer(tools: AtlasTools): McpServer {
  const server = new McpServer({ name: "code-atlas", version: "0.1.0" });

  server.registerTool("atlas_overview",
    { title: "Repository overview", description: "Orientation: counts, entry points, and the threat summary. Call this first.", inputSchema: {}, annotations: RO },
    async () => ok(tools.overview()));

  server.registerTool("atlas_search",
    { title: "Find components", description: "Find files/functions by words. Returns ids + locations only (no source) so you can target a follow-up.", inputSchema: { query: z.string(), limit: z.number().int().min(1).max(50).optional() }, annotations: RO },
    async ({ query, limit }) => ok(tools.search(query, limit)));

  server.registerTool("atlas_get_node",
    { title: "Inspect a component", description: "One node with its neighbors (ids+labels) and flags. Compact — does NOT include source; use atlas_get_source for that.", inputSchema: { id: z.string() }, annotations: RO },
    async ({ id }) => ok(tools.getNode(id)));

  server.registerTool("atlas_get_source",
    { title: "Read source", description: "The source of ONE node (a function's body or a file head). Pull this only when you actually need the code.", inputSchema: { id: z.string() }, annotations: RO },
    async ({ id }) => ok(tools.getSource(id)));

  server.registerTool("atlas_neighbors",
    { title: "Local subgraph", description: "A node's callers/callees/imports as ids+labels, to traverse the graph without reading source.", inputSchema: { id: z.string(), kinds: z.array(z.enum(["calls", "calledBy", "imports"])).optional() }, annotations: RO },
    async ({ id, kinds }) => ok(tools.neighbors(id, kinds)));

  server.registerTool("atlas_context_pack",
    { title: "Minimal context for a task", description: "Horos-style: given a task, selects the minimal source-backed set of components (entrypoint match + bounded graph walk + token budget) and returns a replayable receipt. Use this to load only what a task needs.", inputSchema: { task: z.string(), budgetTokens: z.number().int().min(200).max(20000).optional() }, annotations: RO },
    async ({ task, budgetTokens }) => ok(tools.contextPack(task, budgetTokens)));

  server.registerTool("atlas_threats",
    { title: "Threats for a component", description: "Findings (with grade + ASI reference) on a node id or file path. Grade reflects how it was verified; absence is not proof of safety.", inputSchema: { ref: z.string() }, annotations: RO },
    async ({ ref }) => ok(tools.threats(ref)));

  server.registerTool("atlas_course",
    { title: "Lesson for a component", description: "The grounded lesson + Break & Fix attached to a node, if any.", inputSchema: { id: z.string() }, annotations: RO },
    async ({ id }) => ok(tools.course(id)));

  return server;
}

async function main() {
  const tools = new AtlasTools(loadBundle(process.argv.slice(2)));
  const server = buildServer(tools);
  await server.connect(new StdioServerTransport());
  // stderr is safe for logs on stdio transport (stdout is the protocol channel)
  console.error("code-atlas MCP server ready (stdio)");
}

// Run only when invoked directly.
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { console.error(String(e)); process.exit(1); });
}
