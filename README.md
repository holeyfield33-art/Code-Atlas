# Code Atlas

Turn a repository into a **source-grounded 3D code map** and a **grounded Break & Fix course** — one local command, one self-contained viewer, no server.

> The viewer is **self-contained**: the graph, course, and source are inlined as
> local data, and the 3D rendering library (`3d-force-graph` 1.76.0, MIT) is
> bundled into the file itself — **no CDN and no external script execution**, so a
> generated viewer runs fully offline. (It still links Google Fonts for
> typography; that's a cosmetic request that cannot read page data and falls back
> to system fonts with no network.)

> Working name. The product name is not hardcoded: it is read from the bundle and set with `--product`.

## What it does

```bash
npm install
npm run build
node dist/cli.js build .            # scan this repo
# or in dev:  npm run dev -- build .
open atlas/viewer.html              # double-click — the 3D map + course
```

`build` scans the repo, builds a call/import graph with Babel, generates grounded exercises, and writes:

- `atlas/atlas.bundle.json` — the graph + course, validated against the schema.
- `atlas/viewer.html` — the 3D viewer with the bundle inlined as local data (the
  bundle is injected as inert JSON and parsed, never executed). Secret-like values
  in inlined source are redacted on a **best-effort, pattern-based** basis, and any
  function whose source carries a secret is dropped from the course rather than
  shown. This is a safeguard, not a guarantee: a generated viewer still carries
  real source, so review it before sharing a repo you consider private.

## How it stays honest

- **Every graph edge carries evidence** (path, line, content hash). Anything the
  analyzer can't resolve becomes a *diagnostic*, never a fabricated edge.
- **Every Break & Fix is a reversible mutation of real code.** The `solution` is
  the original source (its sha256 is recorded); the `broken` is that source with
  a defect applied. The generator cannot invent a defect in code that doesn't exist.
- **Every exercise is verified solvable**: its checks fail on the broken code and
  pass on the solution. The test suite asserts this on the repo's own source.

## Layout

```
src/
  schema.ts            the bundle + course contract (Zod + types) — source of truth
  scanner/
    treeScanner.ts     dependency-free workspace walker
    graph.ts           JS/TS graph builder (Babel; swappable for tree-sitter at hosting)
  generator/
    generator.ts       grounded Break & Fix generator + bundle assembler
  cli.ts               the `build` command
viewer/viewer.html     the 3D viewer template (3d-force-graph, MIT)
tests/                 schema validation + dogfood generator proof
```

## Scope (v1)

JS/TS only (Babel). Defect kinds: `removed_guard`, `broken_call_edge` — the
structure takes the other four (`swapped_condition`, `missing_import`,
`wrong_target`, `order_violation`). Security (threat-map colors) and the
plain-language blurb layer are reserved slots in the schema, built later.

## Credits

3D rendering: [3d-force-graph](https://github.com/vasturiano/3d-force-graph) (MIT).
Rendering techniques adapted from InsideAI. Code Atlas is Apache-2.0 licensed.

## MCP server — give an agent the graph (save context)

Instead of loading a whole repo into an agent's context, serve the bundle over MCP
and let the agent pull only what it needs — modeled on Horos's deterministic
context routing, over our richer graph.

```bash
code-atlas build .                       # produce atlas/atlas.bundle.json
code-atlas-mcp --bundle atlas/atlas.bundle.json
```

Agent config:

```json
{ "mcpServers": { "code-atlas": {
    "command": "code-atlas-mcp",
    "args": ["--bundle", "atlas/atlas.bundle.json"] } } }
```

Tools (all read-only):

| Tool | Returns |
|---|---|
| `atlas_overview` | counts, entry points, threat summary — call first |
| `atlas_search` | nodes matching words — ids + locations only, no source |
| `atlas_get_node` | one node + neighbor ids + flags — compact, no source |
| `atlas_get_source` | one node's source — pulled only when needed |
| `atlas_neighbors` | callers / callees / imports — traverse without source |
| `atlas_context_pack` | Horos-style: a task → the minimal source-backed set + a replayable receipt |
| `atlas_threats` | findings (grade + ASI ref) for a node or file |
| `atlas_course` | the lesson + Break & Fix for a node |

The context saving: `search` / `get_node` / `neighbors` cost a few ids, not whole
files; source is fetched one node at a time; `context_pack` budgets a whole task.
