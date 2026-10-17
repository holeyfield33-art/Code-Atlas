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

Or skip the command line: `node dist/cli.js serve` starts a local app on `http://127.0.0.1:4173` (loopback only) with an **Open folder** button that analyzes a project on this computer and loads it into the viewer. See [docs/ingestion.md](docs/ingestion.md) for limits and what the folder picker sends where.

`build` scans the repo (JS/TS, Python, Ruby, and Vue — see **Supported languages**), builds a call/import graph, generates grounded exercises, and writes:

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
  triage.ts            finding disposition layer (confirmed / false_positive / accepted_risk)
  scanner/
    treeScanner.ts     dependency-free workspace walker
    graph.ts           JS/TS graph builder (Babel)
    multilang.ts       tree-sitter backend adapter (Python / Ruby) behind the schema seam
    treeSitter/        vendored grammars (wasm) + tags queries + mapper
    findings.ts        native rule engine (JS + language packs) + external-report adapter
    rules.ts           declarative rule packs (default, Python, Ruby)
    redact.ts          best-effort secret redaction before inlining
  generator/
    generator.ts       grounded Break & Fix generator + bundle assembler
  mcp/                 read/triage MCP server over one bundle
  cli.ts               the `build` command
viewer/viewer.html     the 3D viewer template (3d-force-graph, MIT)
tests/                 schema validation + per-layer dogfood proofs
```

## Supported languages

| Language | Backend | Graph | Course | Threat rules |
|---|---|---|---|---|
| JavaScript / TypeScript (`.js .jsx .ts .tsx .mjs .cjs .mts .cts`) | Babel | files, functions, `contains` / `imports` / `calls` — calls resolved via imports + same-file | `removed_guard`, `broken_call_edge` | default rule pack |
| Python (`.py .pyi`) | tree-sitter | files, functions, classes, constants; `contains` / `imports` / `calls` | `broken_call_edge` | Python pack (code-exec, OS command, unsafe deserialization, secret handling, input-validation control) |
| Ruby (`.rb .rake`) | tree-sitter | same as Python | `broken_call_edge` | Ruby pack (eval/send, system/exec, Marshal/YAML, secret handling, validation control) |
| Vue SFC (`.vue`) | Babel (on the `<script>` block) | same as JS/TS, positions mapped to the real `.vue` | `broken_call_edge` | default rule pack |

### Adding a language

A grammar wasm and its `tags.scm` are necessary but **not sufficient** — dropping
them in alone leaves every file of the new language counted as *unsupported* and
ignored. A new tree-sitter language has to be wired through five points, or the
scanner never routes a file to it:

1. `src/scanner/treeScanner.ts` — add the extension regex and return the new
   name from `fileLanguage()`, and add it to the `FileLanguage` union.
2. `src/scanner/multilang.ts` — add the name to `SUPPORTED_LANGUAGES` (the
   `MultiLang` type derives from it).
3. `src/scanner/treeSitter/mapper.cjs` — add a `LANGUAGE_CONFIG` entry pointing
   at the wasm + `tags.scm`, and a call-extraction branch alongside the existing
   `python` / `ruby` ones (call edges are name-resolved per language).
4. `src/build.ts` — add a `byLang` bucket and include the name in the
   `["python", "ruby"]` language loop so its files are parsed and scanned.
5. `src/scanner/rules.ts` — add a rule pack for the language (or it inherits no
   native findings beyond `broken_call_edge`).

Steps 1–4 are required for a graph; step 5 is required for threat rules. The
`Supported languages` table above is the source of truth for what is currently
wired end to end.

### Honest limits (by design, not omission)

- **Non-JS call edges are resolved by NAME**, not by imports — a real call site to
  the repo's only definition of that name. They are less precise than the JS
  import-resolved edges; an ambiguous name (multiple definitions) is dropped to a
  *diagnostic*, never guessed.
- **The non-JS course emits `broken_call_edge` only.** `removed_guard` needs
  AST-level guard detection the tree-sitter path doesn't do yet, and a paren-less
  call (Ruby `system cmd`) can't be mutated as text so it yields no lesson.
- **Native findings are STATIC leads** — a structural match, not proof the input is
  attacker-controlled or the path reachable. Only `OBSERVED`/`TESTED` findings cast
  a blast radius; a disposition (`confirmed` / `false_positive` / `accepted_risk`,
  via `atlas_triage`) can suppress but never upgrades a grade.
- Defect kinds reserved for later: `swapped_condition`, `missing_import`,
  `wrong_target`, `order_violation`.

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

Tools (nine read-only; `atlas_triage` is the one write tool):

| Tool | Returns |
|---|---|
| `atlas_overview` | counts, entry points, threat summary — call first |
| `atlas_search` | nodes matching words — ids + locations only, no source |
| `atlas_get_node` | one node + neighbor ids + flags — compact, no source |
| `atlas_get_source` | one node's source — pulled only when needed |
| `atlas_neighbors` | callers / callees / imports — traverse without source |
| `atlas_context_pack` | Horos-style: a task → the minimal source-backed set + a replayable receipt |
| `atlas_threats` | findings (grade + ASI ref + any triage disposition) for a node or file |
| `atlas_course` | the lesson + Break & Fix for a node |
| `atlas_exec` | run JS against a frozen read-only `atlas` API in a sandboxed isolate — one programmable tool for any filter/join/aggregate (see below) |
| `atlas_triage` | record a disposition on a finding (`confirmed` / `false_positive` / `accepted_risk`) — the one **write** tool; persists to the bundle, never upgrades a grade |

The context saving: `search` / `get_node` / `neighbors` cost a few ids, not whole
files; source is fetched one node at a time; `context_pack` budgets a whole task.

### `atlas_exec` — one programmable read tool (experimental)

The fixed tools above each spend schema tokens whether used or not, and can't do a
query nobody pre-wrote. `atlas_exec` is the alternative: **one** tool that takes
JavaScript and runs it against a frozen, read-only `atlas` API (`overview`,
`search`, `getNode`, `getSource`, `neighbors`, `contextPack`, `threats`, `course`),
so an agent writes the exact filter/join/aggregate it needs in a single call and
`return`s the result.

```js
// "which entry points carry the most findings?" — one call, no fixed tool for it
const ov = atlas.overview();
return ov.entryPoints
  .map(e => ({ id: e.id, threats: atlas.threats(e.id).findings.length }))
  .sort((a, b) => b.threats - a.threats).slice(0, 5);
```

The security is the jail, not the API's shape. Code runs in a V8 isolate
(`isolated-vm`) with a separate heap and **no** Node bindings — `require`,
`import`, `process`, `fetch`, timers and the host scope do not exist inside it.
The only capability handed in is the `atlas` read API; the host reference behind
it is consumed by a trusted bootstrap and never reachable from agent code, every
host call is checked against a read-only allowlist (there is **no** write path —
`atlas_triage` is not reachable here), all data crosses as JSON, and a wall-clock
timeout plus a memory cap bound every run. Each run returns a replayable receipt
(`sha256` of selector + code + bundle), so the same query over the same bundle is
reproducible — the grounding guarantee, extended to free-form reads.

### Streamable HTTP (read-only by default)

stdio is the default and needs nothing else. For an agent that connects over HTTP:

```bash
export ATLAS_MCP_API_KEY=$(node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('hex'))")
code-atlas-mcp --http --bundle atlas/atlas.bundle.json        # http://127.0.0.1:8000/mcp
```

Windows PowerShell: `$env:ATLAS_MCP_API_KEY = node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('hex'))"`.
Clients send `Authorization: Bearer <key>`; `GET /healthz` is unauthenticated.

What it enforces, on every request, in this order:

| Control | Behaviour |
|---|---|
| Loopback bind | Binds `127.0.0.1`. A non-loopback `--host` is refused unless you pass `--allow-remote` (and put TLS in front). |
| Host allowlist | `localhost`, `127.0.0.1`, `::1` and the bind host. Anything else gets `403` (defeats DNS rebinding). Add a public name with `--allowed-host` / `ATLAS_ALLOWED_HOSTS`. |
| Origin allowlist | A browser `Origin` is refused unless listed (`--allowed-origin` / `ATLAS_ALLOWED_ORIGINS`). No CORS headers are ever sent. |
| Auth | Bearer key, 32+ characters, constant-time compare, checked before the body is read. |
| Rate limits | 300 requests/min per client; 10 failed authentications/min per client, then `429`. Behind a reverse proxy every client shares the proxy's address, so rate-limit there too. |
| Read-only | `atlas_triage` is **not registered** over HTTP unless you pass `--allow-triage`. |
| Bounds | 1 MB request body; header/request timeouts. |

The bundle contains your source: treat the key as a credential and don't expose the
port to a network you don't trust. Rotating the key means restarting the server.
