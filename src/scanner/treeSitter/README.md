# tree-sitter backend (multi-language)

A second graph backend behind the `AtlasBundle` seam. Where the Babel backend
handles JS/TS, this one uses **web-tree-sitter (WASM)** + each grammar's official
`tags.scm` to build the same `AtlasGraph` for other languages. Everything
downstream (viewer, course, MCP, findings) consumes it unchanged.

## Files
- `mapper.cjs` — generic CST → graph mapper (vendored). Runs the tags query,
  emits file/definition nodes and `contains`/`imports`/`calls` edges, resolves
  imports/calls against the project file set. **Never fabricates an edge** —
  zero or ambiguous resolution becomes a diagnostic.
- `grammars/*.wasm` — vendored grammars (`tree-sitter-python`, `tree-sitter-ruby`).
- `queries/<lang>/tags.scm` — the definition/reference queries.
- `../multilang.ts` — the adapter: runs the mapper and converts its generic graph
  into a schema-conformant `AtlasGraph` (label, `from`/`to`, source-backed
  `evidence` with `method: "tree-sitter-static"`), then the existing
  `assembleBundle()` produces a valid bundle.

## Add a language
1. Drop its `tree-sitter-<lang>.wasm` in `grammars/` and `tags.scm` in
   `queries/<lang>/`.
2. Add an entry to `LANGUAGE_CONFIG` in `mapper.cjs` (wasm, tags, extensions)
   and import walker cases for its `import`/`require` syntax.
3. Add it to `SUPPORTED_LANGUAGES` / `languageOf()` in `../multilang.ts`.

## Honest limits (v1)
- `calls` edges originate from the **file** node, not the enclosing function
  (name-based resolution; coarser, never wrong-by-fabrication).
- `contentHash` is per file; line/column are character-based (ASCII-exact).
- No dynamic dispatch / metaprogramming / full module-system resolution — those
  stay unresolved (diagnostics), by design.
- The Break & Fix **course is still JS/TS-only** (Babel); a non-JS repo gets the
  graph + threat map, not lessons, until a language-agnostic generator lands.
- Not yet wired into the `build` CLI flow — this backend + adapter + tests prove
  the seam; CLI wiring and the live scan of a large repo are the next step.
