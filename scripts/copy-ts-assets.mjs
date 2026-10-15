/**
 * Copy the tree-sitter backend's runtime assets into dist after `tsc`.
 * tsc only emits compiled .ts; the mapper (.cjs), grammars (.wasm), and query
 * files (.scm) must sit next to the compiled backend so `require("./treeSitter/
 * mapper.cjs")` resolves from dist/scanner/multilang.js at runtime.
 */
import { cpSync, mkdirSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const from = resolve(root, "src/scanner/treeSitter");
const to = resolve(root, "dist/scanner/treeSitter");

if (!existsSync(from)) { console.error("tree-sitter source assets missing at " + from); process.exit(1); }
mkdirSync(to, { recursive: true });
for (const asset of ["mapper.cjs", "grammars", "queries"]) {
  cpSync(resolve(from, asset), resolve(to, asset), { recursive: true });
}
console.log("copied tree-sitter assets -> dist/scanner/treeSitter");
