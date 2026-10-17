/**
 * Graph builder (JS/TS, Babel). Reads source as DATA only — never executes it.
 * Produces an AtlasGraph: file + function nodes, contains/imports/calls edges,
 * every element carrying evidence. Anything it cannot resolve becomes a
 * diagnostic, NEVER a fabricated edge.
 *
 * Pure over the provided sources (no fs), so it is trivially testable and the
 * language backend (tree-sitter later) can be swapped behind the same output.
 */
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import type { AtlasGraph, AtlasNode, AtlasEdge, Evidence } from "../schema.js";
import { classMemberLabel } from "./jsNames.js";

const traverse: any =
  (typeof _traverse === "function" ? _traverse : (_traverse as any).default);

export interface SourceFile {
  path: string;
  code: string;
  /** Source to HASH for evidence.contentHash, when it differs from `code`.
   *  Used when `code` is a parse-only shim (e.g. a .vue <script> extraction)
   *  but evidence.path + the bundled source refer to the real file — the hash
   *  must identify the real source, per the Evidence contract. Defaults to `code`. */
  hashCode?: string;
}

const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const id = (s: string) => sha(s).slice(0, 24);

function parseTs(code: string) {
  return parse(code, { sourceType: "unambiguous", plugins: ["typescript", "jsx", "decorators-legacy"], ranges: true });
}

/** Resolve a relative import specifier to one of the known file paths. */
function resolveImport(fromPath: string, spec: string, known: Set<string>): string | undefined {
  if (!spec.startsWith(".")) return undefined;                 // external — not resolved
  const base = resolve("/" + dirname(fromPath), spec).slice(1); // posix-ish, rooted at "/"
  const cands = [
    base,
    ...[".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"].map((e) => base + e),
    ...[".ts", ".tsx", ".js", ".jsx"].map((e) => base + "/index" + e),
  ];
  if (/\.js$/.test(base)) cands.push(base.slice(0, -3) + ".ts", base.slice(0, -3) + ".tsx");
  const hits = [...new Set(cands)].filter((c) => known.has(c));
  return hits.length === 1 ? hits[0] : undefined;              // exactly one, or nothing
}

export function buildGraph(revision: string, sources: SourceFile[]): AtlasGraph {
  const graph: AtlasGraph = { version: "0.1", revision, nodes: [], edges: [], diagnostics: [] };
  const known = new Set(sources.map((s) => s.path));
  const fileId = (p: string) => id("file:" + p);
  const fnId = (p: string, name: string, start: number) => id("fn:" + p + ":" + name + ":" + start);

  // name -> function node id, per file (for same-file call resolution) and globally (for cross-file via imports)
  const perFileFns = new Map<string, Map<string, string>>();
  const exportsByFile = new Map<string, Map<string, string>>();        // exported name -> fn id
  const importsByFile = new Map<string, Map<string, { file: string; name: string }>>(); // local -> {file, imported}

  const ev = (path: string, line: number, column: number, code: string): Evidence =>
    ({ path, line, column, revision, contentHash: "sha256:" + sha(code), method: "babel-static", status: "static" });

  // ---- pass 1: files, functions, contains, imports ----
  for (const f of sources) {
    const fid = fileId(f.path);
    const hashSrc = f.hashCode ?? f.code;   // hash the real source, even when `code` is a shim
    graph.nodes.push({ id: fid, kind: "file", label: f.path, evidence: ev(f.path, 1, 1, hashSrc) });
    const fns = new Map<string, string>();
    const exps = new Map<string, string>();
    const imps = new Map<string, { file: string; name: string }>();
    let ast;
    try { ast = parseTs(f.code); }
    catch { graph.diagnostics.push({ path: f.path, message: "Parse failed; relationships unavailable" }); continue; }

    const addClassMember = (p: any) => {
      const label = classMemberLabel(p);
      if (!label) return;
      const nid = fnId(f.path, label, p.node.start);
      graph.nodes.push({ id: nid, kind: "function", label, evidence: ev(f.path, p.node.loc.start.line, p.node.loc.start.column + 1, hashSrc) });
      graph.edges.push({ id: id(fid + ":contains:" + nid), from: fid, to: nid, kind: "contains", evidence: ev(f.path, p.node.loc.start.line, p.node.loc.start.column + 1, hashSrc) });
    };

    traverse(ast, {
      FunctionDeclaration(p: any) {
        if (!p.node.id) return;
        const nid = fnId(f.path, p.node.id.name, p.node.start);
        fns.set(p.node.id.name, nid);
        graph.nodes.push({ id: nid, kind: "function", label: p.node.id.name, evidence: ev(f.path, p.node.loc.start.line, p.node.loc.start.column + 1, hashSrc) });
        graph.edges.push({ id: id(fid + ":contains:" + nid), from: fid, to: nid, kind: "contains", evidence: ev(f.path, p.node.loc.start.line, p.node.loc.start.column + 1, hashSrc) });
      },
      VariableDeclarator(p: any) {
        if (p.node.id?.type !== "Identifier") return;
        if (p.node.init?.type !== "ArrowFunctionExpression" && p.node.init?.type !== "FunctionExpression") return;
        const nid = fnId(f.path, p.node.id.name, p.node.start);
        fns.set(p.node.id.name, nid);
        graph.nodes.push({ id: nid, kind: "function", label: p.node.id.name, evidence: ev(f.path, p.node.loc.start.line, p.node.loc.start.column + 1, hashSrc) });
        graph.edges.push({ id: id(fid + ":contains:" + nid), from: fid, to: nid, kind: "contains", evidence: ev(f.path, p.node.loc.start.line, p.node.loc.start.column + 1, hashSrc) });
      },
      // Class members become function nodes labelled `Class.member`. They get no call
      // edges (a `this.x()` / `obj.x()` receiver is not resolved), but the map and the
      // rule scanner now see them: a class's file writes and DB calls used to be invisible.
      ClassMethod(p: any) { addClassMember(p); },
      ClassPrivateMethod(p: any) { addClassMember(p); },
      ClassProperty(p: any) { addClassMember(p); },
      ImportDeclaration(p: any) {
        const spec = p.node.source.value;
        const target = resolveImport(f.path, spec, known);
        if (!target) { if (spec.startsWith(".")) graph.diagnostics.push({ path: f.path, message: "Unresolved or ambiguous import: " + spec }); return; }
        graph.edges.push({ id: id(fid + ":imports:" + fileId(target)), from: fid, to: fileId(target), kind: "imports", evidence: ev(f.path, p.node.loc.start.line, p.node.loc.start.column + 1, hashSrc) });
        for (const s of p.node.specifiers) {
          if (s.type === "ImportDefaultSpecifier") imps.set(s.local.name, { file: target, name: "default" });
          else if (s.type === "ImportSpecifier") imps.set(s.local.name, { file: target, name: s.imported.type === "Identifier" ? s.imported.name : s.imported.value });
        }
      },
      ExportNamedDeclaration(p: any) {
        const d = p.node.declaration;
        if (d?.type === "FunctionDeclaration" && d.id) exps.set(d.id.name, fnId(f.path, d.id.name, d.start));
        if (d?.type === "VariableDeclaration") for (const v of d.declarations) if (v.id?.type === "Identifier") {
          const nid = fns.get(v.id.name); if (nid) exps.set(v.id.name, nid);
        }
      },
    });
    perFileFns.set(f.path, fns); exportsByFile.set(f.path, exps); importsByFile.set(f.path, imps);
  }

  // ---- pass 2: calls ----
  for (const f of sources) {
    const fns = perFileFns.get(f.path); if (!fns) continue;
    const hashSrc = f.hashCode ?? f.code;   // hash the real source, even when `code` is a shim
    const imps = importsByFile.get(f.path)!;
    let ast;
    try { ast = parseTs(f.code); } catch { continue; }
    traverse(ast, {
      CallExpression(p: any) {
        const callee = p.node.callee;
        if (callee?.type !== "Identifier") { graph.diagnostics.push({ path: f.path, message: "Unsupported dynamic/member call at line " + (p.node.loc?.start.line ?? "?") }); return; }
        // enclosing function (caller)
        let fp = p.getFunctionParent?.();
        let fromId: string | undefined;
        if (fp && fp.node) {
          const nameNode = fp.node.id?.name ?? (fp.parentPath?.node?.id?.type === "Identifier" ? fp.parentPath.node.id.name : undefined);
          if (nameNode) fromId = fns.get(nameNode);
        }
        if (!fromId) fromId = fileId(f.path);               // top-level call → attribute to file
        // resolve target: same-file function, or an imported function's export
        let toId = fns.get(callee.name);
        if (!toId) { const im = imps.get(callee.name); if (im) toId = exportsByFile.get(im.file)?.get(im.name); }
        if (!toId) { graph.diagnostics.push({ path: f.path, message: "Unresolved call: " + callee.name + " at line " + (p.node.loc?.start.line ?? "?") }); return; }
        if (toId === fromId) return;
        graph.edges.push({ id: id(fromId + ":calls:" + toId + ":" + p.node.start), from: fromId, to: toId, kind: "calls", evidence: ev(f.path, p.node.loc.start.line, p.node.loc.start.column + 1, hashSrc) });
      },
    });
  }

  // de-dup identical edges (same from/to/kind) keeping first
  const seen = new Set<string>();
  graph.edges = graph.edges.filter((e) => { const k = e.from + "|" + e.to + "|" + e.kind; if (seen.has(k)) return false; seen.add(k); return true; });
  return graph;
}
