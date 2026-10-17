/**
 * Minimal, dependency-free workspace scanner. Walks a repo, skips the usual
 * noise, returns JS/TS files within size limits. No code is executed.
 */
import { readdirSync, lstatSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";

export const IGNORE_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "coverage",
  ".course", "atlas", ".turbo", "out", "vendor", "__pycache__", ".venv", "venv",
]);
const JS_TS = /\.(?:[cm]?jsx?|tsx?|mts|cts)$/;
const PYTHON = /\.pyi?$/;
const RUBY = /\.(?:rb|rake)$/;
const VUE = /\.vue$/;

/** Which analyzer backend a file routes to. A .vue SFC has its <script> block
 *  extracted and analyzed with the JS/TS (Babel) backend. */
export type FileLanguage = "js" | "python" | "ruby" | "vue";

/** Detect the backend for a filename, or null if unsupported. */
export function fileLanguage(name: string): FileLanguage | null {
  if (JS_TS.test(name)) return "js";
  if (PYTHON.test(name)) return "python";
  if (RUBY.test(name)) return "ruby";
  if (VUE.test(name)) return "vue";
  return null;
}

export interface ScannedFile { relativePath: string; absolutePath: string; language: FileLanguage; }
export interface ScanOptions {
  maxFiles?: number;
  maxBytes?: number;
  /** Scan only these root-relative folders (each with its whole subtree). Paths in the result stay relative to
   *  the ROOT, so evidence and source links are unchanged. A trailing `/.` means that folder's DIRECT files only,
   *  not its subfolders (used by shard plans to split an oversized folder). Empty/absent = the whole tree. */
  include?: string[];
  /** Leave these out. A name without `/` matches a folder of that name at any depth (`spec`); an entry with `/`
   *  matches that root-relative folder and everything under it (`ee/spec`). */
  skip?: string[];
}

/** Normalise a user-supplied include/skip entry: forward slashes, no leading `./` or trailing `/`. */
export function normScopePath(p: string): string {
  return p.replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/+$/, "");
}

interface IncludeRule { path: string; direct: boolean; }
export function parseIncludes(include: string[] | undefined): IncludeRule[] {
  // A lone `.` is the ROOT's own files (not its subfolders): the planner emits it for a repo's root-level
  // sources. (Dropping it silently lost them: 14 root files of a 35,000-file tree.)
  return (include ?? []).map(normScopePath).filter((x) => x).map((x) =>
    x === "." ? { path: "", direct: true }
    : x.endsWith("/.") ? { path: x.slice(0, -2), direct: true } : { path: x, direct: false });
}

/** How a directory relates to the include list: "all" (files and subtree in scope), "direct" (only its own files),
  *  "descend" (outside, but an include lives below it), or "none" (prune). No includes => everything is "all". */
export function scopeOf(rel: string, rules: IncludeRule[]): "all" | "direct" | "descend" | "none" {
  if (!rules.length) return "all";
  let direct = false, below = false;
  for (const r of rules) {
    if (!r.direct && (rel === r.path || rel.startsWith(r.path + "/"))) return "all";
    if (r.direct && rel === r.path) direct = true;
    if (rel === "" || r.path.startsWith(rel + "/")) below = true;
  }
  return direct ? "direct" : below ? "descend" : "none";
}

/** True when `rel` (a root-relative folder path) is excluded by the skip list. */
export function isSkippedDir(rel: string, name: string, skip: string[]): boolean {
  for (const raw of skip) {
    const k = normScopePath(raw); if (!k) continue;
    if (k.includes("/") ? (rel === k || rel.startsWith(k + "/")) : name === k) return true;
  }
  return false;
}

/** Why a regular file (or an ignored directory) was NOT analyzed. Every omitted
 *  item is counted by reason, so coverage is auditable rather than silent. */
export interface ScanCoverage {
  scannedFiles: number;        // files actually included
  totalFilesSeen: number;      // all regular files encountered (scanned + skipped)
  maxFiles: number;            // the file cap in effect
  maxBytes: number;            // the per-file size cap in effect
  skipped: {
    unsupported: number;       // regular file whose extension no backend handles
    tooLarge: number;          // over maxBytes
    overCap: number;           // would have been analyzed, but the file cap was reached
    symlink: number;           // a symlink (never followed — containment)
    ignoredDir: number;        // directories pruned by the ignore list
    ignoredDirFiles: number;   // regular files inside those pruned directories (counted, not analyzed)
    excluded?: number;         // regular files left out by --include / --skip (counted, not analyzed)
    unreadable: number;        // lstat/readdir failed, or a non-file/non-dir entry
  };
}

export function scanWorkspace(root: string, opts: ScanOptions = {}): { files: ScannedFile[]; coverage: ScanCoverage } {
  const maxFiles = opts.maxFiles ?? 2000;
  const maxBytes = opts.maxBytes ?? 200_000;
  const files: ScannedFile[] = [];
  const skipped = { unsupported: 0, tooLarge: 0, overCap: 0, symlink: 0, ignoredDir: 0, ignoredDirFiles: 0, unreadable: 0, excluded: 0 };
  const includeRules = parseIncludes(opts.include);
  const skipRules = opts.skip ?? [];
  let totalFilesSeen = 0;

  // Count-only pass over a pruned directory: tally its regular files (never
  // following symlinks, never reading) so an ignored tree's contents are
  // accounted for rather than silently invisible.
  const countTree = (dir: string): number => {
    let n = 0, entries: string[];
    try { entries = readdirSync(dir); } catch { return n; }
    for (const name of entries) {
      const abs = join(dir, name);
      let st; try { st = lstatSync(abs); } catch { continue; }
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) { n += countTree(abs); continue; }
      if (st.isFile()) n++;
    }
    return n;
  };

  // NOTE: we keep walking after the file cap is hit so every omitted file is
  // counted (as overCap) rather than the traversal silently stopping.
  const walk = (dir: string, rel: string): void => {
    const scope = scopeOf(rel, includeRules);
    let entries: string[];
    try { entries = readdirSync(dir); } catch { skipped.unreadable++; return; }
    for (const name of entries) {
      const abs = join(dir, name);
      let st;
      // lstat (not stat) so we see the link itself, not its target. A symlink is
      // never followed — this keeps the scan inside the repo and blocks a crafted
      // link (e.g. leak.ts -> /etc/passwd) from pulling host files into the bundle.
      try { st = lstatSync(abs); } catch { skipped.unreadable++; continue; }
      if (st.isSymbolicLink()) { skipped.symlink++; continue; }
      if (st.isDirectory()) {
        // An ignored directory is pruned from analysis but its files are COUNTED,
        // so coverage never claims completeness while a tree was dropped.
        if (IGNORE_DIRS.has(name)) { skipped.ignoredDir++; skipped.ignoredDirFiles += countTree(abs); continue; }
        const childRel = rel ? rel + "/" + name : name;
        // Left out by the caller's --skip or because it is outside every --include: counted, never silent.
        if (isSkippedDir(childRel, name, skipRules) || scopeOf(childRel, includeRules) === "none") { skipped.excluded += countTree(abs); continue; }
        walk(abs, childRel); continue;
      }
      if (!st.isFile()) { skipped.unreadable++; continue; }
      totalFilesSeen++;
      if (scope !== "all" && scope !== "direct") { skipped.excluded++; continue; }   // a folder we only walk THROUGH
      if (st.size > maxBytes) { skipped.tooLarge++; continue; }
      const language = fileLanguage(name);
      if (!language) { skipped.unsupported++; continue; }
      if (files.length >= maxFiles) { skipped.overCap++; continue; }
      files.push({ relativePath: relative(root, abs).split(sep).join("/"), absolutePath: abs, language });
    }
  };

  walk(root, "");
  return { files, coverage: { scannedFiles: files.length, totalFilesSeen, maxFiles, maxBytes, skipped } };
}

export function readSource(abs: string): string {
  return readFileSync(abs, "utf8");
}
