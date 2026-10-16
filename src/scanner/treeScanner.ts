/**
 * Minimal, dependency-free workspace scanner. Walks a repo, skips the usual
 * noise, returns JS/TS files within size limits. No code is executed.
 */
import { readdirSync, lstatSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";

const IGNORE_DIRS = new Set([
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
export interface ScanOptions { maxFiles?: number; maxBytes?: number; }

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
    unreadable: number;        // lstat/readdir failed, or a non-file/non-dir entry
  };
}

export function scanWorkspace(root: string, opts: ScanOptions = {}): { files: ScannedFile[]; coverage: ScanCoverage } {
  const maxFiles = opts.maxFiles ?? 2000;
  const maxBytes = opts.maxBytes ?? 200_000;
  const files: ScannedFile[] = [];
  const skipped = { unsupported: 0, tooLarge: 0, overCap: 0, symlink: 0, ignoredDir: 0, ignoredDirFiles: 0, unreadable: 0 };
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
  const walk = (dir: string): void => {
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
        walk(abs); continue;
      }
      if (!st.isFile()) { skipped.unreadable++; continue; }
      totalFilesSeen++;
      if (st.size > maxBytes) { skipped.tooLarge++; continue; }
      const language = fileLanguage(name);
      if (!language) { skipped.unsupported++; continue; }
      if (files.length >= maxFiles) { skipped.overCap++; continue; }
      files.push({ relativePath: relative(root, abs).split(sep).join("/"), absolutePath: abs, language });
    }
  };

  walk(root);
  return { files, coverage: { scannedFiles: files.length, totalFilesSeen, maxFiles, maxBytes, skipped } };
}

export function readSource(abs: string): string {
  return readFileSync(abs, "utf8");
}
