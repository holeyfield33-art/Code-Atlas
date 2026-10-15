/**
 * Minimal, dependency-free workspace scanner. Walks a repo, skips the usual
 * noise, returns JS/TS files within size limits. No code is executed.
 */
import { readdirSync, lstatSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";

const IGNORE_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "coverage",
  ".course", "atlas", ".turbo", "out",
]);
const JS_TS = /\.(?:[cm]?jsx?|tsx?|mts|cts)$/;

export interface ScannedFile { relativePath: string; absolutePath: string; }
export interface ScanOptions { maxFiles?: number; maxBytes?: number; }

export function scanWorkspace(root: string, opts: ScanOptions = {}): { files: ScannedFile[] } {
  const maxFiles = opts.maxFiles ?? 2000;
  const maxBytes = opts.maxBytes ?? 200_000;
  const files: ScannedFile[] = [];

  const walk = (dir: string): void => {
    let entries: string[];
    try { entries = readdirSync(dir); } catch { return; }
    for (const name of entries) {
      if (files.length >= maxFiles) return;
      if (IGNORE_DIRS.has(name)) continue;
      const abs = join(dir, name);
      let st;
      // lstat (not stat) so we see the link itself, not its target. A symlink is
      // never followed — this keeps the scan inside the repo and blocks a crafted
      // link (e.g. leak.ts -> /etc/passwd) from pulling host files into the bundle.
      try { st = lstatSync(abs); } catch { continue; }
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) walk(abs);
      else if (st.isFile() && JS_TS.test(name) && st.size <= maxBytes)
        files.push({ relativePath: relative(root, abs).split(sep).join("/"), absolutePath: abs });
    }
  };

  walk(root);
  return { files: files.slice(0, maxFiles) };
}

export function readSource(abs: string): string {
  return readFileSync(abs, "utf8");
}
