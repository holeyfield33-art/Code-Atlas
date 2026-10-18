/**
 * The commit a scanned folder is checked out at, read straight from `.git` (no git binary, no process):
 * HEAD -> a loose ref, packed-refs, or a detached commit; a `.git` file (worktree / submodule) is followed.
 * It identifies the checkout the map was made from, so a map can be matched to a running instance or a
 * later checkout. It does NOT say the working tree was clean: uncommitted edits are not detected.
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";

const SHA = /^[0-9a-f]{40}([0-9a-f]{24})?$/;
const read = (p: string): string | undefined => {
  try { if (!existsSync(p) || statSync(p).size > 5_000_000) return undefined; return readFileSync(p, "utf8"); } catch { return undefined; }
};

export function readGitHead(root: string): string | undefined {
  let gitDir = join(root, ".git");
  try {
    if (statSync(gitDir).isFile()) {
      const m = /^gitdir:\s*(.+)$/m.exec(read(gitDir) ?? "");
      if (!m) return undefined;
      gitDir = isAbsolute(m[1].trim()) ? m[1].trim() : resolve(root, m[1].trim());
    }
  } catch { return undefined; }
  const head = read(join(gitDir, "HEAD"))?.trim();
  if (!head) return undefined;
  if (SHA.test(head)) return head;                                  // detached
  const ref = /^ref:\s*(\S+)$/.exec(head)?.[1];
  if (!ref || ref.includes("..")) return undefined;
  const dirs = [gitDir];
  const common = read(join(gitDir, "commondir"))?.trim();           // a linked worktree keeps its refs in the main repo
  if (common) dirs.push(isAbsolute(common) ? common : resolve(gitDir, common));
  for (const d of dirs) {
    const loose = read(join(d, ref))?.trim();
    if (loose && SHA.test(loose)) return loose;
    const packed = read(join(d, "packed-refs"));
    if (packed) for (const line of packed.split("\n")) {
      const m = /^([0-9a-f]{40}(?:[0-9a-f]{24})?)\s+(\S+)$/.exec(line.trim());
      if (m && m[2] === ref) return m[1];
    }
  }
  return undefined;
}
