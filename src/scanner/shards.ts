/**
 * Shard planning: split a repository too large for one bundle into several, along folder
 * boundaries, each under a file cap. A bundle is loaded whole into memory by the MCP
 * server, so one bundle for a monorepo (tens of thousands of files) is neither loadable
 * nor drawable; several ~3,000-file bundles are, one named project each.
 *
 * The plan counts exactly what the scanner would analyze (same ignore list, symlink
 * rule, size cap, supported extensions and --skip rules), builds a folder tree of those
 * counts, then packs it:
 *   - a folder that fits the cap is kept whole (its subtree stays together);
 *   - a folder over the cap is opened up: its subfolders are planned recursively and its
 *     DIRECT files become a `folder/.` entry;
 *   - neighbouring pieces, in path order, are packed greedily into shards up to the cap,
 *     so related folders tend to share a shard.
 * A single directory with more direct files than the cap becomes one oversize shard
 * (reported, never split mid-folder).
 *
 * Limits worth knowing: calls and imports resolve only inside one bundle, so a relationship
 * that crosses shards is not drawn. Every shard's coverage record says what it left out.
 */
import { readdirSync, lstatSync } from "node:fs";
import { join } from "node:path";
import { IGNORE_DIRS, fileLanguage, isSkippedDir } from "./treeScanner.js";

export interface Shard {
  /** 1-based position in the plan. */
  index: number;
  /** A readable hint from the folders it holds, e.g. `ee-app-models`. */
  hint: string;
  /** Root-relative folders (`dir`) or a folder's direct files (`dir/.`). Never empty. */
  include: string[];
  /** Files the scanner would analyze in this shard. */
  files: number;
  /** True when one folder alone exceeds the cap and could not be split further. */
  oversize: boolean;
}

export interface PlanOptions {
  maxFiles?: number;
  maxBytes?: number;
  skip?: string[];
}

interface Dir { rel: string; name: string; direct: number; kids: Dir[]; total: number; }
interface Piece { include: string; files: number; oversize: boolean; }

/** Build the folder tree of analyzable-file counts, mirroring scanWorkspace's rules. */
function countTree(root: string, opts: Required<Pick<PlanOptions, "maxBytes">> & { skip: string[] }): Dir {
  const walk = (abs: string, rel: string, name: string): Dir => {
    const d: Dir = { rel, name, direct: 0, kids: [], total: 0 };
    let entries: string[];
    try { entries = readdirSync(abs).sort(); } catch { return d; }
    for (const e of entries) {
      const a = join(abs, e);
      let st; try { st = lstatSync(a); } catch { continue; }
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) {
        const childRel = rel ? rel + "/" + e : e;
        if (IGNORE_DIRS.has(e) || isSkippedDir(childRel, e, opts.skip)) continue;
        const k = walk(a, childRel, e);
        if (k.total > 0) d.kids.push(k);
        continue;
      }
      if (st.isFile() && st.size <= opts.maxBytes && fileLanguage(e)) d.direct++;
    }
    d.total = d.direct + d.kids.reduce((n, k) => n + k.total, 0);
    return d;
  };
  return walk(root, "", "");
}

function pieces(d: Dir, max: number): Piece[] {
  if (d.total <= max) return [{ include: d.rel || ".", files: d.total, oversize: false }];
  const out: Piece[] = [];
  for (const k of d.kids) out.push(...pieces(k, max));
  if (d.direct > 0) out.push({ include: (d.rel ? d.rel + "/" : "") + ".", files: d.direct, oversize: d.direct > max });
  // A folder whose subtree is over the cap and that has no subfolders left is oversize by itself.
  if (!d.kids.length && d.direct === d.total) return [{ include: d.rel || ".", files: d.total, oversize: d.total > max }];
  return out;
}

/** Plan shards for `root`. Returns [] for an empty tree. */
export function planShards(root: string, opts: PlanOptions = {}): Shard[] {
  const max = opts.maxFiles ?? 3000;
  const tree = countTree(root, { maxBytes: opts.maxBytes ?? 200_000, skip: opts.skip ?? [] });
  if (tree.total === 0) return [];
  // The whole tree fits: one shard, include everything (an empty include list = whole tree).
  if (tree.total <= max) return [{ index: 1, hint: "all", include: [], files: tree.total, oversize: false }];

  const shards: Shard[] = [];
  let cur: Piece[] = [], n = 0;
  const flush = () => {
    if (!cur.length) return;
    shards.push({
      index: shards.length + 1,
      hint: cur[0].include.replace(/\/\.$/, "").replace(/[^A-Za-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "root",
      include: cur.map((p) => p.include), files: n, oversize: cur.some((p) => p.oversize),
    });
    cur = []; n = 0;
  };
  for (const p of pieces(tree, max)) {
    if (cur.length && n + p.files > max) flush();
    cur.push(p); n += p.files;
    if (p.oversize) flush();      // an oversize folder gets a shard to itself
  }
  flush();
  return shards;
}
