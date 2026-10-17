/**
 * Splitting a repo too big for one bundle (shards), and scanning part of a tree.
 *  - --include scans only the named folders; paths stay relative to the ROOT; everything left
 *    out is counted in coverage (`excluded`), never silent; `dir/.` means a folder's own files;
 *  - --skip matches a bare name at any depth, or a root-relative path;
 *  - planShards covers every analyzable file EXACTLY ONCE across shards (no gaps, no overlap),
 *    keeps shards within the cap, and reports a single over-cap folder as oversize instead of
 *    splitting it mid-folder.
 */
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { scanWorkspace, scopeOf, parseIncludes } from "../src/scanner/treeScanner.js";
import { planShards } from "../src/scanner/shards.js";
import { buildAtlas } from "../src/build.js";

const root = mkdtempSync(join(tmpdir(), "atlas-shards-"));
const put = (rel: string, body = "x = 1\n") => { const p = join(root, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, body); };
const many = (dir: string, n: number, ext = "py") => { for (let i = 0; i < n; i++) put(`${dir}/f${i}.${ext}`); };
many("app/models", 5); many("app/services", 6); many("app/assets/js", 4, "js"); many("lib", 3);
many("spec/models", 5); many("app/spec", 2);                    // tests: skipped by name at any depth
many("db/migrate", 10);                                         // one flat folder bigger than a small cap
many("ee/spec/lib", 3); many("ee/app", 4);
put("root_a.py"); put("root_b.rb");                              // supported sources at the ROOT of the repo
put("README.md", "# docs\n"); put("node_modules/dep/index.js", "var a=1\n");

const rels = (files: { relativePath: string }[]) => files.map((f) => f.relativePath).sort();
const all = scanWorkspace(root);

// ---- scopeOf: how a folder relates to the include list
const rules = parseIncludes(["app/models", "lib/."]);
assert.equal(scopeOf("app/models", rules), "all");
assert.equal(scopeOf("app/models/x/y", rules), "all", "a subtree of an include is in scope");
assert.equal(scopeOf("app", rules), "descend", "an ancestor is walked through, its own files are not in scope");
assert.equal(scopeOf("lib", rules), "direct", "`dir/.` = the folder's own files only");
assert.equal(scopeOf("lib/sub", rules), "none", "...and not its subfolders");
assert.equal(scopeOf("db", rules), "none");
assert.equal(scopeOf("anything", []), "all", "no includes = the whole tree");
const rootOnly = parseIncludes(["."]);
assert.equal(scopeOf("", rootOnly), "direct", "`.` alone is the root's own files");
assert.equal(scopeOf("app", rootOnly), "none", "...and not its subfolders");
assert.deepEqual(rels(scanWorkspace(root, { include: ["."] }).files), ["root_a.py", "root_b.rb"], "include `.` scans exactly the root-level sources");

// ---- --include: only those folders, root-relative paths, the rest counted
const inc = scanWorkspace(root, { include: ["app/models", "lib/."] });
assert.deepEqual(rels(inc.files), [...rels(all.files).filter((p) => p.startsWith("app/models/") || /^lib\/[^/]+$/.test(p))]);
assert.ok(inc.files.every((f) => !f.relativePath.startsWith("/") && f.relativePath.includes("/")), "paths stay relative to the ROOT");
assert.equal(inc.coverage.skipped.excluded, all.coverage.scannedFiles - inc.files.length + all.coverage.skipped.unsupported,
  "everything outside the include (supported or not) is counted as excluded");
assert.ok(rels(scanWorkspace(root, { include: ["app/."] }).files).every((p) => /^app\/[^/]+$/.test(p)), "app/. matches no files here (all are in subfolders)");

// ---- --skip: bare name at any depth; path prefix only there
const noSpec = scanWorkspace(root, { skip: ["spec"] });
assert.ok(!rels(noSpec.files).some((p) => p.includes("spec/")), "`spec` is skipped at any depth (spec/, app/spec, ee/spec)");
const onlyEeSpec = scanWorkspace(root, { skip: ["ee/spec"] });
assert.ok(rels(onlyEeSpec.files).some((p) => p.startsWith("spec/")) && !rels(onlyEeSpec.files).some((p) => p.startsWith("ee/spec/")), "`ee/spec` skips only that path");

// ---- build with --include keeps real paths in the graph
const { bundle } = await buildAtlas(root, { security: false, include: ["app/models"], repoLabel: "shard-test" });
assert.equal(bundle.repository.label, "shard-test");
const filePaths = bundle.graph.nodes.filter((n) => n.kind === "file").map((n) => n.evidence.path).sort();
assert.deepEqual(filePaths, rels(all.files).filter((p) => p.startsWith("app/models/")), "nodes carry root-relative paths");
assert.ok((bundle.coverage?.skipped.excluded ?? 0) > 0, "the bundle's coverage records what the include left out");

// ---- planShards
const skip = ["spec"];
const total = rels(scanWorkspace(root, { skip }).files);
const one = planShards(root, { maxFiles: 1000, skip });
assert.equal(one.length, 1, "a tree under the cap is one shard");
assert.deepEqual(one[0].include, [], "...with an empty include (the whole tree)");
assert.equal(one[0].files, total.length);

const cap = 8;
const plan = planShards(root, { maxFiles: cap, skip });
assert.ok(plan.length > 1, "a tree over the cap is split");
const covered: string[] = [];
for (const sh of plan) {
  const part = scanWorkspace(root, { include: sh.include, skip });
  assert.equal(part.files.length, sh.files, `shard ${sh.index}: the plan's count matches what the scanner analyzes`);
  assert.ok(sh.files <= cap || sh.oversize, `shard ${sh.index} is within the cap unless one folder forces it`);
  covered.push(...rels(part.files));
}
assert.deepEqual(covered.sort(), total, "every analyzable file is in exactly one shard (no gaps, no overlap)");
const migrate = plan.find((s) => s.include.some((i) => i.startsWith("db/migrate")));
assert.ok(migrate && migrate.oversize && migrate.files === 10, "a single folder over the cap is one oversize shard, not split mid-folder");
assert.ok(!plan.some((s) => s.include.some((i) => i.includes("spec"))), "skipped folders never appear in a plan");
assert.ok(plan.every((s) => s.include.length > 0), "split shards always name their folders");

console.log(`shards.test: include/skip scope the scan with root-relative paths and counted exclusions; a ${total.length}-file tree plans into ${plan.length} shards covering every file exactly once`);
