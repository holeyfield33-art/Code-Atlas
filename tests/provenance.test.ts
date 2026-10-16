/**
 * Provenance and robustness (red-team audit 2026-10-16, findings A/D + P2s):
 *  A  a context-pack receipt is bound to the CONTENT it returned: changing a
 *     function's source (same node ids) changes the receipt hash;
 *  D  launching dist/mcp/server.js directly actually runs main() (the old
 *     `file://${argv[1]}` comparison skipped it on Windows);
 *  P2 triage persistence is atomic: a failed write leaves the original bundle
 *     intact and no temp file behind;
 *  P2 the atlas_exec result cap counts UTF-8 bytes, not UTF-16 code units.
 */
import assert from "node:assert";
import { spawnSync, execSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, mkdirSync, existsSync, chmodSync, statSync, writeSync, symlinkSync, lstatSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseBundle } from "../src/schema.js";
import { AtlasTools } from "../src/mcp/tools.js";
import { runAtlasExec } from "../src/mcp/sandbox.js";
import { writeFileAtomic, writeFully } from "../src/atomicWrite.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const bundlePath = resolve(repoRoot, "atlas/atlas.bundle.json");
if (!existsSync(bundlePath)) execSync("node dist/cli.js build .", { cwd: repoRoot, stdio: "ignore" });
const bundle = parseBundle(JSON.parse(readFileSync(bundlePath, "utf8")));

// ---- A: receipt covers content --------------------------------------------
const task = "build graph resolve imports";
const p1: any = new AtlasTools(bundle).contextPack(task, 1500);
const p1again: any = new AtlasTools(bundle).contextPack(task, 1500);
assert.strictEqual(p1.receipt.hash, p1again.receipt.hash, "same bundle + task => same receipt (replayable)");
assert.ok(p1.sourceIncluded.length > 0, "the pack includes source to bind");
assert.ok(p1.receipt.bundleHash && p1.receipt.sourceHash, "receipt carries bundleHash and sourceHash");
const included = new Set(p1.sourceIncluded.map((i: any) => i.path));
const edited = structuredClone(bundle);
const src = edited.sources!.find((s) => included.has(s.path))!;
src.code = src.code + "\n// edited after the first pack\n";           // same node ids, different bytes
const p2: any = new AtlasTools(edited).contextPack(task, 1500);
assert.deepStrictEqual(p2.receipt.selected, p1.receipt.selected, "node selection is unchanged by the edit");
assert.notStrictEqual(p2.receipt.hash, p1.receipt.hash, "a changed source changes the receipt even when node ids are identical");

// ---- D: direct launch runs main() ------------------------------------------
const serverJs = resolve(repoRoot, "dist/mcp/server.js");
if (!existsSync(serverJs)) execSync("npm run build", { cwd: repoRoot, stdio: "ignore" });
const env = { ...process.env }; delete env.ATLAS_BUNDLE;
const launched = spawnSync(process.execPath, [serverJs], { env, encoding: "utf8", timeout: 20000 });
assert.notStrictEqual(launched.status, 0, "main() ran and rejected the missing --bundle (exit != 0)");
assert.match(launched.stderr, /--bundle|ATLAS_BUNDLE/, "the startup error came from main(), so the entrypoint check matched");

// ---- P2: atomic writes -------------------------------------------------------
const dir = mkdtempSync(join(tmpdir(), "atlas-atomic-"));
const target = join(dir, "bundle.json");
writeFileSync(target, '{"v":1}');
writeFileAtomic(target, '{"v":2}');
assert.strictEqual(readFileSync(target, "utf8"), '{"v":2}', "atomic write replaces the file");
assert.deepStrictEqual(readdirSync(dir), ["bundle.json"], "no temp file left after success");
const asDir = join(dir, "isdir"); mkdirSync(asDir);
assert.throws(() => writeFileAtomic(asDir, "x"), "renaming over a directory fails");
assert.deepStrictEqual(readdirSync(dir).sort(), ["bundle.json", "isdir"], "a failed write cleans up its temp file");
assert.strictEqual(readFileSync(target, "utf8"), '{"v":2}', "other files are untouched by a failed write");

// short writes: a write that returns fewer bytes than asked must be continued, and a stalled one must abort BEFORE the rename
const partial: typeof writeSync = ((fd: number, buf: Buffer, off: number, len: number) => writeSync(fd, buf, off, Math.min(len, 3))) as any;
writeFileAtomic(target, '{"v":3,"pad":"0123456789"}', partial);
assert.strictEqual(readFileSync(target, "utf8"), '{"v":3,"pad":"0123456789"}', "a writer that returns 3 bytes at a time still persists the whole file");
const stalled: typeof writeSync = (() => 0) as any;
assert.throws(() => writeFileAtomic(target, '{"v":4}', stalled), /short write/, "a stalled writer aborts instead of renaming a truncated file");
assert.strictEqual(readFileSync(target, "utf8"), '{"v":3,"pad":"0123456789"}', "the original survives an aborted write");
assert.deepStrictEqual(readdirSync(dir).sort(), ["bundle.json", "isdir"], "no temp file after an aborted write");
assert.throws(() => writeFully(1, Buffer.from("x"), (() => 0) as any), /short write/);

// permissions: the replacement keeps the existing mode (POSIX; Windows only models read-only)
if (process.platform !== "win32") {
  chmodSync(target, 0o644); writeFileAtomic(target, "{}");
  assert.strictEqual(statSync(target).mode & 0o777, 0o644, "an existing 0644 bundle stays 0644");
}

// read-only target: rejected (POSIX 0444 and the Windows read-only attribute)
const ro = join(dir, "ro.json"); writeFileSync(ro, '{"v":1}'); chmodSync(ro, 0o444);
assert.throws(() => writeFileAtomic(ro, '{"v":2}'), "a read-only bundle is not replaced");
assert.strictEqual(readFileSync(ro, "utf8"), '{"v":1}', "the read-only bundle is unchanged");
chmodSync(ro, 0o644);
assert.ok(!readdirSync(dir).some((f) => f.endsWith(".tmp")), "no temp file left by the rejected write");

// exact mode under a restrictive umask (POSIX)
if (process.platform !== "win32") {
  const old = process.umask(0o077);
  try { chmodSync(target, 0o644); writeFileAtomic(target, "{}"); assert.strictEqual(statSync(target).mode & 0o777, 0o644, "0644 survives umask 077"); }
  finally { process.umask(old); }
}

// symlinked bundle: the real file is updated and the link survives (needs symlink permission; skipped where the OS denies it)
const realFile = join(dir, "real.json"), linkFile = join(dir, "link.json");
writeFileSync(realFile, '{"v":1}');
let linked = true;
try { symlinkSync(realFile, linkFile); } catch { linked = false; console.log("  (symlink check skipped: no permission to create symlinks)"); }
if (linked) {
  writeFileAtomic(linkFile, '{"v":9}');
  assert.strictEqual(readFileSync(realFile, "utf8"), '{"v":9}', "the symlink target holds the new content");
  assert.ok(lstatSync(linkFile).isSymbolicLink(), "the link is still a symlink, not replaced by a regular file");
}

// ---- P2: UTF-8 byte cap -------------------------------------------------------
const tools = new AtlasTools(bundle);
const limits = { timeoutMs: 2000, memoryMb: 128, maxCodeChars: 20_000, maxResultBytes: 100_000 };
const ascii = runAtlasExec(tools, `return "a".repeat(60000);`, "h", limits);
assert.strictEqual(ascii.ok, true, "60,000 ASCII bytes fit a 100,000-byte cap");
const wide = runAtlasExec(tools, `return "é".repeat(60000);`, "h", limits);   // 60,000 chars = ~120,000 UTF-8 bytes
assert.strictEqual(wide.ok, false, "60,000 two-byte characters exceed the byte cap even though length < cap");
assert.match(String((wide as any).error), /exceeds 100000 bytes/, "the error names the byte cap");
// agent code cannot swap the byte counter or serializer to dodge the cap
const tamper = runAtlasExec(tools, `globalThis.encodeURIComponent = () => ""; globalThis.unescape = () => ""; return "漢".repeat(40000);`, "h", limits);
assert.strictEqual(tamper.ok, false, "reassigning encodeURIComponent/unescape does not bypass the byte cap");
const tamper2 = runAtlasExec(tools, `JSON.stringify = () => "1"; return "漢".repeat(40000);`, "h", limits);
assert.strictEqual(tamper2.ok, false, "reassigning JSON.stringify does not bypass the byte cap");
const cjk = runAtlasExec(tools, `return "漢".repeat(40000);`, "h", limits);   // 40,000 chars = 120,000 bytes
assert.strictEqual(cjk.ok, false, "three-byte characters are counted as three bytes");

console.log("provenance.test: receipt bound to content; direct launch runs main(); atomic writes; UTF-8 result cap");
