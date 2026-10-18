/**
 * What an agent sees when it connects to a map:
 *  - the server sends a usage guide at connect time (how to search, what coverage means, honesty rules);
 *  - atlas_search ignores filler words and ranks nodes that match MORE of the distinct words first, so a phrase
 *    like "personal_access_tokens rotate service" lands on rotate_service.rb instead of every node containing "a";
 *  - a bundle records the commit its folder was checked out at (read from .git: loose ref, packed-refs, detached,
 *    gitfile), so a map can be matched to a running instance.
 */
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { buildAtlas } from "../src/build.js";
import { AtlasTools } from "../src/mcp/tools.js";
import { buildServer } from "../src/mcp/server.js";
import { readGitHead } from "../src/scanner/gitHead.js";

const root = mkdtempSync(join(tmpdir(), "atlas-agentux-"));
const put = (rel: string, body: string) => { const p = join(root, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, body); };

// ---- git head reader
const SHA = "0123456789abcdef0123456789abcdef01234567", SHA2 = "fedcba9876543210fedcba9876543210fedcba98";
put(".git/HEAD", "ref: refs/heads/main\n"); put(".git/refs/heads/main", SHA + "\n");
assert.equal(readGitHead(root), SHA, "a loose ref");
const packed = mkdtempSync(join(tmpdir(), "atlas-git-packed-"));
mkdirSync(join(packed, ".git"), { recursive: true });
writeFileSync(join(packed, ".git/HEAD"), "ref: refs/heads/master\n");
writeFileSync(join(packed, ".git/packed-refs"), `# pack-refs\n${SHA2} refs/heads/master\n${SHA} refs/heads/other\n`);
assert.equal(readGitHead(packed), SHA2, "a packed ref");
const detached = mkdtempSync(join(tmpdir(), "atlas-git-det-"));
mkdirSync(join(detached, ".git"), { recursive: true }); writeFileSync(join(detached, ".git/HEAD"), SHA + "\n");
assert.equal(readGitHead(detached), SHA, "a detached HEAD");
const wt = mkdtempSync(join(tmpdir(), "atlas-git-wt-"));
mkdirSync(join(wt, "real")); writeFileSync(join(wt, "real/HEAD"), SHA2 + "\n"); writeFileSync(join(wt, ".git"), "gitdir: real\n");
assert.equal(readGitHead(wt), SHA2, "a .git file pointing at the real git dir");
assert.equal(readGitHead(mkdtempSync(join(tmpdir(), "atlas-nogit-"))), undefined, "no .git: no commit, no error");
const bad = mkdtempSync(join(tmpdir(), "atlas-git-bad-"));
mkdirSync(join(bad, ".git"), { recursive: true }); writeFileSync(join(bad, ".git/HEAD"), "ref: ../../etc/passwd\n");
assert.equal(readGitHead(bad), undefined, "a ref that climbs out of .git is ignored");

// ---- a bundle records the commit
put("app/services/personal_access_tokens/rotate_service.rb", "class RotateService\n  def execute\n    1\n  end\nend\n");
put("app/services/projects/create_service.rb", "class CreateService\n  def execute\n    2\n  end\nend\n");
put("lib/api/projects.rb", "class Projects\n  def retrieve\n    3\n  end\nend\n");
put("lib/other.rb", "class Other\n  def a_for_the\n    4\n  end\nend\n");
const { bundle } = await buildAtlas(root, { repoLabel: "ux-demo" });
assert.equal(bundle.repository.sourceCommit, SHA, "the bundle records the commit it was scanned at");
assert.ok(bundle.repository.revision.startsWith("ux-demo@"), "the revision label is unchanged");

// ---- search
const tools = new AtlasTools(bundle);
const top = (q: string) => (tools.search(q, 3) as any).results.map((r: any) => `${r.kind}:${r.path ?? r.evidence?.path ?? r.label}`);
const first = (tools.search("personal_access_tokens rotate service", 5) as any).results[0];
assert.ok(JSON.stringify(first).includes("rotate_service"), "a multi-word identifier phrase finds the right file first");
const proj = (tools.search("find the lib/api/projects file for a project", 5) as any).results[0];
assert.ok(JSON.stringify(proj).includes("lib/api/projects"), "filler words do not outrank the path fragment");
const empty = tools.search("a the for to", 5) as any;
assert.equal(empty.results.length, 0); assert.ok(String(empty.hint).includes("identifier"), "all-filler query gets a hint, not noise");
void top;

// ---- the guide reaches the client
const [ct, st] = InMemoryTransport.createLinkedPair();
const server = buildServer({ tools } as any);
await server.connect(st);
const client = new Client({ name: "t", version: "1" });
await client.connect(ct);
const guide = client.getInstructions() ?? "";
assert.ok(guide.includes("STATIC") && guide.includes("coverage") && guide.includes("atlas_search") && guide.includes("atlas.routes"), "the usage guide is sent at connect time");
assert.ok(/sourceCommit/.test(guide), "the guide tells the agent to check which commit was scanned");
await client.close(); await server.close();

console.log("agent-ux.test: usage guide at connect, filler-proof search, source commit recorded from .git");
