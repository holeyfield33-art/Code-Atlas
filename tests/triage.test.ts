/**
 * Finding disposition / triage layer.
 *
 * Proves: the schema accepts a disposition; applyDisposition records provenance
 * and re-validates; triage is strictly SUPPRESSIVE (never upgrades a grade or
 * invents a blast); the MCP triage op persists to the bundle file and refreshes
 * reads; and atlas_threats reflects the decision.
 */
import assert from "node:assert";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseBundle, type AtlasBundle } from "../src/schema.js";
import { applyDisposition, castsBlastAfterTriage, isDismissed } from "../src/triage.js";
import { makeCtx } from "../src/mcp/server.js";

const ev = { path: "app.py", line: 2, column: 1, revision: "r", contentHash: "sha256:x", method: "tree-sitter-static" as const, status: "static" as const };

// A verified weakness on fn_a, casting a blast radius onto fn_b.
const base: AtlasBundle = parseBundle({
  schemaVersion: "1.0",
  product: { name: "Code Atlas" },
  repository: { label: "demo", revision: "r" },
  generatedAt: new Date().toISOString(),
  graph: {
    version: "ts-0.1", revision: "r",
    nodes: [
      { id: "fn_a", kind: "function", label: "a", evidence: ev },
      { id: "fn_b", kind: "function", label: "b", evidence: ev },
    ],
    edges: [], diagnostics: [],
  },
  findings: [
    { id: "F1", nodeRefs: ["fn_a"], kind: "weakness", title: "verified weakness", explanation: "x",
      grade: "OBSERVED", evidence: [{ source: "t", detail: "d" }], blastRadius: ["fn_b"] },
  ],
  diagnostics: [],
});

// before triage: a verified weakness casts a blast
assert.ok(castsBlastAfterTriage(base.findings![0]), "verified weakness casts blast before triage");

// unknown id throws
assert.throws(() => applyDisposition(base, "NOPE", { status: "confirmed", by: "ashura" }), /Unknown finding id/);

// false_positive -> dismissed, no blast
const fp = applyDisposition(base, "F1", { status: "false_positive", by: "ashura", note: "stdlib, not reachable" });
assert.strictEqual(fp.findings![0].disposition!.status, "false_positive", "disposition recorded");
assert.strictEqual(fp.findings![0].disposition!.by, "ashura", "provenance: who");
assert.ok(fp.findings![0].disposition!.at, "provenance: when (auto-stamped)");
assert.ok(isDismissed(fp.findings![0]), "false_positive is dismissed");
assert.ok(!castsBlastAfterTriage(fp.findings![0]), "a dismissed finding casts no blast");
assert.doesNotThrow(() => parseBundle(fp), "triaged bundle re-validates");

// accepted_risk -> still visible but no blast
const ar = applyDisposition(base, "F1", { status: "accepted_risk", by: "ashura" });
assert.ok(!isDismissed(ar.findings![0]), "accepted_risk is not dismissed");
assert.ok(!castsBlastAfterTriage(ar.findings![0]), "accepted_risk casts no blast");

// confirmed -> grade unchanged, still a verified weakness that casts blast
const cf = applyDisposition(base, "F1", { status: "confirmed", by: "ashura" });
assert.strictEqual(cf.findings![0].grade, "OBSERVED", "disposition does not change the grade");
assert.ok(castsBlastAfterTriage(cf.findings![0]), "a confirmed verified weakness still casts its blast");

// clearing removes the disposition
const cleared = applyDisposition(fp, "F1", null);
assert.strictEqual(cleared.findings![0].disposition, undefined, "disposition cleared");

// --- MCP persistence: triage via the server ctx writes the bundle + refreshes reads ---
const dir = mkdtempSync(join(tmpdir(), "atlas-triage-"));
const path = join(dir, "atlas.bundle.json");
writeFileSync(path, JSON.stringify(base));
const ctx = makeCtx(base, path);

// blast visible before triage
const before = ctx.tools.threats("fn_a") as any;
assert.strictEqual(before.findings[0].blastRadius.length, 1, "blast shown before triage");

const res = ctx.triage("F1", "false_positive", "agent:aletheia", "duplicate of F-7") as any;
assert.ok(res.ok && res.persisted, "triage persisted");

// file on disk now carries the disposition and still validates
const onDisk = parseBundle(JSON.parse(readFileSync(path, "utf8")));
assert.strictEqual(onDisk.findings![0].disposition!.status, "false_positive", "persisted to disk");

// reads refreshed: threats now reports the disposition and drops the blast
const after = ctx.tools.threats("fn_a") as any;
assert.strictEqual(after.findings[0].disposition.status, "false_positive", "threats reflects disposition");
assert.strictEqual(after.findings[0].blastRadius.length, 0, "dismissed finding no longer casts blast in threats");

// a bad status is rejected (the MCP handler turns this throw into {ok:false}),
// and nothing new is written: the file still shows the prior false_positive.
assert.throws(() => ctx.triage("F1", "bogus", "x"), /Invalid disposition/, "invalid status rejected");
const stillFp = parseBundle(JSON.parse(readFileSync(path, "utf8")));
assert.strictEqual(stillFp.findings![0].disposition!.status, "false_positive", "rejected triage did not corrupt the file");

console.log("triage.test: disposition records provenance, suppresses (never upgrades), persists via MCP, and threats reflects it");
