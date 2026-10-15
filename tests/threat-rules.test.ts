/**
 * Native threat rules for non-JS graphs (Python + Ruby rule packs).
 *
 * Proves the tree-sitter backends now get native findings, with the SAME honesty
 * rails as the JS/TS scanner:
 *  - a sink match produces a STATIC lead (never OBSERVED/TESTED);
 *  - a STATIC lead casts NO blast radius (grade gate holds for non-JS too);
 *  - a visible guard (shlex / safe_load) suppresses the matching sink rule;
 *  - every finding maps to a real node; the bundle stays schema-valid.
 */
import assert from "node:assert";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildAtlas } from "../src/build.js";
import { parseBundle } from "../src/schema.js";

const root = mkdtempSync(join(tmpdir(), "atlas-threat-"));
mkdirSync(join(root, "app"), { recursive: true });

// --- Python: a command-exec sink, a dynamic-eval sink, a secret handler, and a
//     GUARDED shell-out that must NOT trip the os-command rule. ---
writeFileSync(join(root, "app", "danger.py"),
  "import os\n" +
  "import subprocess\n" +
  "import shlex\n" +
  "\n" +
  "def run_cmd(c):\n" +
  "    return os.system(c)\n" +            // py-os-command
  "\n" +
  "def run_code(expr):\n" +
  "    return eval(expr)\n" +              // py-code-exec
  "\n" +
  "def get_password(user):\n" +            // py-raw-secret (name-based)
  "    return lookup(user)\n" +
  "\n" +
  "def safe_cmd(c):\n" +
  "    return subprocess.run(shlex.split(c))\n"  // GUARDED: shlex.split present -> no finding
);
// a top-level helper so run_cmd has a resolvable callee / caller graph exists
writeFileSync(join(root, "app", "util.py"), "def lookup(u):\n    return u\n");

// --- Ruby: a system() sink and a guarded one. ---
writeFileSync(join(root, "app", "danger.rb"),
  "def shell(cmd)\n" +
  "  system(cmd)\n" +                      // rb-os-command
  "end\n" +
  "\n" +
  "def safe_shell(cmd)\n" +
  "  system(Shellwords.escape(cmd))\n" +   // GUARDED: shellescape present -> no finding
  "end\n"
);

const { bundle } = await buildAtlas(root, { product: "Code Atlas" });
assert.doesNotThrow(() => parseBundle(bundle), "mixed non-JS bundle with native findings validates");

const findings = bundle.findings ?? [];
const idStarts = (p: string) => findings.filter((f) => f.id.startsWith(p));

// sinks fire, as STATIC leads
assert.ok(idStarts("py-os-command:").length === 1, "python os.system flagged once");
assert.ok(idStarts("py-code-exec:").length === 1, "python eval flagged once");
assert.ok(idStarts("py-raw-secret:").length === 1, "python secret-like handler flagged once");
assert.ok(idStarts("rb-os-command:").length === 1, "ruby system() flagged once");

// the guarded functions do NOT produce an os-command weakness
const flaggedNodes = new Set(findings.flatMap((f) => f.nodeRefs));
const nodeLabel = (id: string) => bundle.graph.nodes.find((n) => n.id === id)?.label;
const osCmdTargets = idStarts("py-os-command:").concat(idStarts("rb-os-command:")).flatMap((f) => f.nodeRefs).map(nodeLabel);
assert.ok(!osCmdTargets.includes("safe_cmd"), "guarded python shell-out (shlex.split) is not flagged");
assert.ok(!osCmdTargets.includes("safe_shell"), "guarded ruby shell-out (Shellwords.escape) is not flagged");

// honesty: every native (py-/rb-) finding is STATIC and casts NO blast
const native = findings.filter((f) => /^(py|rb)-/.test(f.id));
assert.ok(native.length >= 4, "native (python+ruby) findings produced");
for (const f of native) {
  assert.strictEqual(f.grade, "STATIC", `${f.id} is a STATIC lead`);
  assert.strictEqual(f.blastRadius.length, 0, `${f.id} casts no blast radius (static lead)`);
  assert.ok(flaggedNodes.has(f.nodeRefs[0]) && bundle.graph.nodes.some((n) => n.id === f.nodeRefs[0]),
    `${f.id} maps to a real node`);
  assert.ok(f.asiRef?.id, `${f.id} is ASI-linked`);
}

console.log(`threat-rules.test: ${native.length} native findings (py+rb), all STATIC with 0 blast, guards honoured — parseBundle OK`);
