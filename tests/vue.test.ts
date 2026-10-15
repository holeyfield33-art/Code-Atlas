/**
 * Vue SFC proof: a .vue file's <script> block routes to the Babel backend via a
 * position-preserving shim, so a function defined inside <script> appears as a
 * grounded node whose evidence points at the REAL .vue file at the REAL line —
 * template/style outside <script> contribute nothing and never fabricate nodes.
 */
import assert from "node:assert";
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildAtlas } from "../src/build.js";
import { parseBundle } from "../src/schema.js";
import { extractVueScript } from "../src/scanner/vue.js";

// The template carries an ASTRAL emoji (🚀, a UTF-16 surrogate PAIR) BEFORE the
// <script> block: the regression for code-unit vs code-point offsets. The shim
// must keep the same code-unit length so greet still lands on line 6.
const sfc =
  "<template>\n" +           // line 1
  "  <div>🚀 {{ msg }}</div>\n" + // line 2  (astral char before <script>)
  "</template>\n" +          // line 3
  "\n" +                     // line 4
  "<script>\n" +             // line 5
  "export function greet(name) {\n" + // line 6
  "  return \"hi \" + name;\n" +      // line 7
  "}\n" +                    // line 8
  "</script>\n" +            // line 9
  "\n" +                     // line 10
  "<style>\n.x { color: red; }\n</style>\n";
const shim = extractVueScript(sfc);
assert.ok(shim !== null, "shim extracted from a .vue with a <script> block");
assert.strictEqual(shim!.length, sfc.length, "shim is the same code-unit length as the source (offsets preserved, astral-safe)");
assert.ok(/export function greet/.test(shim!), "shim keeps the script verbatim");
assert.ok(!/<template>|<style>|<div>|🚀/.test(shim!), "shim blanks template/style markup and the astral char");
assert.strictEqual(extractVueScript("<template><div/></template>\n<style>.a{}</style>"), null, "no <script> -> null (nothing to analyze)");

// --- integration: the .vue participates in the build with real-file evidence ---
const root = mkdtempSync(join(tmpdir(), "atlas-vue-"));
mkdirSync(join(root, "components"), { recursive: true });
writeFileSync(join(root, "components", "Hello.vue"), sfc);

const { bundle, langSummary } = await buildAtlas(root, { product: "Code Atlas", security: false });
assert.doesNotThrow(() => parseBundle(bundle), "vue bundle validates against the schema");

const greet = bundle.graph.nodes.find((n) => n.label === "greet");
assert.ok(greet, "a function from the .vue <script> appears as a node");
assert.ok(greet!.evidence.path.endsWith("Hello.vue"), "evidence points at the real .vue file, not a shim path");
assert.strictEqual(greet!.evidence.method, "babel-static", "the .vue script was analyzed by the Babel backend");
assert.strictEqual(greet!.evidence.line, 6, "line maps to the real .vue (greet is on line 6) even with an astral char above");
assert.ok(/\bvue\b/.test(langSummary), `langSummary counts the vue file (${langSummary})`);

// contentHash must identify the REAL SFC, not the parse-only shim (Evidence contract).
const realHash = "sha256:" + createHash("sha256").update(sfc).digest("hex");
const vueFile = bundle.graph.nodes.find((n) => n.kind === "file" && n.evidence.path.endsWith("Hello.vue"));
assert.ok(vueFile, "the .vue file node exists");
assert.strictEqual(vueFile!.evidence.contentHash, realHash, "evidence.contentHash hashes the real SFC, not the shim");
assert.strictEqual(greet!.evidence.contentHash, realHash, "function evidence hash also identifies the real SFC");

console.log(`vue.test: ${langSummary} -> greet @ ${greet!.evidence.path}:${greet!.evidence.line} (${greet!.evidence.method}), hash=real SFC — parseBundle OK`);
