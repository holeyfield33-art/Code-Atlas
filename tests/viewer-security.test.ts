/**
 * Viewer security contract (no browser harness, so this is a source-contract +
 * pure-function test):
 *  - the viewer's esc() neutralizes HTML-attribute breakout (quotes, angle brackets);
 *  - EVERY data-goto attribute interpolates the id through esc() — a malicious Linux
 *    filename (which becomes part of a tree-sitter node id) cannot inject an event
 *    handler via the "jump to node" links;
 *  - control coloring is evidence-gated: an unverified (STATIC/INFERRED) control is
 *    NOT painted with the full hardened-green, and the grade map/labels cover it.
 */
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(resolve(here, "../viewer/viewer.html"), "utf8");

// --- esc() actually neutralizes an attribute breakout ---------------------
const escSrc = /function esc\(s\)\{[^}]*\{[^}]*\}[^}]*\}/.exec(html)?.[0]
  ?? /function esc\(s\)\{.*?\}\s*$/m.exec(html)?.[0];
assert.ok(escSrc, "found esc() definition in the viewer");
// eslint-disable-next-line no-new-func
const esc = new Function(escSrc + "; return esc;")() as (s: string) => string;

const attack = 'f" onmouseover="alert(1)';            // a filename crafted to break out of an attr
const escaped = esc(attack);
assert.ok(!/[<>"]/.test(escaped.replace(/&quot;|&lt;|&gt;|&amp;/g, "")), "esc removes raw <, >, and \"");
assert.ok(escaped.includes("&quot;"), "esc encodes the double quote that would close the attribute");
// placed inside a double-quoted attribute, the escaped value cannot start a new attribute
assert.ok(!new RegExp(`data-goto="${escaped}"`).source.includes('" on'), "no raw on* handler survives");

// --- every data-goto interpolation is esc()-wrapped -----------------------
const gotos = [...html.matchAll(/data-goto="\$\{([^}]*)\}"/g)].map((m) => m[1].trim());
assert.ok(gotos.length >= 2, "found the data-goto jump links");
for (const expr of gotos) assert.ok(/^esc\(/.test(expr), `data-goto interpolates through esc(): got \${${expr}}`);

// --- control coloring is evidence-gated -----------------------------------
assert.ok(/f\.kind==="control"\s*\)\s*return\s+VERIFIED\(f\.grade\)\s*\?\s*"green"\s*:\s*"control"/.test(html.replace(/\s+/g, " ")),
  "an unverified control maps to the muted 'control' grade, not 'green'");
assert.ok(/GRADECSS\s*=\s*\{[^}]*control:\s*"--grade-control"/.test(html), "GRADECSS has a distinct control colour");
assert.ok(/--grade-control:/.test(html), "the muted control colour is defined");
assert.ok(/GRADE_LABEL\s*=\s*\{[^}]*control:\s*"CONTROL \(UNVERIFIED\)"/.test(html), "unverified control has an honest label");

console.log("viewer-security.test: esc neutralizes attr breakout; all data-goto ids escaped; unverified controls are not hardened-green");
