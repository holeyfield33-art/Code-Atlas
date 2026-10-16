/**
 * Custom-rule ReDoS is closed: nameMatches patterns run on RE2 (linear time, no
 * backtracking), so a pathological custom rule cannot block a scan.
 *
 *  - a classic catastrophic pattern compiles and matches a long adversarial input
 *    in bounded time (a backtracking engine would hang for minutes);
 *  - the engine still produces correct matches (secret-name rule still fires);
 *  - an RE2-incompatible pattern (backreference) is rejected at LOAD, not run.
 */
import assert from "node:assert";
import { compileNameMatcher, validateRules } from "../src/scanner/rules.js";

// Patterns that are catastrophic on a backtracking (JS RegExp) engine.
const CATASTROPHIC = ["(a+)+$", "(a|aa)+$", "(.*a){25}$", "(a*)*$"];
const evil = "a".repeat(50_000) + "!";   // forces maximal backtracking on a vulnerable engine

for (const p of CATASTROPHIC) {
  const t0 = Date.now();
  const m = compileNameMatcher(p);
  const res = m(evil);                   // must NOT hang
  const ms = Date.now() - t0;
  assert.strictEqual(typeof res, "boolean", `${p}: returns a boolean`);
  assert.ok(ms < 1000, `${p}: linear-time match on a 50k adversarial input (${ms}ms, would be minutes on a backtracking engine)`);
}

// correctness preserved: an ordinary alternation still matches / rejects as expected
const secret = compileNameMatcher("(token|secret|password|credential|api_?key)");
assert.ok(secret("getApiKey"), "nameMatches still matches a real secret-ish name");
assert.ok(secret("reset_password"), "case-insensitive + alternation works");
assert.ok(!secret("helper"), "non-matching name is rejected");

// validateRules compiles patterns at load; a catastrophic one is ACCEPTED (safe on RE2)…
assert.doesNotThrow(() =>
  validateRules([{ id: "r", kind: "weakness", grade: "STATIC", title: "t", when: { nameMatches: "(a|aa)+$" } }]),
  "a backtracking-catastrophic pattern is safe to accept on RE2");

// …but an RE2-incompatible pattern (backreference) is rejected at load, never run.
assert.throws(() =>
  validateRules([{ id: "r", kind: "weakness", grade: "STATIC", title: "t", when: { nameMatches: "(.)\\1" } }]),
  /not a valid RE2 pattern|nameMatches/, "backreference pattern rejected at load");

// oversized pattern rejected
assert.throws(() => compileNameMatcher("a".repeat(1001)), /too long/, "oversized pattern rejected");

console.log("redos.test: catastrophic patterns run in linear time on RE2, matches stay correct, incompatible/oversized patterns rejected at load");
