/**
 * Scanner calibration, measured against a real TypeScript web app (SurfaceTrace):
 * the scanner reported 10 findings, 7 of them false alarms on functions named like
 * `redactTextSecrets`, and none about the file writes and database calls that lived in
 * CLASS METHODS, which were not mapped at all. This pins the fixes:
 *  - class methods / private methods / arrow class properties are function nodes
 *    labelled `Class.member`, so rules can see them;
 *  - dotted sinks (`fs.writeFileSync`, `this.db...`) match as method calls, while a bare
 *    `re.exec(...)` still does not;
 *  - constant SQL (`db.prepare("SELECT ...")`) is not a high-impact sink by itself;
 *  - a function that reads request input AND reaches a sink with no validation is its own
 *    (more specific) lead;
 *  - the secret rule needs a log/write/send in the function and ignores protective names.
 * Everything stays a STATIC lead with no blast radius.
 */
import assert from "node:assert/strict";
import { buildGraph, type SourceFile } from "../src/scanner/graph.js";
import { scan } from "../src/scanner/findings.js";
import { DEFAULT_RULES, validateRules } from "../src/scanner/rules.js";

const code = [
  'import { writeFileSync } from "node:fs";',
  'import * as fs from "node:fs";',
  'import { exec } from "node:child_process";',
  'export class Vault {',
  '  private db: any;',
  '  save(p: string, data: string) { writeFileSync(p, data); }',                       // class method, free sink
  '  dump(p: string, data: string) { fs.writeFileSync(p, data); }',                    // qualified sink
  '  readVersion() { return this.db.prepare("SELECT version FROM schema_version").get(); }', // constant SQL
  '  handler = (req: any) => { fs.writeFileSync(req.body.path, "x"); };',              // class property arrow + request input
  '  #wipe(p: string) { fs.rmSync(p); }',                                              // private method
  '}',
  'export function redactTextSecrets(t: string) { console.log(t); return t.replace(/x/g, "*"); }', // protective name
  'export function hasRedactedCredential(c: string) { console.log(c); return true; }',            // protective name
  'export function logToken(token: string) { console.log(token); }',                              // secret + log -> lead
  'export function getApiKey(store: any) { return store.key; }',                                  // name only -> NOT a lead
  'export function lookup(re: RegExp, s: string) { return re.exec(s); }',                         // regex exec, not a sink
  'export function sqlFromReq(req: any, db: any) { return db.prepare("SELECT * FROM t WHERE id=" + req.query.id); }',
  'export function runIt(req: any) { return exec(req.body.cmd); }',                               // free exec + request input
  'export function safeRun(req: any) { const c = validate(req.body.cmd); return exec(c); }',      // validated
].join("\n");
const sources: SourceFile[] = [{ path: "app.ts", code }];
const graph = buildGraph("cal@test", sources);
const { findings } = scan(graph, sources, DEFAULT_RULES);
const label = (id: string) => graph.nodes.find((n) => n.id === id)!.label;
const flagged = (prefix: string) => findings.filter((f) => f.id.startsWith(prefix + ":")).map((f) => label(f.nodeRefs[0])).sort();

// ---- class members are mapped
const fnLabels = graph.nodes.filter((n) => n.kind === "function").map((n) => n.label);
for (const l of ["Vault.save", "Vault.dump", "Vault.readVersion", "Vault.handler", "Vault.#wipe"])
  assert.ok(fnLabels.includes(l), `${l} is a function node`);
const file = graph.nodes.find((n) => n.kind === "file")!;
assert.ok(graph.edges.some((e) => e.kind === "contains" && e.from === file.id && label(e.to) === "Vault.save"), "a class method is contained by its file");
assert.ok(!graph.edges.some((e) => e.kind === "calls" && label(e.from).startsWith("Vault.")), "class methods get no (unresolved) call edges");

// ---- sinks
assert.deepEqual(flagged("r-unguarded-sink"), ["Vault.#wipe", "Vault.dump", "Vault.handler", "Vault.save", "runIt"],
  "free and qualified sinks inside class members are flagged; regex.exec, constant SQL and a validated call are not");
assert.ok(!flagged("r-unguarded-sink").includes("Vault.readVersion"), "constant SQL via db.prepare is not a high-impact sink by itself");
assert.ok(!flagged("r-unguarded-sink").includes("lookup"), "re.exec(...) is not a process-exec sink");
assert.ok(!flagged("r-unguarded-sink").includes("safeRun"), "a visible validation call suppresses the lead");

// ---- request input reaching a sink
assert.deepEqual(flagged("r-input-to-sink"), ["Vault.handler", "runIt", "sqlFromReq"],
  "request input + a sink with no validation is flagged, including a DB call that is a sink only when input is read");
assert.ok(!flagged("r-input-to-sink").includes("safeRun"), "validated input is not flagged");
const firstForHandler = findings.filter((f) => label(f.nodeRefs[0]) === "Vault.handler")[0];
assert.ok(firstForHandler.id.startsWith("r-input-to-sink:"), "the more specific rule is listed first");

// ---- secrets: protective names are not leaks; a name alone is not enough
assert.deepEqual(flagged("r-raw-secret"), ["logToken"], "only a secret-named function that logs/writes/sends is flagged");
for (const ok of ["redactTextSecrets", "hasRedactedCredential", "getApiKey"])
  assert.ok(!findings.some((f) => label(f.nodeRefs[0]) === ok && f.id.startsWith("r-raw-secret:")), `${ok} is not reported as a secret leak`);

// ---- honesty rails unchanged
for (const f of findings) {
  assert.equal(f.grade, "STATIC", f.id + " stays a STATIC lead");
  assert.equal(f.blastRadius.length, 0, f.id + " casts no blast radius");
}

// ---- rule packs: the new fields validate, and bad ones are refused at load
assert.doesNotThrow(() => validateRules(DEFAULT_RULES), "the shipped pack validates");
const rule = (when: object) => [{ id: "x", kind: "weakness", grade: "STATIC", title: "t", explanation: "e", when }];
assert.doesNotThrow(() => validateRules(rule({ callsAny: ["exec"], textAny: ["req.body"], nameNotMatches: "^safe" })));
assert.throws(() => validateRules(rule({ callsAny: ["exec"], textAny: [""] })), /textAny/, "an empty textAny entry is refused");
assert.throws(() => validateRules(rule({ callsAny: ["exec"], textAny: "req.body" })), /textAny/, "textAny must be an array");
assert.throws(() => validateRules(rule({ callsAny: ["exec"], nameNotMatches: "(" })), /nameNotMatches|RE2|valid/i, "an invalid nameNotMatches is refused at load");

console.log(`calibration.test: ${graph.nodes.filter((n) => n.kind === "function").length} function nodes incl. class members; ` +
  `${findings.length} STATIC leads — sinks in class methods found, regex/constant-SQL/validated/protective names not flagged`);
