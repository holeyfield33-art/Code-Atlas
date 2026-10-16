/**
 * Rule pack for the native findings scanner. Rules are DATA — declarative,
 * JSON-serializable, customizable, sellable as packs. The engine (findings.ts)
 * evaluates each rule against the graph's functions.
 *
 * Honesty rails baked into the type:
 *  - a static rule's grade is STATIC or INFERRED only. OBSERVED/TESTED require
 *    runtime or test evidence a static scanner does not have.
 *  - a rule never claims exploitability; blast radius is "possibly affected".
 *  - a control (green) means a control ARTIFACT is present, not that it works.
 */
import { RE2JS } from "re2js";

export interface RuleWhen {
  /** Function's source contains a call `name(` to any of these (a sink / primitive). */
  callsAny?: string[];
  /** ...and contains a call to NONE of these (e.g. no visible validator). */
  callsNoneOf?: string[];
  /** Function name matches this regex (case-insensitive). */
  nameMatches?: string;
  /** Suppress the finding if any of these substrings appears in the body text.
   *  For guards that are NOT calls (e.g. a keyword argument `Loader=SafeLoader`),
   *  which call-token matching can't see. Only ever REMOVES a finding, so a
   *  lenient text check here is conservative. */
  guardText?: string[];
}

export interface Rule {
  id: string;
  kind: "weakness" | "control";
  grade: "STATIC" | "INFERRED";
  title: string;
  explanation: string;
  when: RuleWhen;
  blast?: "callers" | "none";                 // weakness blast radius from the real call graph
  asi?: { id: string; label: string; mitigation: string; url: string };
}

import { asiUrl, AAC } from "./asi.js";
// ASI classes live in one place (asi.ts). A rule just names the class id.
const asi = (id: string, _label?: string, _mit?: string) =>
  ({ id, label: AAC[id]?.label ?? id, mitigation: AAC[id]?.mitigation ?? "", url: asiUrl(id) });

/** The default pack — a few honest structural leads, ASI-linked to real classes. */
export const DEFAULT_RULES: Rule[] = [
  {
    id: "r-unguarded-sink", kind: "weakness", grade: "STATIC",
    title: "High-impact sink with no visible validator",
    explanation:
      "This function reaches a high-impact sink (file write, process exec, eval, or query) and no validation or guard call is visible inside it. Static lead — not proof the input is attacker-controlled or that the path is reachable.",
    when: {
      callsAny: ["writeFileSync", "writeFile", "exec", "execSync", "spawn", "eval", "Function", "query", "run"],
      callsNoneOf: ["validate", "sanitize", "assert", "check", "guard", "parse", "safeParse", "zod", "schema"],
    },
    blast: "callers",
    asi: asi("AAC-11", "High-impact action without constraint",
      "Constrain and validate inputs before a high-impact sink; apply least privilege."),
  },
  {
    id: "r-raw-secret", kind: "weakness", grade: "STATIC",
    title: "Secret-like handling without visible redaction",
    explanation:
      "This function's name suggests it handles secret material (token / password / credential / apiKey) and no redaction call is visible inside it. Static lead only.",
    when: { nameMatches: "(token|secret|password|credential|apikey)", callsNoneOf: ["redact", "sanitize", "mask"] },
    blast: "none",
    asi: asi("AAC-09", "Secret exposure",
      "Redact secrets before logging or persistence; never store raw credentials."),
  },
  {
    id: "c-input-validation", kind: "control", grade: "STATIC",
    title: "Input validation present",
    explanation:
      "This function calls a validation or schema primitive — a control artifact. Present does not mean effective; a reviewer must confirm it actually guards the relevant input.",
    when: { callsAny: ["validate", "sanitize", "parse", "safeParse", "zod"] },
    blast: "none",
    asi: asi("AAC-01", "Input security", "Validate and constrain untrusted input at the trust boundary."),
  },
];

/**
 * Language-native rule packs for the tree-sitter backends (Python, Ruby).
 *
 * The engine (findings.ts `scanGeneric`) matches `callsAny`/`callsNoneOf` against
 * the QUALIFIED CALL TOKENS the mapper captured from real parsed call nodes — not
 * a regex over source. So comments and strings never match, and paren-less calls
 * (`system cmd`, `Marshal.load payload`) are covered. A token with a dot
 * (`os.system`, `Marshal.load`) matches that callee or a deeper-receiver form but
 * stays precise (never an unrelated `foo.run` for `subprocess.run`); a bare token
 * (`eval`, `system`) matches by last segment. `guardText` handles non-call guards
 * (e.g. a `Loader=SafeLoader` keyword arg) and only ever suppresses a finding.
 *
 * Every rule is STATIC: a structural lead, not proof the input is attacker-
 * controlled or the path reachable. Blast radius stays empty (the engine only
 * casts it for OBSERVED/TESTED), so an unverified lead paints no neighbours.
 */
export const PYTHON_RULES: Rule[] = [
  {
    id: "py-code-exec", kind: "weakness", grade: "STATIC",
    title: "Dynamic code execution",
    explanation:
      "This function reaches a dynamic code-execution primitive (eval / exec / compile). If any part of the argument is attacker-influenced this is arbitrary code execution. Static lead — reachability and input source are unverified.",
    when: { callsAny: ["eval", "exec", "compile", "__import__"], callsNoneOf: ["literal_eval", "ast.literal_eval"] },
    blast: "callers",
    asi: asi("AAC-11"),
  },
  {
    id: "py-os-command", kind: "weakness", grade: "STATIC",
    title: "OS command execution with no visible argument quoting",
    explanation:
      "This function shells out (os.system / subprocess / os.popen) and no shlex quoting/splitting is visible inside it. Static lead for command injection — not proof the command string is attacker-controlled.",
    when: {
      callsAny: ["os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call"],
      callsNoneOf: ["shlex.quote", "shlex.split"],
    },
    blast: "callers",
    asi: asi("AAC-11"),
  },
  {
    id: "py-unsafe-deser", kind: "weakness", grade: "STATIC",
    title: "Unsafe deserialization",
    explanation:
      "This function deserializes with a primitive that can execute code or construct arbitrary objects (pickle / marshal / yaml.load without SafeLoader). Static lead — not proof the payload is untrusted.",
    when: { callsAny: ["pickle.loads", "pickle.load", "marshal.loads", "marshal.load", "yaml.load"], callsNoneOf: ["safe_load"], guardText: ["SafeLoader"] },
    blast: "callers",
    asi: asi("AAC-11"),
  },
  {
    id: "py-raw-secret", kind: "weakness", grade: "STATIC",
    title: "Secret-like handling without visible redaction",
    explanation:
      "This function's name suggests it handles secret material (token / password / credential / api_key) and no redaction call is visible inside it. Static lead only.",
    when: { nameMatches: "(token|secret|password|credential|api_?key)", callsNoneOf: ["redact", "mask", "sanitize"] },
    blast: "none",
    asi: asi("AAC-09"),
  },
  {
    id: "py-input-validation", kind: "control", grade: "STATIC",
    title: "Input validation present",
    explanation:
      "This function calls a validation / quoting primitive — a control artifact. Present does not mean effective; a reviewer must confirm it guards the relevant input.",
    when: { callsAny: ["validate", "is_valid", "clean", "shlex.quote", "escape"] },
    blast: "none",
    asi: asi("AAC-01"),
  },
];

export const RUBY_RULES: Rule[] = [
  {
    id: "rb-code-exec", kind: "weakness", grade: "STATIC",
    title: "Dynamic code execution",
    explanation:
      "This method reaches a dynamic code-execution primitive (eval / instance_eval / class_eval / send). If any part of the argument is attacker-influenced this is arbitrary code or method execution. Static lead only.",
    when: { callsAny: ["eval", "instance_eval", "class_eval", "module_eval", "send", "public_send"] },
    blast: "callers",
    asi: asi("AAC-11"),
  },
  {
    id: "rb-os-command", kind: "weakness", grade: "STATIC",
    title: "OS command execution",
    explanation:
      "This method shells out (system / exec / Open3 / %x). If the command string is attacker-influenced this is command injection. Static lead — not proof the input is untrusted.",
    when: { callsAny: ["system", "exec", "Open3.capture2", "Open3.capture3", "Open3.popen3", "Kernel.system"], callsNoneOf: ["Shellwords.escape", "shellescape"] },
    blast: "callers",
    asi: asi("AAC-11"),
  },
  {
    id: "rb-unsafe-deser", kind: "weakness", grade: "STATIC",
    title: "Unsafe deserialization",
    explanation:
      "This method deserializes with a primitive that can construct arbitrary objects (Marshal.load / YAML.load without safe_load). Static lead only.",
    when: { callsAny: ["Marshal.load", "Marshal.restore", "YAML.load"], callsNoneOf: ["safe_load"] },
    blast: "callers",
    asi: asi("AAC-11"),
  },
  {
    id: "rb-raw-secret", kind: "weakness", grade: "STATIC",
    title: "Secret-like handling without visible redaction",
    explanation:
      "This method's name suggests it handles secret material (token / password / credential / api_key) and no redaction call is visible inside it. Static lead only.",
    when: { nameMatches: "(token|secret|password|credential|api_?key)", callsNoneOf: ["redact", "mask", "sanitize"] },
    blast: "none",
    asi: asi("AAC-09"),
  },
  {
    id: "rb-input-validation", kind: "control", grade: "STATIC",
    title: "Input validation present",
    explanation:
      "This method calls a validation / escaping primitive (validate / permit / sanitize / shellescape) — a control artifact. Present does not mean effective; a reviewer must confirm it guards the relevant input.",
    when: { callsAny: ["validate", "validates", "permit", "sanitize", "shellescape"] },
    blast: "none",
    asi: asi("AAC-01"),
  },
];

/** Native rule pack per tree-sitter language. */
export const LANGUAGE_RULES: Record<string, Rule[]> = {
  python: PYTHON_RULES,
  ruby: RUBY_RULES,
};

/**
 * nameMatches is a CUSTOMIZABLE pattern (rule packs are user-supplied data), so
 * it must never be run on a backtracking engine: a pattern-shape heuristic is
 * provably incomplete (e.g. `(a|aa)+$` is catastrophic yet has no quantified
 * token inside the group). We compile every nameMatches with RE2 (via re2js), a
 * linear-time, backtracking-free engine, so NO pattern — default or custom — can
 * cause catastrophic backtracking and block a scan. RE2 drops backreferences and
 * lookaround; our patterns use neither, and a pattern that needs them is rejected
 * at load rather than silently falling back to a vulnerable engine.
 */
const MAX_PATTERN = 1000;
const matcherCache = new Map<string, (s: string) => boolean>();

/** Compile a case-insensitive, unanchored (RegExp.test-equivalent) matcher on a
 *  linear-time engine. Throws if the pattern is invalid/too long/RE2-incompatible. */
export function compileNameMatcher(pattern: string): (s: string) => boolean {
  const cached = matcherCache.get(pattern);
  if (cached) return cached;
  if (pattern.length > MAX_PATTERN) throw new Error(`nameMatches pattern too long (> ${MAX_PATTERN} chars)`);
  let re: ReturnType<typeof RE2JS.compile>;
  try { re = RE2JS.compile(pattern, RE2JS.CASE_INSENSITIVE); }
  catch (e) { throw new Error(`nameMatches is not a valid RE2 pattern (RE2 has no backreferences/lookaround): ${e instanceof Error ? e.message : e}`); }
  const fn = (s: string) => re.matcher(s).find();     // unanchored partial match, linear time
  matcherCache.set(pattern, fn);
  return fn;
}

/** Minimal shape check for a loaded (customized) rule pack. */
export function validateRules(input: unknown): Rule[] {
  if (!Array.isArray(input)) throw new Error("Rule pack must be a JSON array of rules");
  for (const r of input as any[]) {
    if (!r.id || !r.kind || !r.grade || !r.title || !r.when) throw new Error("Rule missing required fields: " + JSON.stringify(r.id ?? r));
    if (r.kind !== "weakness" && r.kind !== "control") throw new Error(`Rule ${r.id}: kind must be weakness|control`);
    if (r.grade !== "STATIC" && r.grade !== "INFERRED") throw new Error(`Rule ${r.id}: a static rule's grade must be STATIC or INFERRED`);
    // Compile now so an unsafe/invalid pattern is rejected at LOAD, never at scan time.
    if (typeof r.when.nameMatches === "string") {
      try { compileNameMatcher(r.when.nameMatches); }
      catch (e) { throw new Error(`Rule ${r.id}: ${e instanceof Error ? e.message : e}`); }
    }
  }
  return input as Rule[];
}
