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
  /** ...and the name does NOT match this regex (case-insensitive). Removes protective
   *  names so a redactor/validator is not reported as the leak it guards against. */
  nameNotMatches?: string;
  /** The body text contains at least one of these substrings (e.g. `req.body`). Plain
   *  substring match, so a comment can satisfy it: one signal among several. */
  textAny?: string[];
  /** The body text matches this RE2 pattern (linear time, case-insensitive), e.g. a command that is
   *  not a string literal. Like textAny it reads text, so a comment can satisfy it. */
  textMatches?: string;
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
// Sink vocabularies. Bare names match only FREE (imported) calls; dotted names match the
// real-world method form (`fs.writeFileSync(`, `this.db.exec(`) because the receiver is
// part of the token. A bare `exec`/`run`/`query` still cannot match `regex.exec(`.
const FILE_WRITE_SINKS = ["writeFileSync", "writeFile", "appendFileSync", "appendFile", "createWriteStream", "rmSync", "unlinkSync",
  "fs.writeFile", "fs.writeFileSync", "fs.appendFile", "fs.appendFileSync", "fs.createWriteStream", "fs.rm", "fs.rmSync",
  "fs.unlink", "fs.unlinkSync", "fs.promises.writeFile", "fsp.writeFile"];
const PROCESS_SINKS = ["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync",
  "child_process.exec", "child_process.execSync", "child_process.execFile", "child_process.spawn", "child_process.spawnSync",
  "cp.exec", "cp.execSync", "cp.spawn", "cp.spawnSync"];
const EVAL_SINKS = ["eval", "Function"];
// Database calls. `DB_FREE` are the original bare free-call sinks. `DB_METHODS` (receiver-
// qualified) are NOT treated as sinks on their own: most are constant, parameterised SQL
// (`db.prepare("SELECT version FROM schema_version")`), and flagging them drowned real
// findings in calibration. They count only where request input is read in the same function.
const DB_FREE = ["query", "run"];
const DB_METHODS = ["db.exec", "db.run", "db.prepare", "db.query", "pool.query", "client.query", "knex.raw", "sequelize.query"];
const DB_SINKS = [...DB_FREE, ...DB_METHODS];
const FILE_READ_SINKS = ["readFileSync", "readFile", "createReadStream", "sendFile",
  "fs.readFile", "fs.readFileSync", "fs.createReadStream", "fs.promises.readFile", "fsp.readFile", "res.sendFile", "reply.sendFile"];
const NETWORK_SINKS = ["fetch", "axios", "got", "http.request", "https.request", "http.get", "https.get"];
// A trailing * matches any name that starts with it (verifyReceiptChain, checkAccess, assertValid). `parse` stays exact:
// parseInt / parseFloat validate nothing.
const VALIDATORS = ["validate*", "sanitize", "assert*", "check*", "guard*", "verify*", "parse", "safeParse", "zod", "schema"];

export const DEFAULT_RULES: Rule[] = [
  {
    // Listed first so it is the finding a viewer shows when a function matches both rules.
    id: "r-input-to-sink", kind: "weakness", grade: "STATIC",
    title: "Request input and a high-impact operation in one function, with no visible validation",
    explanation:
      "This function reads request data (req/request .body, .query, .params or .headers) and also reaches a high-impact operation (file write or read, process exec, eval, database call, or outbound request), and no validation or guard call is visible inside it. Static lead — it does not prove the request data reaches that operation, or that it is attacker-controlled; trace it before acting. Handlers written as inline callbacks inside a larger function are judged as part of that function.",
    when: {
      textAny: ["req.body", "req.query", "req.params", "req.headers", "request.body", "request.query", "request.params", "request.headers"],
      callsAny: [...FILE_WRITE_SINKS, ...PROCESS_SINKS, ...EVAL_SINKS, ...DB_SINKS, ...FILE_READ_SINKS, ...NETWORK_SINKS],
      callsNoneOf: VALIDATORS,
    },
    blast: "callers",
    asi: asi("AAC-11", "High-impact action without constraint",
      "Validate and constrain request input at the trust boundary before it reaches a file, process, query or outbound request."),
  },
  {
    id: "r-unguarded-sink", kind: "weakness", grade: "STATIC",
    title: "High-impact sink with no visible validator",
    explanation:
      "This function reaches a high-impact sink (file write, process exec, eval, or query) and no validation or guard call is visible inside it. Static lead — not proof the input is attacker-controlled or that the path is reachable.",
    when: {
      callsAny: [...FILE_WRITE_SINKS, ...PROCESS_SINKS, ...EVAL_SINKS, ...DB_FREE],
      callsNoneOf: VALIDATORS,
    },
    blast: "callers",
    asi: asi("AAC-11", "High-impact action without constraint",
      "Constrain and validate inputs before a high-impact sink; apply least privilege."),
  },
  {
    id: "r-raw-secret", kind: "weakness", grade: "STATIC",
    title: "Secret-like handling that logs, stores or sends data, without visible redaction",
    explanation:
      "This function's name suggests it handles secret material (token / password / credential / apiKey), it logs, writes or sends data, and no redaction call is visible inside it. Functions that look like protection (redact, mask, validate, verify, has/is/check, match, hash) are not reported. Static lead only: a name is a hint, not proof that a secret reaches the log, file or request.",
    when: {
      nameMatches: "(token|secret|password|passwd|credential|apikey|api_key|private_?key)",
      nameNotMatches: "^(redact|mask|sanitize|scrub|strip|hash|validate|verify|is|has|check|assert|ensure|match|compare|safe|fingerprint|encrypt|decrypt)|(matches|match|equals|valid|present|count|length|fingerprint|hash|kind|type)$",
      callsAny: ["console.log", "console.info", "console.warn", "console.error", "console.debug",
        "logger.log", "logger.info", "logger.warn", "logger.error", "logger.debug", "log.info", "log.warn", "log.error", "log.debug",
        ...FILE_WRITE_SINKS, "fetch", "res.send", "res.json", "reply.send", "response.send"],
      callsNoneOf: ["redact", "sanitize", "mask"],
    },
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
 * (`eval`, `system`) matches only the receiverless call or its `Kernel.`/`builtins.`
 * form (never `re.compile` for `compile`); `*.name` matches `name` on any receiver. `guardText` handles non-call guards
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
    when: { callsAny: ["pickle.loads", "pickle.load", "marshal.loads", "marshal.load", "yaml.load"], callsNoneOf: ["*.safe_load"], guardText: ["SafeLoader"] },
    blast: "callers",
    asi: asi("AAC-11"),
  },
  {
    id: "py-raw-secret", kind: "weakness", grade: "STATIC",
    title: "Secret-like handling without visible redaction",
    explanation:
      "This function's name suggests it handles secret material (token / password / credential / api_key) and no redaction call is visible inside it. Static lead only.",
    when: { nameMatches: "(token|secret|password|credential|api_?key)", callsNoneOf: ["*.redact", "*.mask", "*.sanitize"] },
    blast: "none",
    asi: asi("AAC-09"),
  },
  {
    id: "py-input-validation", kind: "control", grade: "STATIC",
    title: "Input validation present",
    explanation:
      "This function calls a validation / quoting primitive — a control artifact. Present does not mean effective; a reviewer must confirm it guards the relevant input.",
    when: { callsAny: ["*.validate", "*.is_valid", "*.clean", "shlex.quote", "*.escape"] },
    blast: "none",
    asi: asi("AAC-01"),
  },
];

export const RUBY_RULES: Rule[] = [
  {
    id: "rb-code-exec", kind: "weakness", grade: "STATIC",
    title: "Dynamic code execution",
    explanation:
      "This method reaches a dynamic code-execution primitive: eval, or instance_eval / class_eval / module_eval with an interpolated string or request params. Block forms (class_eval do ... end) are normal Ruby and are not reported. If any part of the string is attacker-influenced this is arbitrary code execution. Static lead only.",
    when: { callsAny: ["eval", "*.instance_eval", "*.class_eval", "*.module_eval"], textMatches: "\\beval\\b|#[{]|params|request[.]" },
    blast: "callers",
    asi: asi("AAC-11"),
  },
  {
    id: "rb-dynamic-dispatch", kind: "weakness", grade: "STATIC",
    title: "Method chosen from request input",
    explanation:
      "This method calls send / public_send with a method name that is not a literal symbol (a variable, an interpolated string, or request params), so a caller-supplied value may choose which method runs. send(:name) is normal Ruby and is not reported, and neither is a call carrying a reviewed `rubocop:disable GitlabSecurity/PublicSend` comment. Static lead only: trace where the name comes from.",
    when: { callsAny: ["*.send", "*.public_send"], textMatches: "params|request[.]|\\b(send|public_send)\\b\\s*[(]?\\s*([a-z_@$]|[\"'][^\"']*#[{])", guardText: ["GitlabSecurity/PublicSend"] },
    blast: "callers",
    asi: asi("AAC-11"),
  },
  {
    id: "rb-os-command", kind: "weakness", grade: "STATIC",
    title: "OS command execution",
    explanation:
      "This method shells out (system / exec / Open3) with a command that is not a plain string literal (a variable, interpolation, or request params). If that command is attacker-influenced this is command injection. Literal commands (system('git', 'push')) are not reported. Static lead — not proof the input is untrusted.",
    when: { callsAny: ["system", "exec", "Open3.capture2", "Open3.capture3", "Open3.popen3", "Kernel.system"], textMatches: "#[{]|params|request[.]|\\b(system|exec|capture2|capture3|popen3)\\b\\s*[(]?\\s*[a-z_@$]", callsNoneOf: ["Shellwords.escape", "*.shellescape"] },
    blast: "callers",
    asi: asi("AAC-11"),
  },
  {
    id: "rb-unsafe-deser", kind: "weakness", grade: "STATIC",
    title: "Unsafe deserialization",
    explanation:
      "This method deserializes with a primitive that can construct arbitrary objects (Marshal.load / YAML.load without safe_load). Static lead only.",
    when: { callsAny: ["Marshal.load", "Marshal.restore", "YAML.load"], callsNoneOf: ["*.safe_load"] },
    blast: "callers",
    asi: asi("AAC-11"),
  },
  {
    id: "rb-raw-secret", kind: "weakness", grade: "STATIC",
    title: "Secret-like handling that logs or sends data, without visible redaction",
    explanation:
      "This method's name suggests it handles secret material (token / password / credential / api_key), it writes a log line, prints, writes a file or sends an HTTP request, and no redaction call is visible inside it. Predicates, setters and protective names (valid?, verify, hash, encrypt, mask...) are not reported. Static lead only: a name is a hint, not proof that a secret reaches the log or request.",
    when: {
      nameMatches: "(token|secret|password|passwd|credential|api_?key|private_?key)",
      nameNotMatches: "[?]$|^(redact|mask|sanitize|scrub|strip|hash|digest|validate|verify|is_|has_|check|assert|ensure|match|compare|safe|fingerprint|encrypt|decrypt|can_|allow|permit)|(matches|match|equals|valid|present|count|length|fingerprint|digest|hash|kind|type|params|path|url|ids?|enabled|expired|name)$",
      callsAny: ["logger.info", "logger.warn", "logger.error", "logger.debug", "logger.fatal", "AppLogger.info", "AppLogger.warn", "AppLogger.error", "Gitlab::AppLogger.info", "Gitlab::AppLogger.warn", "Gitlab::AppLogger.error", "puts", "print", "pp", "File.write", "File.open", "File.binwrite", "Net::HTTP.post", "Net::HTTP.get", "HTTParty.post", "HTTParty.get", "Faraday.post", "Faraday.get", "Gitlab::HTTP.post", "Gitlab::HTTP.get", "Gitlab::HTTP.put"],
      callsNoneOf: ["*.redact", "*.mask", "*.sanitize", "*.filter_attributes"],
    },
    blast: "none",
    asi: asi("AAC-09"),
  },
  {
    id: "rb-input-validation", kind: "control", grade: "STATIC",
    title: "Input validation present",
    explanation:
      "This method calls a validation / escaping primitive (validate / permit / sanitize / shellescape) — a control artifact. Present does not mean effective; a reviewer must confirm it guards the relevant input.",
    when: { callsAny: ["*.validate", "*.validates", "*.permit", "*.sanitize", "*.shellescape"] },
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
    for (const field of ["nameMatches", "nameNotMatches", "textMatches"] as const) {
      if (typeof r.when[field] === "string") {
        try { compileNameMatcher(r.when[field]); }
        catch (e) { throw new Error(`Rule ${r.id}: ${e instanceof Error ? e.message : e}`); }
      }
    }
    if (r.when.textAny !== undefined && (!Array.isArray(r.when.textAny) || r.when.textAny.some((t: unknown) => typeof t !== "string" || !t || (t as string).length > 200)))
      throw new Error(`Rule ${r.id}: textAny must be an array of non-empty strings (max 200 chars)`);
  }
  return input as Rule[];
}
