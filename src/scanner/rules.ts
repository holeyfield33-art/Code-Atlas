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

export interface RuleWhen {
  /** Function's source contains a call `name(` to any of these (a sink / primitive). */
  callsAny?: string[];
  /** ...and contains a call to NONE of these (e.g. no visible validator). */
  callsNoneOf?: string[];
  /** Function name matches this regex (case-insensitive). */
  nameMatches?: string;
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

// The classic nested-quantifier ReDoS shape, e.g. (a+)+ — a custom rule's
// nameMatches is compiled to a RegExp, so refuse this at load time.
const NESTED_QUANTIFIER = /\([^()]*[+*][^()]*\)[+*]/;

/** Minimal shape check for a loaded (customized) rule pack. */
export function validateRules(input: unknown): Rule[] {
  if (!Array.isArray(input)) throw new Error("Rule pack must be a JSON array of rules");
  for (const r of input as any[]) {
    if (!r.id || !r.kind || !r.grade || !r.title || !r.when) throw new Error("Rule missing required fields: " + JSON.stringify(r.id ?? r));
    if (r.kind !== "weakness" && r.kind !== "control") throw new Error(`Rule ${r.id}: kind must be weakness|control`);
    if (r.grade !== "STATIC" && r.grade !== "INFERRED") throw new Error(`Rule ${r.id}: a static rule's grade must be STATIC or INFERRED`);
    if (typeof r.when.nameMatches === "string") {
      if (r.when.nameMatches.length > 1000 || NESTED_QUANTIFIER.test(r.when.nameMatches))
        throw new Error(`Rule ${r.id}: nameMatches pattern is unsafe (too long or catastrophic backtracking shape)`);
      try { new RegExp(r.when.nameMatches, "i"); } catch { throw new Error(`Rule ${r.id}: nameMatches is not a valid regex`); }
    }
  }
  return input as Rule[];
}
