/**
 * atlas_exec: the single-tool sandbox.
 *
 * Instead of shipping N fixed read tools, expose ONE tool that takes code and
 * runs it against a frozen, read-only `atlas` API — the agent writes exactly the
 * query it needs (filter, join, aggregate) in one round-trip, with no tool-schema
 * bloat and no "the tool I need wasn't exposed" dead end.
 *
 * The security is NOT the obscurity of the API; it is the jail:
 *   - a V8 isolate (isolated-vm), a separate heap with NO Node bindings, so
 *     `require`, `process`, `fetch`, `import`, timers and the host scope simply
 *     do not exist inside it;
 *   - the ONLY capability handed in is a single host reference whose every call
 *     is checked against a read-only allowlist (triage and any future write are
 *     unreachable — they are not in the set);
 *   - all data crosses the boundary as JSON strings, so the isolate never holds
 *     a live reference to the AtlasTools instance or the bundle;
 *   - a wall-clock timeout and a memory cap bound every run, so a pathological
 *     script is killed, not merely slowed.
 *
 * A run is reproducible: the receipt is sha256(selector + code + bundleHash), so
 * the same code over the same bundle yields the same receipt — the grounding
 * guarantee the rest of Code Atlas already makes, extended to free-form reads.
 */
import { createHash } from "node:crypto";
import ivm from "isolated-vm";
import type { AtlasTools } from "./tools.js";

/** Read-only surface exposed inside the sandbox. Each maps to an AtlasTools
 *  method that returns JSON-serializable data and never mutates the bundle.
 *  triage is intentionally absent: the sandbox cannot write. */
const READ_METHODS = [
  "overview", "search", "getNode", "getSource", "neighbors", "contextPack", "threats", "course",
] as const;
type ReadMethod = (typeof READ_METHODS)[number];
const ALLOWED = new Set<string>(READ_METHODS);

export interface SandboxLimits {
  /** Wall-clock budget for the script, ms. */ timeoutMs: number;
  /** Isolate heap cap, MB. */ memoryMb: number;
  /** Max length of agent code, chars. */ maxCodeChars: number;
}
export const DEFAULT_LIMITS: SandboxLimits = { timeoutMs: 1000, memoryMb: 128, maxCodeChars: 20_000 };

export interface ExecResult {
  ok: boolean;
  result?: unknown;
  error?: string;
  receipt: { selector: "atlas-exec-v1"; codeHash: string; bundleHash: string; hash: string };
  note: string;
}

const sha = (s: string) => "sha256:" + createHash("sha256").update(s).digest("hex").slice(0, 16);

/** Trusted bootstrap, run as its OWN eval before any agent code. It reads the one
 *  host reference off the global, builds a frozen `atlas` whose methods close over
 *  it, publishes `atlas` on the global, then blanks the global host handle. The
 *  `__host` binding is a local of this IIFE, so once this eval returns it is gone:
 *  the later agent eval shares only the global object, where `atlas` exists but the
 *  host reference does not — the agent can call the read API but cannot name the
 *  capability behind it. */
const BOOTSTRAP = `
  "use strict";
  (function(){
    const __host = __ATLAS_HOST__;
    const __call = (m, args) => {
      const out = __host.applySync(undefined, [m, JSON.stringify(args)]);
      return out === undefined ? undefined : JSON.parse(out);
    };
    globalThis.atlas = Object.freeze({
      overview:    ()            => __call("overview", []),
      search:      (q, limit)    => __call("search", [q, limit]),
      getNode:     (id)          => __call("getNode", [id]),
      getSource:   (id)          => __call("getSource", [id]),
      neighbors:   (id, kinds)   => __call("neighbors", [id, kinds]),
      contextPack: (task, budget)=> __call("contextPack", [task, budget]),
      threats:     (ref)         => __call("threats", [ref]),
      course:      (id)          => __call("course", [id]),
    });
  })();
  globalThis.__ATLAS_HOST__ = undefined;
`;

/** Agent code runs in a strict IIFE so a top-level \`return\` is its result. */
const wrapUser = (code: string) => `(function(){\n"use strict";\n${code}\n})()`;

/**
 * Run agent code against the read-only atlas API inside an isolate.
 * Never throws for sandbox-level failures (timeout, memory, bad code, a blocked
 * call) — those come back as { ok:false, error }. The receipt is always present.
 */
export function runAtlasExec(
  tools: AtlasTools,
  code: string,
  bundleHash: string,
  limits: SandboxLimits = DEFAULT_LIMITS,
): ExecResult {
  const codeHash = sha(code);
  const receiptCore = { selector: "atlas-exec-v1" as const, codeHash, bundleHash };
  const receipt = { ...receiptCore, hash: sha(JSON.stringify(receiptCore)) };
  const base = {
    receipt,
    note: "Read-only sandbox: code ran in an isolate with no network, filesystem, require, or host scope — only a frozen atlas read API. Replayable: same code + bundle => same receipt hash.",
  };

  if (typeof code !== "string" || code.length === 0)
    return { ok: false, error: "empty code", ...base };
  if (code.length > limits.maxCodeChars)
    return { ok: false, error: `code exceeds ${limits.maxCodeChars} chars`, ...base };

  // The one capability: a host function the isolate may call. Every call is
  // allowlist-checked here, on the host side, before touching AtlasTools.
  const host = new ivm.Reference((method: string, argsJson: string) => {
    if (!ALLOWED.has(method)) throw new Error("method not permitted in sandbox: " + String(method));
    const args = JSON.parse(argsJson) as unknown[];
    const out = (tools as unknown as Record<ReadMethod, (...a: unknown[]) => unknown>)[method as ReadMethod](...args);
    return out === undefined ? undefined : JSON.stringify(out);
  });

  const isolate = new ivm.Isolate({ memoryLimit: limits.memoryMb });
  try {
    const context = isolate.createContextSync();
    // Expose the one capability on the global, then let the trusted bootstrap
    // consume it and blank the handle — all before a line of agent code runs.
    context.global.setSync("__ATLAS_HOST__", host);
    context.evalSync(BOOTSTRAP);
    const value = context.evalSync(wrapUser(code), {
      timeout: limits.timeoutMs,
      copy: true,   // deep-copy the return value out to the host
    });
    return { ok: true, result: value, ...base };
  } catch (e) {
    return { ok: false, error: String(e instanceof Error ? e.message : e), ...base };
  } finally {
    // The memory cap may have already disposed the isolate (which releases the
    // reference with it); guard so cleanup never throws over the real result.
    try { host.release(); } catch { /* already released with the isolate */ }
    try { if (!isolate.isDisposed) isolate.dispose(); } catch { /* already disposed */ }
  }
}
