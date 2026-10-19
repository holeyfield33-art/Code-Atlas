/**
 * Threat overlay: bring security LEADS from an external source (e.g. the ASI Threat
 * Graph service) onto THIS graph, without copying that source's graph in.
 *
 * Contract (schemaVersion "1"), what a source emits - see docs/threat-overlay.md:
 *   { schemaVersion: "1",
 *     source:  { identity, ref, asOf },
 *     leads:   [{ id, attackClassId, label, target, status, confidence?, note, rule?, url?, evidence? }],
 *     unresolved: [{ id, attackClassId, description, target? }] }
 * `target` names a place in the code: a node id, `path#functionName`, or a file path.
 *
 * Grounding rules enforced here (not left to the viewer):
 *   - A target must match exactly ONE node. Zero or several matches => the lead is kept
 *     as `unresolved` with the reason; it is never attached to a best guess.
 *   - Status is carried as REPORTED, with one exception: a lead claiming `observed` or
 *     `verified` with no evidence is downgraded to `inferred` (a claim with nothing
 *     behind it is not shown as verified). Nothing is ever upgraded.
 *   - The overlay adds annotations only. It cannot add nodes/edges or colour a node as
 *     a verified weakness (that stays reserved for findings graded on this repo).
 *   - Loading is optional: a missing or broken source leaves the bundle exactly as it
 *     would be without it, and the failure is reported, not swallowed.
 */
import { readFileSync, statSync } from "node:fs";
import { z } from "zod";
import {
  LeadStatusSchema,
  MAX_OVERLAY_ENTRIES,
  hasMeaningfulEvidence,
  type AtlasGraph,
  type AtlasNode,
  type ThreatLead,
  type ThreatOverlay,
  type UnresolvedLead,
} from "./schema.js";

const MAX_OVERLAY_BYTES = 5_000_000;
const FETCH_TIMEOUT_MS = 10_000;
// Shared with ThreatOverlaySchema (schema.ts), which re-enforces the SAME cap on a bundle handed
// straight to parseBundle — this one only applies at build time via resolveOverlay().
const MAX_ENTRIES = MAX_OVERLAY_ENTRIES;

const httpUrl = z.string().refine((u) => /^https?:\/\//i.test(u), "url must be http(s)");
const EvidenceItem = z.object({ source: z.string(), detail: z.string() });

export const OverlayInputSchema = z.object({
  schemaVersion: z.literal("1"),
  source: z.object({ identity: z.string().min(1), ref: z.string().min(1), asOf: z.string().min(1) }),
  leads: z.array(z.object({
    id: z.string().min(1),
    attackClassId: z.string().min(1),
    label: z.string().min(1),
    target: z.string().min(1),
    status: LeadStatusSchema,
    confidence: z.enum(["low", "medium", "high"]).default("low"),
    note: z.string().min(1),
    rule: z.string().optional(),
    url: httpUrl.optional(),
    evidence: z.array(EvidenceItem).default([]),
  })).max(MAX_ENTRIES),
  unresolved: z.array(z.object({
    id: z.string().min(1),
    attackClassId: z.string().min(1),
    description: z.string().min(1),
    target: z.string().optional(),
  })).max(MAX_ENTRIES).default([]),
});
export type OverlayInput = z.infer<typeof OverlayInputSchema>;

/** Drop the `ATLAS:fn:` / `ATLAS:file:` style prefix some sources put on a target. */
function stripPrefix(t: string): string {
  return t.replace(/^(?:ATLAS:)?(?:fn|file):/i, "");
}

type Match = { nodeId: string } | { reason: string };

/** Resolve a target string to exactly one node, or say why not. */
export function resolveTarget(graph: AtlasGraph, rawTarget: string): Match {
  const target = stripPrefix(rawTarget.trim());
  const byId = graph.nodes.filter((n) => n.id === rawTarget || n.id === target || n.stableKey === rawTarget || n.stableKey === target);
  if (byId.length === 1) return { nodeId: byId[0].id };
  if (byId.length > 1) return { reason: `ambiguous: ${byId.length} nodes share that id` };

  const hash = target.indexOf("#");
  let candidates: AtlasNode[];
  if (hash > 0) {
    const path = target.slice(0, hash), name = target.slice(hash + 1);
    candidates = graph.nodes.filter((n) => n.kind === "function" && n.evidence.path === path && n.label === name);
  } else {
    candidates = graph.nodes.filter((n) => n.kind === "file" && (n.label === target || n.evidence.path === target));
  }
  if (candidates.length === 1) return { nodeId: candidates[0].id };
  if (candidates.length === 0) return { reason: "target not found in this graph" };
  return { reason: `ambiguous: ${candidates.length} nodes match` };
}

export interface ResolvedOverlay { overlay: ThreatOverlay; warnings: string[]; }

/** Validate an untrusted overlay document and resolve its leads onto `graph`. Throws on a malformed document. */
export function resolveOverlay(graph: AtlasGraph, raw: unknown): ResolvedOverlay {
  const input = OverlayInputSchema.parse(raw);
  const warnings: string[] = [];
  const leads: ThreatLead[] = [];
  const unresolved: UnresolvedLead[] = [];
  const seen = new Set<string>();

  for (const l of input.leads) {
    if (seen.has(l.id)) { warnings.push(`duplicate lead id '${l.id}' ignored`); continue; }
    seen.add(l.id);
    const m = resolveTarget(graph, l.target);
    if ("reason" in m) {
      unresolved.push({ id: l.id, attackClassId: l.attackClassId, description: l.note, target: l.target, reason: m.reason });
      continue;
    }
    let status = l.status;
    if ((status === "observed" || status === "verified") && !hasMeaningfulEvidence(l.evidence)) {
      warnings.push(`lead '${l.id}' claimed '${status}' with no evidence; shown as 'inferred'`);
      status = "inferred";
    }
    leads.push({
      id: l.id, attackClassId: l.attackClassId, label: l.label, nodeId: m.nodeId, target: l.target,
      status, confidence: l.confidence, note: l.note,
      ...(l.rule ? { rule: l.rule } : {}), ...(l.url ? { url: l.url } : {}), evidence: l.evidence,
    });
  }
  for (const u of input.unresolved) {
    if (seen.has(u.id)) { warnings.push(`duplicate id '${u.id}' ignored`); continue; }
    seen.add(u.id);
    unresolved.push({ id: u.id, attackClassId: u.attackClassId, description: u.description, ...(u.target ? { target: u.target } : {}), reason: "reported unresolved by the source" });
  }
  return { overlay: { source: input.source, leads, unresolved }, warnings };
}

/** Read an overlay document from a file path or an http(s) URL. Bounded in size and time. */
/** Read a response body under a BYTE limit, never buffering past it. Checks the declared
 *  Content-Length upfront (rejects before any read when it alone proves oversize), then
 *  streams and counts actual bytes — not JS string length, which undercounts multi-byte
 *  UTF-8 text and would let an oversized document through. */
async function readBoundedBody(res: Response): Promise<string> {
  const declared = res.headers.get("content-length");
  if (declared && Number(declared) > MAX_OVERLAY_BYTES) {
    throw new Error(`overlay source exceeds ${MAX_OVERLAY_BYTES} bytes (Content-Length ${declared})`);
  }
  const reader = res.body?.getReader();
  if (!reader) {
    // No streaming body (unusual for a real fetch implementation, possible in a test double).
    // Still bounded: a declared Content-Length above was already checked; this is the fallback
    // for a response with neither.
    const buf = new Uint8Array(await res.arrayBuffer());
    if (buf.byteLength > MAX_OVERLAY_BYTES) throw new Error(`overlay source exceeds ${MAX_OVERLAY_BYTES} bytes`);
    return new TextDecoder().decode(buf);
  }
  let total = 0;
  const chunks: Uint8Array[] = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_OVERLAY_BYTES) {
      await reader.cancel().catch(() => {});
      throw new Error(`overlay source exceeds ${MAX_OVERLAY_BYTES} bytes`);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) { out.set(c, offset); offset += c.byteLength; }
  return new TextDecoder().decode(out);
}

export async function readOverlaySource(spec: string, fetchImpl: typeof fetch = fetch): Promise<unknown> {
  if (/^https?:\/\//i.test(spec)) {
    const res = await fetchImpl(spec, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS), redirect: "error", headers: { accept: "application/json" } });
    if (!res.ok) throw new Error(`overlay source returned HTTP ${res.status}`);
    const text = await readBoundedBody(res);
    return JSON.parse(text);
  }
  // Byte size from the filesystem, not a post-read string length: stat() never loads the
  // file, so an oversized local file is rejected before any of it reaches memory.
  const size = statSync(spec).size;
  if (size > MAX_OVERLAY_BYTES) throw new Error(`overlay file exceeds ${MAX_OVERLAY_BYTES} bytes`);
  const text = readFileSync(spec, "utf8");
  return JSON.parse(text);
}
