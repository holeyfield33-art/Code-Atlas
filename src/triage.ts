/**
 * Finding disposition / triage layer (pure).
 *
 * The scanner proposes honest leads; a human or agent then DISPOSITIONS each one
 * (confirmed / false_positive / accepted_risk) with provenance. The map reflects
 * that decision. Triage is strictly SUPPRESSIVE — it never upgrades a grade or
 * fabricates a blast radius, so the grounding invariant is preserved:
 *   - false_positive: the finding stops colouring its node AND casts no blast.
 *   - accepted_risk:  the finding stays visible (acknowledged) but casts no blast.
 *   - confirmed:      unchanged rendering; blast still gated on OBSERVED/TESTED.
 */
import { parseBundle, type AtlasBundle, type Disposition, type Finding } from "./schema.js";

export type DispositionStatus = Disposition["status"];
export const DISPOSITION_STATUSES: readonly DispositionStatus[] = ["confirmed", "false_positive", "accepted_risk"];

/**
 * Set (or clear) the disposition on one finding, returning a NEW, re-validated
 * bundle. Pure — no disk IO. Throws if the finding id is unknown. Pass `null` as
 * the decision to clear a disposition (back to an untriaged lead).
 */
export function applyDisposition(
  bundle: AtlasBundle,
  findingId: string,
  decision: { status: DispositionStatus; by: string; note?: string; at?: string } | null,
): AtlasBundle {
  const findings = bundle.findings ?? [];
  const idx = findings.findIndex((f) => f.id === findingId);
  if (idx < 0) throw new Error(`Unknown finding id: ${findingId}`);
  if (decision && !DISPOSITION_STATUSES.includes(decision.status))
    throw new Error(`Invalid disposition status: ${decision.status}`);
  if (decision && !decision.by.trim()) throw new Error("Disposition requires a non-empty `by` (who made the call)");

  const next: Finding[] = findings.map((f, i) => {
    if (i !== idx) return f;
    if (!decision) { const { disposition: _drop, ...rest } = f; return rest as Finding; }
    const disposition: Disposition = {
      status: decision.status,
      by: decision.by,
      at: decision.at ?? new Date().toISOString(),
      ...(decision.note ? { note: decision.note } : {}),
    };
    return { ...f, disposition };
  });

  // Re-validate so a triage write can never produce an invalid bundle. The stored
  // `integrity` hashes describe the generated graph/bundle and are intentionally
  // left as-is: triage is a post-hoc overlay, not a regeneration.
  return parseBundle({ ...bundle, findings: next });
}

/** A VERIFIED weakness casts a blast radius ONLY if not dismissed/accepted. */
export function castsBlastAfterTriage(f: Finding): boolean {
  if (f.kind !== "weakness") return false;
  if (f.grade !== "OBSERVED" && f.grade !== "TESTED") return false;
  const s = f.disposition?.status;
  return s !== "false_positive" && s !== "accepted_risk";
}

/** A dismissed (false-positive) finding should not colour its node. */
export function isDismissed(f: Finding): boolean {
  return f.disposition?.status === "false_positive";
}
