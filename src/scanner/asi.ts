/**
 * ASI (Agent Security Index) link config — ONE place to point findings at ASI.
 *
 * Swap the live location by setting ASI_BASE_URL, or editing ASI_BASE here.
 * When ASI exposes stable per-class URLs, change `asiUrl` to that scheme — the
 * single edit flows to every rule and the vibe-explainer adapter.
 */
export const ASI_BASE = process.env.ASI_BASE_URL || "https://index.aletheia-core.com";

/** Live link for an ASI attack-class id. The ONLY place the URL scheme lives. */
export function asiUrl(id: string): string {
  return `${ASI_BASE}/#${id}`;
}

/** Pinned labels + mitigations for the classes we reference (snapshot). */
export const AAC: Record<string, { label: string; mitigation: string }> = {
  "AAC-01": { label: "Input security", mitigation: "Validate and constrain untrusted input at the trust boundary." },
  "AAC-02": { label: "Retrieval / RAG security", mitigation: "Validate and attribute retrieved content before it reaches the model or a sink." },
  "AAC-09": { label: "Secret exposure", mitigation: "Redact secrets before logging or persistence; never store raw credentials." },
  "AAC-11": { label: "High-impact action without constraint", mitigation: "Constrain and validate inputs before a high-impact sink; apply least privilege." },
  "AAC-16": { label: "Output handling", mitigation: "Validate and bound model/tool output before it drives a downstream action." },
};

/** vibe-explainer risk category -> ASI attack class (from its asi_matrix bridge). */
export const CATEGORY_TO_AAC: Record<string, string> = {
  INPUT_SECURITY: "AAC-01",
  RAG_SECURITY: "AAC-02",
  SECRET_EXPOSURE: "AAC-09",
  HIGH_IMPACT_ACTION: "AAC-11",
  OUTPUT_SECURITY: "AAC-16",
  MCP_SECURITY: "AAC-11",
};

export function asiRefFor(id: string, asOf: string): { id: string; url: string; label: string; asOf: string } | undefined {
  const c = AAC[id];
  return c ? { id, url: asiUrl(id), label: c.label, asOf } : undefined;
}

export function asiClassFor(id: string): { id: string; label: string; mitigation: string; url: string } | undefined {
  const c = AAC[id];
  return c ? { id, label: c.label, mitigation: c.mitigation, url: asiUrl(id) } : undefined;
}
