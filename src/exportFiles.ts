/**
 * Turn one or more bundles into a few plain Markdown files that can be uploaded to any chat or agent
 * (no server, no port):
 *   leads-NN.md  the security leads (weaknesses) with file:line and the code around them
 *   map-NN.md    every file: its functions with line numbers, what it imports, how many places call into it
 * Each file stays under a size cap so an upload limit is never the problem. Findings are static leads,
 * exactly as in the viewer: a shape worth reading, not a proven vulnerability.
 */
import type { AtlasBundle } from "./schema.js";

export interface ExportedFile { name: string; text: string }

const CONTEXT_LINES = 24;

/** Pack blocks into numbered parts under `maxBytes` (a block is never cut; one bigger than the cap gets its own part). */
function pack(prefix: string, header: string, blocks: string[], maxBytes: number): ExportedFile[] {
  const parts: string[][] = [];
  let cur: string[] = []; let size = 0;
  for (const b of blocks) {
    const n = Buffer.byteLength(b);
    if (cur.length && size + n > maxBytes) { parts.push(cur); cur = []; size = 0; }
    cur.push(b); size += n;
  }
  if (cur.length) parts.push(cur);
  return parts.map((p, i) => ({
    name: `${prefix}-${String(i + 1).padStart(2, "0")}.md`,
    text: `${header} (part ${i + 1} of ${parts.length})\n\n${p.join("\n")}`,
  }));
}

export function exportBundles(bundles: AtlasBundle[], maxBytes = 900_000): ExportedFile[] {
  const lead: string[] = []; const map: string[] = [];
  let weaknesses = 0, files = 0;

  for (const b of bundles) {
    const label = b.repository.label;
    const nodes = new Map(b.graph.nodes.map((n) => [n.id, n]));
    const code = new Map((b.sources ?? []).map((s) => [s.path, s.code]));

    // ---- leads
    for (const f of b.findings ?? []) {
      if (f.kind !== "weakness" || f.disposition?.status === "false_positive") continue;
      weaknesses++;
      for (const ref of f.nodeRefs) {
        const n = nodes.get(ref); if (!n) continue;
        const { path, line } = n.evidence;
        const src = code.get(path);
        let snippet = "";
        if (src) {
          const lines = src.split("\n");
          const from = Math.max(0, line - 1);
          snippet = "\n```\n" + lines.slice(from, from + CONTEXT_LINES).join("\n").replace(/```/g, "'''") + "\n```\n";
        }
        lead.push(`### ${f.title} - \`${path}:${line}\` (${n.label})\n- shard: ${label}; grade: ${f.grade} (static lead, not confirmed)\n- ${f.explanation}${snippet}`);
      }
    }

    // ---- map
    const fileNodes = b.graph.nodes.filter((n) => n.kind === "file").sort((x, y) => x.evidence.path.localeCompare(y.evidence.path));
    const fnsByFile = new Map<string, string[]>();
    for (const n of b.graph.nodes) if (n.kind !== "file") {
      const a = fnsByFile.get(n.evidence.path) ?? []; a.push(`${n.label}:${n.evidence.line}`); fnsByFile.set(n.evidence.path, a);
    }
    const imports = new Map<string, Set<string>>(); const calledIn = new Map<string, number>();
    for (const e of b.graph.edges) {
      const from = nodes.get(e.from), to = nodes.get(e.to); if (!from || !to) continue;
      if (e.kind === "imports") { const s = imports.get(from.evidence.path) ?? new Set(); s.add(to.evidence.path); imports.set(from.evidence.path, s); }
      else if (e.kind === "calls" && from.evidence.path !== to.evidence.path) calledIn.set(to.evidence.path, (calledIn.get(to.evidence.path) ?? 0) + 1);
    }
    map.push(`## ${label}\n`);
    for (const n of fileNodes) {
      const p = n.evidence.path; files++;
      const fns = fnsByFile.get(p) ?? []; const imp = [...(imports.get(p) ?? [])];
      map.push(`- \`${p}\`` + (calledIn.get(p) ? ` (called from ${calledIn.get(p)} places in other files)` : "") +
        (fns.length ? `\n  - functions: ${fns.slice(0, 40).join(", ")}${fns.length > 40 ? ` (+${fns.length - 40} more)` : ""}` : "") +
        (imp.length ? `\n  - imports: ${imp.slice(0, 25).join(", ")}${imp.length > 25 ? ` (+${imp.length - 25} more)` : ""}` : ""));
    }
  }

  const out = [
    ...pack("leads", `# Security leads (${weaknesses}): static, unconfirmed`, lead, maxBytes),
    ...pack("map", `# Code map (${files} files)`, map, maxBytes),
  ];
  const index = [
    "# Code Atlas export: what these files are",
    "",
    `Source: ${bundles.map((b) => b.repository.label + (b.repository.sourceCommit ? " @ " + b.repository.sourceCommit.slice(0, 12) : "")).join(", ")}. Made from a static scan; nothing here was run. Check the commit against the instance you are testing.`,
    "",
    "- `leads-NN.md`: places where the code has a risky *shape* (shell-out, dynamic eval, unsafe deserialization, secret-like handlers...). Each is a lead to read and test, not a confirmed bug. The code shown starts at the flagged function.",
    "- `map-NN.md`: every analysed file with its functions (name:line), what it imports and how often other files call into it.",
    "",
    "Limits: only JS/TS, Python and Ruby are mapped; Ruby/Python call links are name-based guesses; a relationship between two scanned groups is not drawn if they were scanned separately; test folders may be left out. To test a lead, replay the request against the running app (SurfaceTrace or Burp).",
    "",
    "Files:",
    ...out.map((f) => `- ${f.name} (${Math.round(Buffer.byteLength(f.text) / 1024)} KB)`),
  ].join("\n");
  return [{ name: "00-read-me.md", text: index + "\n" }, ...out];
}
