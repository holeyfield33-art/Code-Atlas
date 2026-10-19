/**
 * Threat overlay contract: external leads are resolved onto this graph with the
 * grounding rules enforced in code - exactly-one-match or unresolved, no upgrades,
 * annotations only (findings are untouched), and a bad source never breaks a build.
 */
import assert from "node:assert";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildAtlas } from "../src/build.js";
import { parseBundle } from "../src/schema.js";
import { AtlasTools } from "../src/mcp/tools.js";
import { resolveOverlay, resolveTarget, readOverlaySource, buildTargetIndex } from "../src/threatOverlay.js";
import { safeLog } from "../src/logSanitize.js";

const root = mkdtempSync(join(tmpdir(), "atlas-overlay-"));
try {
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src", "handler.js"), "export function handlePrompt(input) { return render(input); }\nexport function render(x) { return String(x); }\n");
  writeFileSync(join(root, "src", "twin.js"), "export function render(x) { return x; }\n");

  const { bundle: plain } = await buildAtlas(root, { product: "Code Atlas", repoLabel: "overlay-test" });
  const g = plain.graph;
  assert.strictEqual(plain.threatOverlay, undefined, "no overlay unless asked for");

  // --- target resolution: exactly one node, or a stated reason ---------------
  const fn = g.nodes.find((n) => n.kind === "function" && n.label === "handlePrompt")!;
  const file = g.nodes.find((n) => n.kind === "file" && n.evidence.path === "src/handler.js")!;
  assert.deepStrictEqual(resolveTarget(g, fn.id), { nodeId: fn.id }, "by node id");
  assert.deepStrictEqual(resolveTarget(g, "src/handler.js#handlePrompt"), { nodeId: fn.id }, "by path#name");
  assert.deepStrictEqual(resolveTarget(g, "ATLAS:fn:src/handler.js#handlePrompt"), { nodeId: fn.id }, "source-style prefix is stripped");
  assert.deepStrictEqual(resolveTarget(g, "src/handler.js"), { nodeId: file.id }, "file path");
  assert.ok("reason" in resolveTarget(g, "src/handler.js#missing"), "unknown function is unresolved");
  // `render` exists in two files: a bare name is not a valid target, and path#name picks one
  assert.ok("reason" in resolveTarget(g, "nope.js"), "unknown file is unresolved");
  assert.ok(!("reason" in resolveTarget(g, "src/twin.js#render")), "path#name disambiguates same-named functions");

  // --- resolving many targets against one graph reuses a built index, not a per-call scan ---
  // (perf finding: resolveTarget scanned the whole node array twice per lead; resolveOverlay()
  // now builds a TargetIndex once and passes it through, so results must match the unindexed path)
  const idx = buildTargetIndex(g);
  assert.deepStrictEqual(resolveTarget(g, fn.id, idx), resolveTarget(g, fn.id), "indexed lookup agrees with unindexed for a node id");
  assert.deepStrictEqual(resolveTarget(g, "src/handler.js#handlePrompt", idx), resolveTarget(g, "src/handler.js#handlePrompt"), "indexed lookup agrees for path#name");
  assert.deepStrictEqual(resolveTarget(g, "src/handler.js", idx), resolveTarget(g, "src/handler.js"), "indexed lookup agrees for a file path");
  assert.deepStrictEqual(resolveTarget(g, "src/twin.js#render", idx), resolveTarget(g, "src/twin.js#render"), "indexed lookup agrees when disambiguated by path#name");
  assert.ok("reason" in resolveTarget(g, "nope.js#missing", idx), "indexed lookup still reports unresolved targets");

  // --- resolveOverlay: validation + grounding rules ---------------------------
  const doc = (over: Record<string, unknown> = {}) => ({
    schemaVersion: "1",
    source: { identity: "asi-threat-graph", ref: "abc123def456", asOf: "2026-10-17" },
    leads: [
      { id: "L1", attackClassId: "AAC-01", label: "Direct Prompt Injection", target: "src/handler.js#handlePrompt", status: "hypothetical", note: "name heuristic", rule: "prompt-handler-name", url: "https://example.test/AAC-01" },
      { id: "L2", attackClassId: "AAC-11", label: "High-impact action", target: "src/handler.js#render", status: "verified", note: "claims verified, no evidence" },
      { id: "L3", attackClassId: "AAC-09", label: "Secret exposure", target: "src/gone.js#x", status: "hypothetical", note: "target absent" },
      { id: "L1", attackClassId: "AAC-01", label: "dup", target: "src/handler.js", status: "hypothetical", note: "duplicate id" },
    ],
    unresolved: [{ id: "U1", attackClassId: "AAC-29", description: "no mapping for auth check" }],
    ...over,
  });
  const r = resolveOverlay(g, doc());
  assert.strictEqual(r.overlay.leads.length, 2, "two leads attach");
  assert.strictEqual(r.overlay.leads.find((l) => l.id === "L1")!.nodeId, fn.id);
  assert.strictEqual(r.overlay.leads.find((l) => l.id === "L2")!.status, "inferred", "verified-without-evidence is downgraded, never kept");
  assert.ok(r.warnings.some((w) => /L2/.test(w) && /no evidence/.test(w)), "the downgrade is reported");
  assert.ok(r.warnings.some((w) => /duplicate lead id 'L1'/.test(w)), "duplicate ids are reported");
  const ids = r.overlay.unresolved.map((u) => u.id).sort();
  assert.deepStrictEqual(ids, ["L3", "U1"], "unmatched target and source-reported unresolved are both kept as unresolved");
  assert.ok(r.overlay.unresolved.find((u) => u.id === "L3")!.reason.includes("not found"), "reason is stated");

  const withEvidence = resolveOverlay(g, doc({ leads: [{ id: "V", attackClassId: "AAC-11", label: "x", target: "src/handler.js#render", status: "verified", note: "n", evidence: [{ source: "pentest", detail: "reproduced" }] }] }));
  assert.strictEqual(withEvidence.overlay.leads[0].status, "verified", "a lead WITH evidence keeps the reported status");

  // an array of BLANK evidence records is not evidence: EvidenceItem permits empty strings, so
  // `evidence.length > 0` alone must not be treated as grounding.
  const blankEvidence = resolveOverlay(g, doc({ leads: [{ id: "BV", attackClassId: "AAC-11", label: "x", target: "src/handler.js#render", status: "verified", note: "n", evidence: [{ source: "", detail: "" }] }] }));
  assert.strictEqual(blankEvidence.overlay.leads[0].status, "inferred", "an all-blank evidence array is treated as no evidence and still downgraded");
  assert.ok(blankEvidence.warnings.some((w) => /BV/.test(w) && /no evidence/.test(w)), "the downgrade is reported even though evidence.length was 1");

  // untrusted input is rejected, not coerced
  assert.throws(() => resolveOverlay(g, doc({ schemaVersion: "2" })), "unknown contract version rejected");
  assert.throws(() => resolveOverlay(g, doc({ leads: [{ id: "X", attackClassId: "A", label: "l", target: "t", status: "hypothetical", note: "n", url: "javascript:alert(1)" }] })), "non-http(s) url rejected");
  assert.throws(() => resolveOverlay(g, doc({ leads: [{ id: "X", attackClassId: "A", label: "l", target: "t", status: "certain", note: "n" }] })), "unknown status rejected");

  // --- end to end: the build attaches it, validated, and findings are untouched --
  const overlayFile = join(root, "overlay.json");
  writeFileSync(overlayFile, JSON.stringify(doc()));
  const built = await buildAtlas(root, { product: "Code Atlas", repoLabel: "overlay-test", asiOverlay: overlayFile });
  assert.ok(built.overlay?.attached, "overlay attached");
  assert.strictEqual(built.overlay?.leads, 2);
  assert.strictEqual(built.overlay?.unresolved, 2);
  const reparsed = parseBundle(JSON.parse(JSON.stringify(built.bundle)));
  assert.strictEqual(reparsed.threatOverlay?.leads.length, 2, "bundle round-trips through the schema");
  assert.deepStrictEqual(built.bundle.findings ?? null, plain.findings ?? null, "the overlay never adds, removes or regrades a finding");
  assert.deepStrictEqual(built.bundle.graph.nodes.map((n) => n.id), plain.graph.nodes.map((n) => n.id), "the overlay adds no nodes");

  // a lead pointing at a node that is not in the graph is refused by the bundle schema
  const forged = JSON.parse(JSON.stringify(built.bundle));
  forged.threatOverlay.leads[0].nodeId = "not-a-node";
  assert.throws(() => parseBundle(forged), /not in graph/, "forged nodeId rejected");
  const badUrl = JSON.parse(JSON.stringify(built.bundle));
  badUrl.threatOverlay.leads[0].url = "javascript:alert(1)";
  assert.throws(() => parseBundle(badUrl), /http\(s\)/, "forged url scheme rejected");
  // resolveOverlay() downgrades observed/verified-with-no-evidence while BUILDING; a bundle handed
  // straight to parseBundle (e.g. the MCP server reading a bundle file directly) must not be able
  // to bypass that by simply shipping the ungrounded claim pre-baked.
  const ungrounded = JSON.parse(JSON.stringify(built.bundle));
  ungrounded.threatOverlay.leads[0].status = "verified";
  ungrounded.threatOverlay.leads[0].evidence = [];
  assert.throws(() => parseBundle(ungrounded), /claims 'verified' with no evidence/, "an ungrounded status cannot reach the MCP server via a hand-authored bundle");
  const ungroundedBlank = JSON.parse(JSON.stringify(built.bundle));
  ungroundedBlank.threatOverlay.leads[0].status = "verified";
  ungroundedBlank.threatOverlay.leads[0].evidence = [{ source: "", detail: "" }];
  assert.throws(() => parseBundle(ungroundedBlank), /claims 'verified' with no evidence/, "an all-blank evidence array doesn't satisfy parseBundle's check either");

  // --- a bad source never breaks the build; the reason is recorded, not swallowed --
  writeFileSync(join(root, "broken.json"), "{ not json");
  const broken = await buildAtlas(root, { product: "Code Atlas", repoLabel: "overlay-test", asiOverlay: join(root, "broken.json") });
  assert.strictEqual(broken.overlay?.attached, false);
  assert.ok(broken.overlay?.error, "error text is reported");
  assert.strictEqual(broken.bundle.threatOverlay, undefined, "nothing half-attached");
  assert.ok(broken.bundle.diagnostics.some((d) => d.stage === "threat-overlay"), "failure is recorded in the bundle diagnostics");
  // That bundle-level diagnostic must actually be reachable through a consumer, not just present
  // on the object — overview() didn't read bundle.diagnostics at all before this fix, so a loaded
  // bundle's threatOverlay being null gave no sign of why (the CLI's one-time warning is long gone
  // by the time anyone opens the saved bundle via MCP or the viewer).
  const brokenOverview: any = new AtlasTools(broken.bundle).overview();
  assert.strictEqual(brokenOverview.threatOverlay, null, "no overlay attached");
  assert.ok(brokenOverview.overlayDiagnostics.some((d: any) => d.stage === "threat-overlay" && /overlay not attached/.test(d.message)), "overview() surfaces WHY the overlay is missing");
  // sanity: a bundle with no overlay attempt at all reports an empty list, not a stale leftover
  assert.deepStrictEqual((new AtlasTools(built.bundle).overview() as any).overlayDiagnostics, [], "no threat-overlay diagnostics when nothing went wrong");

  // --- cli.ts's safeLog(): an overlay warning/error can embed untrusted text (a lead id, a parse-
  // error excerpt) up to the overlay's 5MB field limit; printed verbatim that's both a terminal-
  // control-sequence injection (ANSI/OSC) and an unbounded-output vector. ------------------------
  assert.strictEqual(safeLog("lead 'L1' claimed 'observed' with no evidence"), "lead 'L1' claimed 'observed' with no evidence", "ordinary text passes through unchanged");
  assert.strictEqual(safeLog("lead '\u001b[31mFAKE ERROR\u001b[0m' claimed X"), "lead '[31mFAKE ERROR[0m' claimed X", "ANSI escape bytes are stripped, not just the printable text around them");
  assert.strictEqual(safeLog("a\u0007b\u009bc"), "abc", "C0 and C1 control characters are stripped");
  const hugeWarning = safeLog("x".repeat(10_000));
  assert.ok(hugeWarning.length < 250, "an oversized warning is capped, not printed in full");
  assert.ok(hugeWarning.endsWith("…"), "a capped warning is marked as truncated");
  const missing = await buildAtlas(root, { product: "Code Atlas", repoLabel: "overlay-test", asiOverlay: join(root, "absent.json") });
  assert.strictEqual(missing.overlay?.attached, false, "a missing file is reported, not fatal");

  // --- URL source: bounded and fail-closed (fake fetch, no network) ----------------
  const okFetch = (async () => new Response(JSON.stringify(doc()), { status: 200 })) as typeof fetch;
  assert.strictEqual(((await readOverlaySource("https://asi.test/overlay", okFetch)) as { schemaVersion: string }).schemaVersion, "1");
  const failFetch = (async () => new Response("no", { status: 503 })) as typeof fetch;
  await assert.rejects(() => readOverlaySource("https://asi.test/overlay", failFetch), /HTTP 503/);
  let sawRedirectMode = "";
  const spyFetch = (async (_u: string, init?: RequestInit) => { sawRedirectMode = String(init?.redirect); return new Response("{}", { status: 200 }); }) as typeof fetch;
  await readOverlaySource("https://asi.test/overlay", spyFetch);
  assert.strictEqual(sawRedirectMode, "error", "redirects are refused (no hop to an internal address)");

  // an oversized Content-Length is rejected outright, before the implementation ever
  // calls reader.read() itself (checked via the explicit getReader spy below)
  let readerRequested = false;
  const oversizeDeclaredFetch = (async () => {
    const res = new Response(new ReadableStream({ pull(c) { c.enqueue(new TextEncoder().encode("x")); c.close(); } }),
      { status: 200, headers: { "content-length": String(6_000_000) } });
    const realGetReader = res.body!.getReader.bind(res.body);
    (res.body as any).getReader = (...a: unknown[]) => { readerRequested = true; return realGetReader(...(a as [])); };
    return res;
  }) as typeof fetch;
  await assert.rejects(() => readOverlaySource("https://asi.test/overlay", oversizeDeclaredFetch), /exceeds 5000000 bytes \(Content-Length/);
  assert.strictEqual(readerRequested, false, "a declared-oversize response never has its body reader requested");

  // no Content-Length, but the stream itself exceeds the limit: rejected mid-stream, not buffered whole first
  let bytesProducedBeforeThrow = 0;
  const unboundedStreamFetch = (async () => new Response(
    new ReadableStream({
      pull(c) {
        const chunk = new Uint8Array(1_000_000);
        bytesProducedBeforeThrow += chunk.byteLength;
        c.enqueue(chunk);
        if (bytesProducedBeforeThrow > 7_000_000) c.close();
      },
    }),
    { status: 200 },
  )) as typeof fetch;
  await assert.rejects(() => readOverlaySource("https://asi.test/overlay", unboundedStreamFetch), /exceeds 5000000 bytes/);
  assert.ok(bytesProducedBeforeThrow < 8_000_000, "streaming stops once the cap is crossed, not at end of stream");

  // the limit is enforced in BYTES, not JS string length: a multi-byte-heavy document can be
  // under 5,000,000 UTF-16 units yet over 5,000,000 UTF-8 bytes, and must still be rejected
  const multibyte = "€".repeat(1_700_001);               // 1 UTF-16 unit, 3 UTF-8 bytes each => ~5.1MB
  assert.ok(multibyte.length < 5_000_000, "fewer JS string units than the byte limit");
  const multibyteBytes = new TextEncoder().encode(multibyte);
  assert.ok(multibyteBytes.byteLength > 5_000_000, "but more actual bytes than the byte limit");
  const multibyteFetch = (async () => new Response(multibyteBytes, { status: 200 })) as typeof fetch;
  await assert.rejects(() => readOverlaySource("https://asi.test/overlay", multibyteFetch), /exceeds 5000000 bytes/);

  // the local-file path is also byte-checked via stat(), before the file is read
  const bigFile = join(root, "big-overlay.json");
  writeFileSync(bigFile, JSON.stringify({ padding: "x".repeat(5_500_000) }));
  await assert.rejects(() => readOverlaySource(bigFile), /overlay file exceeds 5000000 bytes/);

  // --- agents see leads as hypotheses, and receipts move with the overlay --------------
  const tools = new AtlasTools(built.bundle);
  const t: any = tools.threats(fn.id);
  assert.strictEqual(t.leads.length, 1);
  assert.strictEqual(t.leads[0].status, "hypothetical");
  assert.match(t.note, /hypotheses to investigate, not findings/);
  // ThreatLead.target ("the target string the source gave — kept for audit") was preserved on the
  // bundle but never surfaced by threats()/threatLeads(), leaving no way to audit the source's
  // original mapping claim against the resolved node.
  assert.strictEqual(t.leads[0].target, "src/handler.js#handlePrompt", "threats() includes the lead's original target string, not just the resolved node");

  // getNode()'s compact flags must not under-report a lead-only node: a node with no FINDING but
  // an external overlay LEAD should still read as having something flagged, under its own flag
  // (never merged into hasThreats, which an agent reads as "graded on this repo").
  const leadNode: any = tools.getNode(fn.id);
  assert.strictEqual(leadNode.hasThreatLeads, true, "a node with an overlay lead reports hasThreatLeads");
  assert.strictEqual(leadNode.hasThreats, false, "no finding on this node, so hasThreats stays false");
  const noLeadNode: any = tools.getNode(file.id);
  assert.strictEqual(noLeadNode.hasThreatLeads, false, "a node with no lead reports hasThreatLeads: false, not missing");
  const ov: any = tools.overview();
  assert.strictEqual(ov.threatOverlay.leads, 2);
  assert.strictEqual(ov.threatOverlay.unresolvedTotal, 2);
  assert.notStrictEqual(new AtlasTools(plain).bundleHash, tools.bundleHash, "attaching an overlay changes the bundle identity used by receipts");
  assert.strictEqual((new AtlasTools(plain).overview() as any).threatOverlay, null, "no overlay => null, not an empty claim");

  // --- overview()'s unresolved summary caps each TEXT FIELD, not just the array length -----
  // (slicing the array to 50 entries still lets one oversized `description` through in full)
  const hugeDescDoc = doc({ unresolved: [{ id: "U-HUGE", attackClassId: "AAC-29", description: "x".repeat(2_000_000), target: "y".repeat(2_000_000) }] });
  const hugeOverlayFile = join(root, "huge-overlay.json");
  writeFileSync(hugeOverlayFile, JSON.stringify(hugeDescDoc));
  const builtHuge = await buildAtlas(root, { product: "Code Atlas", repoLabel: "overlay-test", asiOverlay: hugeOverlayFile });
  const ovHuge: any = new AtlasTools(builtHuge.bundle).overview();
  const hugeEntry = ovHuge.threatOverlay.unresolved.find((u: any) => u.id === "U-HUGE");
  assert.ok(hugeEntry.description.length < 1000, "a near-5MB description is bounded in the overview summary, not returned whole");
  assert.ok(hugeEntry.target.length < 1000, "the target field is bounded too");

  // --- the SAME unresolved summary must also cap id/attackClassId/reason, not just description/target --
  // (those two were the original fix; id/attackClassId/reason are just as overlay-controlled and were
  // passed through verbatim by the `{ ...u }` spread)
  const hugeOtherFieldsDoc = doc({ unresolved: [{
    id: "U".repeat(1_000_000), attackClassId: "C".repeat(1_000_000), description: "d", reason: "r".repeat(1_000_000),
  }] });
  const hugeOtherFieldsFile = join(root, "huge-unresolved-other-fields-overlay.json");
  writeFileSync(hugeOtherFieldsFile, JSON.stringify(hugeOtherFieldsDoc));
  const builtHugeOther = await buildAtlas(root, { product: "Code Atlas", repoLabel: "overlay-test", asiOverlay: hugeOtherFieldsFile });
  const ovHugeOther: any = new AtlasTools(builtHugeOther.bundle).overview();
  const hugeOtherEntry = ovHugeOther.threatOverlay.unresolved[0];
  assert.ok(hugeOtherEntry.id.length < 1000, "unresolved.id is bounded, not passed through the spread whole");
  assert.ok(hugeOtherEntry.attackClassId.length < 1000, "unresolved.attackClassId is bounded too");
  assert.ok(hugeOtherEntry.reason.length < 1000, "unresolved.reason is bounded too");

  // --- overview()'s threatOverlay.source is also untrusted overlay text, same cap applies -----
  // (leads/unresolved had field caps; source.identity/ref/asOf did not, and overview() is the
  // RECOMMENDED FIRST call — it has to stay cheap even when those three fields are not)
  const hugeSourceDoc = doc({ source: { identity: "i".repeat(1_000_000), ref: "r".repeat(1_000_000), asOf: "a".repeat(1_000_000) } });
  const hugeSourceFile = join(root, "huge-source-overlay.json");
  writeFileSync(hugeSourceFile, JSON.stringify(hugeSourceDoc));
  const builtHugeSource = await buildAtlas(root, { product: "Code Atlas", repoLabel: "overlay-test", asiOverlay: hugeSourceFile });
  const ovHugeSource: any = new AtlasTools(builtHugeSource.bundle).overview();
  assert.ok(ovHugeSource.threatOverlay.source.identity.length < 1000, "source.identity is bounded in the overview summary");
  assert.ok(ovHugeSource.threatOverlay.source.ref.length < 1000, "source.ref is bounded too");
  assert.ok(ovHugeSource.threatOverlay.source.asOf.length < 1000, "source.asOf is bounded too");

  // --- threats()/threatLeads() bound each resolved lead's free-text fields too ----------------
  // (the ROW count being bounded does not bound any ONE row's note/label/evidence)
  // (kept well under the 5MB overlay FILE cap — that's covered separately above — this is testing
  // the per-FIELD cap on an otherwise normal-sized overlay document)
  const hugeNoteDoc = doc({ leads: [{ id: "L-HUGE", attackClassId: "AAC-01", label: "y".repeat(5_000), target: "src/handler.js#handlePrompt", status: "hypothetical", note: "x".repeat(5_000), evidence: [{ source: "s".repeat(5_000), detail: "d".repeat(5_000) }] }] });
  const hugeNoteFile = join(root, "huge-note-overlay.json");
  writeFileSync(hugeNoteFile, JSON.stringify(hugeNoteDoc));
  const builtHugeNote = await buildAtlas(root, { product: "Code Atlas", repoLabel: "overlay-test", asiOverlay: hugeNoteFile });
  const hugeTools = new AtlasTools(builtHugeNote.bundle);
  const hugeThreatsLead = (hugeTools.threats(fn.id) as any).leads.find((l: any) => l.id === "L-HUGE");
  assert.ok(hugeThreatsLead, "the oversized-field lead still resolves and attaches");
  assert.ok(hugeThreatsLead.label.length < 1000 && hugeThreatsLead.note.length < 1000, "threats() bounds a lead's label/note");
  assert.ok(hugeThreatsLead.evidence[0].source.length < 1000 && hugeThreatsLead.evidence[0].detail.length < 1000, "threats() bounds evidence fields too");
  const hugeListLead = (hugeTools.threatLeads() as any).leads.find((l: any) => l.id === "L-HUGE");
  assert.ok(hugeListLead.label.length < 1000 && hugeListLead.note.length < 1000, "threatLeads() bounds a lead's label/note the same way");

  // --- id/attackClassId/rule are just as overlay-controlled as label/note/url, and were passed
  // through threats()/threatLeads() verbatim (the earlier fix only ran label/note/url/evidence
  // through boundLeadText — not these three). Find the lead by TARGET, since id itself is now capped. ---
  const hugeIdRuleDoc = doc({ leads: [{
    id: "I".repeat(1_000_000), attackClassId: "C".repeat(1_000_000), label: "x",
    target: "src/handler.js#handlePrompt", status: "hypothetical", note: "n", rule: "R".repeat(1_000_000),
  }] });
  const hugeIdRuleFile = join(root, "huge-id-rule-overlay.json");
  writeFileSync(hugeIdRuleFile, JSON.stringify(hugeIdRuleDoc));
  const builtHugeIdRule = await buildAtlas(root, { product: "Code Atlas", repoLabel: "overlay-test", asiOverlay: hugeIdRuleFile });
  const hugeIdRuleThreatsLead = (new AtlasTools(builtHugeIdRule.bundle).threats(fn.id) as any).leads[0];
  assert.ok(hugeIdRuleThreatsLead.id.length < 1000, "threats() bounds a lead's id");
  assert.ok(hugeIdRuleThreatsLead.attackClassId.length < 1000, "threats() bounds a lead's attackClassId");
  assert.ok(hugeIdRuleThreatsLead.rule.length < 1000, "threats() bounds a lead's rule");
  const hugeIdRuleListLead = (new AtlasTools(builtHugeIdRule.bundle).threatLeads() as any).leads[0];
  assert.ok(hugeIdRuleListLead.id.length < 1000, "threatLeads() bounds a lead's id the same way");
  assert.ok(hugeIdRuleListLead.attackClassId.length < 1000, "threatLeads() bounds a lead's attackClassId the same way");
  assert.ok(hugeIdRuleListLead.rule.length < 1000, "threatLeads() bounds a lead's rule the same way");

  // --- an oversized url must be OMITTED, not truncated: a truncated url (capText's slice+"…")
  // is a DIFFERENT address that still looks like the source's own reference — a caller that
  // follows or cites it lands somewhere else entirely, which is worse than no url at all. -------
  const hugeUrlDoc = doc({ leads: [{
    id: "L-URL", attackClassId: "AAC-01", label: "x", target: "src/handler.js#handlePrompt",
    status: "hypothetical", note: "n", url: "https://example.test/" + "q".repeat(1_000),
  }] });
  const hugeUrlFile = join(root, "huge-url-overlay.json");
  writeFileSync(hugeUrlFile, JSON.stringify(hugeUrlDoc));
  const builtHugeUrl = await buildAtlas(root, { product: "Code Atlas", repoLabel: "overlay-test", asiOverlay: hugeUrlFile });
  const hugeUrlThreatsLead = (new AtlasTools(builtHugeUrl.bundle).threats(fn.id) as any).leads[0];
  assert.strictEqual(hugeUrlThreatsLead.url, null, "threats() omits an oversized url rather than returning a truncated (different) address");
  const hugeUrlListLead = (new AtlasTools(builtHugeUrl.bundle).threatLeads() as any).leads[0];
  assert.strictEqual(hugeUrlListLead.url, null, "threatLeads() omits an oversized url the same way");
  // a normal-size url (the default doc()'s L1) still comes through untouched, not dropped
  const normalUrlLead = (tools.threats(fn.id) as any).leads.find((l: any) => l.id === "L1");
  assert.strictEqual(normalUrlLead.url, "https://example.test/AAC-01", "a url within bound is passed through unmodified");

  // --- unresolvedLeads(): everything past overview()'s 50-row summary must still be reachable ----
  // (threatLeads() explicitly excludes unresolved entries since they have no node; the viewer's
  // own panel is bounded too — this is the only paginated path to the full unresolved list)
  // leads: [] so the default doc()'s own unresolvable L3 target doesn't add a 121st entry on top
  const manyUnresolvedDoc = doc({
    leads: [],
    unresolved: Array.from({ length: 120 }, (_, i) => ({ id: `UX${i}`, attackClassId: "AAC-29", description: `entry ${i}` })),
  });
  const manyUnresolvedFile = join(root, "many-unresolved-overlay.json");
  writeFileSync(manyUnresolvedFile, JSON.stringify(manyUnresolvedDoc));
  const builtManyUnresolved = await buildAtlas(root, { product: "Code Atlas", repoLabel: "overlay-test", asiOverlay: manyUnresolvedFile });
  const unresolvedTools = new AtlasTools(builtManyUnresolved.bundle);
  const ovManyUnresolved: any = unresolvedTools.overview();
  assert.strictEqual(ovManyUnresolved.threatOverlay.unresolved.length, 50, "overview()'s summary stays capped at 50 even with 120 entries");
  assert.strictEqual(ovManyUnresolved.threatOverlay.unresolvedTotal, 120, "but the true total is still reported");
  const unresPage1: any = unresolvedTools.unresolvedLeads({ limit: 50 });
  assert.strictEqual(unresPage1.unresolved.length, 50);
  assert.strictEqual(unresPage1.total, 120);
  assert.strictEqual(unresPage1.nextOffset, 50, "nextOffset says where the next page starts");
  const unresPage2: any = unresolvedTools.unresolvedLeads({ limit: 50, offset: unresPage1.nextOffset });
  assert.strictEqual(unresPage2.unresolved.length, 50);
  const unresPage3: any = unresolvedTools.unresolvedLeads({ limit: 50, offset: unresPage2.nextOffset });
  assert.strictEqual(unresPage3.unresolved.length, 20, "the last page holds the remainder (120 - 100)");
  assert.strictEqual(unresPage3.nextOffset, null, "the last page reports no further offset");
  const allUnresolvedIds = new Set([
    ...unresPage1.unresolved.map((u: any) => u.id), ...unresPage2.unresolved.map((u: any) => u.id), ...unresPage3.unresolved.map((u: any) => u.id),
  ]);
  assert.strictEqual(allUnresolvedIds.size, 120, "paging with offset reaches every one of the 120 entries, past overview()'s 50-row cap");
  assert.strictEqual(new AtlasTools(plain).unresolvedLeads().unresolved.length, 0, "no overlay => empty list, not an error");

  // --- threats() must also bound the NUMBER of evidence rows one lead carries, not just each row's
  // text. The 5,000-entry overlay cap bounds how many LEADS a bundle holds, not how many evidence
  // records a SINGLE lead's array has — one lead could put its whole document allowance there. -----
  const manyEvidenceDoc = doc({ leads: [{
    id: "L-MANYEV", attackClassId: "AAC-01", label: "many evidence rows", target: "src/handler.js#handlePrompt",
    status: "hypothetical", note: "n",
    evidence: Array.from({ length: 5_000 }, (_, i) => ({ source: `s${i}`, detail: `d${i}` })),
  }] });
  const manyEvidenceFile = join(root, "many-evidence-overlay.json");
  writeFileSync(manyEvidenceFile, JSON.stringify(manyEvidenceDoc));
  const builtManyEvidence = await buildAtlas(root, { product: "Code Atlas", repoLabel: "overlay-test", asiOverlay: manyEvidenceFile });
  const manyEvidenceLead = (new AtlasTools(builtManyEvidence.bundle).threats(fn.id) as any).leads.find((l: any) => l.id === "L-MANYEV");
  assert.ok(manyEvidenceLead, "the many-evidence lead still resolves and attaches");
  assert.ok(manyEvidenceLead.evidence.length <= 50, "the evidence ARRAY is row-capped, not just each row's text fields");
  assert.strictEqual(manyEvidenceLead.evidenceTotal, 5_000, "the true evidence count is still reported, so the cap is visible rather than silent");

  // --- threatLeads() must expose evidence too — threats() row-caps at ROW_CAP (500) and tells
  // callers to page through threatLeads() for the rest, but threatLeads() rows omitted evidence
  // entirely, so evidence on any lead past the first 500 on one node was unreachable through
  // either MCP tool or atlas_exec. -------------------------------------------------------------
  const manyEvidenceListLead = (new AtlasTools(builtManyEvidence.bundle).threatLeads() as any).leads.find((l: any) => l.id === "L-MANYEV");
  assert.ok(manyEvidenceListLead.evidence, "threatLeads() rows now carry evidence, not just threats() rows");
  assert.ok(manyEvidenceListLead.evidence.length <= 50, "threatLeads()'s evidence is row-capped the same way");
  assert.strictEqual(manyEvidenceListLead.evidenceTotal, 5_000, "threatLeads() reports the true evidence count too");

  // --- threats() row-caps leads/findings for ONE ref: the 5,000-entry cap is PER BUNDLE, not per
  // node, so an untrusted overlay can still put hundreds of leads on the SAME node. ---------------
  const manyLeadsDoc = doc({
    leads: Array.from({ length: 30 }, (_, i) => ({
      id: `M${i}`, attackClassId: "AAC-01", label: "l", target: "src/handler.js#handlePrompt", status: "hypothetical", note: "n",
    })),
  });
  const manyLeadsFile = join(root, "many-leads-overlay.json");
  writeFileSync(manyLeadsFile, JSON.stringify(manyLeadsDoc));
  const builtManyLeads = await buildAtlas(root, { product: "Code Atlas", repoLabel: "overlay-test", asiOverlay: manyLeadsFile });
  const manyLeadsTools = new AtlasTools(builtManyLeads.bundle);
  // ROW_CAP (500) is far above 30, so this exercises the plumbing (leadsTotal/findingsTotal present,
  // nothing dropped yet) — the cap's actual truncation is exercised by the schema-level test below.
  const manyLeadsThreats: any = manyLeadsTools.threats(fn.id);
  assert.strictEqual(manyLeadsThreats.leadsTotal, 30);
  assert.strictEqual(manyLeadsThreats.leads.length, 30, "under the row cap, nothing is dropped");

  // --- threats() must direct a FINDINGS overflow to somewhere that can actually page through
  // findings — atlas_threat_leads only paginates LEADS, so pointing a findingsTotal > ROW_CAP
  // overflow there (as it used to) left those findings with no real way to reach them. -------
  const manyFindingsBundle = {
    ...plain,
    findings: Array.from({ length: 600 }, (_, i) => ({
      id: `F${i}`, nodeRefs: [fn.id], kind: "weakness" as const, title: `finding ${i}`, explanation: "e",
      grade: "STATIC" as const, evidence: [{ source: "code-atlas/rule:test", detail: "d" }], blastRadius: [],
    })),
  };
  const manyFindingsTools = new AtlasTools(manyFindingsBundle);
  const manyFindingsThreats: any = manyFindingsTools.threats(fn.id);
  assert.strictEqual(manyFindingsThreats.findingsTotal, 600);
  assert.strictEqual(manyFindingsThreats.findings.length, 500, "findings are row-capped at ROW_CAP (500)");
  assert.match(manyFindingsThreats.note, /atlas\.findings\(\{path: \.\.\., offset\}\)/, "the overflow note points to findings()'s own pagination, not atlas_threat_leads");
  assert.doesNotMatch(manyFindingsThreats.note, /Leads row-capped/, "no lead overflow is claimed when only findings overflowed");
  // and findings() itself must actually be able to page through all 600, via offset/nextOffset
  const findingsPage1: any = manyFindingsTools.findings({ limit: 500 });
  assert.strictEqual(findingsPage1.findings.length, 500);
  assert.strictEqual(findingsPage1.nextOffset, 500, "nextOffset says where the next page starts");
  const findingsPage2: any = manyFindingsTools.findings({ limit: 500, offset: findingsPage1.nextOffset });
  assert.strictEqual(findingsPage2.findings.length, 100, "the second page holds the remainder (600 - 500)");
  assert.strictEqual(findingsPage2.nextOffset, null, "the last page reports no further offset");
  const allFindingIds = new Set([...findingsPage1.findings.map((f: any) => f.id), ...findingsPage2.findings.map((f: any) => f.id)]);
  assert.strictEqual(allFindingIds.size, 600, "paging with offset reaches every one of the 600 findings");

  // --- finding(id): the only way to reach full detail for a finding past threats()'s ROW_CAP ---
  // findingsPage2's rows (offset 500+) are compact; "F550" never appears in manyFindingsThreats'
  // findings array (capped at the first 500), so without finding(id) its explanation/evidence/
  // blastRadius/asiRef/disposition would be permanently unreachable through any other call.
  const lateFinding: any = manyFindingsTools.finding("F550");
  assert.strictEqual(lateFinding.id, "F550");
  assert.strictEqual(lateFinding.explanation, "e", "full detail is returned, not just the compact findings() row shape");
  assert.ok(Array.isArray(lateFinding.evidence) && lateFinding.evidence.length, "evidence is present");
  assert.ok(lateFinding.node && lateFinding.node.id === fn.id, "node reference is resolved");
  assert.deepStrictEqual(manyFindingsTools.finding("nope"), { error: "unknown finding id", id: "nope", hint: "use atlas_exec's atlas.findings({...}) to find an id" }, "an unknown id reports an error, not a throw");
  assert.match(findingsPage2.note, /atlas\.finding\(id\)/, "findings()'s note points at the id lookup for full detail");

  // --- finding(id) must treat a duplicate id as ambiguous, like applyDisposition() already does,
  // not silently resolve to whichever duplicate happened to land last in an id->record map. -------
  const dupFindingsBundle = {
    ...plain,
    findings: [
      { id: "DUP", nodeRefs: [fn.id], kind: "weakness" as const, title: "first", explanation: "e1", grade: "STATIC" as const, evidence: [{ source: "code-atlas/rule:test", detail: "d" }], blastRadius: [] },
      { id: "DUP", nodeRefs: [fn.id], kind: "weakness" as const, title: "second", explanation: "e2", grade: "STATIC" as const, evidence: [{ source: "code-atlas/rule:test", detail: "d" }], blastRadius: [] },
    ],
  };
  const dupFindingsTools = new AtlasTools(dupFindingsBundle);
  const ambiguous: any = dupFindingsTools.finding("DUP");
  assert.strictEqual(ambiguous.error, "ambiguous finding id", "a duplicate id refuses to pick one arbitrarily");
  assert.strictEqual(ambiguous.count, 2, "the ambiguity error states how many matches there are");

  // --- resolveOverlay() must keep its OUTPUT unresolved array within the schema's cap, even
  // though the two INPUT arrays it draws from (leads whose target fails to resolve, and explicit
  // unresolved entries) are each independently capped at MAX_ENTRIES — a legitimately-sized overlay
  // that fails resolution on most of its leads could otherwise synthesize MORE unresolved entries
  // than the output schema allows, and parseBundle's re-validation (build.ts) would then discard
  // the WHOLE overlay, leads included, over a diagnostics-only array being too long. ------------
  const unresolvableLeads = Array.from({ length: 3_000 }, (_, i) => ({
    id: `UR${i}`, attackClassId: "AAC-01", label: "l", target: "src/does-not-exist.js#missing", status: "hypothetical" as const, note: "n",
  }));
  const explicitUnresolved = Array.from({ length: 3_000 }, (_, i) => ({ id: `EU${i}`, attackClassId: "AAC-29", description: `entry ${i}` }));
  const combinedOverCapDoc = doc({ leads: unresolvableLeads, unresolved: explicitUnresolved });
  const combinedOverCap = resolveOverlay(g, combinedOverCapDoc);
  assert.strictEqual(combinedOverCap.overlay.unresolved.length, 5_000, "the combined unresolved output is trimmed to the schema's MAX_ENTRIES cap, not left at 6,000");
  assert.ok(combinedOverCap.warnings.some((w) => /dropped/.test(w) && /unresolved/.test(w)), "the truncation is reported as a warning, not silent");
  assert.doesNotThrow(() => parseBundle({ ...plain, threatOverlay: combinedOverCap.overlay }), "the trimmed overlay re-validates cleanly against the bundle schema");
  // The trim must be PERSISTED on the overlay itself (unresolvedDropped), not just the transient
  // build-time warning above — a bundle reloaded directly (parseBundle, bypassing buildAtlas)
  // would otherwise show unresolvedTotal === MAX_ENTRIES with no sign anything was dropped.
  assert.strictEqual(combinedOverCap.overlay.unresolvedDropped, 1_000, "the true drop count (6,000 - 5,000) is recorded on the overlay");
  const combinedOverCapTools = new AtlasTools({ ...plain, threatOverlay: combinedOverCap.overlay });
  const ovCombined: any = combinedOverCapTools.overview();
  assert.strictEqual(ovCombined.threatOverlay.unresolvedDropped, 1_000, "atlas_overview surfaces the drop count, not just unresolvedTotal");
  const unresolvedLeadsCombined: any = combinedOverCapTools.unresolvedLeads({ limit: 1 });
  assert.strictEqual(unresolvedLeadsCombined.unresolvedDropped, 1_000, "atlas_unresolved_leads surfaces the drop count too");
  assert.match(unresolvedLeadsCombined.note, /1000 additional entries were dropped/, "the note states entries were dropped at build time, not retrievable here");
  // sanity: when nothing was dropped, the field reads 0/absent, not a stale leftover
  assert.strictEqual((tools.overview() as any).threatOverlay.unresolvedDropped, 0, "a normal overlay reports unresolvedDropped: 0, not undefined or a leftover count");

  // --- the bundle schema itself caps lead/unresolved COUNT, not just build-time OverlayInputSchema --
  // (parseBundle is the path the MCP server actually uses to load a bundle file, bypassing build())
  const tooManyLeads = JSON.parse(JSON.stringify(built.bundle));
  tooManyLeads.threatOverlay.leads = Array.from({ length: 5001 }, (_, i) => ({ ...tooManyLeads.threatOverlay.leads[0], id: `X${i}` }));
  assert.throws(() => parseBundle(tooManyLeads), "a bundle with more than 5,000 leads is rejected even when handed directly to parseBundle");

  // --- parseBundle's duplicate-id check must cover the WHOLE overlay, not just `leads` ---------
  // resolveOverlay() de-dupes leads and unresolved together under one `seen` set before this
  // re-validation ever runs via build.ts, so this gap only bites a bundle handed to parseBundle
  // directly (e.g. the MCP server loading a bundle file) that never went through resolveOverlay().
  const dupAcrossUnresolved = JSON.parse(JSON.stringify(built.bundle));
  dupAcrossUnresolved.threatOverlay.unresolved = [
    { id: "U-DUP", attackClassId: "AAC-01", description: "a", reason: "r" },
    { id: "U-DUP", attackClassId: "AAC-02", description: "b", reason: "r" },
  ];
  assert.throws(() => parseBundle(dupAcrossUnresolved), "a duplicate id reused within `unresolved` is rejected");
  const dupLeadAndUnresolved = JSON.parse(JSON.stringify(built.bundle));
  dupLeadAndUnresolved.threatOverlay.unresolved = [
    { id: dupLeadAndUnresolved.threatOverlay.leads[0].id, attackClassId: "AAC-01", description: "a", reason: "r" },
  ];
  assert.throws(() => parseBundle(dupLeadAndUnresolved), "an id shared between a resolved lead and an unresolved entry is rejected");

  // --- atlas.threatLeads(): resolved leads are enumerable without knowing a node id first ---
  const allLeads: any = tools.threatLeads();
  assert.strictEqual(allLeads.leads.length, 2, "both resolved leads are listed with no ref needed");
  assert.ok(allLeads.leads.every((l: any) => l.node && l.node.id), "each row carries a node reference");
  const byClass: any = tools.threatLeads({ attackClassId: "AAC-11" });
  assert.strictEqual(byClass.leads.length, 1);
  assert.strictEqual(byClass.leads[0].id, "L2");
  const byPath: any = tools.threatLeads({ path: "handler.js" });
  assert.strictEqual(byPath.leads.length, 2, "both L1 and L2 resolve into src/handler.js");
  assert.strictEqual(new AtlasTools(plain).threatLeads().leads.length, 0, "no overlay => empty list, not an error");
  assert.strictEqual(allLeads.leads.find((l: any) => l.id === "L1").target, "src/handler.js#handlePrompt", "threatLeads() also includes the original target string per lead");

  // --- atlas.lead(id): full detail by id, with evidence PAGINATED past the 50-row cap ----------
  // threats()/threatLeads() both cap a lead's evidence at EVIDENCE_CAP (50) with no way past it;
  // lead(id) is the dedicated detail lookup, mirroring finding(id)'s role for findings. Reuse
  // builtManyEvidence's "L-MANYEV" lead (5,000 evidence rows) from the row-cap test above.
  const evidenceTools = new AtlasTools(builtManyEvidence.bundle);
  const leadPage1: any = evidenceTools.lead("L-MANYEV");
  assert.strictEqual(leadPage1.evidenceTotal, 5_000);
  assert.strictEqual(leadPage1.evidence.length, 50, "lead() defaults to the same 50-row page size as threats()/threatLeads()");
  assert.strictEqual(leadPage1.evidenceNextOffset, 50, "nextOffset says where the next page starts");
  assert.strictEqual(leadPage1.target, "src/handler.js#handlePrompt", "lead() surfaces the original target too");
  // page through with the max page size (limit is clamped to 1000, same ceiling as threatLeads())
  // and confirm every one of the 5,000 evidence rows is actually reachable, not just the first
  const allEvidenceSources = new Set<string>(leadPage1.evidence.map((e: any) => e.source));
  let evOffset: number | null = leadPage1.evidenceNextOffset;
  let pages = 1;
  while (evOffset !== null) {
    const page: any = evidenceTools.lead("L-MANYEV", { offset: evOffset, limit: 1000 });
    for (const e of page.evidence) allEvidenceSources.add(e.source);
    evOffset = page.evidenceNextOffset;
    pages++;
  }
  assert.strictEqual(allEvidenceSources.size, 5_000, "paging with offset reaches every one of the 5,000 evidence rows");
  assert.ok(pages > 1, "more than one page was needed, so this actually exercised pagination");
  assert.deepStrictEqual(evidenceTools.lead("nope"), { error: "unknown lead id", id: "nope", hint: "use atlas_threat_leads or atlas.threatLeads({...}) to find an id" }, "an unknown lead id reports an error, not a throw");

  // --- threatLeads() pagination: more matches than `limit` must actually be reachable ----------
  const page1: any = manyLeadsTools.threatLeads({ limit: 10 });
  assert.strictEqual(page1.leads.length, 10);
  assert.strictEqual(page1.total, 30);
  assert.strictEqual(page1.nextOffset, 10, "nextOffset says where the next page starts");
  const page2: any = manyLeadsTools.threatLeads({ limit: 10, offset: page1.nextOffset });
  assert.strictEqual(page2.leads.length, 10);
  const page1Ids = new Set(page1.leads.map((l: any) => l.id));
  const page2Ids = new Set(page2.leads.map((l: any) => l.id));
  assert.strictEqual([...page1Ids].filter((id) => page2Ids.has(id)).length, 0, "consecutive pages don't overlap");
  const page3: any = manyLeadsTools.threatLeads({ limit: 10, offset: page2.nextOffset });
  assert.strictEqual(page3.leads.length, 10);
  assert.strictEqual(page3.nextOffset, null, "the last page reports no further offset");
  const allSeenIds = new Set([...page1Ids, ...page2Ids, ...page3.leads.map((l: any) => l.id)]);
  assert.strictEqual(allSeenIds.size, 30, "paging with offset reaches every one of the 30 leads, not just the first page repeated");

  console.log("threat-overlay.test: exactly-one-match resolution, no upgrades, annotations only, bad sources non-fatal, leads are hypotheses to agents");
} finally {
  rmSync(root, { recursive: true, force: true });
}
