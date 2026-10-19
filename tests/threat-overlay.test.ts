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

  // --- the bundle schema itself caps lead/unresolved COUNT, not just build-time OverlayInputSchema --
  // (parseBundle is the path the MCP server actually uses to load a bundle file, bypassing build())
  const tooManyLeads = JSON.parse(JSON.stringify(built.bundle));
  tooManyLeads.threatOverlay.leads = Array.from({ length: 5001 }, (_, i) => ({ ...tooManyLeads.threatOverlay.leads[0], id: `X${i}` }));
  assert.throws(() => parseBundle(tooManyLeads), "a bundle with more than 5,000 leads is rejected even when handed directly to parseBundle");

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
