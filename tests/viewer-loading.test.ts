import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const html = readFileSync(new URL("../viewer/viewer.html", import.meta.url), "utf8");
assert.match(html, /\[hidden\]\s*\{\s*display:\s*none\s*!important\s*\}/, "CSS must respect hidden on flex overlays");
const script = html.slice(html.lastIndexOf("<script>") + 8, html.lastIndexOf("</script>"));
const elements = new Map<string, any>();
function element(id: string) {
  if (!elements.has(id)) elements.set(id, {
    hidden: false, textContent: "", innerHTML: "", title: "", style: {}, classList: { remove() {}, add() {}, toggle() { return false; } },
    setAttribute() {}, getAttribute() { return null; }, addEventListener() {}, querySelectorAll: () => [],
    // real getElementById returns null for an element never created (e.g. "tmPanel", only ever
    // created on demand via createElement) — this stub auto-vivifies instead for convenience, so
    // it needs remove()/parentNode too, now that loadGraph's fix to call updateLegend() exercises
    // that path (`document.getElementById("tmPanel")?.remove()`) on every load, not just a mode switch.
    remove() {}, parentNode: { appendChild() {} },
  });
  return elements.get(id);
}
let renderedNodes = 0;
const fg: any = { graphData(d: any) { renderedNodes = d.nodes.length; return fg; }, nodeColor() { return fg; }, linkColor() { return fg; } };
const context = vm.createContext({
  document: { getElementById: element, createElement: () => ({ innerHTML: "", querySelectorAll: () => [] }) },
  window: { matchMedia: () => ({ matches: false }), addEventListener() {} },
  setTimeout() {}, console,
});
vm.runInContext(script, context);
context.testFG = fg;
vm.runInContext("FG = testFG; loadGraph(SAMPLE_BUNDLE);", context);
assert.ok(renderedNodes > 0);
assert.equal(element("empty").hidden, true, "rendered graph clears loading overlay");
vm.runInContext("loadGraph({nodes:[], edges:[], revision:'empty'});", context);
assert.equal(element("empty").hidden, false);
assert.match(element("empty").textContent, /No graph nodes/);
vm.runInContext("loadGraph(SAMPLE_BUNDLE);", context);
assert.equal(element("empty").hidden, true, "loading a valid graph after an empty one clears the empty state");

// Exercise actual folder filtering and request assembly, then render its response.
let uploaded: any;
context.fetch = async (_url: string, options: any) => {
  uploaded = JSON.parse(options.body);
  assert.equal(options.headers["X-Atlas-Token"], "test-token");
  return { ok: true, json: async () => ({ graph: { nodes: [{ id: "one", kind: "file", label: "main.ts", evidence: { path: "src/main.ts" } }], edges: [] } }) };
};
const file = (path: string, size = 10) => ({ webkitRelativePath: path, name: path.split("/").at(-1), size, text: async () => "export const x = 1;" });
context.testFiles = [file("project/src/main.ts"), file("project/node_modules/pkg/main.ts"), file("project/README.md"), file("project/src/large.ts", 200001)];
await vm.runInContext("ingestFolder(testFiles, 'test-token')", context);
assert.equal(uploaded.name, "project");
assert.deepEqual(uploaded.files.map((f: any) => f.path), ["src/main.ts"]);
assert.equal(renderedNodes, 1);
assert.equal(element("empty").hidden, true);
assert.match(element("sampleBadge").textContent, /skipped 3/);
context.testFiles = [file("project/README.md")];
await assert.rejects(vm.runInContext("ingestFolder(testFiles, 'test-token')", context), /No supported source files/);
console.log("viewer-loading.test: hidden CSS, loading/empty transitions, folder selection filtering, upload, and rendering passed");
