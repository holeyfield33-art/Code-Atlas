import assert from "node:assert/strict";
import { once } from "node:events";
import { request as httpRequest } from "node:http";
import { createAtlasServer, validateUpload, serveAtlas } from "../src/server.js";
import { parseBundle } from "../src/schema.js";

const files = [
  { path: "src/main.ts", code: "export function greet(x: string) { return x; }" },
  { path: "pkg/helper.py", code: "def greet(x):\n    return x\n" },
  { path: "lib/helper.rb", code: "def greet(x)\n  x\nend\n" },
];
for (const path of ["../escape.ts", "/absolute.ts", "C:/drive.ts", "src/../escape.ts", "src\\escape.ts", "src/CON.ts", "src/a.ts.", "node_modules/a.ts", "a.txt"]) {
  assert.throws(() => validateUpload({ name: "fixture", files: [{ path, code: "x" }] }), path);
}
assert.throws(() => validateUpload({ name: "fixture", files: [] }));
assert.throws(() => validateUpload({ name: "fixture", files: [{ path: "a.ts", code: "x".repeat(200001) }] }));
assert.throws(() => validateUpload({ name: "fixture", files: [{ path: "a.ts", code: "" }, { path: "A.ts", code: "" }] }));

// The page opens on a built bundle when one is configured (re-read per load), else the sample.
import { mkdtempSync, writeFileSync as writeFile } from "node:fs";
import { tmpdir } from "node:os";
import { join as joinPath } from "node:path";
const bundleDir = mkdtempSync(joinPath(tmpdir(), "atlas-page-"));
const bundleFile = joinPath(bundleDir, "atlas.bundle.json");
const tiny = (label: string) => ({ schemaVersion: "1.0", product: { name: "Code Atlas" }, repository: { label, revision: "t" },
  generatedAt: new Date().toISOString(), graph: { version: "t", revision: "t", nodes: [], edges: [], diagnostics: [] } });
const pageOf = async (opts: Parameters<typeof createAtlasServer>[0]) => {
  const s = createAtlasServer(opts); s.listen(0, "127.0.0.1"); await once(s, "listening");
  const p = (s.address() as any).port; const html = await (await fetch(`http://127.0.0.1:${p}/`)).text();
  s.closeAllConnections(); await new Promise<void>((r) => s.close(() => r())); return html;
};
assert.ok((await pageOf({})).includes("fn_resolve"), "with no bundle the page shows the built-in sample graph");
assert.ok((await pageOf({ bundlePath: joinPath(bundleDir, "missing.json") })).includes("fn_resolve"), "a missing bundle falls back to the sample");
writeFile(bundleFile, JSON.stringify(tiny("first-label-from-disk")));
const served = await pageOf({ bundlePath: bundleFile });
assert.ok(served.includes("first-label-from-disk"), "the page is rendered from the bundle on disk");
assert.ok(/id="atlas-upload-config">{"token":"[0-9a-f]{64}"}/.test(served), "the Open folder token is still present");
writeFile(bundleFile, JSON.stringify(tiny("second-label-after-rebuild")));
assert.ok((await pageOf({ bundlePath: bundleFile })).includes("second-label-after-rebuild"), "a rebuilt bundle shows on the next load, no restart");
writeFile(bundleFile, "{ not json");
assert.ok((await pageOf({ bundlePath: bundleFile })).includes("fn_resolve"), "a corrupt bundle falls back to the sample instead of failing");

const server = createAtlasServer();
server.listen(0, "127.0.0.1");
await once(server, "listening");
const base = `http://127.0.0.1:${(server.address() as any).port}`;
const port = (server.address() as any).port;
const getWithHost = (host: string) => new Promise<number>((resolve, reject) => {
  const r = httpRequest({ host: "127.0.0.1", port, path: "/", headers: { host } }, (res) => { res.resume(); resolve(res.statusCode ?? 0); });
  r.on("error", reject); r.end();
});
assert.equal(await getWithHost(`localhost:${port}`), 200, "localhost is an accepted loopback name");
assert.equal(await getWithHost("evil.example"), 403, "a foreign Host is refused (DNS rebinding)");
assert.equal(await getWithHost(`localhost:${port + 1}`), 403, "the wrong port is refused");
await assert.rejects(serveAtlas(0, "0.0.0.0"), /Refusing to bind/, "a non-loopback bind needs --allow-remote");
try {
  const response = await fetch(base);
  assert.equal(response.status, 200);
  const html = await response.text();
  const config = JSON.parse(html.match(/id="atlas-upload-config">([^<]+)<\/script>/)![1]);
  assert.equal(typeof config.token, "string");
  assert.ok(!html.includes("/*__ATLAS_RENDERER__*/"));
  const post = (body: unknown, origin = base, token = config.token) => fetch(`${base}/api/build`, {
    method: "POST", headers: { Origin: origin, "X-Atlas-Token": token, "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  assert.equal((await post({ name: "fixture", files }, "http://example.com")).status, 403);
  assert.equal((await post({ name: "fixture", files }, base, "wrong")).status, 403);
  assert.equal((await post({ name: "fixture", files: [{ path: "../leak.ts", code: "x" }] })).status, 400);
  const built = await post({ name: "My project", files });
  assert.equal(built.status, 200);
  const bundle = parseBundle(await built.json());
  assert.equal(bundle.repository.label, "My project");
  for (const file of files) assert.ok(bundle.graph.nodes.some(n => n.evidence.path === file.path), file.path);
  assert.equal(bundle.sources?.length, 3);
  // The server remains usable after invalid input and can replace a project.
  const second = await post({ name: "Second", files: [files[0]] });
  const next = parseBundle(await second.json());
  assert.equal(next.repository.label, "Second");
  assert.equal(next.sources?.length, 1);
  console.log("folder-upload.test: local HTTP ingestion, mixed-language graph, project replacement, and invalid request rejection passed");
} finally {
  server.closeAllConnections();
  await new Promise<void>(resolve => server.close(() => resolve()));
}
