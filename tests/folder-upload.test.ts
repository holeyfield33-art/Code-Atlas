import assert from "node:assert/strict";
import { once } from "node:events";
import { createAtlasServer, validateUpload } from "../src/server.js";
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

const server = createAtlasServer();
server.listen(0, "127.0.0.1");
await once(server, "listening");
const base = `http://127.0.0.1:${(server.address() as any).port}`;
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
