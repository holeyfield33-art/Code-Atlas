/**
 * HTTP routes found in code, and the read-only join with SurfaceTrace's observed endpoints.
 *  - Express / Fastify / router.route chains are read; outbound clients, test clients and plain lookups are not;
 *  - a handler written as a name links to its function node; an inline handler links to the function that registers it;
 *  - a path template collapses params, and matching is by shape with an explicit "prefix assumed" marker;
 *  - correlate pairs routes with observed endpoints, ranks untested routes that carry leads first, and flags a host
 *    that pairs with nothing; it never changes a finding or a grade.
 */
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { buildAtlas } from "../src/build.js";
import { parseBundle } from "../src/schema.js";
import { routeTemplate, routeMatches } from "../src/scanner/routes.js";
import { correlate, formatMarkdown } from "../src/correlate.js";
import { AtlasTools } from "../src/mcp/tools.js";

// ---- template + matching
assert.equal(routeTemplate("/projects/:projectId/open"), "/projects/{param}/open");
assert.equal(routeTemplate("/files/*"), "/files/{param}");
assert.equal(routeTemplate("/"), "/");
assert.equal(routeMatches("/projects/{param}/open", "/projects/{id}/open"), "exact", "an observed {id} placeholder matches a code param");
assert.equal(routeMatches("/projects/{param}/open", "/api/projects/{id}/open"), "prefixed", "extra leading segments are a possible mount prefix");
assert.equal(routeMatches("/projects/{param}/open", "/api/projects/{id}/close"), null);
assert.equal(routeMatches("/", "/anything/at/all"), null, "the root route does not match every path");
assert.equal(routeMatches("/{param}", "/a/b"), null, "a route with no literal segment does not match by prefix");

// ---- extraction
const root = mkdtempSync(join(tmpdir(), "atlas-routes-"));
const put = (rel: string, body: string) => { const p = join(root, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, body); };
put("src/server.js", `
const express = require("express");
const app = express();
const router = express.Router();
function listUsers(req, res) { res.json([]); }
const getUser = (req, res) => res.json({});
app.get("/users", listUsers);
router.get("/users/:id", authenticate, getUser);
app.post("/users", async (req, res) => { res.json({ ok: true }); });
app.delete(\`/users/\${id}\`, (req, res) => res.end());
router.route("/items/:itemId").get(listUsers).put((req, res) => res.end());
app.route({ method: ["GET", "POST"], url: "/fast/:id", handler: listUsers });
app.use("/api", router);
function bootstrap() { app.get("/health", (req, res) => res.send("ok")); }
// not routes:
axios.get("/api/other", config);
cache.get("/key");
const v = map.get("/x");
request(app).get("/users").expect(200);
fetch("/users");
app.get("/only-a-path");
app.get(variablePath, handler);
`);
put("src/server.test.js", `app.get("/test-only", (req, res) => res.end());`);
put("test/helper.js", `app.get("/in-test-dir", (req, res) => res.end());`);
const { bundle } = await buildAtlas(root, { repoLabel: "routes-demo" });
const routes = bundle.routes ?? [];
const sig = routes.map((r) => `${r.method} ${r.path}`).sort();
assert.deepEqual(sig, [
  "GET /fast/:id", "POST /fast/:id", "DELETE /users/:id", "GET /health", "GET /items/:itemId", "GET /users", "GET /users/:id", "POST /users", "PUT /items/:itemId",
].sort(), "exactly the real registrations: no clients, test clients, lookups, or test files");

const byKey = (m: string, p: string) => routes.find((r) => r.method === m && r.path === p)!;
const nodeLabel = (id?: string) => bundle.graph.nodes.find((n) => n.id === id)?.label;
assert.equal(byKey("GET", "/users").handler, "listUsers");
assert.equal(nodeLabel(byKey("GET", "/users").nodeRef), "listUsers", "a named handler links to its function node");
assert.equal(nodeLabel(byKey("GET", "/users/:id").nodeRef), "getUser", "the handler is the last argument, not the middleware");
assert.ok(byKey("POST", "/users").inline, "an inline handler is marked inline");
assert.equal(nodeLabel(byKey("GET", "/health").nodeRef), "bootstrap", "an inline handler links to the function that registers it");
assert.equal(byKey("GET", "/users/:id").template, "/users/{param}");
assert.ok(byKey("GET", "/users").note?.includes("prefix"), "a file that mounts a prefix says the prefix is not applied");
parseBundle(JSON.parse(JSON.stringify(bundle)));                            // the schema accepts routes
assert.ok(parseBundle({ ...JSON.parse(JSON.stringify(bundle)), routes: undefined }), "bundles without routes still load");

// ---- MCP tool
const tools = new AtlasTools(bundle);
const listed = tools.routes({ method: "get", path: "/users" }) as any;
assert.equal(listed.total, 2, "filter by method and path");
assert.ok(listed.note.includes("not evidence"));

// ---- correlate
const campaign = {
  endpoints: [
    { method: "GET", host: "app.test", pathTemplate: "/users", statusCodes: [200], requiresAuth: true, observationCount: 3 },
    { method: "GET", host: "app.test", pathTemplate: "/api/users/{id}", statusCodes: [200, 404], requiresAuth: true, observationCount: 2 },
    { method: "GET", host: "app.test", pathTemplate: "/static/app.js", statusCodes: [200], requiresAuth: false, observationCount: 9 },
    { method: "POST", host: "tracker.example", pathTemplate: "/collect", statusCodes: [204], requiresAuth: null, observationCount: 5 },
  ],
};
const res = correlate(bundle, campaign);
assert.equal(res.counts.routes, 9);
const row = (m: string, p: string) => res.worklist.find((w) => w.method === m && w.path === p)!;
assert.equal(row("GET", "/users").observed[0].match, "exact");
assert.equal(row("GET", "/users/:id").observed[0].match, "prefixed", "paired through an assumed /api prefix, and said so");
assert.equal(row("POST", "/users").observed.length, 0, "a different method does not pair");
assert.equal(res.observedWithoutCode.length, 2, "/static/app.js and the tracker have no code route");
assert.deepEqual(res.hosts.map((h) => [h.host, h.paired]).sort(), [["app.test", 2], ["tracker.example", 0]], "a host that pairs with nothing is visible");
assert.equal(correlate(bundle, campaign, { host: "app.test" }).counts.observedEndpoints, 3, "host filter");
const md = formatMarkdown(res);
assert.ok(md.includes("prefix assumed") && md.includes("Read this first"), "the report states its own limits");
assert.ok(!JSON.stringify(res).includes("OBSERVED"), "correlation never creates an OBSERVED grade");

console.log(`routes.test: ${routes.length} routes read (clients, test clients, lookups and test files ignored); correlate pairs by shape and flags an unrelated host`);
