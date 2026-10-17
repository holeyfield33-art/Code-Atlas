# Using Code Atlas with SurfaceTrace

Code Atlas reads code; SurfaceTrace works with live traffic. This page is the bridge between them. **Both
directions are read-only.** Nothing here sends a request to a target, replays traffic, or changes SurfaceTrace;
testing stays in SurfaceTrace behind its scope, preview and approval gates.

```
code ──scan──▶ Code Atlas bundle ──┐
                                   ├──▶ worklist  ──▶  you choose one route ──▶ SurfaceTrace experiment
HAR ──import──▶ SurfaceTrace ──────┘   (code routes × observed endpoints × leads)
```

## 1. Find the routes in code

`code-atlas build` now records the HTTP routes registered in JS/TS code (Express, Fastify, Koa-router and
similar): method, path template, and the function that handles it, with the file and line. Look at them:

- MCP / sandbox: `atlas.routes({ method: "POST", path: "/users", file: "api/" })`
- Each route carries the static leads on its handler, so "which routes touch a risky pattern" is one call.

What it reads: `app.get("/x", handler)`, `router.post(...)`, `router.route("/x").get(h).post(h2)`, Fastify
`app.route({ method, url, handler })`. What it does **not** do: apply a mount prefix (`app.use("/api", router)`,
`register(..., { prefix })`; the route says so in its note), see paths built at run time, or read routes in Ruby /
Python / generated code. Outbound clients (`axios.get`, `fetch`), test clients (`request(app).get`) and lookups
(`map.get("/x")`) are not routes. A route in code is not evidence that the endpoint is reachable.

## 2. Pair them with what SurfaceTrace has seen

```powershell
.\scripts\atlas.ps1 build C:\path\to\app -Project myapp          # the map (routes included)
.\scripts\atlas-surface.ps1 -Project myapp                       # reads http://127.0.0.1:5173/api/campaign/index
# -> atlas\myapp\worklist.md
```

Without Docker: `code-atlas correlate atlas\myapp --campaign campaign-index.json -o worklist.md`.
The campaign source is either a saved copy of SurfaceTrace's `/api/campaign/index` or its loopback URL; any
other host is refused.

The worklist lists every code route with: its handler and file:line, the observed endpoints that pair with
it (count, statuses, whether auth was seen), and its static leads. Untested routes that carry a weakness lead
come first. It also lists observed endpoints with no code route, and, per observed host, how many paired. A host
with nothing paired is probably a different application than the code you scanned.

## How far to trust a pairing

- Pairs are by method and **path shape**. Observed `{id}` placeholders match a code parameter.
- If the observed path has extra leading segments, the pairing is marked "prefix assumed". A route whose path has
  no literal segment of its own (`/`, `/:id`) is never paired by prefix.
- A route with no traffic is not necessarily untested: the capture may be partial.
- Leads stay static. A pairing never changes a finding or its grade; only a documented SurfaceTrace experiment
  can do that, and that happens in SurfaceTrace.

## Next

Routes for Ruby (Rails / Grape) are not read yet; that is what GitLab needs and is the next step. A node-level
link from a SurfaceTrace observation back to a Code Atlas node (so an experiment can cite the handler) needs a
small addition on the SurfaceTrace side and has not been agreed.
