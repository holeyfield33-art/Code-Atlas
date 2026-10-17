/**
 * HTTP routes registered in JS/TS code (Express / Fastify / Koa-router / Hono style), read as DATA.
 *
 * A route is a lead that connects the code map to live traffic: method + path template + the function
 * that handles it. It is a STATIC reading: a mount prefix (`app.use("/api", router)`, `register(..., { prefix })`)
 * is not applied, a path built at run time is not seen, and a route registered through a framework this
 * does not recognise is missing. A route is never evidence that an endpoint is reachable.
 *
 * Outbound HTTP clients (`axios.get("/x")`, `fetch`) are not routes: a route registration passes a
 * HANDLER (a function or a name) last, a client call passes data; known client receivers are skipped too.
 */
import { createHash } from "node:crypto";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import type { AtlasGraph, Evidence, Route } from "../schema.js";
import type { SourceFile } from "./graph.js";
import { classMemberLabel } from "./jsNames.js";

const traverse: any = (typeof _traverse === "function" ? _traverse : (_traverse as any).default);
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

const METHODS = new Set(["get", "post", "put", "patch", "delete", "head", "options", "all"]);
// receivers that issue requests or look things up, not register routes
const NOT_ROUTERS = new Set([
  "axios", "http", "https", "got", "ky", "request", "superagent", "client", "fetch", "$http", "cache", "map", "headers",
  "params", "searchparams", "storage", "localstorage", "sessionstorage", "supertest", "agent", "rest", "session", "cookies",
  "formdata", "urlsearchparams", "env", "config", "settings", "store", "registry", "reflect", "weakmap", "memo",
]);
const TEST_PATH = /(^|\/)(tests?|__tests__|specs?|e2e|fixtures?|__mocks__)\/|\.(test|spec)\.[cm]?[jt]sx?$/i;
const PREFIX_HINT = /prefix\s*:|\.use\(\s*['"`]\//;

/** "/projects/:projectId/open" -> "/projects/{param}/open"; static segments are kept as written. */
export function routeTemplate(path: string): string {
  const segs = path.split("/").filter((s) => s.length > 0).map((s) =>
    /^:[A-Za-z0-9_$]+/.test(s) || /^\{[^}]*\}$/.test(s) || s === "*" || /^\(.*\)$/.test(s) || /^\*/.test(s) ? "{param}" : s);
  return "/" + segs.join("/");
}

/** Does a code route match a concrete or templated observed path? A {param} segment matches any one segment;
 *  SurfaceTrace-style placeholders ({id}, {uuid}, {hex}) match a {param} segment. */
export function routeMatches(codeTemplate: string, observedPath: string): "exact" | "prefixed" | null {
  const a = codeTemplate.split("/").filter(Boolean), b = observedPath.split("?")[0].split("/").filter(Boolean);
  if (b.length < a.length) return null;
  const tail = b.slice(b.length - a.length);
  if (!a.every((seg, i) => seg === "{param}" || seg === tail[i])) return null;
  if (b.length === a.length) return "exact";
  // Extra leading segments could be a mount prefix we cannot see. Only assume that when the route has a literal
  // segment of its own: "/" or "/{param}" would otherwise "match" nearly every path of every host.
  return a.some((seg) => seg !== "{param}") ? "prefixed" : null;
}

function literalPath(node: any): string | null {
  if (!node) return null;
  if (node.type === "StringLiteral") return node.value;
  if (node.type === "TemplateLiteral") {
    // `/items/${id}` -> /items/:id ; anything that is not a simple identifier makes the path unknown
    let out = "";
    for (let i = 0; i < node.quasis.length; i++) {
      out += node.quasis[i].value.cooked ?? "";
      const e = node.expressions[i];
      if (e) { if (e.type !== "Identifier") return null; out += ":" + e.name; }
    }
    return out;
  }
  return null;
}

const isHandler = (n: any) => !!n && (n.type === "ArrowFunctionExpression" || n.type === "FunctionExpression" || n.type === "Identifier" || n.type === "MemberExpression" || n.type === "CallExpression");
const receiverName = (n: any): string | null => n?.type === "Identifier" ? n.name : (n?.type === "MemberExpression" && !n.computed && n.property?.type === "Identifier" ? n.property.name : null);

export function extractRoutes(revision: string, sources: SourceFile[], graph: AtlasGraph): Route[] {
  const out: Route[] = [];
  const nodeByLabel = new Map<string, string>();                          // path::label -> function node id
  const fileNode = new Map<string, string>();
  for (const n of graph.nodes) {
    if (n.kind === "file") fileNode.set(n.evidence.path, n.id);
    else if (!nodeByLabel.has(n.evidence.path + "::" + n.label)) nodeByLabel.set(n.evidence.path + "::" + n.label, n.id);
  }
  const ev = (path: string, line: number, column: number, code: string): Evidence =>
    ({ path, line, column, revision, contentHash: "sha256:" + sha(code), method: "babel-static", status: "static" });

  for (const f of sources) {
    if (TEST_PATH.test(f.path)) continue;
    // cheap pre-filter: a route registration needs a quoted path and a method name
    if (!/\.(get|post|put|patch|delete|head|options|all|route)\b/.test(f.code) || !/['"`]\//.test(f.code)) continue;
    let ast;
    try { ast = parse(f.code, { sourceType: "unambiguous", plugins: ["typescript", "jsx", "decorators-legacy"], ranges: true }); }
    catch { continue; }
    const hashSrc = f.hashCode ?? f.code;
    const prefixNote = PREFIX_HINT.test(f.code) ? "a mount prefix (use / register) in this file is not applied to the path" : undefined;

    const enclosing = (p: any): string | undefined => {
      const fp = p.getFunctionParent?.();
      if (fp?.node) {
        const m = classMemberLabel(fp);
        const label = m ?? fp.node.id?.name ?? (fp.parentPath?.node?.id?.type === "Identifier" ? fp.parentPath.node.id.name : undefined);
        if (label) { const id = nodeByLabel.get(f.path + "::" + label); if (id) return id; }
      }
      return fileNode.get(f.path);
    };
    const push = (method: string, path: string, p: any, handlerNode: any) => {
      let handler: string | undefined; let nodeRef: string | undefined; let inline = false;
      if (handlerNode?.type === "Identifier") { handler = handlerNode.name; nodeRef = nodeByLabel.get(f.path + "::" + handler); }
      else if (handlerNode?.type === "MemberExpression" && !handlerNode.computed && handlerNode.property?.type === "Identifier") handler = handlerNode.property.name;
      else if (handlerNode?.type === "ArrowFunctionExpression" || handlerNode?.type === "FunctionExpression") inline = true;
      nodeRef = nodeRef ?? enclosing(p);                                  // inline / unresolved: the function that registers it
      const loc = p.node.loc?.start ?? { line: 1, column: 0 };
      out.push({
        method, path, template: routeTemplate(path), nodeRef, handler, inline: inline || undefined,
        evidence: ev(f.path, loc.line, loc.column + 1, hashSrc), framework: "express-like",
        note: prefixNote,
      });
    };

    traverse(ast, {
      CallExpression(p: any) {
        const c = p.node.callee;
        if (c?.type !== "MemberExpression" || c.computed || c.property?.type !== "Identifier") return;
        const name = c.property.name;
        const recv = c.object;

        // app.route({ method, url, handler })  (Fastify)
        if (name === "route" && p.node.arguments.length === 1 && p.node.arguments[0].type === "ObjectExpression" && receiverName(recv)) {
          const props = new Map<string, any>();
          for (const pr of p.node.arguments[0].properties) if (pr.type === "ObjectProperty" && pr.key?.type === "Identifier") props.set(pr.key.name, pr.value);
          const path = literalPath(props.get("url") ?? props.get("path"));
          const m = props.get("method");
          const methods = m?.type === "StringLiteral" ? [m.value] : m?.type === "ArrayExpression" ? m.elements.filter((e: any) => e?.type === "StringLiteral").map((e: any) => e.value) : [];
          if (path && path.startsWith("/") && methods.length) for (const mm of methods) push(String(mm).toUpperCase(), path, p, props.get("handler"));
          return;
        }
        if (!METHODS.has(name)) return;
        const method = name === "all" ? "ANY" : name.toUpperCase();

        // router.route("/x").get(handler).post(handler): walk back through the chained method calls to the .route(path)
        let base = recv;
        while (base?.type === "CallExpression" && base.callee?.type === "MemberExpression" && !base.callee.computed && METHODS.has(base.callee.property?.name)) base = base.callee.object;
        if (base?.type === "CallExpression" && base.callee?.type === "MemberExpression" && base.callee.property?.name === "route" && receiverName(base.callee.object)) {
          const path = literalPath(base.arguments[0]);
          const last = p.node.arguments[p.node.arguments.length - 1];
          if (path && path.startsWith("/") && isHandler(last)) push(method, path, p, last);
          return;
        }
        // a call on a call result (request(app).get(...)) is a test client, not a router
        const rn = receiverName(recv);
        if (!rn || NOT_ROUTERS.has(rn.toLowerCase())) return;
        const args = p.node.arguments;
        const path = literalPath(args[0]);
        if (!path || !path.startsWith("/")) return;
        // the handler is last: a function or a name. (get("/x") or get("/x", { options }) is a data lookup / client call)
        // Fastify: app.get("/x", { schema }, handler) still ends in a handler.
        const last = args[args.length - 1];
        if (args.length < 2 || !isHandler(last)) return;
        push(method, path, p, last);
      },
    });
  }
  // stable order, de-duplicated (the same registration seen twice, e.g. a re-parsed file)
  const seen = new Set<string>();
  return out.filter((r) => { const k = r.method + " " + r.path + " " + r.evidence.path + ":" + r.evidence.line; if (seen.has(k)) return false; seen.add(k); return true; })
    .sort((a, b) => a.template.localeCompare(b.template) || a.method.localeCompare(b.method));
}
