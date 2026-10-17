/**
 * Read-only join of two maps of the same application:
 *   - Code Atlas: the routes registered in code, with the security leads on their handlers;
 *   - SurfaceTrace: the endpoints actually observed in captured traffic (GET /api/campaign/index).
 * The result is a worklist for a human tester: which code routes have no observed traffic yet, which
 * observed endpoints have no matching code, and which routes carry static leads.
 *
 * Nothing is sent anywhere and nothing is executed. A match is by method and path SHAPE, so it is a
 * candidate pairing, not proof the two are the same handler (a mount prefix, a proxy or a second
 * service can make unrelated routes look alike). It never changes a finding or a grade.
 */
import type { AtlasBundle, Route } from "./schema.js";
import { routeMatches } from "./scanner/routes.js";

export interface ObservedEndpoint {
  method: string; host?: string; pathTemplate: string;
  statusCodes?: number[]; requiresAuth?: boolean | null; observationCount?: number;
}
export interface CorrelateOptions { host?: string }

export interface RouteRow {
  method: string; path: string; template: string;
  file: string; line: number; handler?: string; inline?: boolean;
  leads: { title: string; kind: string; grade: string; node: string }[];
  observed: { method: string; host?: string; path: string; match: "exact" | "prefixed"; statuses: number[]; requiresAuth: boolean | null; count: number }[];
  note?: string;
}
export interface CorrelateResult {
  repository: string;
  counts: { routes: number; observedEndpoints: number; routesWithTraffic: number; routesWithoutTraffic: number; observedWithoutCode: number; routesWithWeaknessLeads: number };
  /** untested first: routes with a static weakness lead and no traffic, then other routes with leads, then the rest */
  worklist: RouteRow[];
  observedWithoutCode: ObservedEndpoint[];
  /** observed hosts and how many of their endpoints paired with a code route: all zeros means this is a different application */
  hosts: { host: string; endpoints: number; paired: number }[];
  caveats: string[];
}

export function correlate(bundle: AtlasBundle, campaign: { endpoints?: ObservedEndpoint[] }, opts: CorrelateOptions = {}): CorrelateResult {
  const routes: Route[] = bundle.routes ?? [];
  const endpoints = (campaign.endpoints ?? []).filter((e) => !opts.host || e.host === opts.host);
  const nodeById = new Map(bundle.graph.nodes.map((n) => [n.id, n]));
  const byNode = new Map<string, NonNullable<AtlasBundle["findings"]>>();
  for (const f of bundle.findings ?? []) {
    if (f.disposition?.status === "false_positive") continue;
    for (const r of f.nodeRefs) (byNode.get(r) ?? byNode.set(r, []).get(r)!).push(f);
  }

  const matchedEndpoints = new Set<ObservedEndpoint>();
  const rows: RouteRow[] = routes.map((r) => {
    const observed: RouteRow["observed"] = [];
    for (const e of endpoints) {
      if (r.method !== "ANY" && e.method.toUpperCase() !== r.method) continue;
      const m = routeMatches(r.template, e.pathTemplate);
      if (!m) continue;
      matchedEndpoints.add(e);
      observed.push({ method: e.method, host: e.host, path: e.pathTemplate, match: m, statuses: e.statusCodes ?? [], requiresAuth: e.requiresAuth ?? null, count: e.observationCount ?? 0 });
    }
    const leads = (r.nodeRef ? byNode.get(r.nodeRef) ?? [] : []).map((f) => ({
      title: f.title, kind: f.kind, grade: f.grade, node: nodeById.get(f.nodeRefs[0])?.label ?? f.nodeRefs[0],
    }));
    return { method: r.method, path: r.path, template: r.template, file: r.evidence.path, line: r.evidence.line, handler: r.handler, inline: r.inline, leads, observed, note: r.note };
  });

  const weak = (r: RouteRow) => r.leads.some((l) => l.kind === "weakness");
  const rank = (r: RouteRow) => (weak(r) && !r.observed.length ? 0 : weak(r) ? 1 : !r.observed.length ? 2 : 3);
  rows.sort((a, b) => rank(a) - rank(b) || a.template.localeCompare(b.template) || a.method.localeCompare(b.method));

  const caveats = [
    "Pairs are by method and path shape only: a candidate match, not proof of the same handler.",
    "Mount prefixes (app.use / register) are not applied to code routes; a 'prefixed' match assumes extra leading segments are a prefix.",
    "Only JS/TS routes are read so far; routes in Ruby, Python or generated code are not in this list.",
    "A route with no observed traffic is not necessarily untested: the capture may be partial.",
    "Leads are static pattern matches (never verified); they do not mean the endpoint is vulnerable.",
  ];
  const hostMap = new Map<string, { host: string; endpoints: number; paired: number }>();
  for (const e of endpoints) {
    const h = hostMap.get(e.host ?? "?") ?? { host: e.host ?? "?", endpoints: 0, paired: 0 };
    h.endpoints++; if (matchedEndpoints.has(e)) h.paired++; hostMap.set(h.host, h);
  }
  return {
    repository: bundle.repository.label,
    counts: {
      routes: rows.length, observedEndpoints: endpoints.length,
      routesWithTraffic: rows.filter((r) => r.observed.length).length, routesWithoutTraffic: rows.filter((r) => !r.observed.length).length,
      observedWithoutCode: endpoints.filter((e) => !matchedEndpoints.has(e)).length,
      routesWithWeaknessLeads: rows.filter(weak).length,
    },
    worklist: rows,
    observedWithoutCode: endpoints.filter((e) => !matchedEndpoints.has(e)),
    hosts: [...hostMap.values()].sort((x, y) => y.paired - x.paired || y.endpoints - x.endpoints),
    caveats,
  };
}

export function formatMarkdown(r: CorrelateResult): string {
  const c = r.counts;
  const out: string[] = [
    `# Code and traffic worklist: ${r.repository}`, "",
    `${c.routes} code routes; ${c.observedEndpoints} observed endpoints. ${c.routesWithTraffic} routes have matching traffic, ${c.routesWithoutTraffic} do not; ${c.observedWithoutCode} observed endpoints have no matching code route; ${c.routesWithWeaknessLeads} routes carry a static weakness lead.`, "",
    "## Routes (untested with leads first)", "",
    "| Route | Handler | Traffic | Leads |", "|---|---|---|---|",
  ];
  for (const w of r.worklist) {
    const traffic = w.observed.length
      ? w.observed.map((o) => `${o.method} ${o.path}${o.match === "prefixed" ? " (prefix assumed)" : ""} · ${o.count}× · ${o.statuses.join("/") || "?"} · ${o.requiresAuth === null ? "auth ?" : o.requiresAuth ? "auth" : "no auth seen"}`).join("<br>")
      : "none observed";
    const leads = w.leads.length ? w.leads.map((l) => `${l.kind === "weakness" ? "⚠" : "✓"} ${l.title} (${l.grade})`).join("<br>") : "";
    out.push(`| \`${w.method} ${w.template}\` | ${w.handler ?? (w.inline ? "inline" : "?")} · \`${w.file}:${w.line}\` | ${traffic} | ${leads} |`);
  }
  const top = r.hosts.slice(0, 8);
  if (top.length) {
    out.push("", "## Observed hosts", "", "A host with nothing paired is probably a different application than this code.", "", "| Host | Endpoints | Paired with a code route |", "|---|---|---|");
    for (const h of top) out.push(`| ${h.host} | ${h.endpoints} | ${h.paired} |`);
    if (r.hosts.length > top.length) out.push(`| … ${r.hosts.length - top.length} more hosts | | |`);
  }
  if (r.observedWithoutCode.length) {
    out.push("", "## Observed endpoints with no matching code route", "");
    for (const e of r.observedWithoutCode.slice(0, 100)) out.push(`- \`${e.method} ${e.pathTemplate}\`${e.host ? ` (${e.host})` : ""}: third-party or other service, a prefix mismatch, or code not scanned`);
  }
  out.push("", "## Read this first", "", ...r.caveats.map((c) => `- ${c}`), "");
  return out.join("\n");
}
