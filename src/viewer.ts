import { readFileSync } from "node:fs";
import type { AtlasBundle } from "./schema.js";

/** Embed data as inert JSON; source never becomes executable script. */
export function renderViewer(bundle: AtlasBundle | null, uploadToken: string | null = null): string {
  let html = readFileSync(new URL("../viewer/viewer.html", import.meta.url), "utf8");
  const renderer = readFileSync(new URL("../viewer/vendor/3d-force-graph.min.js", import.meta.url), "utf8")
    .replace(/<\/script/gi, "<\\/script");
  const json = (value: unknown) => JSON.stringify(value).replace(/</g, "\\u003c");
  html = html.replace("/*__ATLAS_RENDERER__*/", () => renderer);
  html = html.replace("/*__ATLAS_BUNDLE_JSON__*/", () => json(bundle));
  return html.replace("/*__ATLAS_UPLOAD_CONFIG__*/", () => json({ token: uploadToken }));
}
