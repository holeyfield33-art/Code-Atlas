import { createServer, type IncomingMessage } from "node:http";
import { randomBytes } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { buildAtlas } from "./build.js";
import { fileLanguage, IGNORE_DIRS } from "./scanner/treeScanner.js";
import { renderViewer } from "./viewer.js";
import { parseBundle, type AtlasBundle } from "./schema.js";

/** The bundle the page should open on: the file at `path`, re-read on every page load so a
 *  rebuild shows up without restarting. Missing or invalid => null (the built-in sample), and
 *  the reason is logged once so a mis-mounted volume is not silent. */
let lastBundleWarning = "";
export function loadBundleForPage(path: string | undefined): AtlasBundle | null {
  if (!path) return null;
  try { return parseBundle(JSON.parse(readFileSync(path, "utf8"))); }
  catch (e) {
    const msg = (e as NodeJS.ErrnoException).code === "ENOENT" ? `no bundle at ${path}; showing the sample graph` : `could not use ${path} (${e instanceof Error ? e.message.slice(0, 120) : e}); showing the sample graph`;
    if (msg !== lastBundleWarning) { lastBundleWarning = msg; console.warn("Code Atlas:", msg); }
    return null;
  }
}

const MAX_BODY = 32 * 1024 * 1024;
export interface UploadedFile { path: string; code: string; }

/** Reject traversal, Windows aliases, and non-source files before touching disk. */
export function validateUpload(input: unknown): { name: string; files: UploadedFile[] } {
  const data = input as any;
  if (!data || typeof data.name !== "string" || !data.name.trim() || data.name.length > 255 || /[\x00-\x1f]/.test(data.name))
    throw new Error("Invalid project folder name.");
  if (!Array.isArray(data.files) || !data.files.length || data.files.length > 2000)
    throw new Error("Select between 1 and 2,000 supported source files.");
  const seen = new Set<string>();
  for (const file of data.files) {
    if (typeof file?.path !== "string" || typeof file?.code !== "string") throw new Error("Invalid source file.");
    const parts = file.path.split("/");
    if (parts.some((p: string) => !p || p === "." || p === ".." || /[\\:\x00-\x1f<>"|?*]/.test(p) || /[. ]$/.test(p)
      || /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(p) || IGNORE_DIRS.has(p)))
      throw new Error("Unsupported source path: " + file.path);
    if (!fileLanguage(file.path) || Buffer.byteLength(file.code, "utf8") > 200_000)
      throw new Error("Unsupported extension or oversized source file: " + file.path);
    const key = file.path.toLowerCase();
    if (seen.has(key)) throw new Error("Duplicate source path: " + file.path);
    seen.add(key);
  }
  return data;
}

export async function buildUploadedFolder(input: unknown) {
  const { name, files } = validateUpload(input);
  const temp = mkdtempSync(join(tmpdir(), "code-atlas-upload-"));
  try {
    // Use a fixed safe directory; the display label is metadata only.
    const root = join(temp, "project");
    for (const file of files) {
      const target = join(root, ...file.path.split("/"));
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, file.code, "utf8");
    }
    const { bundle } = await buildAtlas(root, { repoLabel: name });
    return bundle;
  } finally { rmSync(temp, { recursive: true, force: true }); }
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new Error("Folder upload exceeds 32 MiB. Select a smaller source folder.");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

export interface AtlasServerOptions {
  /** A built bundle to open the page on (instead of the sample). Re-read on each page load. */
  bundlePath?: string;
}

export function createAtlasServer(options: AtlasServerOptions = {}) {
  const token = randomBytes(32).toString("hex");
  let busy = false;
  return createServer(async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    // The page is only valid under the loopback names a browser on THIS machine uses
    // (127.0.0.1 or localhost, on the port we serve). Any other Host is refused, which
    // defeats DNS rebinding; Origin below must then match the Host the browser used.
    const port = req.socket.localPort;
    const host = req.headers.host ?? "";
    if (host !== `127.0.0.1:${port}` && host !== `localhost:${port}`) { res.writeHead(403).end(); return; }
    if (req.method === "GET" && req.url === "/") {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.end(renderViewer(loadBundleForPage(options.bundlePath), token)); return;
    }
    if (req.method !== "POST" || req.url !== "/api/build") { res.writeHead(404).end(); return; }
    if (req.headers.origin !== `http://${host}` || req.headers["x-atlas-token"] !== token) {
      res.writeHead(403).end(); return;
    }
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    if (busy) { res.writeHead(409).end(JSON.stringify({ error: "Another folder is being analyzed. Try again when it finishes." })); return; }
    busy = true;
    try {
      const bundle = await buildUploadedFolder(await readJson(req));
      res.end(JSON.stringify(bundle));
    } catch (error) {
      res.writeHead(400).end(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }));
    } finally { busy = false; }
  });
}

const LOOPBACK = new Set(["127.0.0.1", "localhost", "::1"]);

/** `host` defaults to loopback. Binding anything else (e.g. 0.0.0.0 inside a container
 *  whose published port is itself loopback-only) must be asked for with allowRemote. */
export async function serveAtlas(port = 4173, host = "127.0.0.1", allowRemote = false, bundlePath?: string) {
  if (!LOOPBACK.has(host.toLowerCase()) && !allowRemote)
    throw new Error(`Refusing to bind ${host}: this app analyzes local source and has no login. Pass --allow-remote only when something else (e.g. a loopback-only published container port) keeps it private.`);
  const server = createAtlasServer({ bundlePath });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, resolve);
  });
  console.log(`Code Atlas ready: http://127.0.0.1:${(server.address() as any).port}`);
  console.log(bundlePath ? `Opening on the bundle at ${bundlePath} (rebuild it and refresh to update). Choose Open folder to analyze another project. Press Ctrl+C to stop.`
                         : "Open this URL and choose Open folder. Press Ctrl+C to stop.");
  return server;
}
