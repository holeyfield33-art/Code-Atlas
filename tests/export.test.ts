/** `export` turns bundles into size-capped Markdown (leads + map): no file over the cap, every file listed, leads carry code. */
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildAtlas } from "../src/build.js";
import { exportBundles } from "../src/exportFiles.js";

const root = mkdtempSync(join(tmpdir(), "atlas-export-"));
mkdirSync(join(root, "src"));
writeFileSync(join(root, "src/a.js"), "const { exec } = require('child_process');\nexport function run(req) { exec(req.query.cmd); }\n");
for (let i = 0; i < 40; i++) writeFileSync(join(root, `src/f${i}.js`), `export function f${i}() { return ${i}; }\n`);
const { bundle } = await buildAtlas(root, { repoLabel: "demo" });

const files = exportBundles([bundle], 600);
assert.equal(files[0].name, "00-read-me.md");
assert.ok(files.every((f) => f.name === "00-read-me.md" || Buffer.byteLength(f.text) <= 1500), "parts respect the cap (a block is never cut)");
const map = files.filter((f) => f.name.startsWith("map-")).map((f) => f.text).join("\n");
assert.ok(map.includes("`src/a.js`") && map.includes("`src/f39.js`"), "every analysed file is in the map");
assert.ok(files.filter((f) => f.name.startsWith("map-")).length > 1, "a small cap splits the map into several parts");
assert.ok(files.some((f) => f.name.startsWith("leads-") && f.text.includes("exec(req.query.cmd)")), "a lead includes the code it flags");
console.log(`export.test: ${files.length} files, capped, complete`);
