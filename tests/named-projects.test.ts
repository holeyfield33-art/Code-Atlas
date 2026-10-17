/**
 * Several codebases, one image: each named project has its own bundle folder, port and MCP
 * server. Guards the pieces that make that work and the bug that made two servers
 * indistinguishable (every container build named its project "src", the mount name):
 *  - `build --label` names the project in the bundle (default stays the folder name);
 *  - every compose mount of the bundle folder goes through ATLAS_DATA_DIR, so a named
 *    project cannot silently read or write the default instance's ./atlas;
 *  - the entrypoint forwards ATLAS_LABEL to the build, and both wrappers know -Project.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p: string) => readFileSync(join(repo, p), "utf8").replace(/\r\n/g, "\n");

// ---- build --label
const work = mkdtempSync(join(tmpdir(), "atlas-label-"));
const src = join(work, "myapp"); mkdirSync(src);
writeFileSync(join(src, "a.ts"), "export function a() { return 1; }\n");
const run = (extra: string[], out: string) => {
  const r = spawnSync(process.execPath, [join(repo, "node_modules/tsx/dist/cli.mjs"), join(repo, "src/cli.ts"), "build", src, "--out", join(work, out), ...extra],
    { encoding: "utf8", timeout: 120000 });
  assert.equal(r.status, 0, "build exits 0: " + r.stderr);
  return JSON.parse(readFileSync(join(work, out, "atlas.bundle.json"), "utf8")).repository.label as string;
};
assert.equal(run([], "o1"), "myapp", "default label is the folder name");
assert.equal(run(["--label", "other-project"], "o2"), "other-project", "--label names the project");

// ---- compose: the bundle folder is always ATLAS_DATA_DIR-driven
const compose = read("docker-compose.yml");
const mounts = compose.split("\n").filter((l) => /:\/data(:ro)?"?\s*$/.test(l.trim()));
assert.equal(mounts.length, 3, "app, mcp and build each mount the bundle folder");
for (const m of mounts) assert.ok(m.includes("${ATLAS_DATA_DIR:-./atlas}"), "mount honours ATLAS_DATA_DIR: " + m.trim());
assert.ok(!/^\s*- \.\/atlas:\/data/m.test(compose), "no mount hard-codes ./atlas");
assert.ok(/ATLAS_LABEL: "\$\{ATLAS_LABEL:-\}"/.test(compose), "the build service passes ATLAS_LABEL");

// ---- entrypoint and wrappers
assert.ok(/--label "\$ATLAS_LABEL"/.test(read("docker/entrypoint.sh")), "the entrypoint forwards ATLAS_LABEL as --label");
assert.ok(/\[string\]\$Project/.test(read("scripts/atlas.ps1")) && /-p", "code-atlas-\$Project"/.test(read("scripts/atlas.ps1")), "atlas.ps1 takes -Project and uses its own compose project");
assert.ok(/--project/.test(read("scripts/atlas.sh")) && /code-atlas-\$PROJECT/.test(read("scripts/atlas.sh")), "atlas.sh takes --project and uses its own compose project");

console.log("named-projects.test: --label names bundles; every compose mount follows ATLAS_DATA_DIR; wrappers + entrypoint wired for per-project servers");
