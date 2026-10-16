/**
 * Scan-coverage accounting: every omitted file is counted by reason, so a map's
 * completeness is auditable and absence of a node never silently means absence
 * from the repo. Proves each skip reason is tallied and the cap no longer stops
 * the walk (over-cap files are counted, not invisible).
 */
import assert from "node:assert";
import { mkdtempSync, writeFileSync, mkdirSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildAtlas } from "../src/build.js";
import { parseBundle } from "../src/schema.js";

const root = mkdtempSync(join(tmpdir(), "atlas-cov-"));
writeFileSync(join(root, "app.py"), "a=1\n");            // supported, small -> scanned (cap=1)
writeFileSync(join(root, "helper.py"), "b=2\n");         // supported, small -> over the cap
writeFileSync(join(root, "big.py"), "x".repeat(100));    // supported but > maxBytes -> tooLarge
writeFileSync(join(root, "README.md"), "# docs\n");      // unsupported extension
symlinkSync(join(root, "app.py"), join(root, "link.py")); // symlink -> never followed
mkdirSync(join(root, "node_modules"), { recursive: true });
writeFileSync(join(root, "node_modules", "dep.js"), "var z=1\n"); // inside an ignored dir

const { bundle } = await buildAtlas(root, { product: "Code Atlas", security: false, maxFiles: 1, maxBytes: 20 });
assert.doesNotThrow(() => parseBundle(bundle), "bundle with coverage validates");

const cov = bundle.coverage!;
assert.ok(cov, "coverage is present on the bundle");
assert.strictEqual(cov.scannedFiles, 1, "exactly one file analyzed (the file cap)");
assert.strictEqual(cov.maxFiles, 1, "cap recorded");
assert.strictEqual(cov.skipped.overCap, 1, "the second supported file is counted as over-cap, not dropped silently");
assert.strictEqual(cov.skipped.tooLarge, 1, "the oversized file is counted");
assert.ok(cov.skipped.unsupported >= 1, "the .md file is counted as unsupported");
assert.strictEqual(cov.skipped.symlink, 1, "the symlink is counted (and never followed)");
assert.strictEqual(cov.skipped.ignoredDir, 1, "the ignored directory is counted");
assert.strictEqual(cov.skipped.ignoredDirFiles, 1, "the file inside node_modules is counted (not silently invisible)");
// walked files (outside ignored dirs); the ignored-dir file is counted separately
assert.strictEqual(cov.totalFilesSeen, 4, "app.py + helper.py + big.py + README.md were all walked");

console.log(`coverage.test: analyzed ${cov.scannedFiles}/${cov.totalFilesSeen}; skipped ${JSON.stringify(cov.skipped)} — every omission counted by reason`);
