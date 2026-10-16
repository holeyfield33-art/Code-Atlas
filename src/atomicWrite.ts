/**
 * Atomic file replace: write to a temp file in the SAME directory, flush it to disk,
 * then rename over the target. A crash or full disk mid-write leaves the original
 * file intact (never truncated or half-written JSON); the temp file is removed on
 * failure. Same-directory keeps the rename on one filesystem, so it is atomic.
 */
import { openSync, writeSync, fsyncSync, closeSync, renameSync, unlinkSync } from "node:fs";
import { dirname, basename, join } from "node:path";
import { randomBytes } from "node:crypto";

export function writeFileAtomic(path: string, data: string): void {
  const tmp = join(dirname(path), `.${basename(path)}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`);
  let fd: number | undefined;
  try {
    fd = openSync(tmp, "wx", 0o600);
    writeSync(fd, data);
    fsyncSync(fd);
    closeSync(fd); fd = undefined;
    renameSync(tmp, path);
  } catch (e) {
    if (fd !== undefined) { try { closeSync(fd); } catch { /* already closed */ } }
    try { unlinkSync(tmp); } catch { /* temp already gone */ }
    throw e;
  }
}
