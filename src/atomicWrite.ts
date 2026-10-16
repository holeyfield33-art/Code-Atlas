/**
 * Atomic file replace: write to a temp file in the SAME directory, flush it to disk,
 * then rename over the target. A crash or full disk mid-write leaves the original
 * file intact (never truncated or half-written JSON); the temp file is removed on
 * failure. Same-directory keeps the rename on one filesystem, so it is atomic.
 *
 *  - writeSync may write FEWER bytes than requested without throwing (e.g. a nearly
 *    full disk), so we loop until every byte is written and abort before the rename
 *    if no progress is made.
 *  - If `path` is a symlink, the REAL target is replaced and the link is left in
 *    place (renaming over the link would turn it into a regular file and leave the
 *    file it points at stale).
 *  - The replacement keeps the existing file's EXACT permission bits (a 0644 bundle
 *    stays 0644 even under a restrictive umask: applied with fchmod after open);
 *    a brand-new file gets 0600.
 *  - A read-only existing target is rejected up front: replacing via rename is
 *    governed by the directory's permissions, so without this check a 0444 bundle
 *    would be silently overwritten (writeFileSync used to fail on it).
 */
import { openSync, writeSync, fsyncSync, closeSync, renameSync, unlinkSync, statSync, realpathSync, accessSync, fchmodSync, constants } from "node:fs";
import { dirname, basename, join } from "node:path";
import { randomBytes } from "node:crypto";

/** Write every byte of `buf` to `fd`, or throw. Exported for testing short writes. */
export function writeFully(fd: number, buf: Buffer, write: typeof writeSync = writeSync): void {
  let off = 0;
  while (off < buf.length) {
    const n = write(fd, buf, off, buf.length - off);
    if (n <= 0) throw new Error(`short write: ${off}/${buf.length} bytes written`);
    off += n;
  }
}

export function writeFileAtomic(linkPath: string, data: string, write: typeof writeSync = writeSync): void {
  let path = linkPath;
  try { path = realpathSync(linkPath); } catch { /* does not exist yet: write the path as given */ }
  let mode = 0o600, existed = false;
  try { mode = statSync(path).mode & 0o7777; existed = true; } catch { /* new file: keep 0600 */ }
  if (existed) accessSync(path, constants.W_OK);                 // throws EACCES/EPERM on a read-only target
  const tmp = join(dirname(path), `.${basename(path)}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`);
  let fd: number | undefined;
  try {
    fd = openSync(tmp, "wx", mode);
    if (existed) fchmodSync(fd, mode);                            // open() mode is masked by the umask; restore exactly
    writeFully(fd, Buffer.from(data, "utf8"), write);
    fsyncSync(fd);
    closeSync(fd); fd = undefined;
    renameSync(tmp, path);
  } catch (e) {
    if (fd !== undefined) { try { closeSync(fd); } catch { /* already closed */ } }
    try { unlinkSync(tmp); } catch { /* temp already gone */ }
    throw e;
  }
}
