/**
 * Sanitize untrusted text before it reaches a terminal/log.
 *
 * An overlay warning/error (threatOverlay.ts, surfaced by build.ts and printed by the CLI) can
 * embed untrusted text FROM the overlay source itself (a lead id, an excerpt of a zod parse
 * error) up to the overlay's 5MB document limit on any one field. Printed verbatim, that is both
 * a terminal-control-sequence injection (ANSI/OSC escape sequences can rewrite what the terminal
 * displays, hide text, or move the cursor) and an unbounded-output vector. Strip C0/C1 control
 * characters (a real newline in a warning isn't meaningful here, just a way to fake extra log
 * lines) and cap the length, the same way every other untrusted-overlay-adjacent surface
 * (tools.ts's capText) does.
 */
const LOG_FIELD_CAP = 200;

export function safeLog(s: string): string {
  // eslint-disable-next-line no-control-regex
  const stripped = s.replace(/[\u0000-\u001f\u007f-\u009f]/g, "");
  return stripped.length > LOG_FIELD_CAP ? stripped.slice(0, LOG_FIELD_CAP) + "…" : stripped;
}
