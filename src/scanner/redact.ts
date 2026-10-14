/**
 * Secret redaction for source that ships in the bundle/viewer.
 *
 * The graph and course run on REAL source (grounding + content hashes depend on
 * it). Only the INLINED copy that travels in the shareable artifact is redacted,
 * so a published viewer never carries a live credential. Pattern-based and
 * deliberately conservative: it masks obvious secret shapes, not every string.
 */

interface RedactionPattern { name: string; re: RegExp; assigned?: boolean; }

// Note: each `re` is a literal, author-controlled pattern (no user input), so it
// is not a ReDoS surface. `g` flag is required for replace-all.
const PATTERNS: RedactionPattern[] = [
  { name: "private-key", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g },
  { name: "aws-access-key-id", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: "openai-key", re: /\bsk-[A-Za-z0-9_-]{16,}\b/g },
  { name: "slack-token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { name: "github-token", re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g },
  { name: "google-api-key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: "jwt", re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  // secret-NAMED assignment: keep the key + quote style, mask only the value.
  { name: "assigned-secret", assigned: true,
    re: /((?:password|passwd|secret|secrets|token|api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key)\s*[:=]\s*['"`])([^'"`\n]{6,})(['"`])/gi },
];

export function redactSecrets(code: string): { code: string; redactions: number } {
  let redactions = 0;
  let out = code;
  for (const p of PATTERNS) {
    out = out.replace(p.re, (...args: string[]) => {
      redactions++;
      if (p.assigned) return `${args[1]}«redacted:secret»${args[3]}`; // prefix + mask + closing quote
      return `«redacted:${p.name}»`;
    });
  }
  return { code: out, redactions };
}
