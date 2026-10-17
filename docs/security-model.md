# Security model

What Code Atlas protects, from whom, how, and where the protection stops. It describes
the code as shipped; items marked **open** are known gaps, not promises.

## What it handles

A bundle is a map of a repository **plus its source text**. Treat `atlas/`,
`viewer.html` and any exported JSON exactly like the repository itself. Secret-like
values in embedded source are redacted by pattern on a best-effort basis; that is a
safeguard, not a guarantee.

## Trust boundaries

| Component | Who can reach it | Controls |
|---|---|---|
| CLI `build` | the local user | reads the tree (does not execute it, does not follow symlinks), never modifies it |
| Web app (`serve` / container `app`) | processes on this machine | binds loopback; exact Host check (127.0.0.1 or localhost, on its own port); `POST` also needs a matching Origin and a per-run random token; one build at a time; 32 MiB body cap; upload paths validated (traversal, absolute and drive paths, Windows reserved names, duplicates, ignored dirs, extension, size) |
| MCP over stdio | the client that launched it | no network; the client owns the process |
| MCP over HTTP | clients holding the API key | loopback bind (refuses otherwise without `--allow-remote`); Host allowlist (DNS rebinding); Origin allowlist (no CORS); per-client rate limit and failed-auth lockout (bounded table); bearer key compared in constant time **before** the body is read; 1,000,000-byte body cap; **read-only: `atlas_triage` is not registered unless `--allow-triage`** |
| `atlas_exec` sandbox | an agent's code | V8 isolate (`isolated-vm`): no `require`, `import`, `process`, `fetch`, timers or filesystem; only a frozen read API; host calls checked against a read-only allowlist; wall-clock timeout, 128 MB heap, 20,000-character code limit, 1,000,000-byte (UTF-8) result limit; JSON-only crossing; the trusted built-ins used for the size check are captured before agent code runs |
| Container | the Docker host | non-root, all capabilities dropped, no-new-privileges, read-only root filesystem; published ports bound to host loopback; bundle mounted read-only for the HTTP service |

## Evidence integrity

- Every graph element carries a source path, line and content hash. An unresolvable
  relationship becomes a diagnostic, never an invented edge.
- Python call edges are matched by name only and Ruby edges by receiver and namespace;
  both are labelled **inferred** in the bundle, MCP output and viewer; they are never shown as
  proven.
- A static finding is a **lead** (`STATIC` / `INFERRED`). It colours a node but casts no
  blast radius. Only `OBSERVED` / `TESTED` evidence marks components as possibly
  affected, and a static "control" is displayed as present-but-unverified, never as
  hardened.
- A triage decision can only suppress. It never upgrades a grade or creates a blast radius.
- `atlas_context_pack` and `atlas_exec` return replayable receipts. A context-pack
  receipt hashes the bundle's full query-visible content and the exact source slices
  returned, so a changed function changes the receipt.
- Bundle writes (triage) go through a temp file, fsync and rename, preserving mode,
  owner and symlinks, so an interrupted save cannot leave half a JSON file.

## Threats considered

| Threat | Mitigation |
|---|---|
| Malicious filename or source text breaking the viewer (XSS) | graph ids and text are escaped; the bundle is embedded as inert JSON; no remote script is loaded |
| Hostile repository content steering a build | source is parsed, never executed; symlinks are not followed; size and count caps |
| Another site on your machine's browser calling the local servers | Host and Origin checks, tokens, no CORS |
| Stolen or guessed MCP key | 32+ character random key, constant-time compare, lockout, loopback bind; rotate by editing `.env` and restarting |
| Agent prompt injection via repository text | the read-only surface: even a fully steered agent can read the bundle but not write it, reach the network, or run code outside the isolate |
| Regex denial of service in custom rules | rule patterns compile on a linear-time engine |
| Oversized or runaway sandbox script | timeout, heap and result caps (see open items for host-side limits) |

## Open items (known gaps)

- **Sandbox host-side budgets (open).** The isolate is bounded, but the host functions it
  calls do not yet cap the number of calls, argument size, or intermediate result size,
  and `atlas_exec` does not apply the input bounds that the direct tools enforce
  (for example a token budget). This is being addressed with the sandbox work.
- **No per-client identity.** One shared bearer key; no OAuth, per-client keys or audit
  log. Whether a hosted client accepts a static bearer key is unverified.
- **No TLS.** Put a TLS terminator in front before any non-loopback use.
- **Rate limits are in memory and per source address.** Behind Docker's bridge or a
  reverse proxy every client shares one address.
- **CI has not run.** The GitHub Actions account is billing-locked, so no automated run of
  the test matrix is on record. Two tests that need symlinks (`coverage`, `security`)
  cannot run on the Windows development machine.
- **Redaction is pattern-based** and cannot recognise every secret.

Report a vulnerability: see [../SECURITY.md](../SECURITY.md).
