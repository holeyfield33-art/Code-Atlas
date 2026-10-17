# Known limits

Code Atlas is a **static** analyser that prefers saying "unknown" over guessing. These
are the limits to keep in mind when reading a map or a finding.

## Coverage

- **Languages:** JavaScript/TypeScript (including `.vue` script blocks), Python, Ruby.
  Everything else is not mapped. The build prints, and the bundle records, how many files
  were skipped and why (unsupported, too large, over the cap, symlink, ignored directory,
  unreadable). A map is only as complete as `coverage` says.
- **Defaults:** up to 2,000 files and 200,000 bytes per file (`--max-files`,
  `--max-bytes` for the CLI; the folder picker uses the defaults). Fixed excluded
  directories: `node_modules .git dist build .next coverage .course atlas .turbo out
  vendor __pycache__ .venv venv`. `.gitignore` is not read.
- **Source in the bundle is capped at 40,000 characters per file.** The graph is built
  from the full file, but code past the cap is not embedded: `atlas_get_source` and the
  viewer say "unavailable" for it.
- **Snapshot:** nothing updates by itself. Rebuild after code changes; rebuilding drops
  triage decisions.

## Accuracy

- **JS/TS** calls resolve through imports and same-file declarations.
- **Python** calls are matched **by name only**, ignoring the receiver, and are marked
  *inferred*. If a name is defined exactly once in the scan, any call to that name links to
  it, even a call on an unrelated object (a false edge). If the name is defined more than
  once the call is left unlinked (a missed edge, with a diagnostic). Treat every Python
  call edge as a hint to check.
- **Ruby** calls are resolved by receiver and fully-qualified class/module (constant
  lookup, superclass, `include`/`extend`/`prepend`). A call on a receiver of unknown type
  (`user.save`) gets no edge and a diagnostic listing the candidates. Rails autoloading,
  `method_missing`, DSL-defined methods and dynamic dispatch are invisible. On a large
  partial sample most Ruby calls are therefore *unresolved*; that is expected.
- **Findings are leads.** A rule match (dynamic code execution, shell-out, unsafe
  deserialization, secret-like handlers) shows a risky *shape*, not an exploitable path.
  Absence of a finding is not evidence of safety.
- **Generated lessons** check text, not behaviour: comments are ignored and the original
  call line must be restored, but passing a check does not prove the code runs.
- **Dynamic features** (reflection, `eval`, metaprogramming, string-built imports) are not
  followed.

## Platform

- **Node 20 or 22.** The sandbox uses `isolated-vm`, a native module compiled for the
  exact Node it runs on. It did not build on Node 24.19 / Windows in testing. The Docker
  image pins Node 22.
- **Windows:** tests that create symlinks need Developer Mode or administrator rights and
  fail with `EPERM` otherwise (`coverage`, `security`).
- **WSL / dev containers:** `127.0.0.1` there is not the Windows host; see
  [mcp-setup.md](mcp-setup.md).

## Operations

- No CI record yet (billing lock on the GitHub account), no signed releases, no published
  image, no per-client credentials, no TLS ([security-model.md](security-model.md)).
- The HTTP MCP server is single-process, stateless and has no persistence of its own.
- The browser **Open folder** flow was exercised against a mocked page, not in a real
  browser.
