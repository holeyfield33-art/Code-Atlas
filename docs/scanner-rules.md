# Scanner rules: what each finding means

Every native finding is a **STATIC lead**: a structural pattern in one function. It is not
proof of a vulnerability, it casts no blast radius, and it is painted in the muted "lead"
colour. Red and yellow are reserved for evidence that was actually verified (`OBSERVED` /
`TESTED`), which the built-in scanner never produces, so a map from the native scanner will
never show them. That is by design.

The JS/TS pack lives in `src/scanner/rules.ts` (`DEFAULT_RULES`); Python and Ruby have their
own packs there. A custom pack can be loaded with `build --rules <file>`.

## JavaScript / TypeScript rules

| Rule | Reports a function that... | Does not report |
|---|---|---|
| `r-input-to-sink` | reads request data (`req`/`request` `.body`, `.query`, `.params`, `.headers`) **and** reaches a file write or read, process exec, eval, database call or outbound request, with no validation call visible | functions with a visible `validate` / `sanitize` / `parse` / `check` / `guard` / `assert` / `schema` call |
| `r-unguarded-sink` | calls a high-impact sink (file write, process exec, eval, bare `query` / `run`) with no visible validation | `regex.exec(...)`, `array.query(...)`; constant SQL such as `db.prepare("SELECT ...")` |
| `r-raw-secret` | has a secret-like name (token, secret, password, credential, apiKey, private key) **and** logs, writes or sends data, with no `redact` / `mask` / `sanitize` call | names that describe protection (`redact*`, `mask*`, `validate*`, `verify*`, `is*`, `has*`, `check*`, `match*`, `hash*`, `*Matches`, `*Valid`, ...); a secret-named function that does nothing observable |
| `c-input-validation` (control) | calls a validation primitive | `JSON.parse` (it deserialises; it validates nothing) |

A function matching both `r-input-to-sink` and `r-unguarded-sink` shows the first in the
viewer; both appear in the MCP `atlas_threats` output.

## Ruby rules (calibrated on GitLab)

| Rule | Reports a method that... | Does not report |
|---|---|---|
| `rb-code-exec` | calls `eval`, or `instance_eval` / `class_eval` / `module_eval` together with string interpolation (`#{}`) or request params | block-form `class_eval do ... end` |
| `rb-dynamic-dispatch` | calls `send` / `public_send` with a variable, an interpolated string or request params as the method name | `send(:name)` with a literal symbol |
| `rb-os-command` | calls `system` / `exec` / `Open3` with a command that is not a plain string literal | `system("git", "push")`, `system "ls"` |
| `rb-unsafe-deser` | calls `Marshal.load` / `YAML.load` without `safe_load` | |
| `rb-raw-secret` | has a secret-like name **and** writes a log line, prints, writes a file or sends an HTTP request, with no `redact` / `mask` / `sanitize` | predicates (`token_valid?`), `*_params`, `*_path`, `*_url`, `*_ids`, `verify*`, `hash*`, `encrypt*`; a secret-named method that does nothing observable |
| `rb-input-validation` (control) | calls `validate` / `validates` / `permit` / `sanitize` / `shellescape` | |

On the 35,000-file GitLab tree the first version of these rules reported about 2,270 Ruby and JS weaknesses, almost all
by name alone (`send(:literal)`, any method with "token" in its name). With the shape requirements above it reports about 200.
The 660 `rb-input-validation` controls are unchanged. A `send` call carrying GitLab's reviewed
`rubocop:disable GitlabSecurity/PublicSend` comment is not reported.

Guards are recognised by name prefix (`verify*`, `check*`, `validate*`, `assert*`, `guard*`); `parse` stays exact because `parseInt` validates nothing.

A JS/TS method *definition* named like a sink (`run(inst) { ... }`) is not a call to that sink.

## How matching works (so you can predict it)

- A **bare** sink name (`exec`, `run`, `query`, `writeFile`) matches only a **free** call, so
  `re.exec(...)` is not a process exec.
- A **dotted** sink name (`fs.writeFileSync`, `child_process.exec`, `db.prepare`) matches the
  method form, including after `this.`, because the receiver is part of the token.
- `textMatches` is a linear-time (RE2) pattern test on the function body, for shapes a substring cannot express (a command that is not a string literal). Like `textAny` it reads text, so a comment can satisfy it.
- `textAny` is a plain substring test on the function body, so a comment containing `req.body`
  satisfies it. It is one signal among several, never proof.
- Validators are matched by call name in any form. A function that calls anything named
  `check(...)` or `parse(...)` counts as validated, even if the call is unrelated. This
  keeps leads conservative at the cost of missing some.

## What it cannot see (calibration notes, measured on a real TypeScript app)

- **Taint.** It does not follow data. `r-input-to-sink` means "input and a sink share a
  function", not "input reaches the sink".
- **Inline callbacks.** A route handler written as `app.get("/x", async (req, reply) => { ... })`
  is not its own node: it is judged as part of the enclosing function (often `buildApp`), where
  one validation call anywhere can suppress the lead for the whole function.
- **Class members** are mapped as `Class.member` function nodes (methods, private methods and
  arrow-function properties) so rules can see them, but they get **no call edges**: a
  `this.x()` or `obj.x()` receiver is not resolved. Getters/setters, computed names,
  abstract/overload signatures and anonymous classes are skipped.
- **SQL injection by string building** is not detected: constant `db.prepare(...)` calls are
  not sinks, and a database call counts only where request input is read in the same function.
- **Dynamic dispatch, reflection, generated code, other languages.** See [known-limits.md](known-limits.md).

## Calibrating against your own code

1. Build a bundle and read `atlas_overview`: `counts.findings` and `coverage`.
2. For each finding, open the function (`atlas_get_source`) and decide: real lead, noise, or
   miss. Record misses (code that should have been flagged) as test fixtures in
   `tests/calibration.test.ts`; that file is the regression suite for these rules.
3. Tune the pack: add sink or validator names, a `nameNotMatches` for protective names, or
   `textAny` markers for your framework's request object. Rules are data; no code change needed.
