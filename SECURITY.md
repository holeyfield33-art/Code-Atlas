# Security policy

Code Atlas analyses source code and serves it to agents, so security reports are taken
seriously.

## Reporting a vulnerability

Please **do not open a public issue** with exploit details.

- Use GitHub's private reporting: open the repository's **Security** tab, then
  **Report a vulnerability**.
- If that option is not available, open a public issue that says only that you have a
  security report and ask for a private channel. Do not include details.

Please include: the version or commit, what you did, what you expected, what happened,
and, if you can, a minimal reproduction. Say whether you tested against the shipped
Docker image.

You can expect an acknowledgement, a fix or a clear explanation of why it is not a
vulnerability, and credit if you want it. There is no bounty programme and no response-time
guarantee: this is a small project.

## In scope

The CLI, the local web app (`serve`), the MCP server (stdio and HTTP), the `atlas_exec`
sandbox, the viewer, the container image and compose files. Examples we want to hear
about: sandbox escape or host resource exhaustion from `atlas_exec`; bypass of the
Host, Origin, token or bearer checks; path traversal or file overwrite through uploads or
bundle writes; script injection in the viewer from repository content; a finding or edge
presented as more certain than the evidence allows.

## Out of scope

Findings that a scan reports in *your* code (those are leads, see
[docs/security-model.md](docs/security-model.md)); denial of service by pointing the tool
at a huge repository; attacks that need you to expose the ports to an untrusted network
without TLS and then complain it is exposed; vulnerabilities in dependencies with no
reachable path (report those upstream).

See [docs/security-model.md](docs/security-model.md) for the design and the known open
items.
