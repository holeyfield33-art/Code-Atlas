# Connect your agent to Code Atlas (MCP setup manual)

Code Atlas serves one **bundle** (a source-grounded map of a repository) to an AI
agent over the Model Context Protocol (MCP). The agent pulls only the slice it needs
instead of reading the whole repo. This manual takes you from nothing to a connected
agent, step by step.

> **What was tested.** The Docker image, the HTTP server, the stdio server and the
> `scripts/atlas.*` wrappers were run end to end (see [docker.md](docker.md)). The
> client configuration syntax below was checked against each vendor's current
> documentation (links in each section). **Claude Code 2.1 was connected to the running
> container for real** (`claude mcp add`, then `claude mcp list` reported *Connected* with
> the right key and *HTTP 401* with a wrong one). The other clients' syntax is from their
> docs but those clients were **not** run, and no client was taken through a full model
> conversation, so use the [verify step](#5-verify-the-connection) and report anything
> that differs. Items I could not verify are listed in
> [section 9](#9-not-covered--unverified).

## 1. What the agent gets

Nine **read-only** tools. The tenth, `atlas_triage`, writes finding decisions back to
the bundle and is **off by default over HTTP**.

| Tool | Use it to |
|---|---|
| `atlas_overview` | orient: counts, entry points, scan coverage, findings. Call this first. |
| `atlas_search` | find nodes by words (ids and locations only, no source) |
| `atlas_get_node` | inspect one component and its neighbours |
| `atlas_get_source` | read one function or file head (returns "unavailable" with a reason if it was truncated) |
| `atlas_neighbors` | walk callers / callees / imports |
| `atlas_context_pack` | a task description in, a budgeted, source-backed set of components out |
| `atlas_threats` | findings for a node or file, with grade and any triage decision |
| `atlas_course` | the grounded Break & Fix lesson attached to a node |
| `atlas_exec` | run JavaScript against a frozen read-only `atlas` API in a sandbox (one call for any filter / join / aggregate) |
| `atlas_triage` | **write**: record `confirmed` / `false_positive` / `accepted_risk` on a finding |

The bundle is a **snapshot**. It does not follow your editor or working tree: rebuild it
after the code changes ([section 7](#7-keeping-it-current)).

## 2. Choose a connection path

| Path | Good for | Needs | Auth |
|---|---|---|---|
| **A. HTTP via Docker** | several clients sharing one server; an always-on local service | Docker, the compose stack running | bearer key |
| **B. stdio via `docker run -i`** | one client, nothing left running, no port, no key | Docker | none (the client launches it) |
| **C. stdio via Node** | development on Code Atlas itself | Node 20 or 22 and `npm run build` | none |

If unsure: **A** for Claude Code, Cursor, VS Code and Codex; **B** for Claude Desktop.
Both A and B were tested.

## 3. Prerequisites and a bundle

You need Docker (Docker Desktop on Windows/macOS), and this repository checked out.

1. **Build a bundle of the project you want the agent to investigate.**
   - Windows PowerShell: `.\scripts\atlas.ps1 build C:\path\to\your\project`
   - macOS / Linux / WSL / Git Bash: `./scripts/atlas.sh build /path/to/your/project`

   The first run builds the image (a minute or two). The project is mounted
   **read-only**; the bundle appears in `atlas/atlas.bundle.json`. The command prints
   a coverage line - read it: files over the cap or in unsupported languages are
   counted but not mapped ([known-limits.md](known-limits.md)).
2. Check it: `.\scripts\atlas.ps1 status` should report `atlas\atlas.bundle.json present`.

The bundle contains your source. Treat it like the repository itself.

## 4. Path A - HTTP via Docker

### Start

```powershell
.\scripts\atlas.ps1 start mcp        # or: ./scripts/atlas.sh start mcp
.\scripts\atlas.ps1 mcp-config       # prints the URL, the header and ready-made client commands
```

`start` creates a random API key in `.env` the first time (the file is git-ignored; never
commit it). The server listens on `http://127.0.0.1:8000/mcp`, published on **your
machine's loopback only**. Stop it with `.\scripts\atlas.ps1 stop`.

Every request needs the header `Authorization: Bearer <your key>`. The key is the value
of `ATLAS_MCP_API_KEY` in `.env`. Anyone holding it can read the bundled source, so do
not paste it into chats or tickets. To rotate: edit `.env` (or delete the line and run
`key`), then `restart mcp`, then update every client.

### Claude Code

Source: <https://code.claude.com/docs/en/mcp>

```bash
claude mcp add --transport http code-atlas http://127.0.0.1:8000/mcp \
  --header "Authorization: Bearer YOUR_KEY"
claude mcp list          # shows health
```

Scope: the default (`local`) is private to you and the current project; add
`--scope user` to use it in every project, or `--scope project` to write a shared
`.mcp.json` (then reference the key as `${ATLAS_MCP_API_KEY}` instead of pasting it, so
it never reaches version control):

```json
{
  "mcpServers": {
    "code-atlas": {
      "type": "http",
      "url": "http://127.0.0.1:8000/mcp",
      "headers": { "Authorization": "Bearer ${ATLAS_MCP_API_KEY}" }
    }
  }
}
```

Inside a session, `/mcp` shows status. Remove with `claude mcp remove code-atlas`.

### Cursor

Source: <https://cursor.com/docs/context/mcp>. Put this in `~/.cursor/mcp.json` (all
projects) or `.cursor/mcp.json` (one project):

```json
{
  "mcpServers": {
    "code-atlas": {
      "url": "http://127.0.0.1:8000/mcp",
      "headers": { "Authorization": "Bearer ${env:ATLAS_MCP_API_KEY}" }
    }
  }
}
```

`${env:NAME}` reads an environment variable, so set `ATLAS_MCP_API_KEY` in the
environment Cursor is launched from; or paste the key in place of the variable in your
**user-level** file only.

### VS Code

Source: <https://code.visualstudio.com/docs/copilot/reference/mcp-configuration>. Use
`.vscode/mcp.json` (workspace) or run **MCP: Open User Configuration**. VS Code's key is
`servers`, not `mcpServers`:

```json
{
  "inputs": [
    { "type": "promptString", "id": "atlas-key", "description": "Code Atlas MCP API key", "password": true }
  ],
  "servers": {
    "code-atlas": {
      "type": "http",
      "url": "http://127.0.0.1:8000/mcp",
      "headers": { "Authorization": "Bearer ${input:atlas-key}" }
    }
  }
}
```

VS Code prompts for the key when the server first starts, so it is never written to
the file.

### Codex CLI

Source: <https://learn.chatgpt.com/docs/extend/mcp?surface=cli>. In `~/.codex/config.toml`:

```toml
[mcp_servers.code_atlas]
url = "http://127.0.0.1:8000/mcp"
bearer_token_env_var = "ATLAS_MCP_API_KEY"
```

Export `ATLAS_MCP_API_KEY` in the shell that launches Codex. `codex mcp list` shows
configured servers.

### ChatGPT (custom MCP server, through a Secure MCP Tunnel)

ChatGPT runs in the cloud and cannot reach `127.0.0.1`, so the dialog's **Server URL**
option is not usable for a local server (it needs a public HTTPS address; do not expose
this server publicly). Its **Tunnel** option is the supported route: OpenAI's
`tunnel-client` runs on your machine and relays requests to the local server. Sources:
<https://developers.openai.com/api/docs/guides/secure-mcp-tunnels> and the client's own
`tunnel-client help quickstart`.

**What was tested here:** `tunnel-client` v0.0.16 was downloaded, its SHA-256 checked
against the published list, and `setup` + `doctor` run against this server with
placeholder OpenAI credentials. Every local check passed, including *MCP server reachable*
(HTTP 405 on its probe, which is the authenticated answer) and *OAuth metadata: not
advertised*. **Not tested:** anything that needs a real tunnel id and runtime key (the
tunnel itself, ChatGPT discovering the tools, a tool call from ChatGPT), because those
credentials come from your OpenAI account.

The ChatGPT dialog has no header field, and this server authenticates with a key. With a
tunnel the key never goes into ChatGPT: it sits in the **local** `tunnel-client` profile,
in the URL it forwards to. That needs the server's opt-in URL-key mode (step 1). The
client's `sample_mcp_remote_no_auth` profile ("remote HTTP MCP server without OAuth
metadata") matches this server, so in the dialog the server needs **no OAuth**: pick the
no-authentication choice if the Authentication list offers one.

1. **URL-key mode.** In `.env` add `ATLAS_ALLOW_URL_KEY=1`, then
   `.\scripts\atlas.ps1 restart mcp` (restart recreates the container so the change applies).
   *(Tested: `/mcp?key=<key>` and `/mcp/<key>` authenticate; a wrong key is 401 and counts
   toward the lockout; with the option off both are 404.)*
2. **Two values from OpenAI Platform** (<https://platform.openai.com/settings/organization/tunnels>):
   - a **tunnel id** (`tunnel_` plus 32 hex characters), created in *Tunnels management*;
   - a **runtime API key** (*Runtime API keys*), for a principal with *Tunnels Read + Use*
     (creating the tunnel needs *Read + Manage*). The tunnel must be associated with your
     ChatGPT workspace. The guide does not state which plans are eligible.
3. **Install and set up** (one time):

   ```powershell
   .\scripts\atlas-tunnel.ps1 install                        # download + checksum-verify tunnel-client
   .\scripts\atlas-tunnel.ps1 setup -TunnelId tunnel_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   .\scripts\atlas-tunnel.ps1 doctor                         # asks for the runtime key (hidden)
   ```

   `setup` checks that the Atlas MCP server is up and accepts the URL key, writes the
   `code-atlas` profile (the runtime key is only *referenced* as `env:CONTROL_PLANE_API_KEY`,
   never written), and remembers the tunnel id in `.env`.
4. **Run it** and leave the window open:

   ```powershell
   .\scripts\atlas-tunnel.ps1 run                            # local admin UI: http://127.0.0.1:18080/ui
   ```

5. **In ChatGPT**, only while the tunnel is running: **Plugins > Add > Add custom MCP
   server**, name it, **Connection: Tunnel**, pick your tunnel, **Authentication:** the
   dialog defaults to *OAuth*; this server has none, so choose the no-authentication option.
   If OAuth is the only option the list offers, ChatGPT cannot connect to this server yet.
   Tick the risk acknowledgement, save, then ask it to call `atlas_overview`. Keep
   `tunnel-client` running for discovery and every later tool call.

The profile file contains your Atlas key (it is in the forwarded URL). It lives in the
current user's profile; do not share it or put it under version control. Rotate with
`atlas.ps1 key` after removing the old line from `.env`, then `restart mcp` and
`atlas-tunnel.ps1 setup` again.

If `doctor` or ChatGPT reports 401 or 403, `.\scripts\atlas.ps1 logs mcp` shows what the
server saw; a `Host` other than `localhost` or `127.0.0.1` is refused unless listed in
`ATLAS_ALLOWED_HOSTS`. Whether the tunnel forwards such a Host is not documented.

**Risk of the URL key.** A URL is logged and displayed more freely than a header (shell
history, client logs, config files). Use this mode only for a client on the same machine
and do not paste the URL into chats or tickets. This server never logs request URLs.

## 5. Verify the connection

Independently of any agent, prove the server answers (replace `YOUR_KEY`):

```powershell
# health (no key needed)
Invoke-RestMethod http://127.0.0.1:8000/healthz
# tools (needs the key)
$h = @{ Authorization = "Bearer YOUR_KEY"; Accept = "application/json, text/event-stream" }
(Invoke-RestMethod http://127.0.0.1:8000/mcp -Method Post -Headers $h -ContentType "application/json" `
  -Body '{"jsonrpc":"2.0","id":1,"method":"tools/list"}').result.tools.name
```

```bash
curl -s http://127.0.0.1:8000/healthz
curl -s -X POST http://127.0.0.1:8000/mcp -H "Authorization: Bearer YOUR_KEY" \
  -H "content-type: application/json" -H "accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

You should see nine tools and no `atlas_triage`. A request without the key must return
`401`. Then ask your agent something that needs the tool, for example:

- "Call `atlas_overview` and summarise what this repository is."
- "Use `atlas_search` to find where authentication is handled, then `atlas_get_source` on the best match."
- "Use `atlas_exec` to list the five entry points with the most findings."

If the agent answers without calling a tool, tell it to use the `code-atlas` server by
name; some clients only call tools when asked.

## 6. Path B - stdio via `docker run -i` (no port, no key)

The client launches a throw-away container for each session and talks over stdin/stdout.
Nothing listens on the network. Build the image once (`.\scripts\atlas.ps1 rebuild`).

The bundle folder is mounted into the container. `:ro` makes it read-only; **drop `:ro`
only if you want `atlas_triage` to be able to save decisions** (stdio exposes all ten
tools).

### Claude Desktop

Source: <https://modelcontextprotocol.io/quickstart/user>. Open **Settings > Developer >
Edit Config** (file: `%APPDATA%\Claude\claude_desktop_config.json` on Windows,
`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "code-atlas": {
      "command": "docker",
      "args": ["run", "-i", "--rm",
               "-v", "C:\\path\\to\\Code-Atlas\\atlas:/data:ro",
               "code-atlas:local", "mcp-stdio"]
    }
  }
}
```

Use your real absolute path (backslashes doubled in JSON). Quit and reopen Claude Desktop
completely. Logs: `%APPDATA%\Claude\logs\mcp-server-code-atlas.log`. The same
`command`/`args` work in any client that launches stdio servers.

### Claude Code (stdio)

```bash
claude mcp add --transport stdio code-atlas -- docker run -i --rm \
  -v "/path/to/Code-Atlas/atlas:/data:ro" code-atlas:local mcp-stdio
```

(The `--` is required: everything after it goes to Docker untouched.)

### Cursor / VS Code / Codex (stdio)

Use the same command and arguments in each client's stdio form:

- Cursor: `{"mcpServers": {"code-atlas": {"command": "docker", "args": ["run","-i","--rm","-v","/path/to/atlas:/data:ro","code-atlas:local","mcp-stdio"]}}}`
- VS Code: `{"servers": {"code-atlas": {"type": "stdio", "command": "docker", "args": [ ...same... ]}}}`
- Codex: `codex mcp add code-atlas -- docker run -i --rm -v /path/to/atlas:/data:ro code-atlas:local mcp-stdio`

## 7. Keeping it current

- **Code changed:** rebuild the bundle (`atlas.ps1 build <path>`) then `atlas.ps1 restart mcp`
  (the HTTP server loads the bundle at startup). stdio picks it up on the next session.
- **Code Atlas updated:** `atlas.ps1 rebuild` then `restart`.
- Rebuilding regenerates findings and **does not carry over triage decisions**; keep a
  copy of a triaged bundle if you need that record.

### Several projects, and next to a live tool

Register one server per project (`atlas.ps1 mcp-config -Project myapp` prints the command; see
[docker.md](docker.md#several-projects-at-once)). Each shows up to the agent under its own name
(`atlas-myapp`), so they can be used side by side without swapping bundles.

A useful pairing is Code Atlas for the **static** side next to a tool that sends **live** requests
to the running app: use Code Atlas to find where the behaviour lives (search the route or
function, read the source with `atlas_get_source`, follow callers and imports with
`atlas_neighbors`, check `atlas_threats` for leads on that code), then replay the route in the
live tool and compare what the code says with what the server actually does. Code Atlas never
sends a request to your app and sees only the source snapshot; the live tool never sees the
source. Rebuild the bundle after the code changes.

## 8. Triage (writing decisions back) - opt-in

Over HTTP the write tool is not even registered. To enable it deliberately, remove the
read-only mount for the `mcp` service in `docker-compose.yml` (`./atlas:/data`) and add
`"--allow-triage"` to its `command` (for example `command: ["mcp", "--allow-triage"]`).
Anyone with your key can then change finding dispositions, which colour the map and
suppress blast radius. A disposition never upgrades a finding's grade. Prefer stdio
(Path B, without `:ro`) for local triage.

## 9. Not covered / unverified

- **ChatGPT.** The tunnel route is set up and its local checks pass, but a real tunnel, ChatGPT
  discovering the tools, and a tool call from ChatGPT were **not** run (they need your OpenAI
  tunnel id and runtime key), and whether the dialog's Authentication list offers a
  no-authentication choice was not confirmed.
- **Claude Desktop remote (HTTP) servers.** Local stdio is documented above; adding a
  remote server there was not verified.
- **Other clients** (Windsurf, Gemini CLI, Continue, Zed, ...). Any client that can
  launch a stdio command or send an `Authorization` header to a Streamable HTTP URL
  should work with the same values; check that client's documentation for the file
  format.
- **Browsers.** Browser-based clients are refused by design (no CORS; unlisted Origin
  returns 403).

## 10. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `docker: command not found` / "Docker is not running" | Install/start Docker Desktop, then retry |
| `start mcp` says no bundle | Run `atlas.ps1 build <path>` first |
| Container exits at once, log says `ATLAS_MCP_API_KEY is not set` | Run `atlas.ps1 key`, then `start mcp` |
| `401 Unauthorized` | The client's key differs from `.env`; re-run `mcp-config` and copy it exactly (no quotes, no trailing space) |
| `403 Host not allowed` | You reached it by another name (e.g. a LAN IP or `host.docker.internal`). Use `127.0.0.1` or `localhost` |
| `403 Origin not allowed` | A browser sent an Origin. Use a non-browser client |
| `429 Too many requests` | Repeated bad keys or a request burst; wait a minute. Behind Docker every client shares one source address, so one misconfigured client can lock out the others |
| Port already in use | Set `ATLAS_MCP_PORT` in `.env` (and use it in the client URL) |
| Client says "connection refused" from WSL or a dev container | `127.0.0.1` there is not your Windows host. Use Path B, or run the client on the host |
| Claude Desktop shows no tools | Absolute path wrong or JSON invalid; fully quit and reopen; read `mcp-server-code-atlas.log` |
| `atlas_get_source` says "unavailable" | That function is past the 40,000-character embed cap of a large file; open it in your editor ([known-limits.md](known-limits.md)) |
| Empty or tiny graph | Read the coverage line from `build`; check the project root, supported languages, file and size caps |
| Results look stale | The bundle is a snapshot; rebuild and restart ([section 7](#7-keeping-it-current)) |

Security details: [security-model.md](security-model.md). Container details: [docker.md](docker.md).
