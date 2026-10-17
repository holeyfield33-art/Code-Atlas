# Running Code Atlas in Docker

One image, started and stopped with one command. Tested with Docker 29 / Compose 5 on
Windows (Docker Desktop). The image is based on `node:22-bookworm-slim`.

## Quick start

```powershell
.\scripts\atlas.ps1 build C:\path\to\your\project   # scan it into .\atlas (first run builds the image)
.\scripts\atlas.ps1 start                           # web app + MCP server
.\scripts\atlas.ps1 status
.\scripts\atlas.ps1 stop
```

macOS / Linux / WSL / Git Bash: the same with `./scripts/atlas.sh`.

| Command | Does |
|---|---|
| `start [app\|mcp\|all]` | start the web app and/or the MCP server (the MCP server starts only once a bundle exists) |
| `stop` | stop and remove the containers (your `atlas/` folder and `.env` are untouched) |
| `restart [app\|mcp\|all]` | restart; needed after rebuilding a bundle |
| `status` | running containers and whether a bundle exists |
| `logs [app\|mcp]` | follow logs |
| `build <path>` | scan a project into `atlas/` (source mounted read-only) |
| `rebuild` | rebuild the image after updating Code Atlas |
| `key` | create a random MCP API key in `.env` if there is none |
| `mcp-config` | print the URL, header and ready-made client commands (shows your key) |

Without the scripts: `docker compose up -d app`, `docker compose up -d mcp`,
`docker compose down`, and `ATLAS_SRC=/path/to/project docker compose --profile tools run --rm build`.

## What runs

| Service | Port (host loopback) | What it is |
|---|---|---|
| `app` | 4173 | the web app with **Open folder** (see [ingestion.md](ingestion.md)) |
| `mcp` | 8000 | authenticated, read-only MCP over HTTP ([mcp-setup.md](mcp-setup.md)) |
| `build` | - | one-shot scan, run on demand (compose profile `tools`) |

Open the app at <http://127.0.0.1:4173>. Change ports in `.env` (`ATLAS_APP_PORT`,
`ATLAS_MCP_PORT`; the host and container ports are kept equal on purpose, because the
servers check the `Host` header against the port they serve).

## Hardening applied

- Published ports bind the host's **127.0.0.1** only. Nothing is reachable from your
  network. (Inside the container the servers bind all interfaces, which is why they are
  started with `--allow-remote`; the publish rule is what keeps them private.)
- Runs as the non-root `node` user, `cap_drop: ALL`, `no-new-privileges`, read-only root
  filesystem with a `/tmp` tmpfs.
- The `mcp` service mounts `atlas/` **read-only** and does not register the write tool.
- The build container mounts your project **read-only**; only `atlas/` is writable.
- No secrets are baked into the image. The API key is read from `.env` at start.

## Files and data

- `atlas/` (git-ignored): `atlas.bundle.json` and `viewer.html`. It contains your source.
- `.env` (git-ignored): `ATLAS_MCP_API_KEY` and optional ports. `.env.example` is the
  tracked template with placeholders.
- The app mode keeps nothing on disk: uploaded folders are analysed in `/tmp` and
  discarded. Use **Save bundle** in the viewer to keep a result.

## Linux notes

The container user is uid 1000. If your host user has a different uid and cannot write
`atlas/`, run `chmod -R a+rwX atlas` or build with `docker compose run --user $(id -u):$(id -g) ...`.
All port publishing goes through Docker's bridge, so the MCP server sees every client as
one source address; its per-client rate limit is therefore shared.

## Troubleshooting

| Symptom | Fix |
|---|---|
| "Docker is not running" | Start Docker Desktop |
| `port is already allocated` | Change `ATLAS_APP_PORT` / `ATLAS_MCP_PORT` in `.env`, or stop what holds the port |
| mcp container restarts then stops | `logs mcp`: usually a missing bundle (`build`) or key (`key`) |
| Web app opens but **Open folder** fails with 403 | Open it as `http://127.0.0.1:<port>` or `http://localhost:<port>` with the **same port** as `ATLAS_APP_PORT` |
| Old behaviour after `git pull` | `rebuild`, then `restart` |
| Build fails compiling `isolated-vm` | The image needs Node 22 and a C++ toolchain; do not change the base image to Node 24 (it did not build when tested) |
