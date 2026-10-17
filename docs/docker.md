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
| `restart [app\|mcp\|all]` | **recreates** the containers, so a rebuilt image, a rebuilt bundle or an edited `.env` takes effect (plain `docker compose restart` keeps the old image and environment) |
| `tunnel-url` | copy the MCP URL with the key embedded, for a tunnel client (needs `ATLAS_ALLOW_URL_KEY=1`; see [mcp-setup.md](mcp-setup.md)) |
| `status` | running containers and whether a bundle exists |
| `logs [app\|mcp]` | follow logs |
| `build <path>` | scan a project into `atlas/` (source mounted read-only) |
| `rebuild` | rebuild the image after updating Code Atlas |
| `key` | create a random MCP API key in `.env` if there is none |
| `mcp-config` | print the URL, header and ready-made client commands (shows your key) |

ChatGPT (through OpenAI's Secure MCP Tunnel) has its own script: `.\scripts\atlas-tunnel.ps1` (`install`, `setup`, `doctor`, `run`); see [mcp-setup.md](mcp-setup.md).

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

## Several projects at once

The default instance serves one bundle (`atlas/atlas.bundle.json`). To keep a second codebase
available **at the same time**, give it a name. It gets its own bundle folder, port, container
and MCP server; the image and API key are shared, and the default instance is not touched.

```powershell
.\scripts\atlas.ps1 build C:\path\to\app -Project myapp    # -> atlas\myapp\atlas.bundle.json (+ viewer.html)
.\scripts\atlas.ps1 start -Project myapp                   # MCP server on its own port (8001, 8002, ... remembered in .env)
.\scripts\atlas.ps1 mcp-config -Project myapp              # URL + a ready `claude mcp add ... atlas-myapp` command
.\scripts\atlas.ps1 projects                               # every project: bundle, port, running or stopped
.\scripts\atlas.ps1 stop -Project myapp                    # stop only that one
```

macOS / Linux / WSL: `./scripts/atlas.sh --project myapp build /path/to/app`, and so on. A named
project runs only the MCP server (the web app is shared); the bundle is labelled with the
project name, so `atlas_overview` tells the servers apart. Open its map from
`atlas\myapp\viewer.html`.

## A repo too big for one bundle (shards)

One bundle is loaded whole into memory by its MCP server, and the viewer cannot draw tens of
thousands of files, so a monorepo needs several. `code-atlas plan` splits it along folder
boundaries into groups of up to N files, and each group becomes its own named project:

```powershell
.\scripts\atlas-shard.ps1 plan  -Source /home/me/gdk/gitlab            # show the split (a Linux path = read through WSL)
.\scripts\atlas-shard.ps1 build -Source /home/me/gdk/gitlab -Name gdk   # atlas\gdk-01, gdk-02, ...
.\scripts\atlas.ps1 start -Project gdk-02                               # run one shard's MCP server
```

- The plan counts exactly what the scanner would read (same ignore list, size cap, supported
  extensions) and covers every analyzable file **exactly once**. A folder that fits stays whole;
  one over the cap is opened up and its sub-folders and own files are packed with their neighbours
  in path order. One folder bigger than the cap alone becomes an oversize shard rather than being cut.
- Test folders are skipped by default (`-Skip "spec,test,tests,__tests__,__mocks__,fixtures"`);
  `-Skip ""` includes them.
- Under the hood: `build --include <folders>` scans only those folders but keeps root-relative
  paths (so source links and evidence stay valid), and `--skip` leaves folders out. Everything left
  out is counted in the bundle's coverage record (`excluded`), so a shard never claims to be the
  whole repo.
- **Limit:** calls and imports resolve only inside one bundle, so a relationship that crosses
  shards is not drawn. Search the other shard's server to follow it.
- Each running shard server uses roughly 0.3-0.5 GB: run the ones you are working on.

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
- The `app` opens on your latest `atlas/atlas.bundle.json` (mounted read-only; re-read on
  every page load, so `build` then refresh shows the new map). With no bundle it shows the
  built-in sample graph. **Open folder** results live only in that page and are discarded
  on reload (uploads are analysed in `/tmp`); use **Save bundle** to keep one, or `build`
  the project so it becomes the default.

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
