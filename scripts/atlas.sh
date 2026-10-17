#!/bin/sh
# Start/stop Code Atlas in Docker (macOS / Linux / WSL / Git Bash).
#   ./scripts/atlas.sh <command>
#
#   start [app|mcp|all]   start the web app and/or the MCP server   (default: all)
#   stop                  stop and remove the containers
#   restart [app|mcp|all]
#   status                what is running
#   logs [app|mcp]        follow logs (Ctrl+C to leave)
#   build <path>          scan a project into ./atlas (source is mounted read-only)
#   rebuild               rebuild the image after updating Code Atlas
#   key                   create a random MCP API key in .env if none exists
#   mcp-config            print ready-to-paste client settings (contains your key)
set -eu
cd "$(dirname "$0")/.."

PLACEHOLDER="replace-with-64-random-hex-characters"
cmd="${1:-help}"; [ "$#" -gt 0 ] && shift
target="${1:-all}"

need_docker() {
  command -v docker >/dev/null 2>&1 || { echo "Docker is not installed or not on PATH." >&2; exit 1; }
  docker info >/dev/null 2>&1 || { echo "Docker is installed but not running." >&2; exit 1; }
}
env_value() { [ -f .env ] && sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" .env | head -n1 | tr -d '\r' || true; }
new_key() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }
ensure_key() {
  k="$(env_value ATLAS_MCP_API_KEY)"
  if [ -n "$k" ] && [ "$k" != "$PLACEHOLDER" ] && [ "${#k}" -ge 32 ]; then printf '%s' "$k"; return; fi
  k="$(new_key)"
  [ -f .env ] || cp .env.example .env
  if grep -q '^[[:space:]]*ATLAS_MCP_API_KEY[[:space:]]*=' .env; then
    sed "s|^[[:space:]]*ATLAS_MCP_API_KEY[[:space:]]*=.*|ATLAS_MCP_API_KEY=$k|" .env > .env.tmp && mv .env.tmp .env
  else
    printf 'ATLAS_MCP_API_KEY=%s\n' "$k" >> .env
  fi
  echo "Created a new MCP API key in .env (git-ignored)." >&2
  printf '%s' "$k"
}
ensure_image() { docker image inspect code-atlas:local >/dev/null 2>&1 || { echo "Building the Code Atlas image (first run only; takes a minute or two)..."; docker compose build; }; }
has_bundle() { [ -f atlas/atlas.bundle.json ]; }
port() { v="$(env_value "$1")"; printf '%s' "${v:-$2}"; }

case "$cmd" in
  start)
    need_docker
    svcs=""
    case "$target" in app|all) svcs="app";; esac
    case "$target" in mcp|all)
      if has_bundle; then ensure_key >/dev/null; svcs="$svcs mcp"
      elif [ "$target" = mcp ]; then echo "No bundle yet. Run: ./scripts/atlas.sh build /path/to/project" >&2; exit 1
      else echo "Skipping the MCP server: no bundle yet. Run './scripts/atlas.sh build <path>' then 'start mcp'."; fi;;
    esac
    [ -n "$svcs" ] || { echo "Nothing to start (use app, mcp or all)." >&2; exit 1; }
    # shellcheck disable=SC2086
    ensure_image
    docker compose up -d $svcs
    case "$svcs" in *app*) echo "App:  http://127.0.0.1:$(port ATLAS_APP_PORT 4173)";; esac
    case "$svcs" in *mcp*) echo "MCP:  http://127.0.0.1:$(port ATLAS_MCP_PORT 8000)/mcp   (run 'mcp-config' for client settings)";; esac
    ;;
  rebuild) need_docker; docker compose build; echo "Image rebuilt. Run restart to use it." ;;
  stop)    need_docker; docker compose down ;;
  restart) need_docker; if [ "$target" = all ]; then docker compose restart; else docker compose restart "$target"; fi ;;
  status)  need_docker; docker compose ps; echo; if has_bundle; then echo "Bundle: atlas/atlas.bundle.json present"; else echo "Bundle: none (run build <path>)"; fi ;;
  logs)    need_docker; if [ "$#" -gt 0 ]; then docker compose logs -f --tail 100 "$1"; else docker compose logs -f --tail 100; fi ;;
  build)
    need_docker
    [ "$#" -gt 0 ] || { echo "Usage: ./scripts/atlas.sh build <path-to-project>" >&2; exit 1; }
    src="$(cd "$1" && pwd)"; mkdir -p atlas
    ATLAS_SRC="$src" docker compose --profile tools run --rm build
    echo "Bundle written to atlas/atlas.bundle.json (viewer: atlas/viewer.html)."
    ;;
  key)     k="$(ensure_key)"; echo "ATLAS_MCP_API_KEY is set in .env (${#k} characters)." ;;
  mcp-config)
    k="$(ensure_key)"; url="http://127.0.0.1:$(port ATLAS_MCP_PORT 8000)/mcp"
    echo "URL:    $url"; echo "Header: Authorization: Bearer $k"; echo
    echo "Claude Code:"; echo "  claude mcp add --transport http code-atlas $url --header \"Authorization: Bearer $k\""
    echo "Generic JSON (clients with url + headers):"
    echo "  { \"mcpServers\": { \"code-atlas\": { \"url\": \"$url\", \"headers\": { \"Authorization\": \"Bearer $k\" } } } }"
    echo "More clients: docs/mcp-setup.md"
    ;;
  *) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//' ;;
esac
