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
#   --project NAME        (any command) an independent MCP server for another codebase: own bundle folder
#                         atlas/NAME, own port, same image and key. e.g. build /path/to/app --project myapp
#   tunnel-url            print the MCP URL with the key embedded (needs ATLAS_ALLOW_URL_KEY=1)
set -eu
cd "$(dirname "$0")/.."

PLACEHOLDER="replace-with-64-random-hex-characters"

# --project NAME (anywhere): run an independent MCP server for another codebase next to the default
# one: own bundle folder atlas/NAME, own port, compose project code-atlas-NAME (same image and key).
PROJECT=""; n=$#; i=0
while [ "$i" -lt "$n" ]; do
  a="$1"; shift; i=$((i + 1))
  if [ "$a" = "--project" ]; then PROJECT="${1:-}"; [ "$#" -gt 0 ] && { shift; i=$((i + 1)); }; else set -- "$@" "$a"; fi
done

cmd="${1:-help}"; [ "$#" -gt 0 ] && shift
if [ -n "$PROJECT" ]; then target="${1:-mcp}"; else target="${1:-all}"; fi

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
dc() { if [ -n "$PROJECT" ]; then docker compose -p "code-atlas-$PROJECT" "$@"; else docker compose "$@"; fi; }
project_port() {
  key="ATLAS_MCP_PORT_$(printf '%s' "$1" | tr 'a-z-' 'A-Z_')"
  v="$(env_value "$key")"; if [ -n "$v" ]; then printf '%s' "$v"; return; fi
  base="$(env_value ATLAS_MCP_PORT)"; max="${base:-8000}"
  for q in $(sed -n 's/^[[:space:]]*ATLAS_MCP_PORT_[A-Z0-9_]*[[:space:]]*=[[:space:]]*//p' .env 2>/dev/null | tr -d '\r'); do [ "$q" -gt "$max" ] && max="$q"; done
  new=$((max + 1)); [ -f .env ] || cp .env.example .env; printf '%s=%s\n' "$key" "$new" >> .env; printf '%s' "$new"
}
DATA="atlas"
if [ -n "$PROJECT" ]; then
  case "$PROJECT" in ""|*[!a-z0-9-]*|-*) echo "--project must be lowercase letters, digits and dashes (e.g. myapp)." >&2; exit 1;; esac
  DATA="atlas/$PROJECT"; export ATLAS_DATA_DIR="./atlas/$PROJECT"; ATLAS_MCP_PORT="$(project_port "$PROJECT")"; export ATLAS_MCP_PORT
fi
ensure_image() { docker image inspect code-atlas:local >/dev/null 2>&1 || { echo "Building the Code Atlas image (first run only; takes a minute or two)..."; dc build; }; }
has_bundle() { [ -f "$DATA/atlas.bundle.json" ]; }
mcp_port() { if [ -n "$PROJECT" ]; then printf '%s' "$ATLAS_MCP_PORT"; else port ATLAS_MCP_PORT 8000; fi; }
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
    dc up -d $svcs
    case "$svcs" in *app*) echo "App:  http://127.0.0.1:$(port ATLAS_APP_PORT 4173)";; esac
    case "$svcs" in *mcp*) echo "MCP:  http://127.0.0.1:$(mcp_port)/mcp   (run 'mcp-config' for client settings)";; esac
    ;;
  rebuild) need_docker; dc build; echo "Image rebuilt. Run restart to use it." ;;
  stop)    need_docker; dc down ;;
  restart)
    # Recreate, don't `docker compose restart`: restart keeps the OLD image and OLD environment,
    # so a rebuilt image or an edited .env would silently not take effect.
    need_docker
    svcs=""
    case "$target" in app|all) svcs="app";; esac
    case "$target" in mcp|all) if has_bundle; then ensure_key >/dev/null; svcs="$svcs mcp"; fi;; esac
    [ -n "$svcs" ] || { echo "Nothing to restart (use app, mcp or all; mcp needs a bundle)." >&2; exit 1; }
    # shellcheck disable=SC2086
    dc up -d --force-recreate $svcs
    ;;
  status)  need_docker; dc ps; echo; if has_bundle; then echo "Bundle: $DATA/atlas.bundle.json present"; else echo "Bundle: none (run build <path>)"; fi ;;
  logs)    need_docker; if [ "$#" -gt 0 ]; then dc logs -f --tail 100 "$1"; else dc logs -f --tail 100; fi ;;
  build)
    need_docker
    [ "$#" -gt 0 ] || { echo "Usage: ./scripts/atlas.sh build <path-to-project>" >&2; exit 1; }
    src="$(cd "$1" && pwd)"; mkdir -p "$DATA"
    ATLAS_SRC="$src" ATLAS_LABEL="${PROJECT:-$(basename "$src")}" dc --profile tools run --rm build
    echo "Bundle written to $DATA/atlas.bundle.json (viewer: $DATA/viewer.html)."
    ;;
  tunnel-url)
    k="$(ensure_key)"
    [ "$(env_value ATLAS_ALLOW_URL_KEY)" = 1 ] || { echo "URL keys are off. Add ATLAS_ALLOW_URL_KEY=1 to .env, then: ./scripts/atlas.sh restart mcp" >&2; exit 1; }
    echo "http://127.0.0.1:$(mcp_port)/mcp?key=$k"
    echo "This URL contains your key: use it only in a client running on this machine (docs/mcp-setup.md)." >&2
    ;;
  key)     k="$(ensure_key)"; echo "ATLAS_MCP_API_KEY is set in .env (${#k} characters)." ;;
  mcp-config)
    k="$(ensure_key)"; url="http://127.0.0.1:$(mcp_port)/mcp"; srv="code-atlas"; [ -n "$PROJECT" ] && srv="atlas-$PROJECT"
    echo "URL:    $url"; echo "Header: Authorization: Bearer $k"; echo
    echo "Claude Code:"; echo "  claude mcp add --transport http --scope user $srv $url --header \"Authorization: Bearer $k\""
    echo "Generic JSON (clients with url + headers):"
    echo "  { \"mcpServers\": { \"$srv\": { \"url\": \"$url\", \"headers\": { \"Authorization\": \"Bearer $k\" } } } }"
    echo "More clients: docs/mcp-setup.md"
    ;;
  *) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//' ;;
esac
