#!/bin/sh
# Code Atlas container entrypoint. Usage: entrypoint.sh <mode> [args...]
set -eu

BUNDLE="${ATLAS_BUNDLE:-/data/atlas.bundle.json}"
APP_PORT="${ATLAS_APP_PORT:-4173}"
MCP_PORT="${ATLAS_MCP_PORT:-8000}"

need_bundle() {
  if [ ! -f "$BUNDLE" ]; then
    echo "No bundle found at $BUNDLE." >&2
    echo "Build one first:  docker compose run --rm build   (see docs/docker.md)" >&2
    exit 66
  fi
}

mode="${1:-app}"
[ "$#" -gt 0 ] && shift

case "$mode" in
  app)
    # Binds all container interfaces; the compose file publishes the port on the
    # host's 127.0.0.1 only, which is what keeps the app private.
    exec node dist/cli.js serve --host 0.0.0.0 --allow-remote --port "$APP_PORT"
    ;;
  mcp)
    if [ -z "${ATLAS_MCP_API_KEY:-}" ]; then
      echo "ATLAS_MCP_API_KEY is not set. Put a random 32+ character secret in .env" >&2
      echo "(scripts/atlas.ps1 key  /  scripts/atlas.sh key  creates one)." >&2
      exit 64
    fi
    need_bundle
    exec node dist/mcp/server.js --http --host 0.0.0.0 --allow-remote --port "$MCP_PORT" --bundle "$BUNDLE" "$@"
    ;;
  mcp-stdio)
    need_bundle
    exec node dist/mcp/server.js --bundle "$BUNDLE" "$@"
    ;;
  plan)
    # Split a mounted source tree into shards (prints the plan; builds nothing).
    exec node dist/cli.js plan /src "$@"
    ;;
  correlate)
    # Read-only join of the bundle's code routes with a saved SurfaceTrace campaign index (see docs/surfacetrace.md).
    exec node dist/cli.js correlate "$@"
    ;;
  build)
    # Source is mounted read-only at /src; output goes to /data.
    # ATLAS_LABEL names the project in the bundle (otherwise it would be called "src", the mount name).
    # ATLAS_INCLUDE / ATLAS_SKIP (comma-separated) restrict the scan to a shard of a large repo.
    set -- "$@"
    [ -n "${ATLAS_LABEL:-}" ] && set -- --label "$ATLAS_LABEL" "$@"
    [ -n "${ATLAS_INCLUDE:-}" ] && set -- --include "$ATLAS_INCLUDE" "$@"
    [ -n "${ATLAS_SKIP:-}" ] && set -- --skip "$ATLAS_SKIP" "$@"
    exec node dist/cli.js build /src --out /data "$@"
    ;;
  *)
    exec "$mode" "$@"
    ;;
esac
