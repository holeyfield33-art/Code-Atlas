# Code Atlas container. One image, several modes (see docker/entrypoint.sh):
#   app        local web app with "Open folder"            (port 4173)
#   mcp        authenticated, read-only Streamable HTTP MCP (port 8000)
#   mcp-stdio  MCP over stdin/stdout, for `docker run -i` clients
#   build      scan a mounted source tree into /data
#
# Node 22: isolated-vm (the atlas_exec sandbox) is a native module that must be
# compiled for the exact Node it runs on; Node 24 did not build in our testing.

FROM node:22-bookworm-slim AS build
# Compiler toolchain for isolated-vm. Stays in this stage only.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY scripts ./scripts
COPY src ./src
COPY viewer ./viewer
RUN npm run build && npm prune --omit=dev

FROM node:22-bookworm-slim
ENV NODE_ENV=production \
    ATLAS_BUNDLE=/data/atlas.bundle.json
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/viewer ./viewer
COPY package.json ./
COPY docker/entrypoint.sh ./docker/entrypoint.sh
# /data holds bundles (mount a host folder here); the base image's non-root `node`
# user (uid 1000) owns it. Nothing in the image runs as root.
RUN mkdir -p /data && chown node:node /data && chmod +x docker/entrypoint.sh
USER node
VOLUME ["/data"]
EXPOSE 4173 8000
ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["app"]
