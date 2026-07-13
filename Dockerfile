# Multi-stage build for the AVA Pay /verify API.
# Final image is ~150MB and runs on Node 22 Alpine.

FROM node:22-alpine AS builder
WORKDIR /app

# Install all workspace dependencies (root + packages/agent-sdk).
COPY package.json package-lock.json* ./
COPY packages/agent-sdk/package.json ./packages/agent-sdk/
RUN npm ci --no-audit --no-fund --workspaces --include-workspace-root

# Build the SDK package first (other code resolves @ava-pay/agent through it).
COPY packages/agent-sdk/tsconfig.json ./packages/agent-sdk/
COPY packages/agent-sdk/src ./packages/agent-sdk/src
RUN npm run build -w @ava-pay/agent

# Build the API.
COPY tsconfig.json ./
COPY src ./src
RUN npx tsc -p tsconfig.json

FROM node:22-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0

# su-exec lets the entrypoint fix volume ownership as root, then drop to `node`.
RUN apk add --no-cache su-exec

# Bring over package manifests and install production deps for the workspace.
COPY package.json package-lock.json* ./
COPY packages/agent-sdk/package.json ./packages/agent-sdk/
RUN npm ci --omit=dev --no-audit --no-fund --workspaces --include-workspace-root && npm cache clean --force

# Copy compiled output: SDK dist + API dist.
COPY --from=builder /app/packages/agent-sdk/dist ./packages/agent-sdk/dist
COPY --from=builder /app/dist ./dist

# Static landing page assets.
COPY public ./public

# Entrypoint fixes volume ownership (as root) then drops to `node`.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=2s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:${PORT}/healthz || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["node", "dist/src/index.js"]
