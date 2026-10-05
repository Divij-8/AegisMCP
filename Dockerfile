# AegisMCP gateway image.
#
# Builds the whole pnpm workspace (protocol + apps) and runs the gateway as a
# non-root user. The gateway applies forward-only migrations on startup, so the
# container needs DATABASE_URL and network access to PostgreSQL.
FROM node:24-slim

# Node's built-in corepack provides pnpm; pin via the packageManager field if set.
RUN corepack enable

WORKDIR /app

# Install dependencies first for better layer caching.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/gateway/package.json apps/gateway/
COPY apps/mock-mcp-server/package.json apps/mock-mcp-server/
COPY packages/protocol/package.json packages/protocol/
COPY tests/integration/package.json tests/integration/
RUN pnpm install --frozen-lockfile

# Build sources.
COPY . .
RUN pnpm --filter @aegis/protocol run build \
  && pnpm --filter @aegis/gateway run build \
  && pnpm --filter @aegis/mock-mcp-server run build

ENV NODE_ENV=production
EXPOSE 3000

# Never run as root.
USER node

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "apps/gateway/dist/index.js"]
