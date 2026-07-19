# SPDX-License-Identifier: Apache-2.0
# Provx frontend - builds and runs independently of the rest of the monorepo.
# Multi-stage build producing a small Next.js standalone runtime image.
#
# Pinned to an exact patch release. Not @sha256-pinned: a digest has to be re-resolved by
# hand on every base bump and pins a single architecture, which breaks arm64/amd64 parity
# between dev machines and CI. Revisit as a pre-1.0 supply-chain hardening step.

FROM node:20.20.2-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:20.20.2-slim AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:20.20.2-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

# Drop root: the official node image ships an unprivileged `node` user.
USER node

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["node", "-e", "fetch('http://localhost:3000/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

CMD ["node", "server.js"]
