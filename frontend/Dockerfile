# SPDX-License-Identifier: Apache-2.0
# Provx frontend — builds and runs independently of the rest of the monorepo.
# Multi-stage build producing a small Next.js standalone runtime image.

FROM node:20-slim AS deps
WORKDIR /app
COPY package.json ./
# No lockfile yet at the skeleton stage; install then let CI/Renovate add one later.
RUN npm install

FROM node:20-slim AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:20-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
EXPOSE 3000
CMD ["node", "server.js"]
