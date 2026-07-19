# Frontend audit — 00 Overview

**Scope:** `/Users/mac/Projects/mine/provx/frontend` (Next.js 14 App Router web console) plus
`/Users/mac/Projects/mine/provx/packages/client` (`@provx/client`, TypeScript library).
**Date:** 2026-07-19 · **Stage:** pre-alpha / walking skeleton.

Eight hand-written source files total (7 in `frontend`, 1 in `packages/client`), plus config.
Every one was read end-to-end for this audit.

---

## 1. Stack & versions

Source: [package.json](../../frontend/package.json)

| Dependency | Range | Notes |
|---|---|---|
| `next` | `^14.2.5` | App Router. **Not** 15 — see the `params` migration risk, [F-04](99_FINDINGS.md#f-04). |
| `react` / `react-dom` | `^18.3.1` | React 18; no `use()` / React-19 APIs in play. |
| `typescript` | `^5.5.3` | `strict: true`. |
| `tailwindcss` | `^3.4.6` | v3, matching the `postcss.config.mjs` plugin shape. |
| `eslint` + `eslint-config-next` | `^8.57.0` / `^14.2.5` | extends `next/core-web-vitals`. |
| `autoprefixer` / `postcss` | `^10.4.19` / `^8.4.39` | standard Next + Tailwind pairing. |

**Runtime dependency count: 3.** No UI library, no state manager, no data-fetching library, no
date/icon/chart packages. For a security console this minimal surface is a genuine asset
(supply-chain footprint ≈ the framework itself) and is worth defending as long as possible.

**Zero test dependencies.** No `jest`, `vitest`, `@testing-library/*`, `playwright`, or
`cypress`; no `test` script. This is the largest gap in the repo — see
[99_FINDINGS.md § Test coverage gaps](99_FINDINGS.md#test-coverage-gaps).

### Scripts

```
dev        next dev -p 3000
build      next build
start      next start -p 3000
lint       next lint
typecheck  tsc --noEmit
```

No `test`. CI ([.github/workflows/ci.yml](../../.github/workflows/ci.yml)) runs
`frontend-types` (real, `tsc`) and `frontend-lint` (documented in the workflow header as a
**passing no-op stub**). The only automated signal on this repo today is the type checker.

### Config files

| File | Verdict |
|---|---|
| [next.config.mjs](../../frontend/next.config.mjs) | 6 lines. `reactStrictMode: true`, `output: "standalone"` (feeds the Docker runner stage). Clean. **No `headers()` block** → no CSP / HSTS / `X-Content-Type-Options` / `Referrer-Policy`. See [F-03](99_FINDINGS.md#f-03). |
| [tsconfig.json](../../frontend/tsconfig.json) | `strict: true`, `target: ES2022`, `moduleResolution: "bundler"`, `paths: {"@/*": ["./*"]}`. Missing `noUncheckedIndexedAccess` / `exactOptionalPropertyTypes` — [F-08](99_FINDINGS.md#f-08). |
| [tailwind.config.ts](../../frontend/tailwind.config.ts) | Content globs cover `./app/**` and `./components/**` (the latter does not exist yet — harmless, forward-looking). `theme.extend` empty, no plugins. No design tokens; W-NEXT-10 passes only because every color used is a Tailwind palette utility, never a hex literal. |
| [postcss.config.mjs](../../frontend/postcss.config.mjs) | Textbook `tailwindcss` + `autoprefixer`. |
| [.eslintrc.json](../../frontend/.eslintrc.json) | `next/core-web-vitals` only. No type-aware `@typescript-eslint` rules, no extra `jsx-a11y` beyond the Next preset. |
| [.dockerignore](../../frontend/.dockerignore) | Excludes `node_modules`, `.next`, `.env`, `.env.*`, `*.md`. Correctly keeps env files out of the image (PX-SECRETS). |
| [app/globals.css](../../frontend/app/globals.css) | 11 lines: three Tailwind directives, `color-scheme: light dark`, and a `body` `@apply` for light/dark surfaces. Dark mode is OS-driven only — no toggle, no `class` strategy. Declared scaffolding. |

---

## 2. File & route layout

```
frontend/
├── app/
│   ├── layout.tsx                          RootLayout + metadata   (entry point)
│   ├── page.tsx                            route  /                (static)
│   ├── globals.css
│   └── engagements/
│       └── [id]/
│           ├── page.tsx                    route  /engagements/[id]         (force-dynamic RSC)
│           ├── error.tsx                   client error boundary for the segment
│           ├── not-found.tsx               404 UI for the segment
│           └── report/
│               └── route.ts                route  /engagements/[id]/report  (GET handler, proxy)
├── lib/
│   └── api.ts                              server-only API access layer
├── public/.gitkeep                         (empty — no static assets, no favicon)
└── <config files>
```

**Routes: 3** (`/`, `/engagements/[id]`, `/engagements/[id]/report`). One page is *intentional* —
declared scaffolding per the README and CLAUDE.md project state.

**Absent by design (declared scaffolding, NOT defects):** authentication / session, an
engagement-creation UI (engagements are created via the API today), any design system or
component library, SWR / TanStack Query, styling polish, `middleware.ts`, `favicon.ico`,
`sitemap` / `robots`, i18n.

**Absent and arguably a gap (see findings):** any test runner, `loading.tsx`, a root
`app/error.tsx` / `app/not-found.tsx`, security response headers.

### Entry points

- **[app/layout.tsx](../../frontend/app/layout.tsx)** — the only layout. Exports `metadata`
  (`title: "Provx"` plus a one-line description) and a `RootLayout` rendering
  `<html lang="en"><body>{children}</body></html>`. No font loading (`next/font` unused →
  system font stack, which sidesteps PERF-06 rather than violating it), no providers, no nav
  chrome, no skip link.
- **[app/page.tsx](../../frontend/app/page.tsx)** — the `/` landing page. Pure static JSX; no
  data, no client boundary. Explains the walking-skeleton state and directs the operator to
  create an engagement via the API, then open `/engagements/<id>`.

---

## 3. Environment variables

**Exactly one:** `PROVX_API_BASE_URL`.

Read in two places, both server-side:
- [lib/api.ts:12](../../frontend/lib/api.ts#L12) — `process.env.PROVX_API_BASE_URL ?? "http://localhost:8000"`
- [packages/client/src/index.ts:10](../../packages/client/src/index.ts#L10) — the same expression, duplicated.

### Why it is deliberately NOT `NEXT_PUBLIC_`

A correct and load-bearing decision, documented in the code itself
([lib/api.ts:4-10](../../frontend/lib/api.ts#L4)) and in
[.env.example:23](../../.env.example#L23):

> `NEXT_PUBLIC_`: the API address must never ship in the browser bundle.

Consequences, all of them good:

1. Next.js inlines `NEXT_PUBLIC_*` into client chunks at build time. A non-prefixed var is
   `undefined` in the browser, so the backend address is *structurally* unreachable from
   client code — it cannot leak even by accident.
2. Under Docker the value is `http://backend:8000`, an internal Compose DNS name. A browser
   could not resolve it anyway — which is precisely *why* the report has to be proxied (see
   [01_ARCHITECTURE.md](01_ARCHITECTURE.md)).
3. No CORS surface is opened on the FastAPI service, because the browser never talks to it.
4. It supports PX-SECRETS: the web tier receives one non-secret address and nothing else.
   [docker-compose.yml:43-46](../../docker-compose.yml#L43) is explicit —
   *"The web tier needs only the API base URL; it must not receive backend secrets
   (SECRET_KEY, DATABASE_URL, POSTGRES_PASSWORD). No env_file here on purpose."*
   That is a deliberately narrow blast radius and is exactly right.

**Weakness:** the fallback `?? "http://localhost:8000"` means a production deploy with the var
unset silently points at localhost and fails at request time with a generic message, instead of
failing loudly at boot. See [F-06](99_FINDINGS.md#f-06).

---

## 4. Docker

[frontend/Dockerfile](../../frontend/Dockerfile) — 35 lines, three stages, one of the better-
reasoned files in the repo.

| Stage | Does |
|---|---|
| `deps` | `node:20.20.2-slim`; copies `package.json` + `package-lock.json`; `npm ci` (lockfile-exact, reproducible). |
| `builder` | Copies `node_modules` from `deps`, copies source, `npm run build`. |
| `runner` | `NODE_ENV=production`; copies `public/`, `.next/standalone`, `.next/static`; `USER node`; `EXPOSE 3000`; `HEALTHCHECK`; `CMD ["node","server.js"]`. |

Strengths:

- **Exact patch pin** `node:20.20.2-slim`, with a header comment explaining why it is *not*
  `@sha256`-pinned (digest pins break arm64/amd64 parity and need manual re-resolution on every
  bump), flagged as a pre-1.0 supply-chain item. Honest engineering, not hand-waving.
- **Non-root:** `USER node` in the runner ([Dockerfile:28](../../frontend/Dockerfile#L28)). The
  build stages run as root, which is conventional and acceptable since they are discarded.
- **`output: "standalone"`** keeps the final image to the traced dependency set only — build
  toolchain and full `node_modules` never reach the runtime layer.
- **HEALTHCHECK** ([Dockerfile:32-33](../../frontend/Dockerfile#L32)) in exec form using Node 20's
  global `fetch`, so no `curl`/`wget` is added to the image. `--start-period=15s` accommodates
  Next boot.
- Compose gates the frontend on `depends_on: backend: condition: service_healthy`.

Gaps: the healthcheck probes `/`, which is static — it proves the Node process is alive but not
that the backend link works. Acceptable for a liveness probe; worth noting. `--omit=dev` is
absent, but `standalone` output makes that moot for the runtime image.

---

## 5. Sections index

| File | Covers |
|---|---|
| [00_OVERVIEW.md](00_OVERVIEW.md) | This file — stack, layout, env, Docker. |
| [01_ARCHITECTURE.md](01_ARCHITECTURE.md) | Rendering strategy, data flow, the proxy rationale, error layering, the `packages/client` relationship. |
| [section_app.md](section_app.md) | Every route: `/`, `/engagements/[id]`, `error.tsx`, `not-found.tsx`, the report route handler. |
| [section_lib.md](section_lib.md) | `lib/api.ts` — every export with signature. |
| [section_client_package.md](section_client_package.md) | `packages/client` (`@provx/client`). |
| [99_FINDINGS.md](99_FINDINGS.md) | Findings by severity + Performance / Web Vitals + Test coverage gaps. |
