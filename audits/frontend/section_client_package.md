# Frontend audit — `packages/client` (`@provx/client`)

A four-file package containing one exported constant. Audited here rather than in its own folder
because there is not enough of it to warrant one.

Path: `/Users/mac/Projects/mine/provx/packages/client`

```
packages/client/
├── package.json
├── tsconfig.json
├── README.md
└── src/index.ts        ← 11 lines, 1 export
```

---

## `src/index.ts`

[Source](../../packages/client/src/index.ts) · 11 lines

```ts
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Solomon Nii Amu Darku

/**
 * Provx API client - placeholder.
 *
 * The real client is generated from the backend OpenAPI schema once it stabilizes.
 * For now this exports the default API base URL so the frontend can wire against it.
 */
export const PROVX_API_BASE_URL =
  process.env.PROVX_API_BASE_URL ?? "http://localhost:8000";
```

### Exports

| Export | Signature | Notes |
|---|---|---|
| `PROVX_API_BASE_URL` | `const … : string` | The env var with a localhost fallback. Byte-identical to [frontend/lib/api.ts:12](../../frontend/lib/api.ts#L12). |

That is the entire public surface: **one constant, zero functions, zero types.** It is honest
about being a placeholder, and the docblock states the intended future (generated from
`/openapi.json`). No dead code, no half-built abstraction, no speculative interfaces. As
placeholders go this is the right kind — it reserves the name and the package boundary without
committing to a design that will be replaced.

### Issues

1. **`process.env` in a package that advertises browser use.**
   [tsconfig.json:6](../../packages/client/tsconfig.json#L6) sets `"lib": ["ES2022", "DOM"]` and
   [L11](../../packages/client/tsconfig.json#L11) sets `"types": ["node"]` — the package claims
   both environments simultaneously. But `process.env` **does not exist in a browser**. If a
   third-party integration (an advertised use case, per the README) imported this into
   browser-bundled code without a `process` shim, it throws `ReferenceError: process is not
   defined` at module load. The `DOM` lib entry actively invites that mistake.
   **Fix:** either drop `DOM` from `lib` and declare the package Node-only, or guard the read
   (`typeof process !== "undefined" ? … : default`). Since the whole *point* of not using
   `NEXT_PUBLIC_` is that the API address must never be in a browser bundle
   ([00_OVERVIEW.md §3](00_OVERVIEW.md#3-environment-variables)), the Node-only answer is the
   consistent one — and it should be stated explicitly, because a future contributor reading
   `"DOM"` will reasonably assume browser support is intended.
   → [F-13](99_FINDINGS.md#f-13).

2. **Not consumed by anything.** No importer exists anywhere in the monorepo. It is dead code by
   the strict definition — deliberately so, as a reserved package boundary. Acceptable, but it
   means the CI `client` path filter guards a package that nothing depends on.

3. **Duplicated constant.** Same two lines as the frontend. See
   [01_ARCHITECTURE.md §5](01_ARCHITECTURE.md#5-relationship-to-packagesclient) for why leaving
   them unlinked is currently the right call, and [F-09](99_FINDINGS.md#f-09) for the drift risk.

---

## `package.json`

[Source](../../packages/client/package.json)

```json
{ "name": "@provx/client", "version": "0.0.0", "private": true, "type": "module",
  "main": "src/index.ts", "types": "src/index.ts",
  "scripts": { "typecheck": "tsc --noEmit", "lint": "echo \"[stub] no lint configured yet\"" },
  "devDependencies": { "typescript": "^5.5.3" } }
```

- `"private": true` — correct; nothing should be publishable at `0.0.0` with one constant.
- `"type": "module"` — ESM. Consistent with the rest of the repo.
- **`"main": "src/index.ts"` points at raw TypeScript.** No build step, no `dist/`, no `exports`
  map. Any consumer must compile it themselves, which works for a TS-native workspace consumer
  and fails for anyone else. Fine for an unpublished placeholder; must change before the README's
  promise of *"available to third-party integrations and CI tooling"* is real — that requires a
  build (`tsup`/`tsc -b`), an `exports` map with `import`/`require`/`types` conditions, and
  emitted `.d.ts`.
- **`"lint"` is a self-declared stub** (`echo "[stub] no lint configured yet"`) — it exits 0, so
  the CI lint gate for this package is a no-op that reports green. At least it is labelled as
  such in the script text rather than silently absent. **No ESLint config file exists in the
  package.**
- **No `test` script and no test framework** — same gap as the frontend. With one constant there
  is nothing meaningful to test today, so this is only a problem the moment real client code
  lands. It should not land without the harness already in place.
- License and author present. Apache-2.0 matches the repo (PX-LICENSE consistent).
- `apiVersion`/`engines` absent — minor.

---

## `tsconfig.json`

[Source](../../packages/client/tsconfig.json)

`target: ES2022`, `module: esnext`, `moduleResolution: bundler`, `lib: ["ES2022","DOM"]`,
`strict: true`, `noEmit: true`, `esModuleInterop`, `skipLibCheck`, `types: ["node"]`,
`include: ["src/**/*.ts"]`.

- **`strict: true`** — good, matches the frontend.
- **`noEmit: true`** with `"main": "src/index.ts"` is internally consistent *today* (the package
  is source-only and never built), but the combination is exactly what has to change when the
  package becomes real: `noEmit` must become `declaration + outDir`, and `main` must point at
  the build output.
- **`types: ["node"]` but no `@types/node` in `devDependencies`.** `tsc --noEmit` in this package
  resolves `@types/node` only by hoisting from another workspace package's `node_modules` — and
  there is no root workspace, so in a clean per-package install this **fails**. Either add
  `@types/node` as a devDependency or drop `types: ["node"]`. Small, but it means the one real CI
  gate on this package (`typecheck`) is not reliably runnable in isolation.
  → [F-13](99_FINDINGS.md#f-13).
- **`lib` includes `DOM`** — see issue 1 above.
- `moduleResolution: "bundler"` implies the consumer bundles it. Consistent with the source-only
  `main`, inconsistent with a package intended for standalone Node CI tooling.

---

## `README.md`

[Source](../../packages/client/README.md) — accurate and appropriately scoped. States the Phase-1
skeleton status plainly, and the intended shape: generated from `/openapi.json`, thin ergonomic
wrappers for engagements/scans/findings/reports, published for CI/CD security gates
(ROADMAP §6, the `POST /scan` milestone). It does not oversell what exists. Good.

---

## Verdict

Nothing here is *wrong* in a way that matters today — it is 11 lines of honest placeholder with
correct licensing and a clear stated plan. The findings are all forward-looking:

- the `DOM` lib + `process.env` combination is a trap that will bite the first browser consumer;
- `types: ["node"]` without `@types/node` makes the sole CI gate non-hermetic;
- the source-only `main` + `noEmit` must be replaced by a real build before the README's
  third-party-consumer promise can be met;
- the `lint` stub reports green while checking nothing.

The most important decision about this package is not in the package: it is whether
`frontend/lib/api.ts` eventually becomes a wrapper over it, or stays an independent second
implementation of the API contract. See
[01_ARCHITECTURE.md §5](01_ARCHITECTURE.md#5-relationship-to-packagesclient).
