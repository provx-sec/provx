# Frontend audit — 01 Architecture

How the Provx web console is put together, and whether the shape holds up.

---

## 1. Rendering strategy

Three routes, three different rendering modes — and each choice is the right one.

| Route | Mode | Why |
|---|---|---|
| `/` | Static (prerendered at build) | [app/page.tsx](../../frontend/app/page.tsx) is pure JSX with no data, no hooks, no client boundary. Next statically prerenders it. Zero server work per request. |
| `/engagements/[id]` | **Dynamic Server Component** — `export const dynamic = "force-dynamic"` ([page.tsx:8](../../frontend/app/engagements/[id]/page.tsx#L8)) | Findings are live engagement state. Caching them would be actively harmful in a security tool: an operator must never see a stale finding set after a scan completes. |
| `/engagements/[id]/report` | Route Handler (`GET`) | Not a page — it streams HTML produced by the backend. |

**There is not a single `"use client"` in the app except [error.tsx](../../frontend/app/engagements/[id]/error.tsx#L3)**, where React requires it for an error boundary. That is exactly the discipline W-NEXT-06 asks for: client boundaries only where genuinely needed. The consequence is that the shipped client JS is the React/Next runtime plus one tiny button handler — nothing else.

### On `force-dynamic` and belt-and-braces caching

`getFindings` already passes `{ cache: "no-store" }`
([lib/api.ts:61](../../frontend/lib/api.ts#L61)), which in Next 14 alone is enough to opt the
route into dynamic rendering. The explicit `force-dynamic` is therefore redundant *in
mechanism* but valuable *in intent*: it is a declaration at the top of the file that this route
is never cached, and it survives a future refactor that changes the fetch options. Keep it.

Tension with PERF-08 (*"public read-only SSR data is cached (ISR), not refetched per request"*)
and PERF-12 (TTFB): both are **correctly not applicable here**. Findings are neither public nor
read-only-stable; freshness beats TTFB for this data class. The right optimization is not ISR —
it is `<Suspense>` streaming so the page shell reaches the browser before the API responds. See
[99_FINDINGS.md § Performance](99_FINDINGS.md#performance--web-vitals).

---

## 2. Data flow

### Findings page

```
Browser
  │  GET /engagements/<uuid>
  ▼
Next.js server (Node, port 3000)
  │  EngagementFindingsPage (RSC)
  │    └─ getFindings(params.id)          lib/api.ts
  │         ├─ isEngagementId() gate      ← rejects before any network call
  │         └─ fetch(PROVX_API_BASE_URL + /engagements/<id>/findings, no-store)
  ▼
FastAPI backend (http://backend:8000, Compose-internal DNS)
  │  JSON: Finding[]
  ▼
Next.js server — renders the table to HTML
  ▼
Browser receives fully-rendered HTML. No client fetch. No API address in the bundle.
```

The key property: **the browser never learns the API exists.** No `NEXT_PUBLIC_` var, no
client-side `fetch`, no CORS preflight, no API token in a client store. For a product whose own
positioning is "governed, auditable, safe by default", having the web tier be a pure rendering
proxy with a single narrow egress path is architecturally consistent with the pitch.

### Report

```
Browser  GET /engagements/<uuid>/report
   → Next route handler  (validate id → fetch upstream → re-emit as text/html)
   → FastAPI  GET /engagements/<uuid>/report
```

---

## 3. Why the report is proxied same-origin rather than linked directly

[lib/api.ts:78-86](../../frontend/lib/api.ts#L78) returns a *relative* path,
`/engagements/<id>/report`, and the anchor in
[page.tsx:50-56](../../frontend/app/engagements/[id]/page.tsx#L50) uses it directly. The reason
is stated in the code and it is correct:

> *"Same-origin on purpose: the browser cannot resolve the API's internal address, so the report is served through this app's proxy route."*

Four reasons this is the right call, in increasing order of importance:

1. **It is the only thing that works.** In Compose, `PROVX_API_BASE_URL` is
   `http://backend:8000` — a network-internal name with no DNS entry the browser can resolve.
   A direct link would 404 in the address bar. In a real deployment the backend is on a private
   subnet with no ingress at all.
2. **It preserves the "API address never reaches the browser" invariant.** Emitting an absolute
   upstream URL into an `href` would leak the internal topology into the page source — a
   reconnaissance gift, and exactly the disclosure the `NEXT_PUBLIC_` decision exists to
   prevent.
3. **It creates the one place auth will live.** When sessions land, the report is a
   *client-confidential document*. Same-origin means the session cookie is present on the
   request, and the handler is the natural chokepoint for the session check, ownership check,
   and rate limit. The code says so itself
   ([route.ts:17-19](../../frontend/app/engagements/[id]/report/route.ts#L17)): *"when auth lands this handler is where the session check and rate limit belong (rule S-08)."*
4. **Same-origin keeps the report inside the app's future CSP and cookie scope**, rather than
   being a cross-origin document with its own trust context.

The alternative — exposing the FastAPI service publicly and linking it — would mean CORS,
duplicated auth, and a second public attack surface. Proxying is strictly better.

### Cost of the choice

[route.ts:48](../../frontend/app/engagements/[id]/report/route.ts#L48) does
`await upstream.text()` — the entire report is buffered into the Node process's memory before a
byte reaches the browser. For a walking-skeleton report this is fine; for a 500-finding
engagement report it is a latency and memory regression that streaming
(`new Response(upstream.body, ...)`) removes for free. See [F-07](99_FINDINGS.md#f-07).

---

## 4. Error handling layering

Three distinct mechanisms, cleanly separated by *what kind of wrong* occurred. This is the most
thoughtful part of the codebase.

| Failure | Path | User sees | Rules |
|---|---|---|---|
| Malformed id (not a UUID) | `isEngagementId` fails → `EngagementNotFoundError` → caught in page → `notFound()` | `not-found.tsx`: "Engagement not found" | PX-ERRORS, S-13 |
| Unknown id (backend 404) | upstream 404 → `EngagementNotFoundError` → `notFound()` | **identical** "Engagement not found" | PX-ERRORS |
| Backend 5xx / unreachable / network throw | generic `Error` rethrown | `error.tsx`: "Could not load findings" + *Try again* | W-NEXT-03, W-NEXT-09, S-13 |
| Report: malformed or unknown id | handler returns 404 `text/plain` "Report unavailable." | plain 404 | PX-ERRORS |
| Report: upstream 5xx | handler returns 502 "Report unavailable." | plain 502 | S-13 |

Three properties worth calling out:

**(a) 404 and 400 are deliberately indistinguishable.** [not-found.tsx:8-9](../../frontend/app/engagements/[id]/not-found.tsx#L8) states the intent: *"Deliberately says the same thing in both cases, so the page never reveals what shape a valid id has."* Malformed-vs-unknown collapsing removes an id-format oracle. For a security product this is the correct paranoia level.

**(b) The error boundary is reserved for real failures.** [page.tsx:21-22](../../frontend/app/engagements/[id]/page.tsx#L21) explains that a bad id is a 404, not an error screen. That distinction — *"you asked for something that isn't there"* vs *"we broke"* — is the one most apps get wrong.

**(c) No upstream detail is ever rendered.** `error.tsx` accepts the `error` prop in its type signature but destructures **only `reset`** ([error.tsx:11](../../frontend/app/engagements/[id]/error.tsx#L11)), so there is no code path by which an error message could reach the DOM. The real status is logged server-side via `console.error` ([api.ts:69](../../frontend/lib/api.ts#L69), [route.ts:36](../../frontend/app/engagements/[id]/report/route.ts#L36)). S-13 / W-NEXT-09 / PX-ERRORS all satisfied.

### The layering gap

The boundaries exist **only on the `engagements/[id]` segment**. There is no `app/error.tsx`
and no `app/not-found.tsx`. A thrown error in the root layout, or a request to any unmatched
path (`/foo`), falls through to Next's built-in default — a bare, unbranded error page. In
production Next's default 500 leaks nothing, so this is a polish/consistency issue rather than a
disclosure one, but W-NEXT-03 reads *"every route segment"*. See [F-05](99_FINDINGS.md#f-05).

---

## 5. Relationship to `packages/client`

**`@provx/client` is not a dependency of the frontend.** Verified: it appears nowhere in
[frontend/package.json](../../frontend/package.json), there is no `workspaces` field at the repo
root, no `pnpm-workspace.yaml`, no path alias to it in
[tsconfig.json](../../frontend/tsconfig.json), and no import of it in any `app/` or `lib/` file.
The two are entirely unlinked.

The observable overlap is a **duplicated constant**:

```ts
// frontend/lib/api.ts:12          and         packages/client/src/index.ts:10
export const PROVX_API_BASE_URL =
  process.env.PROVX_API_BASE_URL ?? "http://localhost:8000";
```

Byte-identical, in two packages, with no link between them.

### Assessment — is the non-linkage a problem?

**No, and it is arguably the correct call right now.** Reasons:

- `packages/client` contains **one exported constant** and nothing else. Depending on it would
  buy the frontend zero functionality while adding a workspace-resolution requirement to the
  Docker build — and the current Dockerfile's biggest virtue is that it *"builds and runs
  independently of the rest of the monorepo"* ([Dockerfile:2](../../frontend/Dockerfile#L2)).
  Linking an unbuilt, `"main": "src/index.ts"` TypeScript-source package would force either a
  monorepo-wide build context or a prebuild step. That is real cost for no gain.
- The client's own README is explicit that the real surface arrives generated from the backend
  OpenAPI schema. Wiring a consumer to a placeholder now would mean rewiring it later anyway.
- DRY (rule Q-11) is *technically* violated by the duplicated constant, but a 2-line env-read
  with an obvious default is below the threshold where deduplication pays. Deduplicating it
  today would couple two packages to save two lines.

**The real risk is drift**, and it is a *when*, not an *if*: the moment the client gains auth
headers, retry policy, or error normalization, the frontend's hand-rolled `lib/api.ts` will
diverge from it, and the console will behave differently from every CI/CD consumer of the same
API. Two implementations of "how to talk to Provx" is a correctness hazard for a product that
sells reproducibility.

**Recommendation:** leave them unlinked until the backend OpenAPI schema stabilizes; then make
`lib/api.ts` a thin server-side wrapper over `@provx/client` rather than an independent client,
and add a root workspace + a Docker build context that can see it. Tracked as
[F-09](99_FINDINGS.md#f-09) (Low). Do not do it now.

---

## 6. Architectural verdict

The shape is sound and unusually disciplined for a pre-alpha skeleton: server-only data access,
one narrow egress path, no client-side API surface, an id gate before any network call, a
deliberate 404/400 collapse, and no upstream detail in the UI. The weaknesses are all
*additive* — missing tests, missing headers, missing streaming — not structural. Nothing here
needs to be undone to grow the console out.
