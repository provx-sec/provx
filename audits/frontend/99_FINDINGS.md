# Frontend audit — 99 Findings

Covers `frontend/` and `packages/client/`. Pre-alpha walking skeleton; severities are calibrated
to *"what must be true before this is exposed beyond localhost"*, not to a shipping product.

**Deliberately excluded as declared scaffolding, not defects:** authentication/session,
engagement-creation UI, styling polish, a design system, SWR/TanStack Query, having only one
page.

## Summary

| Sev | Count | IDs |
|---|---|---|
| Critical | 0 | — |
| High | 2 | [F-01](#f-01), [F-TEST](#test-coverage-gaps) |
| Medium | 5 | [F-02](#f-02), [F-03](#f-03), [F-04](#f-04), [F-06](#f-06), [F-12](#f-12) |
| Low | 6 | [F-05](#f-05), [F-07](#f-07), [F-08](#f-08), [F-09](#f-09), [F-10](#f-10), [F-13](#f-13) |
| Info | 1 | [F-11](#f-11) |

**Zero XSS findings. Zero PX-rule violations. Zero open-proxy/SSRF exposure.** All three were
checked hard; see the passes section at the bottom.

---

## Critical

None.

---

## High

### F-01
**Report proxy has no auth, no origin check, and no rate limit (S-08)**
[route.ts:21](../../frontend/app/engagements/[id]/report/route.ts#L21)

Any client that can reach port 3000 and supplies a valid engagement UUID receives a full
client-confidential pentest report. The only control is UUIDv4 unguessability. There is likewise
no rate limit, so an unauthenticated caller can drive unbounded backend report renders — cheap
amplification once exposed.

This is **accepted and documented** today: the upstream is unauthenticated in the walking
skeleton, so a frontend check would guard nothing, and the code names this handler as where the
session check belongs ([route.ts:17-19](../../frontend/app/engagements/[id]/report/route.ts#L17)).
It is High not because it is wrong now, but because it is the item that must not be forgotten —
the blast radius is "third-party pentest findings for a named client".

**Fix:** when sessions land, in this handler: (1) require a valid session; (2) authorize the
session against *this* engagement (ownership, not just authentication); (3) per-IP/per-user rate
limit; (4) add `Cache-Control: no-store` and a `Content-Disposition` so the confidential document
is not cached by intermediaries. Do not ship an externally-reachable deployment before (1)–(3).

---

## Medium

### F-02
**No `loading.tsx` on the dynamic segment (Q-16, PERF-07, PERF-12)**
`app/engagements/[id]/` — file absent

With `force-dynamic` and no Suspense boundary, a hard navigation (pasted URL or refresh) shows
**nothing** until the full backend round-trip completes; FCP is gated on backend latency with no
floor. A soft navigation from `/` blocks the transition entirely, so the click feels dead.

Assessed honestly rather than pedantically: the specific failure modes Q-16 targets (an
`isLoading` flag never surfaced, a stale value left on screen, a submit button with no busy
state) genuinely do not exist here, because there is no client-side async at all. But PERF-12
names the fix explicitly — *"stream non-critical sections via `<Suspense>` so the shell's first
byte isn't blocked"* — and a `loading.tsx` is what gives Next a boundary to stream against.

**Fix:** add `app/engagements/[id]/loading.tsx` rendering the same header block **and the
PX-HUMAN banner** as real text (PERF-02 — a skeleton of grey boxes is not an FCP candidate),
plus table-row skeletons at the real row height (PERF-11, no CLS on swap). Extract the header
into a shared component so the two states cannot drift. ~20 lines.

### F-03
**No security response headers; report HTML served same-origin with no CSP**
[next.config.mjs](../../frontend/next.config.mjs) — no `headers()`;
[route.ts:48-51](../../frontend/app/engagements/[id]/report/route.ts#L48)

There is no CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy`, or `Permissions-Policy`
anywhere in the app.

This matters most on the report route, which serves **backend-generated HTML embedding untrusted
scan output in the console's own origin**. Currently mitigated upstream: the backend uses Jinja
`select_autoescape(default=True, default_for_string=True)`
([report.py:31](../../backend/app/services/report.py#L31)), so it is **safe today**. But the
frontend has zero defence in depth — a single `| safe` filter added to that template later turns
this route into same-origin XSS against the operator, with no second control to stop it.

**Fix:** (a) add a `headers()` block in `next.config.mjs` with `X-Content-Type-Options: nosniff`,
`Referrer-Policy: strict-origin-when-cross-origin`, `X-Frame-Options: DENY`, and a baseline CSP;
(b) on the report response specifically, set a tight per-response CSP
(`default-src 'none'; style-src 'unsafe-inline'; img-src data:`) so the document cannot execute
script or exfiltrate regardless of upstream template mistakes.

### F-04
**`params` read synchronously — breaks on the Next 15 upgrade**
[page.tsx:25](../../frontend/app/engagements/[id]/page.tsx#L25),
[page.tsx:40](../../frontend/app/engagements/[id]/page.tsx#L40),
[page.tsx:51](../../frontend/app/engagements/[id]/page.tsx#L51),
[route.ts:26](../../frontend/app/engagements/[id]/report/route.ts#L26),
[route.ts:31](../../frontend/app/engagements/[id]/report/route.ts#L31)

**Correct for Next 14.2 — not a defect today.** Logged as a migration risk: in **Next 15
`params` became `Promise<{ id: string }>`**, and synchronous property access is
deprecated-then-removed. All five sites break on upgrade, including the id validation that gates
the proxy — a silently-`undefined` `params.id` would fail the regex and 404, so it fails safe,
but the route stops working.

**Fix (at upgrade time, not now):** `const { id } = await params;` and retype the prop as
`Promise<{ id: string }>`. `npx @next/codemod@latest next-async-request-api .` handles it.
Record the risk in the upgrade checklist so it is not discovered in production.

### F-06
**Silent localhost fallback for `PROVX_API_BASE_URL`**
[lib/api.ts:12](../../frontend/lib/api.ts#L12),
[packages/client/src/index.ts:10](../../packages/client/src/index.ts#L10)

`?? "http://localhost:8000"` means a deployment that forgets the env var **boots successfully**
and fails per-request with a generic "Could not load findings." The operator sees a UI error, not
a configuration error — the most expensive kind of misconfiguration to diagnose. There is also no
validation that the value is a well-formed `http(s)` URL.

**Fix:** keep the fallback only when `NODE_ENV !== "production"`. In production, validate at
module load with `new URL(...)`, reject non-`http(s)` schemes, and throw at boot with a clear
message. Fail fast, not per-request.

### F-12
**Unchecked `as Finding[]` assertion at the trust boundary (S-05 spirit)**
[lib/api.ts:75](../../frontend/lib/api.ts#L75)

`return (await response.json()) as Finding[];` tells the compiler to trust the network. If the
backend returns an object, `null`, or a renamed schema with a 200, `findings.map` throws a raw
`TypeError` inside the Server Component.

It fails *safely* — the error boundary catches it and nothing leaks — but the console reports
"Could not load findings" for what is actually a contract violation, and no server-side log
identifies which field broke. The `Finding` type is hand-maintained against the SDK's canonical
contract with **nothing keeping them in sync**: no codegen, no schema check, no contract test. A
backend field rename type-checks fine here and renders `undefined`.

**Fix:** parse, don't assert. A Zod schema (or a hand-written `Array.isArray` + per-field guard
for a zero-dependency option) at [api.ts:75](../../frontend/lib/api.ts#L75), logging the parse
failure server-side and throwing the same generic user-facing `Error`. This is the highest-value
change in `lib/api.ts` after tests.

---

## Low

### F-05
**Error boundaries exist only on one segment (W-NEXT-03)**
`app/error.tsx`, `app/not-found.tsx`, `app/global-error.tsx` — all absent

`error.tsx` and `not-found.tsx` cover `engagements/[id]` only. A throw in the root layout, or a
request to any unmatched path (`/foo`), falls through to Next's built-in default — an unbranded
page. In production Next's default 500 leaks nothing, so this is consistency/polish, not
disclosure. W-NEXT-03 reads *"every route segment"*.

**Fix:** add `app/not-found.tsx` and `app/error.tsx` mirroring the segment versions, plus
`app/global-error.tsx` for root-layout failures.

### F-07
**No fetch timeout, and the report is fully buffered**
[lib/api.ts:59](../../frontend/lib/api.ts#L59),
[route.ts:30](../../frontend/app/engagements/[id]/report/route.ts#L30),
[route.ts:48](../../frontend/app/engagements/[id]/report/route.ts#L48)

Two related resilience gaps:
1. **No `AbortSignal`.** A hung backend (connection accepted, no response) holds the render open
   indefinitely. Combined with [F-02](#f-02), the user sees an apparently frozen browser.
2. **`await upstream.text()`** buffers the entire report into Node memory before a byte reaches
   the browser. Fine for a skeleton report; a latency and memory regression on a 500-finding
   engagement, and a per-request memory amplifier under concurrency.

**Fix:** add `signal: AbortSignal.timeout(10_000)` to both fetches (Node 20 native), and stream
the report with `new Response(upstream.body, { headers: … })` instead of `.text()`.

### F-08
**`tsconfig` misses the two strictness flags that matter here**
[tsconfig.json](../../frontend/tsconfig.json)

`strict: true` is set, but `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes` are not.
The former is the one that bites a data-rendering app: array/record indexing yields `T` rather
than `T | undefined`, so an out-of-range access type-checks and crashes at runtime. Low today
(the code indexes nothing), pre-emptive value as the console grows.

**Fix:** enable both now, while the fix cost is near zero.

### F-09
**API contract implemented twice; `@provx/client` unlinked and drifting**
[lib/api.ts:12](../../frontend/lib/api.ts#L12) ↔ [packages/client/src/index.ts:10](../../packages/client/src/index.ts#L10)

`PROVX_API_BASE_URL` is duplicated byte-for-byte across two packages with no link between them,
and the frontend's `Finding` type independently restates the SDK's canonical contract.

**Assessed as Low deliberately.** Linking them today would buy zero functionality (the client is
one constant) while costing the Dockerfile its best property — that it *"builds and runs
independently of the rest of the monorepo"*. Q-11/DRY does not justify coupling two packages to
save two lines. See [01_ARCHITECTURE.md §5](01_ARCHITECTURE.md#5-relationship-to-packagesclient).

The real risk is **drift**: when the client gains auth headers, retries, and error normalization,
the console will behave differently from every CI/CD consumer of the same API — bad for a product
selling reproducibility.

**Fix (deferred, not now):** once the backend OpenAPI schema stabilizes, generate the client, add
a root workspace, and reduce `lib/api.ts` to a thin server-side wrapper over `@provx/client`.

### F-10
**`lib/api.ts` is server-only by convention, not enforcement**
[lib/api.ts:1](../../frontend/lib/api.ts#L1) — no `import "server-only"`

The module's entire security rationale is that it never runs in the browser, but nothing enforces
it. A future `"use client"` component importing `getFindings` compiles cleanly;
`process.env.PROVX_API_BASE_URL` is `undefined` in the browser and the fetch silently targets
`undefined/engagements/...`.

**Fix:** `npm i server-only` and add `import "server-only";` at the top of `lib/api.ts`. One line;
converts a convention into a build-time error.

### F-13
**`packages/client` config is internally inconsistent**
[tsconfig.json:6](../../packages/client/tsconfig.json#L6),
[tsconfig.json:11](../../packages/client/tsconfig.json#L11),
[package.json:9](../../packages/client/package.json#L9)

Three related issues:
1. **`lib: ["ES2022","DOM"]` + `process.env`.** The package claims browser support while reading
   a Node-only global. A browser consumer — an advertised use case in the README — gets
   `ReferenceError: process is not defined` at module load.
2. **`types: ["node"]` with no `@types/node` devDependency.** With no root workspace, a clean
   per-package install cannot resolve it, so the package's *only real CI gate* (`typecheck`) is
   not hermetically runnable.
3. **`"main": "src/index.ts"` + `noEmit: true`.** Source-only, no build, no `exports` map, no
   `.d.ts`. Consistent today; blocks the README's third-party-consumer promise.

Also: `"lint"` is an `echo` stub that exits 0, so the CI lint gate reports green while checking
nothing (labelled as a stub, at least).

**Fix:** drop `DOM` from `lib` and declare the package Node-only (consistent with the whole
reason the var is not `NEXT_PUBLIC_`); add `@types/node` to devDependencies; before first real
use, add a build (`tsc -b` or `tsup`) with `declaration`, an `exports` map, and a real linter.

---

## Info

### F-11
**No favicon / app icon**
`frontend/public/` contains only `.gitkeep`

No `favicon.ico`, `app/icon.tsx`, or `app/apple-icon.png`. Every page load takes a 404 for
`/favicon.ico`, and the browser tab is unbranded. Cosmetic.

**Fix:** add `app/icon.svg` (Next generates the tags automatically).

---

## Performance / Web Vitals

No profiling was run; this is a static assessment. Overall the app is in an unusually good
starting position — **3 runtime dependencies, one client component, no images, no fonts, no
animation** — so the classic regressions are absent by construction rather than by tuning.

### LCP — Largest Contentful Paint

| Route | LCP element (predicted) | Assessment |
|---|---|---|
| `/` | `<h1>Provx</h1>` or the paragraph block | **Good.** Statically prerendered, real text in initial HTML, no opacity animation → **PERF-01 pass**. Effectively network-time only. |
| `/engagements/[id]` | The findings `<table>`, or the amber PX-HUMAN banner | **Backend-bound.** With `force-dynamic` and no Suspense boundary, *nothing* paints until the API responds — LCP inherits full backend latency with no floor. This is the app's single biggest Web Vitals exposure, and [F-02](#f-02) is the fix: streaming the shell makes the banner/heading paint immediately and lets only the table wait. |

No `<img>` anywhere, so **W-NEXT-07 and PERF-03 are not applicable** — there is no image LCP
candidate to mis-prioritize.

### FCP — First Contentful Paint

`/` is excellent (prerendered text). `/engagements/[id]` has **no FCP before the backend
responds** — see above. When `loading.tsx` is added it must satisfy **PERF-02**: it needs real
text (the heading + PX-HUMAN banner), because a skeleton built only from background-color boxes
is *not* an FCP candidate and would defer FCP anyway.

### INP — Interaction to Next Paint

**Excellent, near-best-case.** The only interactive element in the entire app is the *Try again*
button in [error.tsx:19-25](../../frontend/app/engagements/[id]/error.tsx#L19). Its handler is
`onClick={reset}` — a direct function reference, no closure work, no state derivation, no layout
thrash. **PERF-10 pass.**

Texture worth fixing with [F-02](#f-02): `reset()` triggers a server re-render with **no busy
state on the button**, so a slow retry looks like a dead click (Q-16). A `useTransition` +
"Retrying..." label closes it.

### CLS — Cumulative Layout Shift

**Low risk, one real vector.**
- No images, no web fonts, no late-injected banners, no ads → the three usual CLS sources are all
  absent. `next/font` is unused, so there is no FOUT reflow (PERF-06 not applicable).
- **The real vector is the findings table.** Column widths are computed from content, so a table
  rendering while data streams — or a future skeleton whose row height differs from real rows —
  shifts everything below it. **PERF-11** applies directly: when [F-02](#f-02) is implemented,
  the skeleton row height must match real rows, and fixed column widths (`table-fixed` +
  `min-w-`) would remove the reflow entirely.
- `break-all` on the target cell ([page.tsx:81](../../frontend/app/engagements/[id]/page.tsx#L81))
  is a good pre-emptive guard against a long URL blowing out the layout.

### TTFB

`/` ≈ 0 (static). `/engagements/[id]` = **full backend round-trip before the first byte**, since
`force-dynamic` + `await` before render means Next cannot flush the shell early.

**PERF-08 (cache public read-only SSR data with ISR) is correctly not applicable** — findings are
neither public nor stable, and serving a stale finding set after a scan completes would be a
correctness bug in a security tool, not an optimization. **PERF-12's other lever is the right
one:** `<Suspense>` streaming, so the shell's first byte is not blocked on the data. `metadata`
is a static object, not `generateMetadata`, so it adds nothing to the response path.

Secondary: no fetch timeout ([F-07](#f-07)) means a hung backend produces unbounded TTFB.

### Bundle

**Small and clean, with nothing to trim.**
- 3 runtime deps (`next`, `react`, `react-dom`). No lodash, no moment, no icon library, no chart
  library, no UI kit. **PERF-04 and PERF-05 are not applicable** — there is no heavy or
  feature-flagged dependency that could leak into the shared bundle.
- Exactly **one** `"use client"` in the app ([error.tsx:3](../../frontend/app/engagements/[id]/error.tsx#L3)),
  where React requires it. Client JS is the framework runtime plus one button. **W-NEXT-06 pass.**
- `output: "standalone"` keeps the *image* small (build toolchain never reaches the runtime layer),
  which is a deployment win rather than a browser one.
- **PERF-09 is unmet as a practice, not as a defect:** no one has run `next build` and recorded
  the per-route First Load JS, so there is no baseline to detect a future regression against.

**Recommendations, in priority order:** (1) `loading.tsx` + `<Suspense>` on the findings segment —
fixes LCP, FCP, and TTFB together and is the only change with real Web Vitals impact; (2) fetch
timeouts; (3) stream the report instead of buffering; (4) fixed table layout for CLS; (5) record a
`next build` First Load JS baseline now, while the bundle is minimal, so later regressions are
visible.

---

## Test coverage gaps

**This is the highest-severity finding in the repo, tied with [F-01](#f-01).**

### F-TEST — Zero test infrastructure (W-02) — **High**

Quantified:

| Metric | Value |
|---|---|
| Test runner configured | **none** (no `jest.config`, `vitest.config`, `playwright.config`, `cypress.config`) |
| Test dependencies | **0** (no `vitest`, `jest`, `@testing-library/*`, `playwright`, `msw`) |
| `test` script in `package.json` | **absent** (both `frontend` and `packages/client`) |
| Test files (`*.test.*`, `*.spec.*`, `__tests__/`) | **0** |
| Source files under test | **0 of 8** |
| **Statement coverage** | **0%** |
| Security-relevant functions untested | `isEngagementId`, `getFindings`, the report `GET` handler |
| CI gates on this repo | `frontend-types` (real, `tsc`) + `frontend-lint` (**documented no-op stub**) |

The contrast with the rest of the monorepo is stark: the backend has real `pytest` gates and the
adapters have fixture tests, per [.github/workflows/ci.yml](../../.github/workflows/ci.yml). The
frontend has a type checker and nothing else. **The only automated statement that can be made
about this code is that it compiles.**

Why it matters more than the file count suggests: the untested functions are precisely the
security controls. `isEngagementId` is the sole gate preventing arbitrary path construction into
the backend proxy; `getFindings`'s error taxonomy is what keeps upstream detail out of the UI
(S-13 / PX-ERRORS); the 404/400 collapse in `not-found.tsx` is a deliberate anti-enumeration
control. **All three are currently enforced by code review alone.** A refactor that loosens the
regex anchoring, or that renders `error.message`, produces no failing signal anywhere.

Also untested and load-bearing: the PX-HUMAN banner. A regression that removes or conditionally
hides it is a **rule violation shipping silently** in a product whose core claim is that machine
findings are never presented as confirmed.

### Recommendation — concrete, ~1 day of work

**1. Unit tests (Vitest).** `npm i -D vitest @vitejs/plugin-react`, add `"test": "vitest run"`,
wire it into the CI `frontend` job in place of the lint stub.

`lib/api.test.ts` — highest value per line:
- `isEngagementId`: valid v4; **uppercase**; nil UUID (expect `false`); `../../etc/passwd`;
  `<uuid>/../admin`; `<uuid>%00`; a UUID with a trailing newline; empty string; a **UUIDv7** (documents
  the [section_lib.md](section_lib.md) v7-rejection risk explicitly).
- `getFindings` with a mocked `fetch`: 200 happy path; 404 → `EngagementNotFoundError`; malformed
  id → `EngagementNotFoundError` **with no fetch call at all** (asserts validation-before-I/O);
  500 → generic `Error` **whose message does not contain the upstream body** (a direct S-13
  regression test); malformed JSON.
- `reportUrl`: returns a relative same-origin path; never emits `javascript:` / `data:` for hostile
  input.

**2. Component tests (Vitest + Testing Library).**
- The findings page renders one row per finding, uses `display_id`, and handles `cvss: null` /
  empty `attack_techniques`.
- **The PX-HUMAN banner is present whenever findings render** — assert on the "not been confirmed
  by a human" text. Make removing it break the build.
- A finding whose `target` is `javascript:alert(1)` or `<img src=x onerror=…>` renders as **text**
  and produces no `href`/`src` attribute. This is the S-06/S-07 regression test, and it is the one
  that protects against the most plausible future mistake (someone making `target` clickable).
- `error.tsx` renders the fixed copy and **never** the error message.

**3. Route handler tests.** Call the exported `GET` directly with mocked `fetch`:
- valid id → 200 `text/html`, upstream called exactly once with the expected URL;
- malformed id → 404 **and `fetch` never called**;
- upstream 404 → 404; upstream 500 → **502**;
- the response `content-type` is pinned server-side and not taken from upstream.

**4. Optional (later): one Playwright smoke test** — `/` loads, an unknown engagement shows the
404 copy — once there is a compose target to run it against.

Target: **≥80% statements on `lib/`, 100% on `isEngagementId`**, and the S-06/S-07 and PX-HUMAN
assertions treated as non-negotiable regression tests. Add the harness *before* the console grows
— the cost of retrofitting tests rises with every route.

---

## Explicit passes (checked hard, found clean)

| Check | Verdict |
|---|---|
| **S-06** — unsanitized HTML | **Pass.** `dangerouslySetInnerHTML` appears **nowhere** in `app/` or `lib/`; nor do `innerHTML`, `eval`, `new Function`, or `document.write`. |
| **S-07** — `href`/`src` allowlist | **Pass.** `finding.target` (untrusted scan output) is rendered **only** as a JSX text child at [page.tsx:81](../../frontend/app/engagements/[id]/page.tsx#L81) — React-escaped, never an attribute. The app's only variable `href` is `reportUrl()`, which returns a relative path built with `encodeURIComponent` and is structurally incapable of producing a `javascript:` or `data:` URL. **Caveat:** the day anyone writes `href={finding.target}`, this becomes click-to-XSS against the operator. Write an `isSafeUrl()` helper *before* that feature, not after. |
| **Open proxy / SSRF** | **Not an open proxy. Not an SSRF pivot.** Four independent grounds: the upstream URL's host/scheme/path are all fixed server-side with only a UUID variable segment (no `?url=`, no catch-all route); `isEngagementId` is a fully-anchored hex allowlist that cannot match `..`, `/`, `@`, `:`, `%`, CR/LF, or NUL; `encodeURIComponent` is a redundant second layer; and the response content-type is pinned server-side rather than forwarded. Additionally **no client headers are forwarded** — `_request` is unused, so no cookie, `Authorization`, or `Host` reaches the backend. Only `GET` is exported. Full reasoning in [section_app.md](section_app.md). |
| **W-NEXT-01** — real data, not mocks | **Confirmed pass.** [page.tsx:25](../../frontend/app/engagements/[id]/page.tsx#L25) renders the live `GET /engagements/{id}/findings` response. No mock array, no fixture import, no `TODO: fetch from API` anywhere in the repo. |
| **W-NEXT-02** — SWR/TanStack | **Not a violation.** The rule's own Detect clause targets `useEffect(() => { fetch(...) })` **in client components**, and its Fix explicitly permits *"Server components can use direct `fetch` with Next.js cache options"* — which is exactly what [lib/api.ts:59](../../frontend/lib/api.ts#L59) does with `{ cache: "no-store" }`. There is no client-side data fetching in the app at all. Adding SWR here would *add* a client bundle, *add* a hydration boundary, and *weaken* the "API address never reaches the browser" invariant. Flagging this would be pedantry. Pass. |
| **W-NEXT-03** — error boundaries | Pass on `engagements/[id]`; partial repo-wide → [F-05](#f-05). |
| **W-NEXT-05** — forms | **N/A.** No forms exist. |
| **W-NEXT-06** — `"use client"` discipline | **Pass.** Exactly one, where React requires it. |
| **W-NEXT-07** — `next/image` | **N/A.** No images. |
| **W-NEXT-08** — `next/link` | **Pass.** Internal navigation uses `Link` ([page.tsx:36](../../frontend/app/engagements/[id]/page.tsx#L36), [not-found.tsx:18](../../frontend/app/engagements/[id]/not-found.tsx#L18)). The raw `<a>` at [page.tsx:50](../../frontend/app/engagements/[id]/page.tsx#L50) is **correct** — its target is a Route Handler returning `text/html`, not an App Router page. |
| **W-NEXT-09 / S-13 / PX-ERRORS** | **Pass, rigorously.** `error.tsx` declares the `error` prop but **deliberately does not destructure it** ([error.tsx:11](../../frontend/app/engagements/[id]/error.tsx#L11)) — there is no binding in scope that could reach the DOM. The upstream response body is never read in `getFindings`, so it cannot leak. Real detail goes to `console.error` server-side. |
| **W-NEXT-10** — theme tokens | **Pass.** Every colour is a Tailwind palette utility; no hex literal anywhere. |
| **PX-HUMAN** | **Pass, and well done.** [page.tsx:43-47](../../frontend/app/engagements/[id]/page.tsx#L43) renders an unconditional, visually distinct banner stating both provenance and limitation, with the rule cited by ID in a comment. Note for later: it is a static string, so once findings carry per-item validation state it will need to derive from `status`/`confidence` — a global "unvalidated" banner over human-confirmed rows would be wrong in the other direction. |
| **PX-SECRETS** | **Pass.** No credentials in the frontend at all. `console.error` logs only a numeric status and an engagement id — never headers, bodies, or tokens. `.dockerignore` excludes `.env*`. [docker-compose.yml:43-46](../../docker-compose.yml#L43) explicitly withholds `SECRET_KEY`, `DATABASE_URL`, and `POSTGRES_PASSWORD` from the web tier. |
| **PX-AI-OPTIONAL** | **Pass.** No LLM dependency, no AI code path, no network call other than to the Provx API. Fully functional air-gapped. |
| **PX-LICENSE** | **Pass.** Apache-2.0 throughout; SPDX headers on every source file; no GPL/AGPL dependencies (3 deps, all permissive). |
| **Q-13 / Q-15** — no AI tells | **Pass.** No AI attribution in code or comments; prose consistently avoids em dashes and other tells. |
| **Docker hardening** | **Pass.** Multi-stage, exact patch pin with documented reasoning for not `@sha256`-pinning, `USER node`, `npm ci`, standalone output, exec-form `HEALTHCHECK` using native `fetch`. Among the better Dockerfiles in the repo. |
