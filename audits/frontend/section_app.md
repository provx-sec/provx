# Frontend audit — `app/`

File-by-file, component-by-component. Five files, three routes.

---

## `app/layout.tsx` — RootLayout

[Source](../../frontend/app/layout.tsx) · 21 lines · Server Component

```tsx
export const metadata: Metadata
export default function RootLayout({ children }: { children: React.ReactNode }): JSX.Element
```

**`metadata`** ([L6-9](../../frontend/app/layout.tsx#L6)) — static object, `title: "Provx"`,
`description: "Governed automated security validation - web, API & infra. Safe by default."`
Static (not `generateMetadata`), so it costs nothing on the response path — PERF-12 satisfied
trivially.

**`RootLayout`** ([L11-21](../../frontend/app/layout.tsx#L11)) — renders
`<html lang="en"><body>{children}</body></html>`. Nothing else: no providers, no nav, no font.

Observations:

- `lang="en"` present. Good — a surprisingly common a11y miss.
- **No `next/font`.** The app falls back to the browser default serif/sans stack. This *avoids*
  PERF-06 (font preload discipline) rather than violating it — there is no font to preload and
  no FOIT/FOUT, hence no font-driven CLS. When typography lands, `next/font` with `display:
  swap` and its automatic size-adjust fallback is the required path.
- No `favicon.ico` / `icon.tsx` anywhere; `public/` holds only `.gitkeep`. Every page request
  eats a 404 for `/favicon.ico`. Cosmetic. [F-11](99_FINDINGS.md#f-11).
- No `<a href="#main">` skip link and no landmark chrome, but with one content block per page
  and each page's root being `<main>`, there is nothing to skip past yet. Not a defect at this
  size.
- No `suppressHydrationWarning`, no theme script — correct, since dark mode is pure CSS
  `prefers-color-scheme` with no JS involvement, so there is no hydration mismatch to suppress.
- SPDX + copyright header present, consistent with the rest of the repo.

**Verdict:** minimal and correct. Nothing to fix.

---

## `app/page.tsx` — `/` (Home)

[Source](../../frontend/app/page.tsx) · 18 lines · Server Component, statically prerendered

```tsx
export default function Home(): JSX.Element
```

A `<main>` with `mx-auto flex min-h-screen max-w-2xl flex-col justify-center gap-4 px-6`,
containing an `<h1>Provx</h1>`, a positioning line, and an operator note explaining the
walking-skeleton flow: create an engagement and run a scan through the API, then open
`/engagements/<id>`.

Observations:

- **No data fetch, no client boundary, no hooks.** Prerendered at build; served from the static
  cache. TTFB ≈ 0 (PERF-12) and the `<h1>` — almost certainly the LCP element — is real text in
  the initial HTML with no opacity animation, so **PERF-01 is satisfied cleanly**.
- Colors are Tailwind palette utilities (`text-neutral-600`, `dark:text-neutral-400`), never hex
  literals → **W-NEXT-10 pass**.
- `&amp;` and `&lt;`/`&gt;` entities used correctly.
- Prose uses `-` where an em dash would read better; this is consistent with the repo-wide
  convention of avoiding typographic AI-tells (rule Q-13). Intentional, not sloppy.
- Honest copy: it tells the operator what does *not* exist yet rather than showing dead nav.
  For a pre-alpha console that is the right choice — a fake dashboard would violate W-NEXT-01
  in spirit.
- `justify-center` + `min-h-screen` centers a short block; harmless now, will need rework when
  the page grows.

**Verdict:** appropriate scaffolding. Nothing to fix.

---

## `app/engagements/[id]/page.tsx` — `/engagements/[id]` (Findings)

[Source](../../frontend/app/engagements/[id]/page.tsx) · 93 lines · **async Server Component**

```tsx
export const dynamic = "force-dynamic";
export default async function EngagementFindingsPage(
  { params }: { params: { id: string } }
): Promise<JSX.Element>
```

The only real page in the app. Walkthrough:

### Data acquisition — [L23-31](../../frontend/app/engagements/[id]/page.tsx#L23)

```tsx
let findings;
try {
  findings = await getFindings(params.id);
} catch (error) {
  if (error instanceof EngagementNotFoundError) {
    notFound();
  }
  throw error;
}
```

Textbook narrow catch: the *only* error class converted to a 404 is
`EngagementNotFoundError`; everything else is rethrown to the segment error boundary. No
swallowing, no `catch {}`, no `any`.

Two nits:
- `let findings;` is implicitly `Finding[] | undefined` until the assignment. TypeScript's
  control-flow analysis narrows it correctly after the `try/catch` because `notFound()` returns
  `never` and the `throw` is unconditional, so this is *type-safe* — but an explicit
  `let findings: Finding[];` would state the intent and survive a refactor that widens the
  catch. Trivial.
- **W-NEXT-01 confirmed: this page renders real API data.** There is no mock array, no
  placeholder fixture, no `TODO: fetch from API`. The table is driven entirely by the live
  `GET /engagements/{id}/findings` response. Pass.

### Header block — [L34-41](../../frontend/app/engagements/[id]/page.tsx#L34)

`<main>` (max-w-5xl), a `next/link` back to `/` (**W-NEXT-08 pass** — internal navigation uses
`Link`, not `<a>`), an `<h1>Findings</h1>`, and `Engagement {params.id}` rendered as text.

`params.id` reaching the DOM here is **safe**: it is interpolated as a JSX text child, which
React escapes, and it has already passed the strict UUID regex in `getFindings` — anything
non-UUID took the `notFound()` branch and this JSX never rendered.

### PX-HUMAN banner — [L43-47](../../frontend/app/engagements/[id]/page.tsx#L43)

```tsx
{/* PX-HUMAN: the console must never present a machine finding as confirmed. */}
<p className="rounded-md border border-amber-600 bg-amber-50 ...">
  <strong>Machine-found, unvalidated.</strong> These findings were produced by a
  deterministic passive check and have not been confirmed by a human.
</p>
```

**This is the single most important line of UI in the repo and it is done right.** PX-HUMAN
demands that machine output is never presented as confirmed truth; the banner is unconditional,
above the table, visually distinct (amber, bordered), and states both the provenance
("deterministic passive check") and the limitation ("not been confirmed by a human"). It cites
the rule by ID in a comment, so a future refactor knows why it exists.

Refinements worth making later, none blocking:
- The banner is a static string, not derived from finding `status`/`confidence`. Once findings
  carry per-item validation state, a globally-unvalidated banner over a table containing
  human-confirmed rows becomes *wrong in the other direction*. The `status` and `confidence`
  fields already exist on the `Finding` type but are **not rendered anywhere** — see below.
- No `role="note"` / `aria-live`; purely visual emphasis. Minor a11y.

### Report link — [L49-57](../../frontend/app/engagements/[id]/page.tsx#L49)

```tsx
<a href={reportUrl(params.id)} className="text-sm underline" rel="noreferrer">
```

Uses a raw `<a>` rather than `next/link` — **correct**, because the target is a Route Handler
returning `text/html`, not an App Router page. Client-side navigation to it would be wrong.
W-NEXT-08 is not violated.

`rel="noreferrer"` without `target="_blank"` is harmless but near-meaningless on a same-origin
same-tab link; it reads like a leftover from a `target="_blank"` version. The href is
same-origin and built from a validated UUID via `encodeURIComponent` → **S-07 pass** (no
protocol-controllable input can reach it; see the trace below).

### Findings table — [L59-90](../../frontend/app/engagements/[id]/page.tsx#L59)

Empty state ([L60-62](../../frontend/app/engagements/[id]/page.tsx#L60)): a dashed-border panel,
*"No findings recorded yet. Run a scan for this engagement."* Real text, actionable, not a blank
screen. Good.

Populated state: `<div className="overflow-x-auto">` wrapping a `<table>` with six columns —
ID, Title, Target, Severity, CVSS, ATT&CK.

Per-row rendering ([L77-86](../../frontend/app/engagements/[id]/page.tsx#L77)):

| Cell | Expression | Note |
|---|---|---|
| ID | `{finding.display_id}` | mono/xs; the PVX-0001 human id. |
| Title | `{finding.title}` | |
| Target | `{finding.target}` | `break-all` to stop long URLs blowing out the layout. |
| Severity | `{finding.severity}` | Raw string. No color coding — a severity table where "critical" and "info" look identical is a real usability gap for triage. |
| CVSS | `{finding.cvss ?? "-"}` | Correct null handling. |
| ATT&CK | `{finding.attack_techniques.join(", ") \|\| "-"}` | Correct empty-array handling. |

`key={finding.id}` uses the stable UUID, not the array index. Correct.

**Not rendered although present on the type:** `module`, `confidence`, `status`, `remediation`,
`evidence_sha256`, `captured_at`. For a governed/auditable product, `evidence_sha256` and
`captured_at` are the audit trail (PX-EVIDENCE) and `status`/`confidence` are the human-validation
state (PX-HUMAN); surfacing them is the obvious next increment. Scaffolding, but named here so
it does not get forgotten.

Table a11y: no `<caption>`, no `scope="col"` on the `<th>`s. Two-attribute fix, worth doing.

### Security trace — how does `finding.target` reach the DOM?

This was checked explicitly because `target` is **untrusted scan output** — it originates from
whatever a scanned host returned, and is therefore attacker-influenceable.

```
FastAPI JSON  →  getFindings() → response.json() as Finding[]
              →  findings.map(...)
              →  <td className="p-2 break-all">{finding.target}</td>
```

- It is rendered as a **JSX text child**. React escapes text children — `<script>` becomes
  `&lt;script&gt;`. Not HTML.
- It is **never** used as `href`, `src`, `action`, `formaction`, `style`, or any attribute at
  all. A `javascript:target` payload has nowhere to land. **S-07: pass.**
- **`dangerouslySetInnerHTML` does not appear anywhere in the repo.** Verified across every file
  in `app/` and `lib/`. Nor do `innerHTML`, `eval`, `new Function`, or `document.write`.
  **S-06: pass.**
- `title`, `severity`, `display_id`, and `attack_techniques` follow the identical text-child
  path.

**Verdict on XSS: clean.** The one thing that would break this is a future "open target in a new
tab" affordance — the moment anyone writes `href={finding.target}`, S-07 is violated and the
console becomes a click-to-XSS vector against its own operator. A `isSafeUrl()` helper enforcing
`http`/`https` should be written *before* that feature is attempted, not after.

### Next 15 migration risk

`params` is read **synchronously** — `params.id` at
[L25](../../frontend/app/engagements/[id]/page.tsx#L25),
[L40](../../frontend/app/engagements/[id]/page.tsx#L40),
[L51](../../frontend/app/engagements/[id]/page.tsx#L51), and in
[route.ts:26](../../frontend/app/engagements/[id]/report/route.ts#L26) /
[route.ts:31](../../frontend/app/engagements/[id]/report/route.ts#L31).

**Correct for Next 14.** In **Next 15 `params` became a Promise** (`Promise<{ id: string }>`),
and synchronous access is deprecated-then-broken. On upgrade, both files need
`const { id } = await params;` and the prop type changed to `Promise<{ id: string }>`. The
official codemod handles it; the risk is forgetting. Logged as [F-04](99_FINDINGS.md#f-04).

### Missing `loading.tsx` — is it a real gap? (Q-16 / PERF-07)

**Honest answer: yes, but a mild one — and it will get worse, not better.**

The argument that it is fine: with `force-dynamic` SSR and no client-side fetch, the browser
shows the *previous* page while the server renders, then swaps to a complete page. The user is
never staring at a blank screen or a half-populated table, and the browser's own tab spinner is
running. There is no "silent update" and no stale-value-while-refetching problem — the specific
failure modes Q-16 was written to catch (an `isLoading` flag that never reaches the UI, a
button with no busy state) do not exist here because there is no client-side async at all.

The argument that it is a gap, which wins:
- On a **hard navigation** (pasting an engagement URL, or a refresh), there is no previous page.
  The browser shows *nothing* until the server has finished the full backend round-trip. FCP is
  gated on backend latency with no floor.
- On a **soft navigation** from `/`, the App Router blocks the transition on the RSC payload.
  Without a `loading.tsx` there is no Suspense boundary, so nothing renders early and the click
  feels dead for the duration of the fetch.
- **PERF-12 names the fix directly:** *"stream non-critical sections via `<Suspense>` so the
  shell's first byte isn't blocked."* A `loading.tsx` in this segment gives Next a boundary to
  stream against, so the shell (heading + PX-HUMAN banner + back link) paints immediately and
  only the table waits.
- PERF-02 constrains the fix: the loading state must contain **real contentful text**, not grey
  boxes. Here that is free — the heading and the PX-HUMAN banner are static and can render in
  both states identically, with no flash.

**Recommendation:** add `app/engagements/[id]/loading.tsx` rendering the same header block and
PX-HUMAN banner plus a table skeleton with matching row height (PERF-11, to avoid CLS on swap).
Roughly 20 lines. Logged as [F-02](99_FINDINGS.md#f-02).

---

## `app/engagements/[id]/error.tsx` — segment error boundary

[Source](../../frontend/app/engagements/[id]/error.tsx) · 28 lines · **Client Component**

```tsx
"use client";
export default function EngagementError(
  { reset }: { error: Error; reset: () => void }
): JSX.Element
```

Renders a fixed heading (*"Could not load findings"*), a fixed explanatory line (*"...Check that
the engagement exists and that the Provx API is reachable."*), and a **Try again** button wired
to `reset`.

Assessment:

- **W-NEXT-03: pass** for this segment. The boundary exists and catches everything the page
  rethrows.
- **S-13 / W-NEXT-09 / PX-ERRORS: pass, and rigorously so.** The `error` prop is declared in the
  type (Next requires the signature) but **deliberately not destructured** — so there is no
  binding in scope that could be rendered. Not "we remembered not to print it"; structurally
  impossible to print it. The real failure is logged server-side at
  [lib/api.ts:69-71](../../frontend/lib/api.ts#L69).
- `"use client"` is justified — error boundaries and the `onClick` require it. **W-NEXT-06:
  pass.**
- `reset()` re-renders the segment on the server. Because the underlying failure is usually a
  down backend, an immediate retry often fails again with no feedback — the button gives no busy
  state and no rate limiting. Minor Q-16 texture: a `useTransition` + "Retrying..." label would
  close it.
- Not logged client-side to any telemetry sink. Fine pre-alpha; for an air-gapped-capable
  product, any future client telemetry must be opt-in and local.

**Verdict:** correct and disciplined.

---

## `app/engagements/[id]/not-found.tsx` — segment 404 UI

[Source](../../frontend/app/engagements/[id]/not-found.tsx) · 23 lines · Server Component

```tsx
export default function EngagementNotFound(): JSX.Element
```

Heading *"Engagement not found"*, the line *"No engagement matches that address. Check the link
and try again."*, and a `next/link` back to `/`.

The value is in the comment ([L8-9](../../frontend/app/engagements/[id]/not-found.tsx#L8)):

> *"Deliberately says the same thing in both cases, so the page never reveals what shape a valid id has (rules PX-ERRORS, S-13)."*

A malformed id and a real-but-unknown id produce byte-identical output. That removes an
id-format oracle and, more usefully, prevents the page from being used to **enumerate which
engagement UUIDs exist** — which, in a product where engagement identifiers map to real client
pentests, is a meaningful confidentiality property, not a theoretical one.

`next/link` for internal navigation → **W-NEXT-08 pass**. No dynamic content at all, so no
injection surface.

**Verdict:** correct. Nothing to fix.

---

## `app/engagements/[id]/report/route.ts` — the report proxy

[Source](../../frontend/app/engagements/[id]/report/route.ts) · 52 lines · Route Handler

```ts
function notFoundResponse(): Response
export async function GET(
  _request: Request,
  { params }: { params: { id: string } }
): Promise<Response>
```

### `notFoundResponse()` — [L5-11](../../frontend/app/engagements/[id]/report/route.ts#L5)

Returns a fresh 404 `text/plain` "Report unavailable." The comment explains why it is a factory
rather than a module-level constant: *"a Response body is a single-use stream and cannot be
shared."* Correct and non-obvious — a shared `Response` constant would throw
`TypeError: body used already` on the second call. Good catch by the author.

### `GET` — [L21-51](../../frontend/app/engagements/[id]/report/route.ts#L21)

1. **[L26-28] Validate first.** `if (!isEngagementId(params.id)) return notFoundResponse();` —
   before any network call. The comment says *"Checked before any upstream call, so a malformed
   id never reaches the API."*
2. **[L30-33]** `fetch(`${PROVX_API_BASE_URL}/engagements/${encodeURIComponent(params.id)}/report`, { cache: "no-store" })`
3. **[L35-46]** Non-OK → `console.error` with the status, then 404 → `notFoundResponse()`,
   anything else → **502** "Report unavailable." Correct status semantics: a failing *upstream*
   is a gateway error, not a 500 blamed on the client.
4. **[L48-51]** OK → re-emit the body with `content-type: text/html; charset=utf-8`, status 200.

### Open-proxy / SSRF verdict — **NOT an open proxy. Not an SSRF pivot.**

Definitive, on four independent grounds — any *one* of which is sufficient:

1. **The URL is not attacker-constructible.** The upstream URL is a template literal whose only
   variable segment is `params.id`. The host, port, scheme, and both path segments
   (`/engagements/…/report`) are fixed in server-side code. There is no
   `?url=` / `?target=` / catch-all `[...path]` parameter anywhere. The handler can reach
   **exactly one endpoint shape on exactly one host**.
2. **`isEngagementId` is a strict allowlist, not a denylist.** The regex at
   [lib/api.ts:15-16](../../frontend/lib/api.ts#L15) is fully anchored (`^…$`) and admits only
   `[0-9a-f]` hex and hyphens in RFC 4122 layout. It is *incapable* of matching `..`, `/`, `@`,
   `:`, `%`, `?`, `#`, a newline, or a null byte. Path traversal (`../../admin`), authority
   injection (`evil.com#`), and CRLF request splitting are all structurally impossible.
3. **`encodeURIComponent` is a second, redundant layer.** Belt-and-braces — even if the regex
   were loosened, the id could not break out of its path segment.
4. **The response content type is pinned server-side** to `text/html; charset=utf-8` rather than
   forwarded from upstream, so the proxy cannot be coerced into emitting an attacker-chosen
   content type (no `application/octet-stream` smuggling, no reflected-file-download).

Also checked: **no upstream headers are forwarded** — `_request` is explicitly unused
(underscore-prefixed), so no cookie, `Authorization`, `X-Forwarded-*`, `Host`, or `Range` header
from the client reaches the backend. Nothing from the client influences the upstream request
except the UUID. That is about as tight as a proxy gets.

**Only the `GET` method is exported**, so `POST`/`PUT`/`DELETE`/`PATCH` to this path return 405
from Next automatically. Correct.

### Residual risks on this handler (real, but not SSRF)

- **S-08 partial.** The rule requires proxies to have *auth + origin check + rate limit*; this
  has none. Today that is accepted and documented — the upstream is unauthenticated in the
  walking skeleton, so a proxy check would guard nothing, and the code names this handler as
  where auth belongs. **But the report is client-confidential**: anyone who can reach port 3000
  and guess or obtain an engagement UUID retrieves a full pentest report. UUIDv4 unguessability
  is the *only* control right now. That is acceptable on localhost, and unacceptable the day
  this is exposed. Logged [F-01](99_FINDINGS.md#f-01) (High).
- **No rate limit** → an unauthenticated caller can drive unbounded backend report renders. A
  cheap amplification/DoS vector once exposed. Same finding.
- **Stored-XSS surface, currently mitigated upstream.** The handler serves backend-generated
  HTML *same-origin*. Because the report embeds untrusted scan output (`target`, response
  snippets), an unescaped template would execute in the console's own origin. Checked the
  backend: [backend/app/services/report.py:31](../../backend/app/services/report.py#L31) uses
  Jinja `select_autoescape(default=True, default_for_string=True)` — **autoescape is on, so this
  is currently safe.** The frontend nonetheless has zero defence in depth here: no CSP header,
  no sandboxing. A single `| safe` filter added to that template later would turn this route into
  same-origin XSS. A CSP on this response (`default-src 'none'; style-src 'unsafe-inline'`) and a
  `X-Content-Type-Options: nosniff` would make the frontend robust to a backend mistake. Logged
  [F-03](99_FINDINGS.md#f-03).
- **Full buffering** via `await upstream.text()` ([L48](../../frontend/app/engagements/[id]/report/route.ts#L48))
  — see [F-07](99_FINDINGS.md#f-07).
- **No `Content-Disposition`, no `Cache-Control: no-store`** on the response. A confidential
  report served without `no-store` may be cached by an intermediary or the browser's disk cache.
  Worth adding with the auth work.
