# Frontend audit — `lib/`

One file, 86 lines, five exports. It is the entire data layer of the console and the only place
the frontend touches the network.

---

## `lib/api.ts`

[Source](../../frontend/lib/api.ts)

Module docblock ([L4-10](../../frontend/lib/api.ts#L4)):

> *"Server-side access to the Provx API. The base URL is deliberately not `NEXT_PUBLIC_`: every call here runs in a Server Component, so the API stays unreachable from the browser and no backend address is shipped in the client bundle."*

That is the correct rationale, and it holds — see [00_OVERVIEW.md §3](00_OVERVIEW.md#3-environment-variables).

**One structural gap:** the file has no `import "server-only";`. Its server-only-ness is
maintained *by convention* — every current importer happens to be a Server Component or Route
Handler. Nothing enforces it. The day someone adds `"use client"` to a component and imports
`getFindings` from here, it compiles, `process.env.PROVX_API_BASE_URL` silently becomes
`undefined` in the browser, and the fetch goes to `undefined/engagements/...`. The `server-only`
package turns that into a build-time error. One-line fix, high leverage.
Logged [F-10](99_FINDINGS.md#f-10).

---

### Export 1 — `PROVX_API_BASE_URL`

```ts
export const PROVX_API_BASE_URL: string
```
[L12-13](../../frontend/lib/api.ts#L12)

```ts
export const PROVX_API_BASE_URL =
  process.env.PROVX_API_BASE_URL ?? "http://localhost:8000";
```

- Evaluated **once at module load**, not per request. In a long-lived Node server that means the
  value is frozen at boot — fine here (it is deployment config, not per-request state), and
  worth knowing if runtime reconfiguration ever becomes a requirement.
- `??` (not `||`) is the right operator: an empty-string env var stays empty rather than
  silently falling back, which surfaces a misconfiguration instead of masking it. Small detail,
  correctly handled.
- **The localhost fallback is the weak point.** A production deploy that forgets the env var
  boots successfully, points at `http://localhost:8000`, and fails per-request with a generic
  "Could not load findings." The operator sees a UI error, not a config error. A pre-alpha app
  should fail fast at boot instead. [F-06](99_FINDINGS.md#f-06).
- No URL validation. If the value were `https://attacker.example`, every call would go there.
  Env vars are trusted config, so this is low priority — but for a security product, parsing the
  value with `new URL()` at boot and rejecting non-`http(s)` schemes is cheap insurance and
  doubles as the fail-fast check above.
- **Duplicated verbatim** in [packages/client/src/index.ts:10](../../packages/client/src/index.ts#L10).
  See [section_client_package.md](section_client_package.md) and
  [F-09](99_FINDINGS.md#f-09).

---

### Internal — `UUID_PATTERN`

[L15-16](../../frontend/lib/api.ts#L15) · not exported

```ts
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
```

A strict RFC 4122 pattern: fully anchored, version nibble constrained to `1-5`, variant nibble to
`[89ab]`, hex-and-hyphen only.

- **Fully anchored** (`^…$`) — no prefix/suffix smuggling. This anchoring is what makes the
  proxy safe (see [section_app.md](section_app.md#open-proxy--ssrf-verdict--not-an-open-proxy-not-an-ssrf-pivot)).
- **No ReDoS risk:** no nesting, no alternation, no unbounded quantifiers — all fixed-length
  character classes. Linear time.
- The `/i` flag means uppercase UUIDs pass and are forwarded to the backend as-is. If the
  backend's lookup is case-sensitive, `ABCDEF…` 404s where `abcdef…` succeeds. Cosmetic
  inconsistency at worst; normalizing with `.toLowerCase()` before use would remove the question.
- It rejects the nil UUID `00000000-0000-0000-0000-000000000000` (version nibble `0`), which is
  correct behaviour but non-obvious — worth knowing if a fixture ever uses it.
- Duplicating the backend's id contract in a regex is acceptable given the SDK is Python; the
  risk is drift if the backend ever adopts UUIDv7 (version nibble `7`), which **this pattern
  would reject**. Given the repo already moved to UUID + `display_id`, that is a plausible
  future change and a plausible future bug. Worth a comment at minimum.

---

### Export 2 — `isEngagementId`

```ts
export function isEngagementId(value: string): boolean
```
[L24-26](../../frontend/lib/api.ts#L24)

```ts
export function isEngagementId(value: string): boolean {
  return UUID_PATTERN.test(value);
}
```

Docblock cites **rule S-05** (validate input at the boundary): *"Engagement ids reach this app
straight from the URL, so their shape is checked before they are used to address the API."*

- Pure, total, side-effect-free, no regex `lastIndex` hazard (no `/g` flag).
- **Called at both entry points** — [api.ts:55](../../frontend/lib/api.ts#L55) and
  [route.ts:26](../../frontend/app/engagements/[id]/report/route.ts#L26). There is no path into
  the backend that skips it. That completeness is what makes it a real control rather than
  decoration.
- Returns `boolean` rather than being a type predicate. `value is EngagementId` with a branded
  type would let the compiler enforce that only validated ids reach `getFindings`/`fetch`.
  Over-engineering at two call sites; worth revisiting at ten.
- **This is a shape check, not an authorization check.** It answers "is this a well-formed id",
  never "may *you* see it". Nothing in the code confuses the two — but as auth lands, the
  distinction must stay explicit so a passing `isEngagementId` is never mistaken for access
  control.

---

### Export 3 — `Finding` (type)

```ts
export type Finding = {
  id: string;
  display_id: string;
  title: string;
  target: string;
  module: string;
  severity: string;
  cvss: number | null;
  confidence: string;
  status: string;
  attack_techniques: string[];
  remediation: string | null;
  evidence_sha256: string;
  captured_at: string;
};
```
[L28-42](../../frontend/lib/api.ts#L28)

- Field names are `snake_case`, mirroring the FastAPI/Pydantic wire format exactly. Correct
  choice — no mapping layer means no mapping bugs, and the type is a faithful description of
  what actually arrives.
- Nullability is modelled (`cvss`, `remediation` are `| null`) and both are handled at the render
  site ([page.tsx:83](../../frontend/app/engagements/[id]/page.tsx#L83)).
- **Weak typing on the enum-ish fields.** `severity`, `confidence`, and `status` are `string`.
  Narrowing to unions (`"critical" | "high" | "medium" | "low" | "info"`) would make
  severity-colour maps exhaustiveness-checked and catch a backend rename at compile time. This
  is the single highest-value typing improvement in the file — and it becomes near-mandatory the
  moment severity drives colour or sort order.
- `captured_at` is `string` (ISO). Fine on the wire; parse at the render boundary when it is
  displayed.
- **This type is hand-maintained and unverified.** It duplicates the SDK's canonical `Finding`
  contract ([packages/adapters/src/provx_sdk/findings.py](../../packages/adapters/src/provx_sdk/findings.py))
  with nothing keeping them in sync — no codegen, no schema check, no contract test. A backend
  field rename type-checks fine here and renders `undefined` at runtime. This is the concrete
  cost of not generating the client from OpenAPI, and it is the strongest argument for
  [F-09](99_FINDINGS.md#f-09).

---

### Export 4 — `EngagementNotFoundError`

```ts
export class EngagementNotFoundError extends Error {}
```
[L45](../../frontend/lib/api.ts#L45)

*"Raised when an engagement does not exist, or its id is not a well-formed UUID."*

- A dedicated error class is the right mechanism: it lets the page distinguish "not there" from
  "we broke" with `instanceof`, without string-matching messages.
- **Deliberately collapses 400 and 404** into one class — the mechanical counterpart to the
  identical `not-found.tsx` copy. The oracle-removal property is enforced by the *type system*,
  not by remembering to write the same sentence twice. Elegant.
- No `name` assignment, so `err.name` is `"Error"` in stack traces rather than
  `"EngagementNotFoundError"`. `instanceof` still works (ES2022 target, no transpilation
  down-levelling to break the prototype chain), so this is a log-readability nit only.

---

### Export 5 — `getFindings`

```ts
export async function getFindings(engagementId: string): Promise<Finding[]>
```
[L54-76](../../frontend/lib/api.ts#L54)

Docblock: *"Throws EngagementNotFoundError for a malformed or unknown id, and a generic Error for anything else - the upstream body is never surfaced to the user, since it can carry detail meant for operators (rules W-NEXT-09, S-13)."*

Line by line:

| Lines | Behaviour | Assessment |
|---|---|---|
| [55-57](../../frontend/lib/api.ts#L55) | `if (!isEngagementId(...)) throw new EngagementNotFoundError("Malformed engagement id.")` | Validation before I/O. No malformed id ever reaches the network. **S-05 pass.** |
| [59-62](../../frontend/lib/api.ts#L59) | `fetch(...encodeURIComponent(engagementId)..., { cache: "no-store" })` | Double-guarded interpolation; `no-store` guarantees freshness. |
| [64-66](../../frontend/lib/api.ts#L64) | 404 → `EngagementNotFoundError("Engagement not found.")` | Distinct message, same class → identical UI. Intentional. |
| [68-73](../../frontend/lib/api.ts#L68) | `console.error(status + id)` then `throw new Error("Could not load findings for this engagement.")` | **The core S-13 / W-NEXT-09 / PX-ERRORS behaviour.** The upstream body is never read, so it cannot leak. Only the numeric status and the id are logged — no headers, no body, no credentials → **PX-SECRETS pass**. |
| [75](../../frontend/lib/api.ts#L75) | `return (await response.json()) as Finding[];` | **The weak line — see below.** |

#### Issues

- **`as Finding[]` is an unchecked assertion.** [L75](../../frontend/lib/api.ts#L75) tells the
  compiler to trust the wire. If the backend returns `{"detail": ...}` with a 200, or an object
  instead of an array, `findings.map` throws a raw `TypeError` inside the Server Component. That
  surfaces as the error boundary — so it fails *safely*, and no internals leak — but the console
  shows "Could not load findings" for what is actually a contract violation, and the operator
  gets no signal about which field broke. A runtime parse at the trust boundary (Zod, or even a
  hand-written `Array.isArray` + per-field check) would convert a silent shape mismatch into a
  precise server-side log line. This is the highest-value change in the file after tests.
  [F-12](99_FINDINGS.md#f-12).
- **No timeout / `AbortSignal`.** [L59](../../frontend/lib/api.ts#L59) has no
  `signal: AbortSignal.timeout(n)`. A hung backend (accepting the connection but never
  responding) holds the Server Component render open indefinitely; with `force-dynamic` and no
  `loading.tsx`, the user sees a browser that appears frozen. Node's default socket timeout will
  not save this in the common case. `AbortSignal.timeout(10_000)` is available on Node 20 and is
  a one-line fix. [F-07](99_FINDINGS.md#f-07).
- **No retry** on transient 5xx/network errors. Defensible — a security console arguably
  *should* show failure rather than paper over an unstable backend — but it should be a stated
  decision, not an omission.
- `console.error` rather than a structured logger. Acceptable pre-alpha; note that S-13's "log
  the full error server-side via the structured logger with enough context to debug from logs
  alone" is only partially met — the status and id are there, the timing and request id are not.
- **No `React.cache` wrapper.** Irrelevant today (one call per render), but if a future layout
  and page both call `getFindings` for the same id, that becomes two backend round-trips.
  `cache()` dedupes within a render pass. Note for later, not now.

#### What it gets right

Validation before I/O; a narrow, typed error taxonomy; the upstream body never read let alone
rendered; only non-sensitive fields logged; explicit no-store. For a 23-line function this is
carrying a lot of the product's security posture, and it carries it correctly.

---

### Export 6 — `reportUrl`

```ts
export function reportUrl(engagementId: string): string
```
[L84-86](../../frontend/lib/api.ts#L84)

```ts
export function reportUrl(engagementId: string): string {
  return `/engagements/${encodeURIComponent(engagementId)}/report`;
}
```

Docblock: *"Same-origin on purpose: the browser cannot resolve the API's internal address, so the report is served through this app's proxy route."*

- Returns a **relative, same-origin path**. It is structurally incapable of producing a
  `javascript:` or `data:` URL — the leading `/` is a literal and `encodeURIComponent` neutralizes
  everything else. The one place in the app where a variable reaches an `href`
  ([page.tsx:51](../../frontend/app/engagements/[id]/page.tsx#L51)) is therefore **S-07 clean by
  construction**, not by review.
- `encodeURIComponent` here is redundant (the caller's id has already passed the UUID gate) but
  correct as defence in depth, and it makes the function safe in isolation — it does not depend
  on its caller having validated first.
- **Does not itself validate.** It will happily build a path from garbage; the garbage is then
  rejected by the route handler's own `isEngagementId` check. The validation lives at the right
  boundary (the handler), so this is fine — but it means `reportUrl` is a URL *builder*, not a
  guarantee, and should not be mistaken for one.
- The `/engagements/{id}/report` shape is duplicated between this function and
  [route.ts:31](../../frontend/app/engagements/[id]/report/route.ts#L31) (as the upstream path).
  They are coincidentally identical; nothing enforces it. Harmless, worth a comment.
