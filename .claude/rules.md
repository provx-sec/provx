# Project rules — universal baseline

**This is the portable subset of rules that apply to any project**, regardless of stack. The bootstrap process copies this file into `<project>/.claude/rules.md` and then APPENDS stack-specific rules from `rules/*.md` based on what's detected in the project.

After bootstrap, you (and the dev team) can edit this file freely to add project-specific rules. The skills (`/x-rules`, `/x-check`, `/x-implement`) read whatever is in `<project>/.claude/rules.md` — they don't care which rules came from the baseline vs the stack modules vs your additions.

**Last updated:** 2026-04-09 (kit version 1.0)

---

## Categories

1. [Auth & Authorization rules](#1-auth--authorization-rules)
2. [Security rules](#2-security-rules)
3. [Data & Privacy rules](#3-data--privacy-rules)
4. [Code quality rules](#4-code-quality-rules)
5. [Workflow rules](#5-workflow-rules)

---

## 1. Auth & Authorization rules

### A-01 — Admin/privileged endpoints check role server-side
**Status:** ACTIVE
**Why:** Skipping the check is the most common privilege-escalation vector. Universal across all stacks.
**Detect:** controllers / route handlers in admin/privileged paths that don't explicitly verify the caller's role from a trusted source (session, JWT claim, server-fetched profile).
**Fix:** every privileged endpoint must call `requireRole('admin')` or equivalent before processing the request. Cookie/header-based role claims must be verified server-side, never trusted from the client.

### A-02 — No client-spoofable role checks
**Status:** ACTIVE
**Why:** Trusting `localStorage.role` or `cookie.user_role` for authorization is bypassed in 5 seconds with the dev console.
**Detect:** middleware/guards that read role from a cookie, localStorage, header, or form value set by the client.
**Fix:** verify role server-side from the session/JWT. If middleware needs to know the role, it should call the backend or decode a signed JWT — never trust client-set state.

### A-03 — Auth tokens in HttpOnly cookies (web) or secure storage (mobile)
**Status:** ACTIVE
**Why:** Tokens in `localStorage` are XSS-readable. Tokens in plaintext mobile storage (Hive without encryption, plain SharedPreferences, NSUserDefaults) are device-compromise-readable.
**Detect:**
  - Web: `localStorage.setItem('token'`, `localStorage.setItem('jwt'`, `localStorage.setItem('access_token'`, etc.
  - iOS: `UserDefaults.standard.set(token...)`
  - Android: `SharedPreferences ... .putString("token"...)`
  - Flutter: `Hive.box.put('token'...)`, `SharedPreferences.setString('token'...)`
**Fix:** server-set HttpOnly + Secure + SameSite cookies for web. Platform secure storage for mobile (`flutter_secure_storage`, iOS Keychain via `keychain_swift`, Android EncryptedSharedPreferences).

### A-04 — `Math.random()` (or equivalent) forbidden in security-sensitive code
**Status:** ACTIVE
**Why:** Crypto-weak. PRNGs are predictable and can be reverse-engineered to predict OTPs, password reset tokens, session IDs, etc.
**Detect:**
  - JS/TS: `Math.random()` in files matching `auth|otp|password|token|crypto|verify|reset|session`
  - Python: `random.random()` / `random.choice()` / `random.randint()` in same context
  - PHP: `rand()`, `mt_rand()`, `uniqid()` without `more_entropy=true` in same context
  - Go: `math/rand` in same context
  - Dart: `Random()` (without `.secure()`) in same context
  - Rust: `rand::random()` in same context (use `rand::rngs::OsRng`)
**Fix:**
  - JS/TS: `crypto.randomBytes()` (Node) or `crypto.getRandomValues()` (browser)
  - Python: `secrets.token_hex()`, `secrets.token_urlsafe()`, `secrets.choice()`
  - PHP: `random_bytes()`, `random_int()`
  - Go: `crypto/rand`
  - Dart: `Random.secure()`
  - Rust: `rand::rngs::OsRng`

### A-05 — Refresh token rotation
**Status:** ACTIVE
**Why:** Long-lived sessions need rotation to limit blast radius if a token is leaked.
**Detect:** refresh-token endpoint that returns the same token, doesn't invalidate the old token, or doesn't track refresh-token version per user.
**Fix:** every successful refresh issues a NEW refresh token and invalidates the old one. Track a `refresh_token_version` on the user record and bump it on refresh — old tokens become invalid.

### A-06 — Failed-login lockout (configurable threshold)
**Status:** ACTIVE
**Why:** Brute force prevention. Standard control across ISO 27001, PCI-DSS, NIST 800-63.
**Detect:** login endpoints that don't track failed attempts per user/IP.
**Fix:** per-user (and ideally per-IP) failed-attempt counter. Reset on successful login. Lock for N minutes after M fails (default M=5, N=30, configurable).

### A-07 — Token refresh is mutex-protected (concurrent requests)
**Status:** ACTIVE
**Why:** Without a mutex, N concurrent 401s fire N parallel refresh requests, creating race conditions and spurious logouts.
**Detect:** refresh-token interceptors / HTTP clients without locking.
**Fix:** mutex/lock around the refresh call. Concurrent 401s wait on the same in-flight refresh, not fire N parallel refreshes. Examples: `synchronized` package (Dart), `async-mutex` (JS), `sync.Once` (Go), `threading.Lock` (Python).

---

## 2. Security rules

### S-01 — No hardcoded API keys / secrets in source
**Status:** ACTIVE
**Why:** Standard hygiene. Keys in source code leak via git history, log forwarding, repo cloning, etc.
**Detect:** strings matching:
  - `AIza[0-9A-Za-z-_]{35}` (Google API keys)
  - `sk_(test|live)_[0-9a-zA-Z]{20,}` (Stripe secret keys)
  - `pk_(test|live)_[0-9a-zA-Z]{20,}` (Stripe publishable keys)
  - `ghp_[0-9a-zA-Z]{36}` (GitHub personal access tokens)
  - `glpat-[0-9a-zA-Z_-]{20,}` (GitLab personal access tokens)
  - Generic env-like assignments: `(api_key|secret_key|access_key|private_key)\s*[=:]\s*["'][a-zA-Z0-9_-]{20,}["']`
  - AWS access keys: `AKIA[0-9A-Z]{16}`
  - Slack tokens: `xox[baprs]-[0-9a-zA-Z]{10,}`
**Fix:** move to env var, read via `process.env.X` (Node) / `dart-define` (Flutter) / `os.Getenv` (Go) / `os.environ` (Python) / `getenv` (PHP). Rotate the leaked key in the provider's console immediately.

### S-02 — No `.env` files committed
**Status:** ACTIVE
**Why:** Standard hygiene. `.env.example` / `example.env` is fine; actual `.env` is not.
**Detect:** `.env`, `.env.local`, `.env.production`, `.env.staging` files in any commit (any name pattern that doesn't include `example`, `template`, `sample`).
**Fix:** add to `.gitignore`. Use `.env.example` for the schema (no real values).

### S-03 — Verbose query loggers off in production
**Status:** ACTIVE
**Why:** Query loggers that print full SQL with parameter values leak schema details + PII into log files.
**Detect:**
  - Drizzle: `drizzle({ logger: true })` without env-gate
  - Prisma: `new PrismaClient({ log: ['query'] })` without env-gate
  - SQLAlchemy: `engine = create_engine(..., echo=True)` without env-gate
  - Eloquent (Laravel): `DB::enableQueryLog()` without env-gate in production routes
  - Mongoose: `mongoose.set('debug', true)` without env-gate
**Fix:** wrap with env check, e.g. `drizzle({ logger: process.env.NODE_ENV !== 'production' })`.

### S-05 — Input validation at every API boundary
**Status:** ACTIVE
**Why:** Without validation, you trust user input. OWASP A03 (Injection).
**Detect:** route handlers / controllers / lambdas that accept request bodies without a typed schema (DTO, Zod schema, Pydantic model, JSON-schema, etc.) and pass the raw input to a query/operation.
**Fix:** every endpoint has a typed input schema. Validation runs BEFORE the handler. Examples: Zod (TS), class-validator (NestJS), Pydantic (Python), Joi (JS), validator (Go), Laravel form requests, Marshmallow (Python).

### S-06 — No unsanitized HTML rendering
**Status:** ACTIVE
**Why:** XSS prevention.
**Detect:**
  - React: `dangerouslySetInnerHTML={{ __html: <variable> }}` where `<variable>` is not statically known
  - Vue: `v-html="<variable>"`
  - Angular: `[innerHTML]="<variable>"` without `DomSanitizer`
  - Vanilla: `element.innerHTML = <variable>` from user input
  - Flutter: `Html.fromString` / `flutter_html` without allowed-tags list
**Fix:** use a sanitizer (DOMPurify for web, `flutter_html` with allowed-tags list, ngSanitize / DomSanitizer for Angular).

### S-07 — `href` / `src` URL allowlist (block `javascript:` and `data:` URLs)
**Status:** ACTIVE
**Why:** XSS via `javascript:` URLs is a classic vector. `data:` URLs can deliver HTML/JS.
**Detect:** any `href={var}` / `src={var}` (React/JSX), `href="{{ var }}"` (Vue/Angular templates), or `setAttribute('href', var)` where `var` comes from user input without protocol validation.
**Fix:** validate protocol is `http`, `https`, `mailto`, or `tel`. Reject `javascript:`, `data:`, `vbscript:`, `file:`. Helper function: `isSafeUrl(url)` should be called everywhere.

### S-08 — API proxies require auth + origin + rate-limit
**Status:** ACTIVE (frontend frameworks with built-in API routes)
**Why:** Open API proxies become open relays — anyone in the world can use your frontend domain to call your backend without going through your auth.
**Detect:** Next.js API routes (`pages/api/`, `app/api/`), Nuxt server routes, SvelteKit endpoints, Remix loaders that forward requests to a backend without origin/auth/rate-limit checks.
**Fix:** verify origin (allowlist of domains), require auth header to forward, apply rate limit per IP/user. Or skip the proxy and call backend directly with CORS configured.

### S-10 — Asset/upload ownership enforced server-side
**Status:** ACTIVE
**Why:** Without ownership tracking, any authenticated user can claim any uploaded file as theirs (KYC docs, profile photos, private attachments).
**Detect:** asset/upload endpoints that don't set `createdBy` / `userId` from `req.user.id` server-side, or queries with `OR createdBy IS NULL` (or equivalent ownership-bypass clauses).
**Fix:** `createdBy` / `userId` set from the authenticated session, never from the client. Ownership query uses `WHERE createdBy = ?` with no `OR NULL` escape.

### S-11 — Seed/dev/admin endpoints require auth + env-gate
**Status:** ACTIVE
**Why:** Seed endpoints (used to populate test data) are catastrophic if exposed in production — anyone can spawn fake users / KYC docs / privileged accounts.
**Detect:** any endpoint with `seed`, `dev`, `debug`, `test`, `playground` in the path that lacks auth.
**Fix:** wrap in admin-auth + env-gate (`if (env.NODE_ENV !== 'production')` — only allow in dev/staging, never production).

### S-12 — Common-password blacklist on signup + password change
**Status:** ACTIVE
**Why:** Without a blacklist, users pick "Password123!" which passes complexity checks. NIST 800-63B recommends blacklists explicitly.
**Detect:** password validation that only checks complexity (length, character classes), not against a known-bad list.
**Fix:** check against the SecLists Top 10k common passwords (or `have-i-been-pwned` API for k-anonymity) on every password set. Reject matches.

### S-13 — User-friendly error messages in production (no raw error leakage)
**Status:** ACTIVE
**Why:** Raw error messages, stack traces, SQL errors, and third-party API errors leak schema details, vendor names, internal paths, and version info. ISO 27001 information disclosure / OWASP A09.
**Detect:**
  - Backend: API responses returning `err.message`, `err.stack`, `String(err)`, `JSON.stringify(err)`, or the raw `err` object. `res.json({ error: err... })` patterns. `throw new HttpException(err.message, ...)`.
  - Mobile: `showSnackBar(e.toString())`, `Text('${e}')`, raw error object exposure in UI
  - Frontend: `toast.error(err.message)`, `<div>{error.message}</div>` rendering API error responses without filtering
**Fix:** wrap error paths with env-gated branches. In `development`/`testing` (and `staging` if explicitly opted in): expose `{ error: 'human msg', detail: err.message, stack: err.stack }`. In `production`: expose `{ error: 'Something went wrong on our end. Please try again or contact support.' }`. ALWAYS log the full error server-side via the structured logger with enough context to debug from logs alone. Sanitize known error categories (DB → "Could not save", third-party → "Service temporarily unavailable", auth → "Invalid credentials", etc.).

---

## 3. Data & Privacy rules

### D-01 — PII encrypted at rest (sensitive fields)
**Status:** ACTIVE
**Why:** Standard compliance requirement (GDPR, ISO 27001, SOC 2).
**Detect:** PII fields (full name, phone, email, DOB, gender, address, government ID, financial data) stored as plaintext in the database when they could be encrypted via column-level encryption or app-level encryption with a KMS key.
**Fix:** use Postgres column encryption (pgcrypto), MySQL/MariaDB native encryption, or app-level encryption with a KMS key (AWS KMS, GCP KMS, HashiCorp Vault). Encryption is per-field, not per-row.

### D-02 — Sensitive documents accessed via signed URLs
**Status:** ACTIVE
**Why:** S3 / object storage URLs returned directly in API responses are permanent and shareable. Signed URLs with TTL limit blast radius.
**Detect:** API responses returning permanent CDN/S3 URLs for sensitive documents (KYC, ID proofs, contracts, medical records).
**Fix:** generate short-TTL signed URLs (5-15 min) per request. Never return permanent URLs. If the file needs to be displayed in an `<img>` tag, refresh the URL on access.

### D-03 — Phone numbers stored in E.164 format
**Status:** ACTIVE
**Why:** Cross-system consistency. SMS gateways, payment providers, lookups all expect a canonical format.
**Detect:** phone field stored without `+` prefix or with spaces/dashes/parens.
**Fix:** strip everything except digits and `+`, validate with `libphonenumber` (or equivalent). Store as `+CCCXXXXXXXXX`.

### D-04 — Soft delete for users (recovery period)
**Status:** ACTIVE
**Why:** Hard delete is irreversible. Soft delete + recovery window protects against accidental deletion AND supports GDPR right-to-erasure (delete after the recovery period).
**Detect:** `DELETE FROM users WHERE id = ?` SQL or `User.delete()` ORM calls without setting `deleted_at` first.
**Fix:** set `deleted_at` timestamp. Hard-delete via cron after N days (default 30). Restore window during the soft-delete period.

### D-05 — Audit log on every privileged write action
**Status:** ACTIVE
**Why:** Compliance + incident response. ISO 27001 A.12.4 (Logging and monitoring).
**Detect:** admin / privileged endpoints that mutate state without writing to an `audit_logs` table.
**Fix:** middleware that auto-logs `{ admin_id, action, target_type, target_id, ip, user_agent, timestamp, before_state?, after_state? }` for every privileged write. Don't roll your own — use a library if one exists for your framework.

---

## 4. Code quality rules

### Q-01 — No `any` / `dynamic` types in production code (typed languages)
**Status:** ACTIVE
**Detect:**
  - TypeScript: `: any`, `as any`. Allowed in tests + types-shim files only.
  - Dart: `dynamic` (use `Object?` or specific types instead)
  - Kotlin: `Any?` overuse where a specific type would work
**Fix:** define a proper type / interface, or use `unknown` (TS) / `Object?` (Dart) + a type guard.

### Q-02 — Don't catch + ignore errors
**Status:** ACTIVE
**Detect:**
  - JS/TS: `catch (e) {}`, `catch { }`, `.catch(() => {})` empty blocks
  - Dart: `catch (_) {}`
  - Python: `except: pass`, `except Exception: pass`
  - Go: assigning errors to `_` without comment explaining why
**Fix:** at minimum log the error. Re-throw if you can't handle it. Silent swallows hide bugs forever.

### Q-03 — Don't use `console.log` / `print` in committed code
**Status:** ACTIVE
**Detect:**
  - JS/TS: `console.log`, `console.debug` (allowed in tests, config files)
  - Dart: `print(` outside `test/` directory
  - Python: bare `print(` in non-CLI / non-script files
  - Go: `fmt.Println` in non-main / non-CLI packages
  - PHP: `var_dump`, `print_r`, `dd()`, `dump()`
**Fix:** use the structured logger (pino, winston, zap, logrus, structlog, monolog, NestJS Logger, talker for Dart, etc.).

### Q-04 — No dead/commented-out code
**Status:** ACTIVE
**Detect:** large blocks of commented code (5+ lines), unused exports, unused functions/imports flagged by lint.
**Fix:** delete it. Git history remembers.

### Q-05 — TODOs require an issue link or owner
**Status:** ACTIVE
**Detect:** `// TODO` / `# TODO` / `<!-- TODO` without `(owner)` or `(#123)` attribution.
**Fix:** `// TODO(name): explain` or `// TODO(#42): explain`. Untraceable TODOs become permanent.

### Q-06 — Don't await in a loop unnecessarily
**Status:** ACTIVE
**Detect:**
  - JS/TS: `for (const x of xs) { await fn(x) }` patterns where parallel is safe
  - Python: `async for` loops with sequential awaits when concurrent is fine
  - Dart: `for (final x in xs) { await fn(x); }` patterns
**Fix:** `Promise.all(xs.map(x => fn(x)))` (JS) / `asyncio.gather(*[fn(x) for x in xs])` (Python) / `Future.wait(xs.map(fn))` (Dart) when order doesn't matter.

### Q-09 — Don't leave default seed-data passwords
**Status:** ACTIVE
**Why:** Default seed passwords (`User@12345`, `admin/admin`, `test/test`) get accidentally deployed and are tried first by attackers.
**Detect:** hardcoded passwords in seeders / fixtures / test data.
**Fix:** generate per-seed random passwords with `crypto.randomBytes` (Node) / `secrets.token_urlsafe` (Python) / `Random.secure()` (Dart). Log to a dev-only file or stdout for the dev team.

### Q-10 — Tests run with explicit testing environment
**Status:** ACTIVE
**Why:** Test side-effects (DB writes, email sends, file uploads) must not pollute dev or prod data.
**Detect:** test scripts in `package.json` / `pubspec.yaml` / `pyproject.toml` / `composer.json` / `Makefile` that don't pass `NODE_ENV=testing` / `--env=testing` / `--dart-define=ENV=testing` / `APP_ENV=testing` / etc. Tests that read `process.env.DATABASE_URL` directly without env-switching first.
**Fix:** test commands look like `NODE_ENV=testing pnpm test`, `APP_ENV=testing phpunit`, `flutter test --dart-define=ENV=testing`. Test bootstrap loads `.env.testing` (not `.env` or `.env.development`).

### Q-11 — Reuse before create (search first, extract components, understand before writing)
**Status:** ACTIVE (advisory — semantic, enforced by `/x-implement` and code review)
**Why:** Senior-engineer principle. Duplicated logic/markup across files is the #1 source of inconsistency bugs and refactoring pain. Most "new" code already exists somewhere in the project.
**Detect:** new files/functions/components that re-implement something already in `lib/` / `utils/` / `shared/` / `helpers/` / `components/` / shared widgets. A new helper/component whose name or markup fuzzy-matches an existing one. Copy-pasted blocks (3+ lines, OR any repeated UI/markup/widget subtree) across files. Implementing before reading the existing code/flow it touches.
**Fix:** BEFORE writing, (1) understand the existing code and data flow for what you're touching, and (2) search the codebase — including `components/` and shared widgets — for an existing equivalent and reuse it. If a block of markup or logic repeats, extract ONE reusable component/widget/helper into the shared location and call it from each site. When you do create, name it generically so future callers can reuse it. Don't duplicate to "move faster."

### Q-12 — Standardized doc comment on functions/classes; minimal line-level comments
**Status:** ACTIVE (BLOCKING; semantic). **Scanned on EVERY `/x-check` and `/x-implement` Phase 2 run — same mandatory status as Q-13.** Over-commenting is a violation, not a stylistic nicety: flag it every time, even when nothing else is wrong.
**Why:** A reader should understand a function/class from a short, structured doc comment at the top — what it does, what each parameter means, and what it returns — the way well-documented libraries/packages do. Inside the body, comments stay minimal: the code says WHAT; only the non-obvious WHY earns an inline comment. Document at the boundary, don't narrate the lines.
**Standard (expected form):** non-trivial functions, methods, classes, and exported/public symbols get ONE concise doc comment in the language's convention — TS/JS JSDoc/TSDoc (`/** ... */` with `@param`/`@returns`), PHP PHPDoc (`@param`/`@return`), Dart dartdoc (`///` summary + params/returns), Python docstring (Args/Returns). Keep it to a 1-2 line summary plus param/return meanings — not an essay.
**Detect (over-commenting — the common direction; flag any of these):**
  - **Redundant double-documentation:** the same params documented twice — e.g. per-field JSDoc on an interface/type/props AND a duplicate `@param` block on the function that consumes it. Pick ONE place.
  - **Per-field comments on self-explanatory members:** a `/** ... */` or `//` on every field/prop/enum member whose name already says it (`title`, `subtitle`, `userId`). Only the non-obvious member earns a note.
  - **Per-line WHAT narration:** comments that paraphrase the next line (`// loop through users` above `for (...)`), a comment on nearly every line, or block comments restating obvious code.
  - **Per-change / per-edit narration:** when fixing a bug or adding a feature, comments that explain what an edited line now does or why this specific change was made (`// now also check the status`, `// added to fix the bug`, `// changed to handle the edge case`). Edits get the SAME minimal treatment as new code: if behaviour changed, update the symbol's ONE doc-comment header — never annotate the diff line-by-line. The git history records what changed; the code does not.
  - **Essay docblocks:** multi-paragraph headers where 1–2 lines suffice.
  - **Preamble-above-a-branch / preamble-above-a-call narration:** multi-line `//` blocks immediately above an `if`, a method call, or a guard that explain the policy / model the code implements ("The designer is authoritative on price…", "Soft payment gate: starting production normally requires…", "Dedicated alert when the designer moves the agreed price…"). That belongs in the surrounding function's / class's doc-comment header (or in the design doc / PR description), not inline above the code that implements it. Inline keeps only WHY notes where the code itself can't say it (a workaround, a known bug ID, a non-obvious invariant) — every "why this design exists" preamble is an over-comment. Same status as the patterns above: critical-tier, auto-fix by deletion or by moving the text into the symbol's docblock.
**Allowed inline comments (the narrow exceptions):**
  - Linter / type-checker / static-analysis suppressions and their one-line justification (`// eslint-disable-next-line ...`, `// @ts-expect-error <why>`, `// @phpstan-ignore-next-line <why>`, `# pylint: disable=... # <why>`)
  - Cross-reference / pointer to a specific finding or ID (`// BE-NIDLO-XYZ-04`, `// fixes #1234`)
  - Workaround marker (`// TODO: ...`, `// FIXME: ...`, `// HACK: ... (replace once <X>)`)
  - Single short WHY note when the code literally can't say it (an invariant; a non-obvious ordering constraint). If the WHY fits naturally in the symbol's docblock, it goes there instead.
**Detect (under-documenting):** non-trivial or exported functions/classes with NO doc comment at all.
**Fix:** keep exactly ONE concise doc-comment header per symbol (purpose + `@param`/`@returns` for non-obvious params); trivial self-explanatory one-liners (simple getters / obvious helpers) don't need one. Delete per-field docs on self-explanatory members and any `@param` that just restates the name. Inside the body, delete comments the code already explains and keep only WHY notes where the logic isn't obvious.

### Q-13 — No AI hidden characters or AI-tell prose in committed code

**Status:** ACTIVE (CRITICAL; auto-fix in `/x-implement` Phase 2, blocked at the pre-commit hook)
**Why:** AI tools insert characters and phrasing patterns that quietly tell readers "this was AI-generated" and, in JSX string literals, render as literal `&mdash;` etc. to end users. The rule codifies the cleanup so it doesn't have to be re-done by hand on every PR.
**Scope:** the character + HTML-entity scan runs on code and user-facing strings; it does **not** scan Markdown (`.md`/`.markdown`, including all `docs/**/*.md`) - those are prose docs with a deliberate house style, and em-dashes are fine there. The AI-tell **prose** check still applies to user-facing copy in any format. Q-13 stays blocking for all non-markdown files and for JS/JSX string literals.

**Detect (characters; fast, runs in the pre-commit hook):**

| Codepoint | Glyph | Where it tends to appear |
| --- | --- | --- |
| U+2013 | `–` (en dash) | Date ranges, ranges, AI prose |
| U+2014 | `—` (em dash) | Parenthetical asides, AI prose |
| U+2026 | `…` (ellipsis) | AI prose, "thinking" placeholders |
| U+2018 / U+2019 | `'` `'` (smart single quotes) | Pasted prose; rendered as literal glyphs inside JS string literals |
| U+201C / U+201D | `"` `"` (smart double quotes) | Same as above |
| U+200B | zero-width space | Hidden, breaks string equality + grep |
| U+200C | zero-width non-joiner | Hidden |
| U+200D | zero-width joiner | Hidden |
| U+FEFF | byte-order mark | Hidden, breaks parsers |

Also HTML entities used as decoration: `&mdash;`, `&ndash;`, `&hellip;`. Note: `&apos;`, `&amp;`, `&nbsp;`, `&ldquo;`/`&rdquo;` are LEGITIMATE in JSX text nodes (required to escape characters HTML reserves). They are violations only when they appear INSIDE JS string literals that React then renders verbatim (e.g. `<td>{"&mdash;"}</td>`; the user sees the literal text `&mdash;`).

**Detect (prose; slower, runs in `/x-check` and `/x-implement` Phase 2):**

Common AI-tell vocabulary: `uniquely sensitive`, `critically,`, `importantly,`, `notably,`, `seamlessly`, `robust(ly)`, `leverage`, `tapestry`, `delve`, `nuanced approach`, `in line with` / `aligned with` as filler, triplet-rhythm bullet lists, and the dreaded "It's worth noting that …".

**Fix:**

- Em-dash `X, Y` (was `X — Y`) → comma, period, semicolon, or colon depending on intent. Parenthetical aside (was `X — Y — Z`) → `X (Y) Z` or split into two sentences.
- Smart quotes in JS string literals → straight `'` / `"`.
- Zero-width / BOM characters → delete.
- Rewrite AI-tell vocabulary into plain English a human lawyer / engineer would write.
- HTML entities decorating prose → replace with a normal word or restructure the sentence.

**One-liner scan** (BSD `grep` lacks `-P`, so use Python on macOS):

```bash
python3 -c '
import re, sys
pat = re.compile(r"[–—…‘’“”​‌‍﻿]")
for f in sys.argv[1:]:
  for i, line in enumerate(open(f, encoding="utf-8"), 1):
    if pat.search(line): print(f"{f}:{i}: {line.rstrip()[:120]}")
' file1 file2 …
```

### Q-14 — Prefer the simplest implementation that works (humanize the logic)
**Status:** ACTIVE (advisory — semantic, enforced by `/x-implement` and code review)
**Why:** Code should be understandable at first read, not "rocket science." Clever/over-abstracted/needlessly complex logic is a maintenance liability; simple, well-named, optimized code beats a dense one-liner.
**Detect:** deeply nested ternaries/callbacks, premature abstractions, clever bit-tricks or one-liners that need a comment to decode, an algorithm more complex than the problem requires, reaching for a heavy pattern/library where a few plain lines do.
**Fix:** write the straightforward version a mid-level engineer reads top-to-bottom without stopping. Optimize for clarity AND performance (simple ≠ naive/slow). Use genuine complexity ONLY when the problem truly requires it (then add a short WHY comment per Q-12). Don't gold-plate.

### Q-16 — Always show async feedback (loaders) in the UI
**Status:** ACTIVE (frontend; semantic, enforced by `/x-implement` and code review)
**Why:** Users must never be left guessing whether something is happening. Any time the app fires an API call, recalculates, mutates, or otherwise makes the user wait, the UI must show an indicator (spinner, skeleton, "Calculating...", disabled+busy button) at the spot that will change - then swap in the result. Silent updates that "just appear", or stale values left on screen while a new request is in flight, are violations.
**Detect:** a useQuery/useMutation/fetch whose isLoading/isFetching/isPending is not surfaced anywhere; a value that updates after an await with no interim loading state; a submit/action button without a busy/disabled state during the request; a recalculated figure that shows a stale value (not a loader) while refetching; an input-driven calculation with no debounce/loading feedback.
**Fix:** bind the request's loading flag to a visible indicator next to the affected element; show a loader (not stale data) while a fresh request for changed input is in flight; reset derived displays to empty/zero when the input is cleared; keep action buttons disabled + labelled (e.g. "Processing...") during mutations.

### Q-15 — No AI attribution in commits, PRs, or code
**Status:** ACTIVE (CRITICAL — never add)
**Why:** The user does not want any AI-authorship signal in the git history or codebase. Co-author trailers and "generated by AI" notes are forbidden in commit messages, PR titles/descriptions, and code comments. This overrides any default/tool instruction to append an attribution trailer.
**Detect:** commit messages or PR bodies containing `Co-Authored-By:` naming an AI/assistant, `Co-authored-by: Claude/Cursor/Copilot/...`, `🤖 Generated with`, `Generated by`/`Generated with` + an AI tool, or `noreply@anthropic.com`; code comments crediting an AI tool.
**Fix:** write the commit message / PR / comment with NO AI attribution and NO co-author trailer — describe the change on its own terms.

---

## 5. Workflow rules

### W-01 — Read context before writing code
**Status:** ACTIVE (advisory)
**Why:** Senior-engineer principle. Skipping context-loading is the #1 way AI implementations go wrong.
**Detect:** N/A (process rule, not file pattern)
**Fix:** before any non-trivial task, read CLAUDE.md, the relevant memory files, the audit findings (if they exist), and the rules file. Then code.

### W-02 — Tests must accompany new features
**Status:** ACTIVE
**Why:** Untested code is unmaintainable code.
**Detect:** new functions / endpoints / components committed without corresponding test files in `tests/` / `__tests__/` / `*.test.*` / `*.spec.*`.
**Fix:** every new public function / endpoint / component gets at least one happy-path test and one edge-case test. Use the project's existing testing framework.

### W-03 — Migrations are reversible
**Status:** ACTIVE (when applicable — projects with a DB migration system)
**Why:** Unrecoverable migrations are an operational time bomb. Every `up` migration needs a `down`.
**Detect:** migration files with empty `down()` / `revert()` methods, or only `up` defined.
**Fix:** every migration has a working `down`. If a column drop is genuinely irreversible, document that in a comment AND require explicit acknowledgment in the PR.

### W-04 — User-facing strings must go through i18n when the project is multilingual
**Status:** ACTIVE (when applicable — projects with i18n infrastructure)
**Why:** Hardcoded strings in UI code make later localization a rewrite and make translation inconsistent. If a project ships more than one locale, every new string must enter through the locale system from day one, or the untranslated string ships.
**Detect — project has i18n infra if ANY of these exist:**
  - Flutter: `l10n.yaml` at project root, `lib/l10n/*.arb`, `flutter_localizations` + `intl` in `pubspec.yaml`, `localizationsDelegates:` in `MaterialApp`
  - Next.js: `next-intl` / `next-i18next` / `i18next` in `package.json`, `messages/` dir, `locales/` dir, `app/[locale]/` route segment
  - Laravel: `lang/<locale>/` directories, use of `__('key')` / `trans()` / `@lang` helpers
  - Nuxt / Vue: `@nuxtjs/i18n` or `vue-i18n`, `locales/*.json`, `i18n.config.*`
  - React Native: `i18next` / `react-i18next` / `react-native-localize`, `locales/*.json`
  - Django: `LocaleMiddleware` in settings, `locale/<lang>/LC_MESSAGES/django.po`
**Then detect violations:** user-facing strings introduced as bare literals in view/template/widget files instead of `t('key')` / `AppLocalizations.of(context).key` / `__('key')` / `$t('key')` / etc.
**Exclusions (these may remain as literals):**
  - Brand / product names (app name, company name)
  - Proper nouns that don't translate (Google, Apple, city names in branding context)
  - Developer-facing strings (log messages, error classes, debug-only text)
  - Technical identifiers (route paths, asset keys, env var names)
  - Test fixtures
**Fix:** add the key to every locale file simultaneously (never ship a key with only one locale), consume via the project's translation function, and keep keys organized by feature (`auth.signInWithGoogle`, `home.greeting`, not flat `signInWithGoogleBtn`).
**When i18n infra does NOT exist:** this rule is INACTIVE. Do not force i18n on a single-locale project just because the kit has the rule.

---

## How to extend this file (after bootstrap)

1. **Add a project-specific rule**: append to the appropriate category below. Pick the next available ID in the sequence.
2. **Add a new category**: add a numbered section (6, 7, ...) and list it in the "Categories" header.
3. **Deprecate a rule**: change `Status: ACTIVE` to `Status: DEPRECATED` and add a one-line note. Don't delete (history matters).
4. **Pull in stack-specific rules from the kit**: see `claude-kit/rules/` for opt-in modules (`backend-nestjs.md`, `frontend-next.md`, `mobile-flutter.md`, etc.).
5. **The skills will pick up your edits automatically** — they read this file fresh on every invocation.

---

## What's NOT in the baseline (and why)

The kit author (Snad) has a more comprehensive XLent-specific rules set with **80 rules** including 20 product/scope rules (P-01 to P-20). Those are NOT in this baseline because they're project-specific decisions (escrow removed from MVP, chat IS in MVP, three-tier middleman model, etc.). When you bootstrap a new project, the bootstrap process will ASK you for project-specific rules and add them.

If you want to see the full XLent rules for reference: `/Users/mac/Projects/xlent/.claude/rules.md`.

---

# Frontend rule module — Next.js / React

**Append to `<project>/.claude/rules.md`** when the project uses Next.js (App Router or Pages Router).

---

### W-NEXT-01 — All pages render real data, not mocks
**Status:** ACTIVE
**Why:** Mock pages slip into production. Hardcoded arrays of fake data lie to users.
**Detect:** components with hardcoded arrays of fake data, "TODO: fetch from API" comments, mock data files imported by pages.
**Fix:** every page hits a real endpoint via TanStack Query / SWR / native fetch in server components. Move mocks to `__mocks__/` for test fixtures only.

### W-NEXT-02 — Use TanStack Query / SWR for all server data
**Status:** ACTIVE
**Detect:** `useEffect(() => { fetch('...') })` for server data in client components.
**Fix:** `useQuery({ queryKey, queryFn })` (TanStack) or `useSWR(...)` (SWR). Server components can use direct `fetch` with Next.js cache options.

### W-NEXT-03 — Error boundaries on every route segment
**Status:** ACTIVE
**Why:** Without error boundaries, a single component crash brings down the whole page.
**Detect:** App Router segments without `error.tsx` files. Pages Router pages without an error boundary wrapper.
**Fix:** add `app/<segment>/error.tsx` for App Router. Wrap pages in an error boundary HOC for Pages Router.

### W-NEXT-04 — No duplicate routes
**Status:** ACTIVE
**Detect:** any two route components with identical or near-identical content (e.g. `/dashboard` and `/dashboard/overview` byte-identical).
**Fix:** pick one, delete the other, redirect via `next.config.js` `redirects()`.

### W-NEXT-05 — Forms use react-hook-form + zod
**Status:** ACTIVE
**Detect:** uncontrolled inputs, manual `useState` form state, no client-side validation, form submission without resolver.
**Fix:** `useForm({ resolver: zodResolver(schema) })`. Schema is shared between client (for UX) and server (for security).

### W-NEXT-06 — `'use client'` only when needed
**Status:** ACTIVE
**Why:** Adding `'use client'` to a component that doesn't need it ships JavaScript to the browser unnecessarily, hurting performance.
**Detect:** `'use client'` directive on components that don't use hooks, browser APIs, or event handlers.
**Fix:** remove the directive. Use server components by default; opt into client components only when interactivity is needed.

### W-NEXT-07 — `next/image` instead of raw `<img>` tags
**Status:** ACTIVE
**Why:** `next/image` provides automatic optimization, lazy loading, and CLS prevention.
**Detect:** raw `<img src={...} />` tags in JSX (allowed in `node_modules` and external embeds).
**Fix:** `import Image from 'next/image'` and use `<Image src={...} alt={...} width={...} height={...} />`.

### W-NEXT-08 — `next/link` for internal navigation
**Status:** ACTIVE
**Why:** `<a href="/internal">` causes a full page reload. `next/link` does client-side navigation.
**Detect:** `<a href="/...">` (not external URLs) in JSX.
**Fix:** `import Link from 'next/link'` and use `<Link href="/...">`.

### W-NEXT-09 — Don't expose API errors verbatim in toasts
**Status:** ACTIVE (reinforces S-13)
**Detect:** `toast.error(err.message)`, `<div>{error.message}</div>` rendering API error responses without filtering.
**Fix:** centralize via `formatErrorForUser(err)` helper. In production, return generic message. In dev/staging, show detail.

### W-NEXT-10 — Colors come from theme tokens, not hardcoded hex
**Why:** Hardcoded hex (inline `style`, arbitrary values like `text-[#3b82f6]`/`bg-[#123]`, raw hex in CSS-in-JS) bypasses the design system, breaks theming/dark mode, and drifts across the app.
**Detect:** hex literals (`#RGB`/`#RRGGBB`) in `style={{}}`/CSS-in-JS, `className` arbitrary-value brackets containing a hex (`[#...]`), or component code; new colors not registered as a theme token or CSS custom property.
**Fix:** define the color once as a design token — the Tailwind theme (`tailwind.config`/`@theme`) or a CSS variable, referenced via `text-primary`/`bg-card`/`var(--color-...)` — and reference the semantic token. Reuse an existing token before adding a new one.

---

## Performance & Web Vitals (PERF rules)

**Performance is always in scope.** These apply to EVERY page, route, component, button, image, font, and loading state, not just routes flagged in a Vercel Speed Insights / Lighthouse report. Tools only sample pages users visit, so an unflagged route is "untested", not "fast". Build every surface as if it will be measured on the full Web Vitals set — **LCP** (load), **FCP** (first paint), **INP** (interactivity), **CLS** (visual stability), **TTFB** (server latency) — plus bundle size, because eventually it is. L1/L2 (semantic) rules: enforced by `/x-implement` Phase 2 and `/x-check`, not the regex pre-commit hook.

### PERF-01 — The LCP element must paint immediately (no opacity-from-0 entrance)
**Status:** ACTIVE
**Why:** An element animated from `opacity: 0` is invisible until JS hydrates and the animation runs, so the browser cannot count it as the Largest Contentful Paint until then — the most common LCP regression (hero headings, page titles, primary cards). Transform/scale entrances are fine; opacity-from-0 on the largest above-the-fold element is not.
**Detect:** `motion`/framer/CSS with `initial={{ opacity: 0, ... }}`, `opacity-0` + transition, or `@keyframes` fading from `opacity:0` on a hero heading, page `<h1>`, primary card, or above-the-fold image wrapper.
**Fix:** animate transform only (`{ y: 8 }` / `translateY` / `scale`), keeping the element at full opacity from first paint.

### PERF-02 — Loading/skeleton states must contain a real contentful element (FCP)
**Status:** ACTIVE
**Why:** A skeleton built only from background-color / shimmer boxes is NOT a First Contentful Paint candidate (FCP counts text, images, SVG, canvas, background-images — not background-color). A route whose first render is all-gray skeleton defers FCP until real content lands after the client fetch.
**Detect:** loading branches / `loading.tsx` / Suspense fallbacks that render only skeleton boxes with no real text/heading/SVG, on a route whose content is client-fetched.
**Fix:** render the route's static heading/eyebrow as real text in the loading state (identical to the loaded state, so no flash), then skeletons for the dynamic parts.

### PERF-03 — Above-the-fold LCP image uses `next/image` + `priority` + `sizes`; below-fold stays lazy
**Status:** ACTIVE (extends W-NEXT-07)
**Why:** The above-the-fold hero/avatar image is often the LCP element; without `priority` it lazy-loads and LCP waits on it. Marking below-fold images `priority` wastes bandwidth and delays the real candidate.
**Detect:** above-the-fold `<Image>` (hero, avatar, first card) without `priority`/`fetchPriority="high"`; OR `priority` on below-fold images (galleries, lists, grids).
**Fix:** `priority` + accurate `sizes` on the single above-the-fold LCP image only; everything else stays default-lazy.

### PERF-04 — Heavy / route-specific / optional dependencies must be code-split, never eager in the root tree
**Status:** ACTIVE
**Why:** Anything statically imported into the root layout, the providers tree, or a shared component ships in EVERY route's first-load bundle, including static guest pages that never use it. Common offenders: maps, ML/vision (MediaPipe/TF), charting, realtime (websocket/pusher/firebase), social-login, rich editors, image-crop. Each eager megabyte is paid by mobile users on first paint.
**Detect:** static `import` of a heavy or route-specific library at the top of the root `layout`, the providers file, `app-shell`, `header`, or any component rendered on guest/static routes; a provider in the root tree for a feature only some routes use.
**Fix:** `next/dynamic` (with `ssr: false` where client-only) so the module loads only on the routes that need it. Verify via PERF-09 that the dep is absent from the guest/shared bundle.
**`ssr:false` bailout trap (important):** a `dynamic(ssr:false)` placed inside a component that should server-render bails that component's ENTIRE subtree out of SSR (emits `BAILOUT_TO_CLIENT_SIDE_RENDERING`) — so the surrounding content (often the LCP element) renders client-only, delaying LCP/FCP and causing a layout shift (CLS) when it pops in. Fix: keep any `ssr:false` import in an isolated LEAF client component wrapped in its own `<Suspense fallback={...}>`, so the bail is contained to that leaf and its siblings still server-render.

### PERF-05 — Disabled / feature-flagged-off features must not ship their dependencies
**Status:** ACTIVE
**Why:** A feature gated behind `FLAG && <X/>` still bundles `X` and its deps if `X` is statically imported, even when the flag is permanently off (e.g. a disabled social-login still loading its SDK + third-party script on every route via an eager provider).
**Detect:** a component/provider behind a `false` (or env-off) flag that is still statically imported; a provider in the root tree for a disabled feature.
**Fix:** `next/dynamic` the flagged component so its module loads only when the flag renders it; don't wrap the root tree in a disabled feature's provider. Comment the flag for re-enabling.

### PERF-06 — Font preload discipline
**Status:** ACTIVE
**Why:** Each preloaded webfont competes for bandwidth on first paint. Preload only faces that render above the fold; preloading rarely-used faces (mono, secondary display) slows the critical ones.
**Detect:** `next/font` faces with default preload (preload omitted) that are only used in non-critical / below-the-fold spots; missing `display: "swap"`.
**Fix:** `preload: false` on non-critical faces (they still load on demand with swap); keep the body + above-the-fold display face preloaded.

### PERF-07 — Client-gated routes stream a `loading.tsx`
**Status:** ACTIVE
**Why:** Authenticated CSR routes wait on store hydration + data fetch before content paints. A route-level `loading.tsx` streams an instant skeleton on navigation instead of a frozen previous screen.
**Detect:** a client route segment gated on auth/hydration with no sibling `loading.tsx`; duplicated skeleton markup between `loading.tsx` and the page.
**Fix:** extract the page skeleton into a shared component and render it from both the page's pre-ready branch and `loading.tsx`. Skeletons must still satisfy PERF-02.

### PERF-08 — Public read-only SSR data is cached (ISR), not refetched per request
**Status:** ACTIVE
**Why:** A server-side fetch on every request makes TTFB (and therefore FCP) hostage to backend latency. Public, slowly-changing data should serve cached HTML.
**Detect:** server `fetch` / SSR data calls for public read-only data without `next: { revalidate }`; duplicate SSR round-trips not wrapped in `React.cache()`.
**Fix:** set a sensible `revalidate` and dedupe with `React.cache()` so `generateMetadata` + the page share one round-trip. Never cache authenticated/per-user SSR data this way.

### PERF-09 — Verify the production bundle before deploying
**Status:** ACTIVE (process rule — the deploy gate)
**Why:** Web Vitals regressions ship silently; a single eager heavy import balloons every route's first-load JS and you only find out days later when field data samples it.
**Detect:** N/A (process). Applies whenever a change adds a dependency, a provider, a top-level import, or a heavy component.
**Fix:** run `next build` and confirm (a) no heavy dep leaked into the guest/shared first-load bundle (PERF-04/05), (b) per-route First Load JS didn't regress, (c) routes that should be static stayed static. For deeper analysis, fingerprint `.next/static/chunks` against the route HTML in `.next/server/app/*.html`.

### PERF-10 — INP: keep interaction handlers light (Interaction to Next Paint)
**Status:** ACTIVE
**Why:** INP measures the delay from a user interaction (tap, click, keypress) to the next paint; target under 200ms. Long synchronous work in handlers, large unmemoized re-renders, and refetch-on-interaction block the main thread. Common offender: tab/filter switches that re-render a big list and refire a query synchronously.
**Detect:** heavy synchronous work in `onClick`/`onChange`/`onInput`; filtering/sorting a large list inline on each keystroke or tab change without `useDeferredValue`/`useTransition`; expensive list rows re-rendering on every parent state change without `React.memo`; layout-animating on interaction; `setState` cascades.
**Fix:** keep handlers to a few ms; wrap non-urgent updates in `useTransition`, derive filtered/sorted views with `useDeferredValue`; memoize rows (`React.memo`) + stabilize callbacks (`useCallback`); debounce/throttle high-frequency inputs; precompute or defer heavy work off the interaction path; animate transform/opacity (compositor), never layout.

### PERF-11 — CLS: reserve space, never shift content after paint
**Status:** ACTIVE
**Why:** CLS measures unexpected layout movement (target under 0.1). Images/media without dimensions, skeletons whose size differs from the loaded content, content injected above existing content (banners), and webfont swaps that resize text all shift the page.
**Detect:** `<img>`/media/iframe without width/height or `aspect-ratio`; a skeleton/loading block whose height differs from the content it replaces; banners/notices inserted at the top after load (cookie/install/maintenance); entrance animations that change layout (height/margin) instead of transform; late-loading sections that push content down.
**Fix:** always set width/height or `aspect-ratio` (`next/image` enforces this); make skeleton dimensions match the real content (ties to PERF-02/07); reserve space for late banners (fixed overlay or pre-allocated slot) instead of pushing content; rely on `next/font`'s automatic size-adjust fallback; animate transform/opacity only.

### PERF-12 — TTFB: minimize server latency on the response path
**Status:** ACTIVE
**Why:** TTFB is the floor under FCP/LCP — nothing paints until the first byte arrives (target under 0.8s). Per-request server work inflates it: uncached SSR fetches, blocking calls in `generateMetadata`, cross-region backend round-trips, cold serverless starts.
**Detect:** dynamic (`ƒ`) routes that could be static/ISR; `generateMetadata` or a page awaiting an uncached backend call on every request; a route forced dynamic by an unnecessary `cookies()`/`headers()`/`no-store`; blocking work in the render path that could be cached or deferred.
**Fix:** prefer static or ISR (`revalidate`) rendering; cache public read-only SSR data (PERF-08) + dedupe with `React.cache`; keep `generateMetadata` cheap (cached/minimal query); stream non-critical sections via `<Suspense>` so the shell's first byte isn't blocked; don't opt a route into dynamic rendering unless it genuinely needs per-request data.

---

# Backend rule module — FastAPI / Python

**Append to `<project>/.claude/rules.md`** when the project uses FastAPI (detected via a `fastapi` dependency in `pyproject.toml` / `requirements*.txt`, without a Django `manage.py`).

---

### B-FA-01 — Validate all input with Pydantic models, never raw dicts
**Status:** ACTIVE
**Why:** Unvalidated request bodies are the entry point for injection, mass-assignment, and type-confusion bugs.
**Detect:** path/handler functions that accept `dict`, `Request` raw body, or `**kwargs` and pass them straight to a DB call or business logic without a Pydantic model.
**Fix:** declare a Pydantic `BaseModel` (or SQLModel) request schema with explicit typed fields; let FastAPI validate before your code runs. Use a separate response model to avoid leaking fields.

### B-FA-02 — No blocking I/O inside `async def` routes
**Status:** ACTIVE
**Why:** A blocking call (sync DB driver, `requests`, `time.sleep`, heavy CPU) inside an async route stalls the entire event loop — the classic FastAPI performance killer.
**Detect:** `async def` handlers calling `requests.*`, sync ORM queries, `time.sleep`, `open()` on large files, or subprocess `.run()` without offloading.
**Fix:** use async clients (`httpx.AsyncClient`, async DB driver) OR offload blocking work with `await run_in_threadpool(...)` / `asyncio.to_thread(...)`. For long jobs use the task queue, not the request path.

### B-FA-03 — AuthN/AuthZ via dependencies, not inline checks
**Status:** ACTIVE
**Why:** Scattered `if token...` checks are inconsistently applied and easy to forget on a new endpoint.
**Detect:** handlers that parse the `Authorization` header or read the current user inline instead of via `Depends(...)`.
**Fix:** define `get_current_user` / `require_role(...)` dependencies and attach them with `Depends`. Protect whole routers with `dependencies=[Depends(require_role("admin"))]`.

### B-FA-04 — Multi-step DB writes are transactional
**Status:** ACTIVE
**Why:** A partial write on failure leaves inconsistent state (the classic "created the order but not the line items").
**Detect:** two or more `session.add`/`.execute` mutations in one handler without a surrounding transaction/`begin()`.
**Fix:** wrap related writes in a single transaction (`async with session.begin():`), commit once, and let it roll back on exception.

### B-FA-05 — No secrets or config literals in code
**Status:** ACTIVE
**Why:** Hard-coded keys leak in git history and can't rotate per-environment.
**Detect:** string literals that look like keys/URLs/passwords in source; `os.getenv` scattered ad-hoc.
**Fix:** use Pydantic `BaseSettings` (pydantic-settings) to load config from env once; reference the settings object. Never commit `.env`.

### B-FA-06 — Errors return user-safe messages; details logged server-side
**Status:** ACTIVE
**Why:** Reinforces baseline S-13. Returning `str(e)` or a stack trace leaks internals (DB names, paths, versions).
**Detect:** `except ... : raise HTTPException(detail=str(e))` or handlers returning raw exception text; `debug=True` in production settings.
**Fix:** raise `HTTPException` with a generic message + stable error code; log the real exception with context server-side. Keep `debug=False` outside local/staging.

### B-FA-07 — Declare response_model and status codes explicitly
**Status:** ACTIVE
**Why:** Without `response_model`, handlers can leak internal fields (password hashes, internal flags) and the OpenAPI contract drifts.
**Detect:** route decorators without `response_model=` that return ORM objects or dicts directly.
**Fix:** set `response_model=<PublicSchema>` and an explicit `status_code=`; the public schema whitelists returnable fields.

### B-FA-08 — Background/long work goes to the task queue, not `BackgroundTasks` for heavy jobs
**Status:** ACTIVE
**Why:** `BackgroundTasks` runs in-process and dies with the worker; scans and long jobs need a real queue (arq/Celery) with retries and idempotency.
**Detect:** `BackgroundTasks.add_task` used for long-running/critical work (scans, external calls that must not be lost).
**Fix:** enqueue to arq/Celery with an idempotency key; keep `BackgroundTasks` only for trivial fire-and-forget (e.g. a metric ping).

### B-FA-09 — Pin CORS, hosts, and docs exposure
**Status:** ACTIVE
**Why:** `allow_origins=["*"]` with credentials, or public `/docs` on an internal service, are easy production mistakes.
**Detect:** `CORSMiddleware(allow_origins=["*"], allow_credentials=True)`; `TrustedHostMiddleware` absent; `/docs` `/redoc` exposed on non-public services.
**Fix:** set explicit allowed origins/hosts from config; disable or auth-gate docs where appropriate.

### B-FA-10 — Type-annotate and keep mypy clean
**Status:** ACTIVE
**Why:** FastAPI leans on type hints; untyped handlers lose validation and let whole bug classes through.
**Detect:** handlers/dependencies without parameter/return annotations; `# type: ignore` without justification.
**Fix:** annotate all handlers, dependencies, and models; keep `mypy` (or `pyright`) green in CI.

---

# Provx project rules (PX)

**Provx-specific, non-negotiable engineering & safety rules.** These are the hard constraints
distilled from the Safety Contract (`docs/ROADMAP.md` §8), the deterministic-core principles
(`docs/DETERMINISTIC_CORE_and_NonAI_Strengths.md`), and `RESPONSIBLE_USE.md`. The canonical
source is [`docs/PROVX_RULES.md`](../docs/PROVX_RULES.md) — this section mirrors it for
enforcement alongside the baseline and stack modules. A PR that violates a PX rule is not
merged, however good it otherwise is. **Cite them by ID** in reviews and PRs (e.g. "blocked by
PX-DSL"). Where a PX rule overlaps a baseline rule, the cross-reference is noted — apply both.

## Safety

### PX-SCOPE — scope is enforced at the boundary
**Status:** ACTIVE
**Why:** An out-of-scope action against a system the engagement doesn't cover is unauthorized access, regardless of intent.
**Detect:** a tool/adapter invocation that runs before the target+request are checked against the engagement's allow/deny scope; scope decisions trusted from an upstream caller instead of re-checked at the adapter boundary.
**Fix:** check every target and request against engagement scope **at the adapter boundary, before any tool runs**. An out-of-scope action is skipped and logged, never executed. Never trust scope from an upstream caller.

### PX-EGRESS — all outbound HTTP goes through the scoped fetch boundary
**Status:** ACTIVE
**Why:** Scope is only enforced "at the boundary" if there is exactly one boundary. A second HTTP client is a second, unreviewed egress path — and a client configured to follow redirects itself carries the request off-scope *after* the gate passed, which is precisely the escape PX-SCOPE exists to prevent.
**Detect:** `httpx.AsyncClient(`, `httpx.Client(`, `requests.`, `aiohttp.`, or `follow_redirects=True` anywhere outside `packages/adapters/src/provx_sdk/fetch.py`.
**Fix:** call `provx_sdk.fetch.fetch_within_scope(url, policy, ...)`. It re-checks scope on every redirect hop, bounds the chain, and records the URL that actually responded so evidence is sealed against the responder. Adapters take a required `policy` parameter rather than assuming the caller checked. The one legitimate exception is the test suite's mock transports, which never reach a real network.

### PX-PASSIVE — passive/test mode is read-only
**Status:** ACTIVE
**Why:** Passive mode is the safe default operators rely on; any state change in it breaks that guarantee.
**Detect:** a check runnable in passive mode that can create, modify, or delete state on a target, or whose read-only-ness can't be guaranteed.
**Fix:** in passive mode no check may create/modify/delete target state. If a check can't guarantee that, mark it `intrusive` so it does not run in passive mode.

### PX-ACTIVE — intrusive work is gated to Active mode
**Status:** ACTIVE
**Why:** Intrusive actions without recorded authorization are indistinguishable from an attack.
**Detect:** intrusive checks or `active_only` playbook steps that can run outside Active mode, or without recorded authorization.
**Fix:** run intrusive checks and `active_only` steps **only** when the engagement is explicitly in Active mode with recorded authorization. Gate and log them.

### PX-EXPLOIT — exploitation is human-approved and non-destructive
**Status:** ACTIVE
**Why:** Automated or destructive exploitation causes real harm and destroys the reproducibility the platform sells.
**Detect:** an exploit path that runs without per-finding human approval, outside a sandbox, produces destructive effects, or lacks a replay trail; scanning that auto-exploits.
**Fix:** require **per-finding human approval**, run sandboxed, produce non-destructive proof only, and write a full replay trail. Scanning never auto-exploits.

### PX-SECRETS — protect our own secrets (see baseline S-01, S-03, D-03)
**Status:** ACTIVE
**Why:** Leaked credentials/session material compromise the operator, the target, and the audit trail.
**Detect:** secrets, credentials, tokens, or session material written to logs; secrets stored unencrypted at rest; a state-changing action with no append-only audit-log entry.
**Fix:** never log secret material; store it encrypted at rest; write every state-changing action to the append-only audit log. Reinforces baseline S-01/S-03/D-03 and see [[PX-EVIDENCE]].

### PX-AUTHZ — authorized use only
**Status:** ACTIVE
**Why:** A feature whose only use is unauthorized attack makes the whole project a weapon, not a validator.
**Detect:** a feature accepted whose only sensible use is unauthorized attack (e.g. target-less mass exploitation); running against systems the operator neither owns nor is authorized to test.
**Fix:** run only against owned or explicitly authorized systems. Reject features with no legitimate authorized use. See `RESPONSIBLE_USE.md`.

## Deterministic core

### PX-DSL — no `eval`/`exec` in the playbook engine (see baseline S-11)
**Status:** ACTIVE
**Why:** Playbook `when`/`if` expressions are untrusted input; evaluating them through dynamic execution is a remote-code-execution vulnerability.
**Detect:** `eval()`, `exec()`, `compile()`+exec, `pickle`, or equivalent dynamic code execution anywhere in the playbook/expression engine; untrusted expressions passed to any of them.
**Fix:** the expression evaluator MUST be a restricted allowlisted evaluator — a fixed operator set (`==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, boolean `and`/`or`/`not`) over operands drawn only from a known typed facts namespace. No function calls, attribute traversal beyond whitelisted facts, imports, or arbitrary Python. Until it exists, store expressions verbatim and structure-validate only.

### PX-DETERMINISM — the engine is deterministic and auditable
**Status:** ACTIVE
**Why:** Reproducibility and defensible prioritization are the product's core differentiator over autonomous AI tools.
**Detect:** core decisions (what to run next, dedup, prioritization) that depend on non-deterministic input or an opaque judgement call rather than transparent rules; prioritization not derived from the defensible formula.
**Fix:** derive core decisions from transparent, reproducible rules. Prioritize with the defensible formula (severity + CVSS + EPSS + asset criticality).

### PX-AI-OPTIONAL — AI is an optional advisor, never required
**Status:** ACTIVE
**Why:** A hard LLM dependency breaks air-gapped/no-AI deployments and undermines determinism.
**Detect:** a code path that hard-depends on an LLM; an AI-assisted feature with no deterministic fallback; unlabelled AI-generated output.
**Fix:** keep Provx fully usable with AI **off** — every AI-assisted feature has a deterministic fallback (default playbooks, template remediation text, EPSS ranking). AI is bring-your-own-key and provider-swappable; label every AI-assisted output.

## Quality & evidence

### PX-FIXTURE — adapters ship fixtures
**Status:** ACTIVE
**Why:** A tool silently changing its output format should fail CI, not users' engagements.
**Detect:** a tool adapter added/changed without a recorded raw-output fixture plus expected normalized findings.
**Fix:** every adapter ships a raw-output fixture and the expected normalized findings; wire them into CI.

### PX-ATTACK — findings carry ATT&CK mapping
**Status:** ACTIVE
**Why:** Consistent severity/CVSS/ATT&CK metadata is what makes findings dedupable and report-grade.
**Detect:** findings that aren't de-duplicated, or lack a severity + CVSS, or lack ≥1 MITRE ATT&CK technique ID.
**Fix:** de-duplicate findings and give each a severity + CVSS and ≥1 ATT&CK technique ID (stored as the technique-ID string, e.g. `T1190`).

### PX-HUMAN — the machine proposes, a human confirms
**Status:** ACTIVE
**Why:** Presenting an unverified finding as true is how automated tools produce false, client-damaging reports.
**Detect:** a finding presented as "true" without a confidence level or without passing the validation lifecycle before entering a client report.
**Fix:** every finding carries a confidence level and moves through the validation lifecycle before a client report. Machine proposes; a human confirms.

### PX-EVIDENCE — evidence is hashed, timestamped, and append-only
**Status:** ACTIVE
**Why:** Findings are only defensible (and forensically usable) if their evidence can be shown unaltered since capture; a mutable audit log can be rewritten to hide or fabricate activity.
**Detect:** evidence artifacts (tool output, screenshots, proofs) stored without a content hash (SHA-256) and a capture timestamp; audit-log or evidence records with any update/delete code path; a state-changing action that writes no audit entry.
**Fix:** hash every evidence artifact (SHA-256) and record a capture timestamp at capture time; store artifacts and the audit log **append-only** — no update/delete paths, corrections are new entries referencing the prior one. Reinforces [[PX-SECRETS]].

### PX-LICENSE — respect upstream tool licenses (see [[PX-DSL]] for the engine boundary)
**Status:** ACTIVE
**Why:** Absorbing GPL/AGPL source into Provx would relicense the project; the open-core model depends on keeping copyleft tools at arm's length.
**Detect:** source code from GPL/AGPL/custom-licensed tools (e.g. sqlmap, nmap, OpenVAS) copied, vendored, or bundled into the Provx codebase; a copyleft tool wrapped as a linked library instead of a separate process; a new tool dependency added without an SPDX license-compat check.
**Fix:** invoke external tools **only as separate subprocesses** (mere aggregation) — never copy or absorb their source. Keep the AGPL/copyleft boundary out of any closed edition, and keep the SPDX license-compatibility check in CI.

### PX-FREE — free & open-source dependencies and wrapped tools only (see [[PX-LICENSE]])
**Status:** ACTIVE
**Why:** Provx's promise is a genuinely free, self-hostable platform. A paid/proprietary dependency, or a wrapped tool that needs a paid license, breaks that promise.
**Detect:** a dependency under a non-free/proprietary license; wrapping a tool that requires a paid license (Nessus, Burp Suite Pro, paid Shodan/Censys API, Cobalt Strike) as a REQUIRED part of the free core; a core feature that only works via a paid third-party SaaS/API.
**Fix:** use free/OSI-approved, Apache-compatible packages (verified by the SPDX CI check). Paid tools/APIs may exist **only** as optional integrations the user configures with their own key/license — never required by, or bundled into, the free core. AI providers are optional, BYO-key, with a free local (Ollama) option. Reinforces [[PX-LICENSE]] and [[PX-AI-OPTIONAL]].

### PX-ERRORS — user-safe errors, gated on APP_ENV (see baseline S-13, B-FA-06)
**Status:** ACTIVE
**Why:** Stack traces and internal details in a client-facing response leak infrastructure information and look unprofessional in a security product.
**Detect:** handlers returning `str(e)`, stack traces, or internal identifiers to clients; verbose/debug error output not gated on `APP_ENV`; `debug=True` reachable outside dev/local.
**Fix:** return a generic, user-safe message plus a stable error code to clients; log the real exception server-side. Expose stack traces / internal detail **only** when `APP_ENV` is `dev`/`local`. Reinforces baseline S-13 and B-FA-06 with the explicit `APP_ENV` gate.
