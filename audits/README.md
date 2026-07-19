# Provx codebase audit

Full-depth, file-by-file audit of every repo in the monorepo. Generated **2026-07-19**,
replacing the bootstrap audit of the same date (which predated the walking skeleton and
reported findings H1/M2/M3/M4 that are now fixed).

Findings cite the PX rules from [docs/PROVX_RULES.md](../docs/PROVX_RULES.md) and the
baseline/module rules from [.claude/rules.md](../.claude/rules.md) by ID.

> [!IMPORTANT]
> **This audit has been partly actioned.** The safety-in-motion and cleanup passes that
> followed closed findings 1, 4 and 5 below, plus `SDK-002`, `SDK-025`–`SDK-027`, `F-M2` and
> `F-M10`. Fixed findings are marked **✅ FIXED** in the per-repo files and kept for the
> record. The Top-5 below is preserved **as audited** — rewriting history would hide what the
> codebase actually looked like. Current open defects live in
> [`docs/KNOWN_ISSUES.md`](../docs/KNOWN_ISSUES.md).
>
> Still open from this list: **3** (no auth) and the residual DNS-resolution risk under
> finding 4, now tracked as `KI-003`.

> **Read this first.** Provx is pre-alpha. Authentication, the job queue, the PX-DSL
> expression evaluator, Active mode, exploitation, and additional adapters are **deliberately
> absent** and are recorded as *declared scaffolding*, not defects. The findings below are
> things that are wrong, unsafe, or inconsistent **within what is actually built**.

## Audit index

| Repo | Stack | Source files | Audit docs | Top severity |
|---|---|---|---|---|
| [backend/](backend/) | FastAPI · SQLModel · Alembic · Python 3.12 | 15 `app/` + 3 alembic + 7 tests | 8 | **Critical** |
| [frontend/](frontend/) | Next.js 14 App Router · React 18 · TS | 7 + 1 (`packages/client`) | 6 | **High** |
| [sdk/](sdk/) | `provx_sdk` library + `lab/` accuracy harness | 10 SDK + 4 lab + 10 tests | 10 | **High** |

23 documents, 5 832 lines. Roughly 37 source files plus 24 test/config files, read in full.

## Top 5 findings across all repos

Ordered by real-world consequence, not by label.

### 1. Scope is enforced on the first hop only — `follow_redirects=True`

`SDK-001` (High) · `F-H2` (High) — [module_scope.md](sdk/module_scope.md),
[module_services.md](backend/module_services.md)

[`probe()`](../packages/adapters/src/provx_sdk/adapters/security_headers.py) checks scope
against the *configured* URL, then lets httpx follow up to 20 unchecked hops. An in-scope
host can 302 the scanner onto `evil.test` or `169.254.169.254`. This is the exact failure
**PX-SCOPE** exists to prevent, and it is reported independently by two auditors.

It has a second, nastier half: the raw-output envelope records the **requested** target, not
`response.url`. So `seal()` computes a SHA-256 over a response and labels it with a host that
never sent it — **PX-EVIDENCE** turns a false attribution into a cryptographically attested
one. Wrong evidence made more convincing is worse than no evidence.

The current test suite **cannot** catch this: every test stubs `probe`.

### 2. The accuracy gate is itself non-deterministic

`SDK-003` (Medium) — [module_lab.md](sdk/module_lab.md)

[`score_target`](../lab/harness.py) builds `found = {check_id(d): d for d in drafts}` — a
last-wins dict. Two findings sharing a `matched_rule` on one target collapse to whichever came
last, and with a `min_severity` floor that flips the verdict. Executed and confirmed:

```text
HIGH,INFO  -> passed=False   TP=0 FP=1
INFO,HIGH  -> passed=True    TP=1 FP=0
```

Same findings, opposite results. **PX-DETERMINISM violated inside the determinism gate.**

**Latent, not live:** the one shipped adapter emits a unique `matched_rule` per header (5
unique rules), so no single target can produce a collision today. It becomes reachable the
moment a second adapter, or a multi-instance check, lands.

### 3. Anonymous caller controls both the scope allow-list and the targets

`F-C1` + `F-H4` (Critical/High) — [module_api.md](backend/module_api.md)

Auth being absent is declared scaffolding. The *compound* consequence is not: a caller
supplies the allow-list and the targets in the same unauthenticated request, and nothing
rejects internal addresses. `scope_allow: ["169.254.169.254"]` is accepted — confirmed:

```text
ScopePolicy(allow=['169.254.169.254']).is_in_scope('http://169.254.169.254/latest/meta-data/')
-> True
```

Scope is an *engagement* boundary, not an SSRF control, and it is currently doing neither job.
A deny-list of link-local/RFC-1918/loopback ranges belongs at the adapter boundary regardless
of what the engagement says.

### 4. Deny is exact-match while allow is subtree — and IP encodings evade deny

`SDK-026/027/028` (Medium) — [module_scope.md](sdk/module_scope.md)

The asymmetry in [`scope.py`](../packages/adapters/src/provx_sdk/scope.py) is a carve-out
that silently fails to carve. Confirmed:

```text
allow=['*.example.com'], deny=['prod.example.com']
  prod.example.com        -> False   (denied, correct)
  a.b.prod.example.com    -> True    (IN SCOPE — the deny did not cover the subtree)
```

Deny by IP is likewise defeatable by alternate encoding — `2130706433` and `0x7f.0.0.1` are
distinct hostnames that resolve to `127.0.0.1` but do not match `deny=['127.0.0.1']`.

Credit where due: the matcher **resisted 7 of 11** attempted bypasses, including userinfo
spoofing (`http://example.com@evil.test`) and suffix confusion (`example.com.evil.test`).

### 5. `SAFE_MODE` is inert — a safety control that looks wired and isn't

`F-H3` (High) — [module_core.md](backend/module_core.md)

`SAFE_MODE` is documented as an org-wide safety lock and injected by
[docker-compose.yml](../docker-compose.yml), but `Settings` has no `safe_mode` field and
`extra="ignore"` silently discards it. An operator setting `SAFE_MODE=true` gets no error and
no effect. Adjacent: an engagement's `mode` is validated `^passive$` only on the create
schema — never re-checked at scan time, no CHECK on the column — and `adapter.safety` is
never consulted at all.

## Cross-cutting themes

**Validation is strong at rest, weak in motion.** The `Finding` contract, the display-id
pattern, the ATT&CK validator, and the Jinja autoescaping are all solid. What is thin is
everything about a request *in flight*: the redirect chain, the mode at scan time, the
adapter's declared safety class, the resolved IP behind a hostname.

**The safety story is declarative, not enforced.** `SAFE_MODE`, `mode: passive`, and
`adapter.safety` are all *recorded* and none are *checked* at the moment of action. Each
reads as a control and functions as documentation.

**Tests stub exactly the boundary that carries the risk.** Every scan test monkeypatches
`probe`, which is where scope, redirects, TLS, and evidence attribution all actually live.
Coverage is good (104 tests) and structurally blind in one specific place.

**Test coverage is asymmetric across tiers.** Backend + SDK are well covered; the frontend has
**zero test infrastructure** — no runner, no deps, no `test` script — and the CI
`frontend-lint` gate is still a no-op stub. The untested frontend code is precisely the
security-control code (`isEngagementId`, the error taxonomy, the proxy handler, the PX-HUMAN
banner).

**Determinism is doctrine everywhere except the gate that enforces it.** See finding 2.

## Verified clean

Worth recording, so future audits do not re-litigate:

- **PX-DSL** — no `eval`/`exec`/`compile`/`pickle`/unsafe `yaml.load` anywhere in the SDK.
  `parse_output` verified genuinely pure and order-stable.
- **XSS** — `select_autoescape(default=True, default_for_string=True)` correctly covers the
  `.j2` extension; zero `| safe`. On the frontend, `finding.target` reaches the DOM only as a
  React-escaped text child, never as an attribute; no `dangerouslySetInnerHTML` in the repo
  (**S-06/S-07 clean**).
- **The report proxy is not an open proxy or SSRF pivot** — four independent grounds; no
  client headers are forwarded; the path is hardcoded and the id is UUID-gated.
- **PX-ERRORS** — the 500 handler's `APP_ENV` gate fails closed; production leaks nothing.
- **B-FA-04** — the scan write is genuinely one transaction; no orphaned `Scan` row on
  adapter failure.
- **PX-EVIDENCE (append-only)** — no update or delete path exists on evidence or findings.
- **Playbook loader** — raises on duplicate workflow names, with a test. The bootstrap
  audit's H1 is **closed**.
- **W-NEXT-02** — judged *not* violated; the rule's own text permits direct `fetch` in Server
  Components.

## Suggested order of work

1. Re-check scope on every redirect hop, and record `response.url` in the envelope (finding 1).
   This is one fix for two rule violations.
2. Make deny subtree-aware and resolve hostnames before the scope decision (finding 4).
3. Block internal/link-local address ranges at the adapter boundary, independent of engagement
   scope (finding 3).
4. Wire `SAFE_MODE`, re-check `mode` at scan time, and assert `adapter.safety` (finding 5).
5. Make `score_target` collision-explicit before a second adapter lands (finding 2).
6. Add a frontend test runner; the security-control functions are the first cases.
7. Add one integration test that does **not** stub `probe`, against a local redirecting target.

## Known race, not in the top 5

`F-H1` (High) — `display_id` allocation is a lock-free read-then-write
([scan_runner.py](../backend/app/services/scan_runner.py)). Two concurrent scans on one
engagement both compute `PVX-{N+1}`. The unique constraint on `(engagement_id, display_id)`
prevents corruption, so the loser's scan rolls back with an unretried 500 rather than writing
bad data. Ranked below the five above because it fails safe. Fix: `pg_advisory_xact_lock` on
the engagement id.
