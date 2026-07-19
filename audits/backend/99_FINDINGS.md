# Backend audit — 99 Consolidated findings

**Scope:** `/Users/mac/Projects/mine/provx/backend` — 15 files under `app/`, 3 under `alembic/`,
7 under `tests/`, plus `Dockerfile`, `docker-entrypoint.sh`, `pyproject.toml`, `requirements.lock`,
`alembic.ini`, and the root `docker-compose.yml`, `.env.example`, `pytest.ini`, `mypy.ini`,
`ruff.toml`. Every file read in full.

**Baseline:** the repo is a pre-alpha walking skeleton and is *deliberately* missing auth/RBAC, the
arq queue, the playbook engine, Active mode, exploitation, AI, PDF reports, EPSS enrichment, and a
second adapter. Those are listed under **Declared scaffolding** and are not defects. Everything
under Critical → Low is something genuinely wrong, unsafe, or inconsistent *within what is built*.

**Counts as audited:** 1 Critical (context-dependent) · 4 High · 11 Medium · 26 Low · 9 declared
scaffolding · 7 test-coverage gaps.
**Counts now:** 1 Critical (auth, partially mitigated) · **0 High** · ~9 Medium · 26 Low.


> [!NOTE]
> **Post-audit status (safety-in-motion + cleanup passes).** Findings marked **✅ FIXED**
> below were resolved after this audit was written. They are kept, not deleted: the record of
> what was found — and what it took to close it — is the point of an audit.
>
> Fixed since: `F-H2`, `F-H3`, `F-H4` (all High), `F-M2`, `F-M10`; `F-C1` partially mitigated
>
> Still open, deliberately: see [`docs/KNOWN_ISSUES.md`](../../docs/KNOWN_ISSUES.md).

---

## Critical

### F-C1 — Unauthenticated API that performs attacker-directed outbound HTTP requests

[`engagements.py:76`](../../backend/app/api/engagements.py#L76) ·
[`engagements.py:108`](../../backend/app/api/engagements.py#L108) ·
[`main.py:35`](../../backend/app/main.py#L35)

Absence of auth is declared scaffolding. Its **compound effect with the scan endpoint** is not, and
must be stated: `POST /engagements` is anonymous and lets the caller define the scope allow-list;
`POST /engagements/{id}/scan` then makes the server issue HTTP GETs to those targets. An anonymous
caller therefore supplies both the policy and the targets, and the server does the fetching. The
scope gate is not a boundary against the API caller — it is a boundary the API caller configures.

Consequences on any reachable port: use as an HTTP request relay; reach of hosts routable only from
inside the deployment network (see **F-H4**); unbounded outbound traffic with no rate limit; and,
because the SDK adapter follows redirects (**F-H2**), reach beyond even the caller's own declared
scope.

**Not** an argument for building RBAC now. It is an argument for (a) never publishing port 8000
beyond localhost until auth lands, (b) making that constraint explicit in the README and compose
comments, and (c) implementing `SAFE_MODE` (**F-H3**) as the interim kill switch. Cite PX-AUTHZ.

---

## High

### F-H1 — `display_id` allocation is a lock-free read-then-write; concurrent scans collide

[`scan_runner.py:79-88`](../../backend/app/services/scan_runner.py#L79) ·
constraint at [migration:117](../../backend/alembic/versions/b1428574732c_walking_skeleton_core_tables.py#L117)

```python
already_seen = await _existing_dedup_keys(session, engagement.id)  # line 79
allocated = len(already_seen)                                       # line 80
...
allocated += 1
display_id=display_id_for(allocated)                                # line 88
```

The next sequence number derives from an unlocked read inside the scanning transaction. No
`FOR UPDATE`, no advisory lock, no DB sequence. Under READ COMMITTED, two concurrent
`POST /{id}/scan` calls on the same engagement both observe N existing findings and both insert
`PVX-{N+1}`. `uq_finding_engagement_display_id` correctly refuses the second — so there is **no
corruption**, but the losing transaction rolls back **entirely**, the whole scan is discarded, and
the client gets an unretried 500 through the generic handler. A double-clicked button reproduces it.

Second, quieter defect in the same two lines: `allocated` is seeded from the count of **distinct
dedup keys**, not `MAX(display_id)`. Those coincide only because every row is written through this
dedup path and nothing is ever deleted. That invariant is real, undocumented, and unenforced — the
first import path, backfill, or delete makes the sequence silently restart into a collision.

**Fix:** take a `pg_advisory_xact_lock` on the engagement id (or `SELECT … FOR UPDATE` the
engagement row) at the top of `run_scan`. One line, serializes scans per engagement, and also
prevents concurrent duplicate probing. Additionally seed from `MAX(display_id)` rather than a count.

### F-H2 — Scope is enforced on the first URL only; the adapter follows redirects — ✅ FIXED

> **✅ Fixed after this audit.** Same fix as `SDK-001` — scope is re-checked on every redirect hop and evidence is sealed against the responding URL.

[`scan_runner.py:66-74`](../../backend/app/services/scan_runner.py#L66) ·
[`security_headers.py:124`](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L124)

`policy.is_in_scope(target.url)` validates the URL as supplied. The probe then executes:

```python
async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
    response = await client.get(target)
```

`follow_redirects=True` means an in-scope target answering `302 Location: https://out-of-scope.example/`
causes the client to fetch the out-of-scope host. The engagement scope is enforced once, on the
first hop, and not on any subsequent hop. The target controls the redirect, so the target controls
where Provx goes next.

Two distinct consequences:

1. **PX-SCOPE violation.** Provx makes a request to a host the engagement does not authorize. For a
   product whose core promise is provable scope discipline, this is the finding that matters most —
   and the existing test (`test_out_of_scope_target_is_never_reached`) cannot catch it, because it
   stubs `probe` and therefore never exercises redirect behaviour.
2. **Evidence integrity.** `encode_response(target, ...)` records the **originally requested** URL,
   not `response.url`. A finding sourced from a redirected host is attributed to the in-scope
   target, and the sha256 seal attests to a response the labelled target never sent. That is a
   PX-EVIDENCE problem as well as a scope one.

**Fix:** either `follow_redirects=False` and record the redirect as a finding/observation, or
re-run `policy.is_in_scope` on every hop via an httpx event hook / manual redirect loop. Record
`response.url` in the envelope either way. (Fix lands in the SDK; recorded here because the backend
is the component that owns the scope contract.)

### F-H3 — `SAFE_MODE` is advertised as an org-wide safety lock and is never read — ✅ FIXED

> **✅ Fixed after this audit.** `safe_mode` is a declared `Settings` field (default **true**) and is read by `app/services/safety.py`. `backend/tests/test_config_drift.py` fails if any injected variable is ever silently discarded again.

[`.env.example`](../../.env.example) · [`docker-compose.yml:19`](../../docker-compose.yml#L19) ·
[`config.py:21`](../../backend/app/config.py#L21)

`.env.example` documents it as: *"Org-wide safe-mode lock. When true, forces safety regardless of
engagement mode."* Compose injects it into the backend container. `Settings` declares **no
`safe_mode` field**, and `extra="ignore"` means it is silently discarded. Nothing in `app/` reads
it — verified by full-tree search.

A safety control that is documented, configured, deployed, and inert is worse than an absent one: an
operator setting `SAFE_MODE=true` reasonably believes they have engaged a guard. Given F-C1, this is
also the most natural place to put the interim "refuse to scan" kill switch.

**Fix:** add `safe_mode: bool = True` to `Settings` and consult it in `run_scan` alongside
`engagement.mode` and `adapter.safety`. Default true, fail closed, matching the `.env.example`
default. Cite PX-ACTIVE, PX-AUTHZ.

### F-H4 — Scope rules are host-string matches with no internal/link-local guard — ✅ FIXED

> **✅ Fixed after this audit.** `ScopePolicy` refuses loopback/RFC-1918/link-local/reserved/multicast literals unless `allow_dangerous_ranges` is explicitly set and logged.

[`scope.py:41-68`](../../packages/adapters/src/provx_sdk/scope.py#L41)

`ScopePolicy` matches hostnames against exact or `*.`-prefixed rules. There is no blocklist for
loopback, RFC1918, link-local, or metadata addresses. `scope_allow: ["localhost"]`,
`["169.254.169.254"]`, or `["*.internal"]` are all accepted and scanned. Combined with F-C1
(anonymous engagement creation) the backend becomes a general SSRF primitive against its own
deployment network — cloud metadata endpoints, the `db` and `redis` service names, internal
dashboards.

Note also `_matches` at [line 45](../../packages/adapters/src/provx_sdk/scope.py#L45):
`host.endswith(suffix)` where `suffix = rule[1:]` (i.e. `.example.com`). That is correct — it will
not match `notexample.com` — and the exact-apex case is handled separately. The matching logic
itself is sound; it is the missing address-class policy that is the gap.

**Fix:** resolve and reject non-public address ranges by default, with an explicit
`allow_private_ranges` engagement flag for authorized internal work (which is a legitimate pentest
use case and should be a recorded authorization, per PX-AUTHZ).

---

## Medium

### F-M1 — Failed scans leave no record; `Scan.status` is never assigned

[`tables.py:85`](../../backend/app/models/tables.py#L85) ·
[`scan_runner.py:57-101`](../../backend/app/services/scan_runner.py#L57)

The `Scan` row is flushed but not committed until the end, so any probe failure rolls it back with
the findings. The transaction discipline is correct (see B-FA-04 below) but the audit consequence is
not: Provx made real network requests to client infrastructure and there is no record it happened.
`status` is born `"completed"` and never assigned anywhere — there is no `running`, `failed`, or
`partial`, and `finished_at` is nullable to model a state that can never be observed.
**Fix:** commit the `Scan` row as `running` before probing; update to `completed`/`failed` after.

### F-M2 — `mode` is validated only at creation, never at scan time — ✅ FIXED

> **✅ Fixed after this audit.** `assert_scan_permitted()` re-reads `engagement.mode` at scan time, not only at creation.

[`schemas.py:32`](../../backend/app/api/schemas.py#L32) ·
[`tables.py:62`](../../backend/app/models/tables.py#L62) ·
[`scan_runner.py:41`](../../backend/app/services/scan_runner.py#L41)

`Field(pattern="^passive$")` on `EngagementCreate` is the *only* guard. The column is an
unconstrained `AutoString` with no CHECK, and `run_scan` never reads `engagement.mode`. Any future
PATCH route, import, admin fix-up, or direct SQL sets `active` and scanning proceeds. The safety
property currently rests on "the only installed adapter is harmless." Cite PX-ACTIVE, PX-PASSIVE.

### F-M10 — `adapter.safety` is never checked against the engagement mode — ✅ FIXED

> **✅ Fixed after this audit.** `assert_scan_permitted()` asserts `adapter.safety`.

[`scan_runner.py:49`](../../backend/app/services/scan_runner.py#L49) ·
[`plugins.py`](../../packages/adapters/src/provx_sdk/plugins.py)

`ToolAdapter` declares `safety: "passive" | "intrusive"`, `run_scan` accepts an `adapter_name`
parameter, and adapters are discovered dynamically from installed packages. Nothing asserts that
the loaded adapter's safety class matches what the engagement authorizes. The moment a second
adapter is installed — the explicit design goal of the entry-point registry — an intrusive one can
run against a passive engagement. This is the seam where PX-ACTIVE is actually enforced, and it is
two lines now versus a retrofit later.

### F-M11 — A single probe failure aborts the entire scan

[`scan_runner.py:74`](../../backend/app/services/scan_runner.py#L74)

`await adapter.probe(...)` has no `try/except`. `ConnectError`, `ReadTimeout`, DNS failure, or
`TooManyRedirects` on one target discards the whole run — nineteen successful probes wasted because
the twentieth host was down. Unreachable hosts are the normal case in a real engagement.
**Fix:** per-target error capture with a `targets_failed` counter.

### F-M3 — The error envelope does not cover framework-raised 404/405

[`main.py:38`](../../backend/app/main.py#L38)

The handler is registered for `fastapi.exceptions.HTTPException`, a **subclass** of
`starlette.exceptions.HTTPException`. Starlette raises the **parent** for unmatched routes and
method-not-allowed, and dispatch is by the raised class, so those bypass this handler and return
FastAPI's default `{"detail":"Not Found"}` instead of the `error_code`/`message` envelope the module
docstring promises. Not a leak, but the "stable envelope" contract is not actually stable.
**Fix:** register for `starlette.exceptions.HTTPException` — it catches both.

### F-M4 — No `RequestValidationError` handler; 422s fall outside the envelope

[`main.py:38-65`](../../backend/app/main.py#L38)

Validation failures return FastAPI's default body, which includes an `input` field echoing the
submitted value. Not a server-internals leak (PX-ERRORS is satisfied on the 500 path), but every
422 the API emits has a different shape from every other documented error.

### F-M5 — `GET /findings` is unpaginated, unfiltered, unbounded

[`engagements.py:130`](../../backend/app/api/engagements.py#L130) ·
[`engagements.py:41`](../../backend/app/api/engagements.py#L41)

Returns every finding for an engagement with no `limit`/`offset`, no severity or status filter, and
no cap. The report path loads the same unbounded set and additionally rebuilds every row through
`to_contract()` and renders it synchronously on the event loop.

### F-M6 — Compose publishes Postgres and passwordless Redis to the host

[`docker-compose.yml:62-63`](../../docker-compose.yml#L62) ·
[`docker-compose.yml:73-74`](../../docker-compose.yml#L73)

`5432:5432` and `6379:6379` bind on all host interfaces by default; Redis has no `requirepass`.
Postgres at least requires the `.env` password. On a laptop on an untrusted network this exposes the
findings database. **Fix:** bind to `127.0.0.1:5432:5432` / `127.0.0.1:6379:6379`, or drop the port
mappings entirely (the backend reaches both by service name).

### F-M7 — No logging configuration; the one structured audit log is invisible

[`scan_runner.py:68`](../../backend/app/services/scan_runner.py#L68) ·
[`main.py:28`](../../backend/app/main.py#L28)

The out-of-scope skip is logged with `extra={"engagement_id": ..., "target": ...}` — exactly the
right instinct — but there is no `dictConfig`, no formatter, and no level set anywhere. Python's
default formatter **drops `extra` fields entirely**, so the single piece of structured audit data
the application emits never appears in the output. For a tool selling an audit trail, structured
JSON logging is a core feature, not a nicety.

### F-M8 — `order_by(display_id)` sorts lexicographically and breaks past `PVX-9999`

[`engagements.py:47`](../../backend/app/api/engagements.py#L47) ·
[`scan_runner.py:38`](../../backend/app/services/scan_runner.py#L38)

`display_id` is a string column, so ordering is lexicographic. The SDK deliberately allows the
sequence to widen past four digits (`^PVX-\d{4,}$`, explicitly regression-tested), which means an
engagement exceeding 9999 findings lists as `PVX-10000, PVX-1001, …, PVX-9999`. Two individually
correct decisions interacting badly. **Fix:** order by a numeric sequence column, or `captured_at`.

### F-M9 — `from_draft` re-validates display_id and ATT&CK ids but not `cvss`

[`tables.py:136-149`](../../backend/app/models/tables.py#L136)

The whole premise of `from_draft` is that SQLModel skips Pydantic validation on `table=True`
classes, so the row constructor must be an independent gate rather than trusting the caller. It
re-checks `DISPLAY_ID_PATTERN` and re-runs `validate_attack_techniques`, but passes `cvss` through
without the SDK's `ge=0.0, le=10.0` bound (and `title`/`target` unbounded). A draft with `cvss=99.0`
writes cleanly and then breaks `to_contract()` — precisely the failure mode the method exists to
prevent, and the tests prove the authors understand it by constructing a bad draft with
`object.__setattr__`.

---

## Low

| ID | Finding | Location |
|---|---|---|
| F-L1 | `_existing_dedup_keys` loads full `FindingRow` ORM objects to build a set of two strings; should select two columns. | [`scan_runner.py:109`](../../backend/app/services/scan_runner.py#L109) |
| F-L2 | `targets` accepts arbitrary strings with no URL validation; a malformed target is silently counted as "skipped out of scope", indistinguishable from a real scope violation. | [`schemas.py:29`](../../backend/app/api/schemas.py#L29) |
| F-L3 | `httpx` is a runtime dependency of the scan path but declared only under the `dev` extra. | [`pyproject.toml:29`](../../backend/pyproject.toml#L29) |
| F-L4 | `load_adapter` calls `load_adapters()`, which re-scans entry points and re-instantiates **every** installed adapter on **every** scan. Should be cached. | [`registry.py:33`](../../packages/adapters/src/provx_sdk/registry.py#L33) |
| F-L5 | `handle_http_exception` splats an arbitrary detail dict into `ErrorResponse(**detail)`, which is `extra="forbid"` — an extra key makes the error handler itself raise. | [`main.py:43`](../../backend/app/main.py#L43) |
| F-L6 | Migrations run in the container entrypoint; a multi-replica deploy races `alembic upgrade head`. | [`docker-entrypoint.sh:8`](../../backend/docker-entrypoint.sh#L8) |
| F-L7 | `pip install -r requirements.lock` without `--require-hashes`; the lock pins versions but not artifact digests. | [`Dockerfile`](../../backend/Dockerfile) |
| F-L8 | Append-only evidence is enforced by code convention only — the app's DB role has full DML. A restricted role (no UPDATE/DELETE on `finding`) would make PX-EVIDENCE structural. | [`tables.py:10`](../../backend/app/models/tables.py#L10) |
| F-L9 | `/docs`, `/redoc`, `/openapi.json` unconditionally public; should be gated on `is_debug_env` once auth lands. | [`main.py:30`](../../backend/app/main.py#L30) |
| F-L10 | `database_url` silently defaults to a guessable local DSN rather than failing fast when unset in production. | [`config.py:27`](../../backend/app/config.py#L27) |
| F-L11 | `http_timeout` has no bounds; `HTTP_TIMEOUT=0` or negative reaches httpx unchecked. | [`config.py:28`](../../backend/app/config.py#L28) |
| F-L12 | No pool configuration — notably no `pool_pre_ping=True`, which surfaces as intermittent 500s against Postgres behind a connection killer or after a container restart. | [`db.py:29`](../../backend/app/db.py#L29) |
| F-L13 | `ScanRead.findings_count` reports the engagement total, not this run's count — a rescan finding nothing new still reports 5. | [`engagements.py:124`](../../backend/app/api/engagements.py#L124) |
| F-L14 | The HTML report response sets no `Content-Security-Policy` or cache headers. Autoescaping is correct, but CSP is cheap defence in depth on a document rendered from attacker-influenced output. | [`engagements.py:147`](../../backend/app/api/engagements.py#L147) |
| F-L15 | `FindingRead` omits `scan_id`; a client cannot tell which run produced a finding. | [`engagements.py:59`](../../backend/app/api/engagements.py#L59) |
| F-L16 | No cap on `targets` / `scope_allow` list length; 100k targets is one inline request. | [`schemas.py:27`](../../backend/app/api/schemas.py#L27) |
| F-L17 | Two import paths for the same seven contract names (`app.models` shim vs `provx_sdk.findings`). | [`models/findings.py`](../../backend/app/models/findings.py) |
| F-L18 | `scope_allow`, `scope_deny`, `attack_techniques` are `nullable=True` in the DB but non-optional in the models; a NULL becomes a 500 at read. | [migration:36](../../backend/alembic/versions/b1428574732c_walking_skeleton_core_tables.py#L36) |
| F-L19 | No uniqueness on `(engagement_id, url)`; a duplicate target is probed twice and inflates `targets_scanned`. | [`tables.py:66`](../../backend/app/models/tables.py#L66) |
| F-L20 | The dedup key is defined twice — `FindingDraft.dedup_key` in the SDK and the tuple in `_existing_dedup_keys`. Divergence yields duplicate findings, not an error. | [`scan_runner.py:112`](../../backend/app/services/scan_runner.py#L112) |
| F-L21 | The report omits engagement scope, the target list, scan timestamps, and evidence hashes — the fields that make a report compliance-grade. All are persisted; only the template omits them. | [`report.html.j2:24`](../../backend/app/templates/report.html.j2#L24) |
| F-L22 | `retest(finding_id: str)` and `RiskAcceptance.finding_id` are keyed on the ambiguous per-engagement `display_id` rather than the globally unique UUID. | [`retest.py:14`](../../backend/app/services/retest.py#L14) |
| F-L23 | Alembic `context.configure` sets neither `compare_type=True` (autogenerate silently misses type changes) nor `render_as_batch=True` (no future SQLite ALTER, though tests migrate SQLite). | [`env.py:47`](../../backend/alembic/env.py#L47) |
| F-L24 | `env.py` calls `asyncio.run()` at import; cannot be driven from inside a running event loop. Latent only. | [`env.py:66`](../../backend/alembic/env.py#L66) |
| F-L25 | No `ondelete` behaviour on any FK; the append-only intent is not expressed in the schema. | [migration:112](../../backend/alembic/versions/b1428574732c_walking_skeleton_core_tables.py#L112) |
| F-L26 | `evidence_tool_output` stores the full raw response envelope for **every** finding — five missing headers on one page stores five copies of the same body, uncapped. Deduplicating evidence by its sha256 would align storage with the seal already computed. | [`tables.py:112`](../../backend/app/models/tables.py#L112) |

---

## Declared scaffolding (not defects)

| Item | Status |
|---|---|
| **No auth / RBAC / tenancy** | Later phase. Consequence recorded as F-C1 — the gap itself is expected; the *deployment* implication is what must not be forgotten. |
| **arq job queue; scans run inline** | B-FA-08 deviation, explicitly documented at [`scan_runner.py:11`](../../backend/app/services/scan_runner.py#L11) with the seam correctly identified: the API awaits `run_scan` and knows nothing else. Redis runs and is health-gated; no code connects. Well handled — noted once, not re-reported. |
| **Playbook / workflow engine** | Absent. `DEFAULT_ADAPTER` is hardcoded; `plugins.PlaybookPlugin` is a signature-only Protocol. Consistent with PX-DSL — **verified zero `eval`, `exec`, `compile`, or `pickle` anywhere in the backend.** |
| **Active mode / exploitation** | Absent. Refused at the create schema. See F-M2/F-M10 for where the *runtime* gate belongs. |
| **AI features** | Absent entirely — no LLM import, no provider abstraction, no code path. PX-AI-OPTIONAL satisfied by construction, not by configuration. `AI_*` env vars are documented and unread. |
| **PDF / branded reports** | HTML only; stated in the `report.py` docstring. |
| **EPSS enrichment** | `FindingRow.epss` column and `Finding.epss` field exist and are never populated. Correct modelling — an adapter cannot know an EPSS score; it is post-normalization enrichment. |
| **`FindingStatus` lifecycle** | The seven-state enum exists in the SDK, the migration, and the API response, and **no code path can transition a finding out of `NEW`.** Correct that adapters cannot set it (PX-HUMAN). Noted rather than filed because triage UI is a later phase — but `RiskAcceptance` also has no table and no persistence path, so the governance surface is further from complete than the enums suggest. |
| **Second adapter** | One passive adapter (`security_headers`). The entry-point registry is real and working, which is what makes F-M10 worth fixing before the second one arrives. |

---

## Test coverage gaps

The existing suite is genuinely good: 47 tests across 6 files, hermetic (the probe is stubbed, no
network), running against a real file-backed SQLite via the **unmodified** production session
dependency, with `APP_ENV=testing` set at import (Q-10). Migrations are tested up *and* down. The
scope assertion checks the list of URLs actually reached rather than a counter — the correct
assertion. The XSS test asserts both the payload's absence and the escaped form's presence.

| # | Gap | Why it matters |
|---|---|---|
| T-1 | **No concurrency test.** Nothing exercises two simultaneous scans on one engagement. | F-H1 is a genuine, reachable defect that the suite cannot see. |
| T-2 | **No redirect test.** `probe` is stubbed in every API test, so `follow_redirects=True` is never exercised. | F-H2 — the single most important PX-SCOPE property is untested. |
| T-3 | **No probe-failure test.** No case where `adapter.probe` raises. | Would immediately expose F-M1 (no scan record) and F-M11 (whole run aborts). |
| T-4 | **No unhandled-500 test.** `handle_unexpected_exception` and the `is_debug_env` gate — the core PX-ERRORS mechanism — are never executed. Neither is the production branch (`detail is None`). | The safety-critical branch of the error path is unverified in both directions. |
| T-5 | **No unknown-route test.** Would have caught F-M3 (framework 404 bypasses the envelope) immediately. | |
| T-6 | **No `Settings`/`config.py` unit tests.** `async_database_url` has five rewrite branches and `is_debug_env` has a fail-closed contract; none are directly tested. | Small, pure, high-value — the cheapest coverage in the repo. |
| T-7 | **No pagination/scale test** and no test past `PVX-9999` *through the API* (`test_scan_runner.py` covers `display_id_for` in isolation but not the ordering). | F-M5, F-M8. |

---

## What this codebase does well

Worth recording, because the ratio of deliberate-and-documented to accidental is unusually high for
pre-alpha:

- **Write-time contract revalidation.** `FindingRow.from_draft` exists specifically because SQLModel
  skips Pydantic validation on `table=True` classes, and the docstring explains the failure mode it
  prevents (a bad row breaking every subsequent read of its engagement). The test that proves it is
  an *independent* gate bypasses the draft validator with `object.__setattr__`. That is senior work.
- **`select_autoescape(default=True, default_for_string=True)`** — the default would not have
  covered a `.j2` extension. Zero `| safe` in the template, no interpolation in script/attribute/URL
  context, and `target` rendered as text rather than a link.
- **Enum cleanup in `downgrade()`** with a dialect guard and `checkfirst=True` — PostgreSQL does not
  drop implicitly-created enum types with the table, and reversibility is actually tested.
- **Timezone-aware columns everywhere,** with the reasoning ("an audit trail with ambiguous local
  times is not an audit trail") written down.
- **`echo=False` justified as a secrets decision,** not left as a default.
- **`APP_ENV` fails closed** — unset or unrecognized is production.
- **Frontend deliberately receives no `env_file`,** with the reason in a comment.
- **No committed DSN in `alembic.ini`;** the URL comes from settings.
- **Zero raw SQL, zero string interpolation into queries, zero `eval`/`exec`/`pickle`.**
- **The unvalidated banner cannot be suppressed by data,** and PX rules are cited inline at the
  places they constrain rather than only in a docs file.
