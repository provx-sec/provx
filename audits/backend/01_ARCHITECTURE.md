# Backend audit — 01 Architecture

---

## 1. Request lifecycle

```
uvicorn (uvloop)
  └─ Starlette ServerErrorMiddleware   ← app.exception_handler(Exception) lands here
      └─ ExceptionMiddleware           ← app.exception_handler(HTTPException) lands here
          └─ APIRouter("/engagements")
              └─ route coroutine
                   ├─ Depends(get_session)  → one AsyncSession per request
                   ├─ business call         → services.scan_runner / services.report
                   └─ response_model        → Pydantic serialization / HTMLResponse
```

There is **no custom middleware**: no CORS, no request-ID, no rate limiting, no auth. The app object
is three statements — construct, include router, register handlers
([`main.py:30-35`](../../backend/app/main.py#L30)).

Session teardown: `get_session()` is `async with get_sessionmaker()() as session: yield session`
([`db.py:38-41`](../../backend/app/db.py#L38)). Exiting the `async with` closes the session, which
rolls back any uncommitted work. That is the mechanism that makes the failure case in §2 safe.

---

## 2. Scan pipeline data flow

Entry: `POST /engagements/{id}/scan` →
[`scan_engagement`](../../backend/app/api/engagements.py#L109) → `run_scan(session, engagement)`
([`scan_runner.py:41`](../../backend/app/services/scan_runner.py#L41)).

| # | Stage | Where | Notes |
|---|---|---|---|
| 1 | Adapter resolution | [`scan_runner.py:49`](../../backend/app/services/scan_runner.py#L49) | `load_adapter("security_headers")` via the `provx.adapters` entry-point group. Name is hardcoded as `DEFAULT_ADAPTER`; the workflow engine that would choose it is a later phase. |
| 2 | Scope policy build | [`scan_runner.py:50`](../../backend/app/services/scan_runner.py#L50) | `ScopePolicy(allow=engagement.scope_allow, deny=engagement.scope_deny)` — read from the DB row, not from the request. Correct: the caller cannot widen scope at scan time. |
| 3 | Target load | [`scan_runner.py:53`](../../backend/app/services/scan_runner.py#L53) | `select(Target).where(Target.engagement_id == ...)`. |
| 4 | Scan row insert + flush | [`scan_runner.py:57-59`](../../backend/app/services/scan_runner.py#L57) | Flushed (not committed) to obtain `scan.id` for the FK on findings. |
| 5 | **Scope gate** | [`scan_runner.py:66-72`](../../backend/app/services/scan_runner.py#L66) | `if not policy.is_in_scope(target.url): skipped += 1; log; continue`. |
| 6 | Probe | [`scan_runner.py:74`](../../backend/app/services/scan_runner.py#L74) | `await adapter.probe(url, timeout=...)` — the only network call. |
| 7 | **Evidence seal** | [`scan_runner.py:75`](../../backend/app/services/scan_runner.py#L75) | `seal(raw)` immediately after the response, before parsing. |
| 8 | Normalize | [`scan_runner.py:77`](../../backend/app/services/scan_runner.py#L77) | `adapter.parse_output(raw)` → `list[FindingDraft]`; pure function, fixture-drivable (PX-FIXTURE). |
| 9 | Dedup | [`scan_runner.py:79-84`](../../backend/app/services/scan_runner.py#L79) | Key = `(target, title)` from `FindingDraft.dedup_key`; existing keys loaded per engagement. |
| 10 | display_id allocation | [`scan_runner.py:81-88`](../../backend/app/services/scan_runner.py#L81) | `allocated = len(already_seen)`, incremented per accepted draft → `PVX-{n:04d}`. **Race here — see F-H1.** |
| 11 | Persist | [`scan_runner.py:86-94`](../../backend/app/services/scan_runner.py#L86) | `FindingRow.from_draft(...)` revalidates the contract at write time. |
| 12 | Finalize + commit | [`scan_runner.py:96-101`](../../backend/app/services/scan_runner.py#L96) | Counters + `finished_at` set, single `await session.commit()`. |
| 13 | Report | [`report.py:35`](../../backend/app/services/report.py#L35) | `render_report(engagement, [row.to_contract() for row in rows])` — every stored row is rebuilt into the canonical SDK `Finding` before rendering. |

### PX-SCOPE — verified enforced before any network call

Traced end to end: the only call site of `adapter.probe` in the whole repo is
[`scan_runner.py:74`](../../backend/app/services/scan_runner.py#L74), and it is unreachable unless
`policy.is_in_scope(target.url)` returned true at line 66. `ScopePolicy.is_in_scope` fails closed —
an empty allow list matches nothing, a non-http(s)/hostless URL raises `OutOfScopeError` and is
caught as `False`, and deny is evaluated before allow. The test
[`test_out_of_scope_target_is_never_reached`](../../backend/tests/test_api_engagements.py#L121)
asserts on the list of URLs the stubbed probe actually received, which is the right assertion — it
proves absence of the call, not just the counter.

**Two real gaps remain** (see `99_FINDINGS.md`):
- **F-H2** — the adapter uses `follow_redirects=True`, so scope is enforced on the *first* URL only.
- **F-H4** — allow rules are host-string matches with no internal/link-local address guard.

### PX-EVIDENCE — verified capture-time seal, verified no mutation path

`seal(raw)` is called on the line immediately after the probe returns, before `parse_output`
touches the bytes, and computes `sha256(raw)` + `datetime.now(UTC)` together
([`evidence.py:29-32`](../../packages/adapters/src/provx_sdk/evidence.py#L29)). The seal therefore
attests to what the tool saw. `EvidenceSeal` is `frozen=True`.

Append-only was verified by exhaustive search: there is **no** `session.delete`, no `DELETE`
statement, no `update()`, no PATCH/PUT route, and no code path that assigns to an existing
`FindingRow` attribute anywhere in `app/`. The only writes are `session.add` of new rows. The
`Scan` row is mutated after flush ([`scan_runner.py:96-98`](../../backend/app/services/scan_runner.py#L96))
but that is within the same uncommitted transaction, so no committed record is ever edited. This
is enforced by convention, not by DB grants — noted as **F-L8**.

Caveat worth recording: one seal covers the whole response envelope for a target and is copied onto
**every** finding derived from it ([`scan_runner.py:77`](../../backend/app/services/scan_runner.py#L77)),
so `evidence_sha256` is a per-response hash, not a per-finding hash. Defensible, but it means two
findings from the same page are indistinguishable by seal.

### B-FA-04 — is the scan write one transaction?

**Yes, and the failure case is clean.** All of `Scan`, the `Target` reads, and every `FindingRow`
share the request-scoped session and a single `commit()` at
[`scan_runner.py:100`](../../backend/app/services/scan_runner.py#L100). If `adapter.probe` raises
mid-loop (timeout, DNS failure, connection reset — all common), the exception propagates out of
`run_scan`, out of the route, and `get_session`'s `async with` closes the session **without
committing**. The flushed `Scan` row is rolled back. **No orphaned Scan row, no partial findings.**

The cost of that cleanliness is **F-M1**: a failed scan leaves *no record at all*. Network requests
were genuinely made to client infrastructure, and nothing in the database says so. For a tool whose
value proposition is an auditable trail of what was touched and when, "we probed three hosts and
then crashed, and there is no evidence any of it happened" is the wrong outcome. Relatedly,
`Scan.status` is initialized to `"completed"` and never assigned anywhere
([`tables.py:85`](../../backend/app/models/tables.py#L85)) — there is no `running` or `failed` state.

### Concurrency — can display_id collide?

**Yes. Definitively, and it is not theoretical.** Trace:

```python
already_seen = await _existing_dedup_keys(session, engagement.id)   # line 79
allocated = len(already_seen)                                        # line 80
...
allocated += 1
display_id=display_id_for(allocated)                                 # line 88
```

The next sequence number is derived from a **read** performed in the scanning transaction, with no
lock, no `SELECT … FOR UPDATE`, no advisory lock, and no DB sequence. Two `POST /scan` requests for
the same engagement arriving concurrently each get their own session and transaction. Under
PostgreSQL's default READ COMMITTED, both read the same set of existing findings (neither has
committed), both compute `allocated = N`, and both attempt to insert `PVX-{N+1}`. The unique
constraint `uq_finding_engagement_display_id` on `(engagement_id, display_id)`
([migration line 117](../../backend/alembic/versions/b1428574732c_walking_skeleton_core_tables.py#L117))
then does exactly its job: the second transaction to commit raises `IntegrityError`.

Consequences: the losing scan is lost entirely (whole transaction rolls back), and the client gets a
500 through the generic handler. The constraint prevents *corruption* — good design — but nothing
prevents the *collision*, and there is no retry. Two users triaging the same engagement, or a
double-clicked button, reproduce it. See **F-H1** for remediation options.

A second, quieter property of the same two lines: `allocated` is seeded from
`len(already_seen)` — the number of **distinct dedup keys**, not `MAX(display_id)`. These coincide
only because every row is written through this dedup path and no row is ever deleted. The moment a
delete path, an import path, or a second writer exists, the sequence silently restarts and collides.
The invariant is real but undocumented and unenforced.

### Does anything re-check `mode` at scan time?

**No.** `run_scan` never reads `engagement.mode`. The only enforcement is
`Field(pattern="^passive$")` on the **create** request schema
([`schemas.py:32`](../../backend/app/api/schemas.py#L32)). The column itself is a plain
`AutoString` with `default="passive"`
([`tables.py:62`](../../backend/app/models/tables.py#L62)), constrained by nothing in the database.
Any future PATCH endpoint, data import, admin fix-up, or direct SQL sets `mode='active'` and
`run_scan` executes without complaint. Today's adapter happens to be passive, so nothing intrusive
occurs — but the safety property rests entirely on "the only installed adapter is harmless", not on
a check. See **F-M2** (PX-ACTIVE, PX-PASSIVE).

### B-FA-08 — inline execution (known accepted deviation)

Scans run inline in the request coroutine; `POST /scan` blocks for the duration of every probe
(up to `http_timeout` × number of in-scope targets, 10s each by default). This is a **declared and
documented deviation**, stated in the module docstring at
[`scan_runner.py:11-12`](../../backend/app/services/scan_runner.py#L11), with the seam explicitly
identified: the API awaits `run_scan` and knows nothing about how the work happens, so moving to
arq means changing that one call site and returning a job id instead of a `ScanRead`. The seam is
genuine and correctly placed. Recorded once, not re-reported.

### B-FA-02 — blocking I/O in async routes

Clean. All four routes are `async def`; DB access is asyncpg/aiosqlite through `AsyncSession`; the
probe is `httpx.AsyncClient`. `health()` and `root()` are `def` (sync), which FastAPI correctly runs
in a threadpool — appropriate for trivial handlers.

The one synchronous-CPU call in an async route is `render_report()`
([`engagements.py:146`](../../backend/app/api/engagements.py#L146)) — Jinja rendering on the event
loop. Negligible at skeleton scale; becomes real at thousands of findings, and is compounded by the
unpaginated query behind it (**F-M5**).

---

## 3. Authentication strategy

**There is none.** No auth dependency, no `Security()`, no API key, no session, no user table, no
tenant column. Every route is fully anonymous. This is declared scaffolding (RBAC is a later phase,
and the module docstring at [`engagements.py:6`](../../backend/app/api/engagements.py#L6) says so).

The consequence must be stated plainly, because it is larger than "the API is open":

> `POST /engagements` is unauthenticated and `POST /engagements/{id}/scan` makes the server issue
> outbound HTTP requests. An anonymous caller therefore supplies both the scope allow-list and the
> targets, and the server performs the requests. The scope gate is not a security boundary against
> the API caller — it is a boundary that the API caller configures. Anyone who can reach port 8000
> can use this service as an HTTP request relay against arbitrary hosts, including hosts reachable
> only from inside the deployment network.

Recorded as **F-C1**. This does not make the scope gate pointless — it is the right mechanism, and
it will be a real boundary once engagements are owned by authenticated principals. It does mean the
service must not be exposed beyond localhost until then. `SAFE_MODE` would be the natural place to
express that guard, and it is currently unread (**F-H3**).

---

## 4. Data access patterns

- One `AsyncSession` per request, injected by `Depends(get_session)`. Every route takes it and hands
  it down; no service opens its own session. Consistent and testable — the test suite exercises the
  real dependency unmodified rather than overriding it.
- `expire_on_commit=False`, so ORM objects stay usable after `commit()`. This is why
  `run_scan` can return `scan` and the route can read its attributes.
- Explicit `await session.refresh(...)` after commit in both write paths.
- Queries use `session.exec(select(...))` (SQLModel's typed wrapper) rather than raw SQL. **Zero raw
  SQL strings and zero string interpolation into queries anywhere in the repo** — no SQL injection
  surface (S-*).
- No relationship/`selectinload` usage; joins are done as separate queries by FK. Fine at this size.
- `_existing_dedup_keys` loads **entire `FindingRow` objects** to build a set of two-string tuples
  ([`scan_runner.py:109-112`](../../backend/app/services/scan_runner.py#L109)) — should select the
  two columns. **F-L1**.

### Tables touched per route

| Route | Reads | Writes |
|---|---|---|
| `POST /engagements` | — | `engagement`, `target` |
| `POST /engagements/{id}/scan` | `engagement`, `target`, `finding` | `scan`, `finding` |
| `GET /engagements/{id}/findings` | `engagement`, `finding` | — |
| `GET /engagements/{id}/report` | `engagement`, `finding` | — |

---

## 5. Cross-cutting concerns

### Error envelope and APP_ENV gating (PX-ERRORS, B-FA-06, S-13)

Two handlers in [`main.py`](../../backend/app/main.py):

- `handle_http_exception` ([line 38](../../backend/app/main.py#L38)) — if `exc.detail` is a dict
  carrying `error_code`, it is rebuilt as `ErrorResponse`; otherwise it becomes
  `{"error_code": "http_error", "message": str(detail)}`.
- `handle_unexpected_exception` ([line 49](../../backend/app/main.py#L49)) — `logger.exception(...)`
  server-side, then a fixed generic client message. `detail=repr(exc)` is attached **only** when
  `settings.is_debug_env`. The gate is `is_debug_env`, which lowercases/strips and checks membership
  in `DEBUG_ENVIRONMENTS`; an unset or garbage `APP_ENV` falls through to production behaviour.
  **This fails closed and is correct.** No leak found on this path.

Two envelope gaps, neither a leak but both inconsistencies (**F-M3**, **F-M4**):

1. The handler is registered for `fastapi.exceptions.HTTPException`, a **subclass** of
   `starlette.exceptions.HTTPException`. Starlette raises the **parent** class for unmatched routes
   and wrong methods, and handler lookup is by exception class MRO, so a 404 on an unknown path is
   served by FastAPI's built-in default handler and returns `{"detail":"Not Found"}` — not the
   `error_code`/`message` envelope every documented error uses.
2. `RequestValidationError` (422) is unhandled, so validation failures return FastAPI's default
   body, which includes an `input` field echoing the submitted value. Not a server-internals leak,
   but it is outside the contract and reflects caller-supplied data.

The 404 path *inside* the router is done correctly — `_get_engagement` raises with a structured
detail dict ([`engagements.py:34-37`](../../backend/app/api/engagements.py#L34)), which the handler
turns into a proper envelope, and
[`test_unknown_engagement_returns_a_user_safe_error`](../../backend/tests/test_api_engagements.py#L202)
asserts no traceback or `sqlalchemy` string reaches the client.

### Logging

`logging.getLogger(__name__)` in `main.py` and `scan_runner.py`. Two call sites: the
`logger.exception` in the global handler, and a structured `logger.warning` on out-of-scope skips
carrying `engagement_id` and `target` in `extra` ([`scan_runner.py:68`](../../backend/app/services/scan_runner.py#L68)).

- **PX-SECRETS:** no credential, token, header value, or response body is ever logged. `echo=False`
  on the engine keeps SQL out of stdout. Clean.
- No logging configuration exists — no `dictConfig`, no formatter, no level. Output depends entirely
  on uvicorn's defaults, and the `extra` fields are dropped by the default formatter, so the one
  piece of structured audit data the app emits is invisible in practice. **F-M7**.

### Validation layering

Four independent layers, deliberately arranged:

1. **HTTP in** — `EngagementCreate` with `extra="forbid"`, `min_length` on name/scope/targets, and
   the `^passive$` mode pattern.
2. **Domain** — `ScopePolicy` (fails closed) and the SDK's `FindingDraft` validators (ATT&CK id
   pattern, CVSS 0-10 range).
3. **Write** — `FindingRow.from_draft` re-checks `DISPLAY_ID_PATTERN` and re-runs
   `validate_attack_techniques` ([`tables.py:136-149`](../../backend/app/models/tables.py#L136)).
   This layer exists because **SQLModel does not run Pydantic validation on `table=True` classes** —
   without it a bad row would write cleanly and then break every subsequent read of that engagement
   via `to_contract()`. The reasoning is documented in the docstring and pinned by
   [`test_scan_runner.py`](../../backend/tests/test_scan_runner.py). This is the strongest piece of
   engineering in the repo.
4. **HTTP out** — `FindingRead` / `EngagementRead` / `ScanRead` whitelist fields, and `_to_read`
   projects field by field so a new column stays unpublished until someone opts in (B-FA-01).

**Not validated anywhere:** `targets` entries are accepted as arbitrary strings with no URL format
check at creation ([`schemas.py:29`](../../backend/app/api/schemas.py#L29)). A malformed target is
silently counted as "skipped out of scope" at scan time, indistinguishable from a genuine scope
violation. **F-L2.**

### External integrations

| Integration | How | State |
|---|---|---|
| `provx_sdk` | Python import; path-installed in the image. Supplies `findings`, `evidence`, `scope`, `registry`, `plugins`, `adapters.security_headers`. | Live. The dependency direction is correct — the SDK never imports the backend. |
| Adapter discovery | `importlib.metadata.entry_points(group="provx.adapters")` | Live. `load_adapters()` re-scans and **re-instantiates every adapter on every call**, and `load_adapter` calls it per scan — see **F-L4**. |
| httpx | inside the SDK adapter's `probe` | Live; the only outbound network path. `follow_redirects=True` (**F-H2**). |
| PostgreSQL 16 | asyncpg | Live. |
| Redis 7 | — | Container runs and is health-gated, `REDIS_URL` is injected, **no code connects**. Declared scaffolding for arq. |
| LLM / AI | — | Absent entirely. PX-AI-OPTIONAL satisfied by construction. |
