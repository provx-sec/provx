# Module — `app/api`

**Path:** `/Users/mac/Projects/mine/provx/backend/app/api/`
**Purpose:** the HTTP surface. All four business endpoints plus the request/response contracts that
bound what a client may send and see.

---

## Files

| File | Purpose | Exported symbols |
|---|---|---|
| [`api/__init__.py`](../../backend/app/api/__init__.py) | Docstring only ("HTTP routers for the Provx control plane"). No re-exports. | — |
| [`api/engagements.py`](../../backend/app/api/engagements.py) | The engagement router: create, scan, list findings, render report. | `router`, `ENGAGEMENT_NOT_FOUND`, `create_engagement`, `scan_engagement`, `list_findings`, `engagement_report`, `_get_engagement`, `_findings`, `_to_read` |
| [`api/schemas.py`](../../backend/app/api/schemas.py) | Request/response Pydantic models. | `EngagementCreate`, `EngagementRead`, `ScanRead`, `FindingRead`, `ErrorResponse` |

**Dependencies:** `fastapi`, `sqlmodel`, `provx_sdk.findings` (enum types for response typing),
`app.db.get_session`, `app.models.tables`, `app.services.report`, `app.services.scan_runner`.

**Router:** `APIRouter(prefix="/engagements", tags=["engagements"])`.

---

## Endpoints

### 1. `POST /engagements` → [line 76](../../backend/app/api/engagements.py#L76)

| | |
|---|---|
| Handler | `async create_engagement(payload: EngagementCreate, session: AsyncSession = Depends(get_session)) -> EngagementRead` |
| Request | `EngagementCreate` (body) |
| Response model | `EngagementRead` |
| Status | `201 CREATED` |
| Tables | writes `engagement`, `target` |

Constructs the `Engagement`, `flush()`es to obtain its PK, bulk-adds one `Target` per URL, commits,
refreshes, and returns. Targets are stored verbatim; nothing is reached until a scan runs, and the
docstring correctly points at PX-SCOPE as the place that is enforced.

Note the response builds `targets=list(payload.targets)` from the **request**, not from the persisted
rows. Equivalent today, but it means the response is not a read-back of what was stored — a
divergence between the two would go unnoticed.

### 2. `POST /engagements/{engagement_id}/scan` → [line 108](../../backend/app/api/engagements.py#L108)

| | |
|---|---|
| Handler | `async scan_engagement(engagement_id: uuid.UUID, session: AsyncSession = Depends(get_session)) -> ScanRead` |
| Request | path param `engagement_id: uuid.UUID` (FastAPI validates the format → 422 on garbage) |
| Response model | `ScanRead` |
| Status | `201 CREATED` |
| Tables | reads `engagement`, `target`, `finding`; writes `scan`, `finding` |

404s via `_get_engagement`, then delegates the whole pipeline to `run_scan`. `findings_count` is
computed as the count of **all** findings on the engagement after the scan, not the count produced
*by this scan* — so a second scan that discovers nothing new still reports `findings_count: 5`
while `targets_scanned: 1`. Misleading for a per-run record. **F-L13.**

The adapter is not selectable — `run_scan` is called without `adapter_name`, so `DEFAULT_ADAPTER`
always applies. Correct for the skeleton (one adapter exists).

### 3. `GET /engagements/{engagement_id}/findings` → [line 130](../../backend/app/api/engagements.py#L130)

| | |
|---|---|
| Handler | `async list_findings(engagement_id: uuid.UUID, session=Depends(get_session)) -> list[FindingRead]` |
| Request | path param only — **no query params, no pagination, no filtering** |
| Response model | `list[FindingRead]` |
| Status | 200 (implicit) |
| Tables | reads `engagement`, `finding` |

Returns every finding for the engagement ordered by `display_id`. **F-M5** — unbounded result set.
Also note the ordering is a **lexicographic string sort** on `display_id`, so once an engagement
passes 9999 findings the order becomes `PVX-10000, PVX-1001, PVX-9999` rather than numeric. The SDK
deliberately allows widening past four digits (and `test_scan_runner.py` pins that behaviour), so
this is a real interaction between two correct-looking decisions. **F-M8.**

### 4. `GET /engagements/{engagement_id}/report` → [line 139](../../backend/app/api/engagements.py#L139)

| | |
|---|---|
| Handler | `async engagement_report(engagement_id: uuid.UUID, session=Depends(get_session)) -> HTMLResponse` |
| Request | path param only |
| Response class | `HTMLResponse` (no `response_model`, correct for HTML) |
| Status | 200 (implicit) |
| Tables | reads `engagement`, `finding` |

Rebuilds every stored row through `row.to_contract()` before rendering — so the report path is also
an implicit integrity check on the whole engagement: a row written in a shape the SDK contract
rejects breaks the entire report, not one line. That is exactly why `FindingRow.from_draft`
validates at write time. `test_stored_findings_round_trip_through_the_contract` covers this.

No `Content-Disposition`, no `Cache-Control`, no `Content-Security-Policy` header on the response.
For an HTML document rendered from attacker-influenced scan output, a restrictive CSP is cheap
defence in depth even with autoescaping on. **F-L14.**

---

## Helper functions

| Signature | Description |
|---|---|
| `async _get_engagement(session, engagement_id) -> Engagement` | `session.get`; raises `HTTPException(404, detail={"error_code": "engagement_not_found", "message": "Engagement not found."})`. The structured detail dict is what lets `handle_http_exception` produce a proper envelope. |
| `async _findings(session, engagement_id) -> list[FindingRow]` | `select(FindingRow).where(engagement_id == ...).order_by(display_id)`. Single shared query for the list and report routes — good DRY (Q-11). |
| `_to_read(row: FindingRow) -> FindingRead` | Field-by-field projection. Deliberately explicit so a new table column stays unpublished until someone opts in (B-FA-01); the reasoning is in the docstring. |

`_to_read` publishes 13 of `FindingRow`'s 19 columns. Withheld: `engagement_id`, `scan_id`, `epss`,
and all three `evidence_*` payload columns. Withholding the raw evidence body is a deliberate
PX-SECRETS decision (stated in the `schemas.py` docstring, asserted by
[`test_findings_response_omits_raw_evidence`](../../backend/tests/test_api_engagements.py#L214)).
Withholding `scan_id` is a small provenance gap — a client cannot tell which run produced a finding.
**F-L15.**

---

## Schemas (`api/schemas.py`)

All five models set `model_config = ConfigDict(extra="forbid")`.

### `EngagementCreate` — [line 21](../../backend/app/api/schemas.py#L21)

| Field | Type | Validation |
|---|---|---|
| `name` | `str` | `min_length=1`, `max_length=200` |
| `scope_allow` | `list[str]` | `min_length=1` — an engagement **cannot** be created with an empty allow list. Correct fail-closed posture, tested. |
| `scope_deny` | `list[str]` | `default_factory=list` |
| `targets` | `list[str]` | `min_length=1`. **No URL format validation, no per-item length cap, no list length cap.** |
| `mode` | `str` | `default="passive"`, `pattern="^passive$"` — the only place Active mode is refused (PX-ACTIVE). Tested by `test_create_engagement_rejects_active_mode`. |

Findings: **F-L2** (targets unvalidated — a malformed target is silently reported as "skipped out of
scope", indistinguishable from a real scope violation) and **F-L16** (no cap on list sizes; 100k
targets is one inline request). Also **F-M2**: `^passive$` is enforced *only here*, never re-checked
at scan time.

### `EngagementRead` — [line 35](../../backend/app/api/schemas.py#L35)

`id: UUID`, `name: str`, `scope_allow: list[str]`, `scope_deny: list[str]`, `mode: str`,
`targets: list[str]`, `created_at: datetime`.

Note this **echoes the full scope allow/deny lists** back to an unauthenticated caller. Correct
today (the caller supplied them) but becomes a disclosure surface the moment engagements have
owners.

### `ScanRead` — [line 49](../../backend/app/api/schemas.py#L49)

`id`, `engagement_id`, `adapter: str`, `status: str`, `targets_scanned: int`,
`targets_skipped_out_of_scope: int`, `findings_count: int`, `started_at: datetime`,
`finished_at: datetime | None`.

`status` is typed `str`, not an enum — and since `Scan.status` is never assigned anywhere, it is
always the literal `"completed"`. See **F-M1**.

### `FindingRead` — [line 65](../../backend/app/api/schemas.py#L65)

`id: UUID`, `display_id: str`, `title: str`, `target: str`, `module: Module`,
`severity: Severity`, `cvss: float | None`, `confidence: Confidence`, `status: FindingStatus`,
`attack_techniques: list[str]`, `remediation: str | None`, `evidence_sha256: str`,
`captured_at: datetime`.

Uses the SDK's `StrEnum` types directly, so responses serialize to the stable lowercase string
values (`"low"`, `"web"`, `"new"`) rather than Python enum names — consistent with the JSON the
frontend and any future CLI consume. `display_id` is typed plain `str` here with **no**
`pattern=DISPLAY_ID_PATTERN`, unlike the SDK `Finding`; harmless on an output model but an
inconsistency worth knowing.

`evidence_sha256` is exposed and `evidence_*` bodies are not — the seal is verifiable without
shipping the payload. Good PX-EVIDENCE / PX-SECRETS balance.

### `ErrorResponse` — [line 85](../../backend/app/api/schemas.py#L85)

`error_code: str`, `message: str`, `detail: str | None = None`. `extra="forbid"` — see **F-L5** in
`module_core.md` for the sharp edge this creates in `handle_http_exception`.

---

## Module findings summary

| ID | Sev | Summary |
|---|---|---|
| F-C1 | Critical | Every route is unauthenticated; anonymous callers configure scope *and* trigger outbound requests. |
| F-M2 | Medium | `mode` is only validated at creation, never re-checked at scan time. |
| F-M5 | Medium | `GET /findings` is unpaginated and unfiltered. |
| F-M8 | Medium | `order_by(display_id)` sorts lexicographically; breaks past `PVX-9999`. |
| F-L2 | Low | `targets` accepts arbitrary strings; malformed targets masquerade as scope violations. |
| F-L13 | Low | `ScanRead.findings_count` reports engagement totals, not this run's. |
| F-L14 | Low | Report response sets no CSP / cache headers. |
| F-L15 | Low | `FindingRead` omits `scan_id`; no provenance link from finding to run. |
| F-L16 | Low | No cap on `targets` / `scope_allow` list sizes. |

✅ **Done well:** separate in/out models with `extra="forbid"` (B-FA-01); explicit `response_model` +
`status_code` on both write routes (B-FA-07); structured error detail dicts feeding a stable
envelope (PX-ERRORS); raw evidence deliberately withheld (PX-SECRETS); shared `_findings` query
avoiding duplication (Q-11); every route `async def` with async DB access (B-FA-02).
