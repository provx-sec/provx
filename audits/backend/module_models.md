# Module — `app/models`

**Path:** `/Users/mac/Projects/mine/provx/backend/app/models/`
**Purpose:** persistence tables, and the compatibility shim that keeps the historical
`app.models.findings` import path alive after the canonical contract moved into `provx_sdk`.

---

## Files

| File | Purpose | Exported symbols |
|---|---|---|
| [`models/__init__.py`](../../backend/app/models/__init__.py) | Re-exports the SDK contract types under `app.models`. Explicit `__all__`. | `Confidence`, `Evidence`, `Finding`, `FindingStatus`, `Module`, `RiskAcceptance`, `Severity` |
| [`models/findings.py`](../../backend/app/models/findings.py) | Pure re-export shim → `provx_sdk.findings`. Contains no logic. | same seven names |
| [`models/tables.py`](../../backend/app/models/tables.py) | The four SQLModel tables + the row↔contract conversion. | `Engagement`, `Target`, `Scan`, `FindingRow`, `_now`, `_timestamp_column` |

**Dependencies:** `sqlmodel`, `sqlalchemy.DateTime`, `provx_sdk.evidence.EvidenceSeal`,
`provx_sdk.findings` (enums, `FindingDraft`, `Finding`, `Evidence`, `DISPLAY_ID_PATTERN`,
`validate_attack_techniques`).

**Architectural note:** the dependency direction is correct. `provx_sdk` never imports the backend,
so an adapter package can depend on the contract without dragging in FastAPI or SQLAlchemy. Neither
`__init__.py` nor `findings.py` exports `FindingDraft`, so backend code that needs it imports from
`provx_sdk` directly (as `tables.py` and `scan_runner.py` both do) — the shim is genuinely
legacy-only and is not accreting new surface. Fine, though two import paths for the same seven names
is a small ongoing DRY cost (**F-L17**): consider deleting the shim once nothing imports it.

---

## Helpers

| Signature | Description |
|---|---|
| `_now() -> datetime` | `datetime.now(UTC)`. Every timestamp default. |
| `_timestamp_column(nullable: bool = False) -> Column[datetime]` | `Column(DateTime(timezone=True), nullable=nullable)`. Explicit because SQLModel's default maps to `TIMESTAMP WITHOUT TIME ZONE`, which PostgreSQL rejects for aware datetimes — and, as the docstring says, an audit trail with ambiguous local times is not an audit trail (PX-EVIDENCE). Correct and well reasoned. |

---

## `Engagement` — table `engagement` ([line 50](../../backend/app/models/tables.py#L50))

| Field | Type | DB | Notes |
|---|---|---|---|
| `id` | `uuid.UUID` | PK, `default_factory=uuid.uuid4` | client-side UUID generation |
| `name` | `str` | `AutoString`, indexed | |
| `scope_allow` | `list[str]` | `JSON`, nullable in DB | PX-SCOPE allow rules |
| `scope_deny` | `list[str]` | `JSON`, nullable in DB | deny wins |
| `mode` | `str` | `AutoString NOT NULL`, default `"passive"` | **no CHECK constraint, no enum** |
| `created_at` | `datetime` | `TIMESTAMPTZ NOT NULL` | |

**Findings:**
- **F-M2** — `mode` is a free string in the database. The `^passive$` guard lives only on the create
  request schema and is never re-checked at scan time (see `01_ARCHITECTURE.md`). A CHECK constraint
  or a `Severity`-style `StrEnum` would make the invariant structural rather than procedural.
- **F-L18 (Low)** — `scope_allow`/`scope_deny` are `nullable=True` in the migration but non-optional
  `list[str]` in the model. The app always writes lists, but a NULL arriving from any other source
  makes `ScopePolicy(allow=None)` raise a `ValidationError` → 500. `nullable=False` with a server
  default would match the model. The same mismatch applies to `FindingRow.attack_techniques`, where
  a NULL would make `list(row.attack_techniques)` raise `TypeError` in `_to_read`.

---

## `Target` — table `target` ([line 66](../../backend/app/models/tables.py#L66))

| Field | Type | DB |
|---|---|---|
| `id` | `uuid.UUID` | PK |
| `engagement_id` | `uuid.UUID` | FK → `engagement.id`, indexed |
| `url` | `str` | `AutoString NOT NULL` |
| `created_at` | `datetime` | `TIMESTAMPTZ NOT NULL` |

No uniqueness on `(engagement_id, url)`, so the same URL can be added twice and will be probed
twice. Dedup at the finding layer hides the duplicate findings, but the **network requests are
duplicated** — mild, and it inflates `targets_scanned`. **F-L19.**

---

## `Scan` — table `scan` ([line 77](../../backend/app/models/tables.py#L77))

| Field | Type | DB | Notes |
|---|---|---|---|
| `id` | `uuid.UUID` | PK | |
| `engagement_id` | `uuid.UUID` | FK, indexed | |
| `adapter` | `str` | `NOT NULL` | always `"security_headers"` today |
| `status` | `str` | `NOT NULL`, default `"completed"` | **never assigned anywhere in the codebase** |
| `targets_scanned` | `int` | `NOT NULL`, default 0 | |
| `targets_skipped_out_of_scope` | `int` | `NOT NULL`, default 0 | |
| `started_at` | `datetime` | `TIMESTAMPTZ NOT NULL` | |
| `finished_at` | `datetime \| None` | `TIMESTAMPTZ NULL` | set only on success |

**F-M1 (Medium)** — the `status` column is vestigial. A scan is born `"completed"` and there is no
`running`, `failed`, or `partial` state, because the only way a scan can fail is by rolling the whole
transaction back and leaving no row at all. The result: `finished_at` is nullable to model an
in-flight scan that can never be observed, and a scan that made real network requests to client
infrastructure before crashing leaves **zero trace** in the audit trail. For a governance tool this
is the wrong default — the fix is to commit the `Scan` row with `status="running"` before probing,
then update it to `completed`/`failed` in a second transaction, accepting that findings and the scan
record are no longer atomic together (they do not need to be — findings have a FK to the scan).

---

## `FindingRow` — table `finding` ([line 92](../../backend/app/models/tables.py#L92))

| Field | Type | DB | Populated by `from_draft`? |
|---|---|---|---|
| `id` | `uuid.UUID` | PK | auto |
| `engagement_id` | `uuid.UUID` | FK, indexed | ✅ arg |
| `scan_id` | `uuid.UUID` | FK, indexed | ✅ arg |
| `display_id` | `str` | indexed (non-unique), **unique with `engagement_id`** | ✅ arg, regex-validated |
| `title` | `str` | `NOT NULL` | ✅ |
| `target` | `str` | `NOT NULL` | ✅ |
| `module` | `Module` | native enum `module` | ✅ |
| `severity` | `Severity` | native enum `severity` | ✅ |
| `cvss` | `float \| None` | `Float NULL` | ✅ |
| `epss` | `float \| None` | `Float NULL` | ❌ **never set** |
| `confidence` | `Confidence` | native enum, default MEDIUM | ✅ |
| `status` | `FindingStatus` | native enum, default NEW | ❌ **never set, never updated** |
| `attack_techniques` | `list[str]` | `JSON` nullable | ✅ revalidated |
| `remediation` | `str \| None` | nullable | ✅ |
| `evidence_tool_output` | `str \| None` | nullable | ✅ from `draft.evidence` |
| `evidence_matched_rule` | `str \| None` | nullable | ✅ |
| `evidence_reproduction_cmd` | `str \| None` | nullable | ✅ |
| `evidence_sha256` | `str` | `NOT NULL` | ✅ from the seal |
| `captured_at` | `datetime` | `TIMESTAMPTZ NOT NULL` | ✅ from the seal |

Unique constraint: `uq_finding_engagement_display_id` on `(engagement_id, display_id)` — the right
grain (display ids are per-engagement, so two engagements can each hold a `PVX-0001`), asserted by
[`test_finding_display_id_is_unique_per_engagement`](../../backend/tests/test_migrations.py#L54).

### The `epss` / `status` asymmetry — confirmed and assessed

Confirmed by reading both models: `FindingRow` carries `epss` and `status`; `FindingDraft`
([`provx_sdk/findings.py:147`](../../packages/adapters/src/provx_sdk/findings.py#L147)) carries
neither. `from_draft` therefore never passes them and both take their column defaults.

**This asymmetry is correct by design, and it is the right design** — but only one half of it is
currently harmless:

- **`epss`** — an adapter genuinely cannot know an EPSS score; it is enrichment applied after
  normalization from an external feed. Leaving it off the draft is correct modelling. The column
  exists ahead of the enrichment step. **Declared scaffolding, no action.**
- **`status`** — likewise correct that an adapter cannot set it: status is a *human* judgement, and
  a machine-proposed finding must start at `NEW` (PX-HUMAN, "the machine proposes, a human
  confirms"). But the consequence is that **`status` is currently write-once and unreachable**.
  There is no endpoint, service, or code path anywhere in the backend that transitions a finding to
  `TRIAGED`, `VALIDATED`, `FALSE_POSITIVE`, `ACCEPTED_RISK`, `FIXED`, or `REGRESSION`. The full
  seven-state lifecycle exists in the enum, in the migration, and in the API response — and no value
  other than `new` can ever be observed. The report banner mitigates the risk today by declaring
  everything unvalidated, and triage UI is legitimately a later phase. Recorded as **declared
  scaffolding** with one caveat: `RiskAcceptance` exists in the SDK with no table and no persistence
  path, so the governance story is further from complete than the enum surface suggests.

### Methods

#### `FindingRow.from_draft(draft, *, engagement_id, scan_id, display_id, stamp) -> FindingRow`

[line 120](../../backend/app/models/tables.py#L120)

Builds a row from a draft, **re-validating on the way in**: `re.match(DISPLAY_ID_PATTERN, display_id)`
raising `ValueError`, and `validate_attack_techniques(...)` re-run over the technique list.

This exists because **SQLModel does not run Pydantic validation on `table=True` classes** — without
it, a malformed row would write cleanly and then break every subsequent read of its engagement via
`to_contract()`, since the SDK `Finding` *does* validate. The docstring says exactly this, and
[`test_scan_runner.py`](../../backend/tests/test_scan_runner.py) pins both gates, including a test
that bypasses the draft's own validator with `object.__setattr__` to prove the row constructor is an
independent gate rather than a caller-trusting one. This is the best-engineered piece of the module.

Two gaps in that gate: `cvss` is passed through **without** the SDK's `ge=0.0, le=10.0` bound, and
`title`/`target` are unbounded strings. A draft with `cvss=99.0` would write and then fail at
`to_contract()` — precisely the failure mode `from_draft` exists to prevent. `FindingDraft` itself
enforces the range, so this only matters for a non-Pydantic or hand-built draft, but the whole
premise of the method is not trusting the caller. **F-M9.**

#### `FindingRow.to_contract() -> Finding`

[line 158](../../backend/app/models/tables.py#L158)

Rebuilds the canonical SDK `Finding`. The single conversion point, so a new contract field has
exactly one place to be wired through (the docstring cites prior audit item M4). Always constructs
an `Evidence` object even when all three fields are `None`, so `Finding.evidence` is never `None`
from this path — a small semantic difference from a fresh `Finding` (default `None`) that no current
code depends on.

---

## Module findings summary

| ID | Sev | Summary |
|---|---|---|
| F-M1 | Medium | `Scan.status` never assigned; failed scans leave no record at all. |
| F-M2 | Medium | `mode` is an unconstrained string column; no CHECK, no scan-time re-check. |
| F-M9 | Medium | `from_draft` re-validates display_id and ATT&CK ids but not `cvss` range. |
| F-L17 | Low | Two import paths for the same seven contract names (`app.models` shim). |
| F-L18 | Low | `scope_allow`/`scope_deny`/`attack_techniques` nullable in DB, non-optional in model. |
| F-L19 | Low | No uniqueness on `(engagement_id, url)`; duplicate targets are probed twice. |
| — | Scaffolding | `epss` unpopulated (enrichment later); `status` write-once with no transition path (triage later). |

✅ **Done well:** timezone-aware columns everywhere; write-time contract revalidation with a clear
documented rationale; a single `to_contract` conversion point; correct per-engagement grain on the
unique constraint; clean SDK-does-not-depend-on-backend layering.
