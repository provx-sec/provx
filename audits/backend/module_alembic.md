# Module — `alembic/` (migrations)

**Path:** `/Users/mac/Projects/mine/provx/backend/alembic/` + `backend/alembic.ini`
**Purpose:** the auditable record of how the schema got to where it is. Schema is owned here and
never by `create_all` in application code.

---

## Files

| File | Purpose | Exported symbols |
|---|---|---|
| [`alembic.ini`](../../backend/alembic.ini) | Alembic config. Mostly the stock template with comments retained. | — |
| [`alembic/env.py`](../../backend/alembic/env.py) | Migration environment; async-aware. | `config`, `target_metadata`, `run_migrations_offline`, `do_run_migrations`, `run_async_migrations`, `run_migrations_online` |
| [`alembic/script.py.mako`](../../backend/alembic/script.py.mako) | Revision template (stock). | — |
| [`alembic/README`](../../backend/alembic/README) | Stock one-liner. | — |
| [`alembic/versions/b1428574732c_walking_skeleton_core_tables.py`](../../backend/alembic/versions/b1428574732c_walking_skeleton_core_tables.py) | The only revision. Creates `engagement`, `scan`, `target`, `finding`. | `revision`, `down_revision`, `branch_labels`, `depends_on`, `ENUM_TYPES`, `upgrade`, `downgrade` |

---

## `alembic.ini`

Key settings: `script_location = %(here)s/alembic`, `prepend_sys_path = .`, `path_separator = os`.

**No `sqlalchemy.url` is set in the file.** It is injected at runtime from application settings
([`env.py:30`](../../backend/alembic/env.py#L30)). This is the right call twice over: one source of
truth for the DSN (B-FA-05), and **no connection string — and therefore no credentials — committed
to the repo** (S-01, PX-SECRETS). Verified: no DSN literal appears anywhere in `alembic.ini`.

`prepend_sys_path = .` means Alembic must be invoked from `backend/`, which is what the Dockerfile's
`WORKDIR /app` layout provides.

---

## `alembic/env.py`

| Function | Signature | Description |
|---|---|---|
| `run_migrations_offline` | `() -> None` | `--sql` mode. Configures with the URL string and `literal_binds=True`; emits SQL without connecting. |
| `do_run_migrations` | `(connection: Connection) -> None` | Sync callback run inside `connection.run_sync`; configures the context and runs migrations in a transaction. |
| `run_async_migrations` | `async () -> None` | Builds an async engine from the config section with `poolclass=NullPool`, connects, delegates to `do_run_migrations`, disposes. |
| `run_migrations_online` | `() -> None` | `asyncio.run(run_async_migrations())`. |

`target_metadata = SQLModel.metadata`, populated by the deliberate side-effect import
`from app.models import tables as _tables  # noqa: F401`
([line 24](../../backend/alembic/env.py#L24)) — correctly commented as to *why* the unused import
exists, and correctly `noqa`'d for ruff F401.

### Findings

- ✅ No committed credentials; URL from settings.
- ✅ `NullPool` — correct for a short-lived migration process.
- **F-L23 (Low)** — `context.configure` in `do_run_migrations` sets neither `compare_type=True` nor
  `render_as_batch=True`. Without `compare_type`, `alembic revision --autogenerate` will silently
  miss column type changes (e.g. `Float` → `Numeric`, or a widened `VARCHAR`) — a real hazard for a
  project whose schema is still moving. Without `render_as_batch`, no future migration can ALTER a
  column on SQLite, which matters because the test suite runs migrations against SQLite.
- **F-L24 (Low)** — `env.py` calls `asyncio.run()` at import time via the module-level
  `if context.is_offline_mode()` block. Standard Alembic layout, but it means `env.py` cannot be
  invoked from inside a running event loop. `test_migrations.py` correctly uses the sync
  `command.upgrade`, so this is latent only — worth knowing if migrations are ever driven from an
  async fixture or an async admin endpoint.

---

## Revision `b1428574732c` — "walking skeleton core tables"

`down_revision = None` (the base revision). Created 2026-07-19.

### `upgrade()`

Creates four tables in FK-safe order: `engagement` → `scan` → `target` → `finding`.

| Table | Columns | Constraints / indexes |
|---|---|---|
| `engagement` | id (Uuid PK), name, scope_allow (JSON NULL), scope_deny (JSON NULL), mode, created_at (TIMESTAMPTZ) | `ix_engagement_name` |
| `scan` | id, engagement_id, adapter, status, targets_scanned, targets_skipped_out_of_scope, started_at, finished_at (NULL) | FK → engagement.id; `ix_scan_engagement_id` |
| `target` | id, engagement_id, url, created_at | FK → engagement.id; `ix_target_engagement_id` |
| `finding` | id, engagement_id, scan_id, display_id, title, target, module, severity, cvss, epss, confidence, status, attack_techniques (JSON NULL), remediation, evidence_tool_output, evidence_matched_rule, evidence_reproduction_cmd, evidence_sha256, captured_at | FKs → engagement.id, scan.id; `uq_finding_engagement_display_id (engagement_id, display_id)`; indexes on display_id, engagement_id, scan_id |

Native enum types created: `module (WEB, API, INFRA)`, `severity (INFO…CRITICAL)`,
`confidence (HIGH, MEDIUM, LOW)`,
`findingstatus (NEW, TRIAGED, VALIDATED, FALSE_POSITIVE, ACCEPTED_RISK, FIXED, REGRESSION)`.

**Verified against `models/tables.py`: the migration and the models agree.** Every column, type,
nullability, index, and constraint matches. No drift.

### `downgrade()`

Drops indexes and tables in exact reverse order, then — the part most projects miss —
explicitly drops the four named enum types when `bind.dialect.name == "postgresql"`:

```python
ENUM_TYPES = ("module", "severity", "confidence", "findingstatus")
...
for enum_name in ENUM_TYPES:
    sa.Enum(name=enum_name).drop(bind, checkfirst=True)
```

PostgreSQL creates named enum types implicitly with the table but does **not** drop them with it, so
without this a `downgrade` followed by an `upgrade` fails with "type already exists". The
dialect guard keeps SQLite (where the enums are CHECK constraints) working, and `checkfirst=True`
makes it idempotent. The rationale is written into a comment citing rule W-03. Genuinely good
migration hygiene — reversibility is tested by
[`test_downgrade_reverses_the_migration`](../../backend/tests/test_migrations.py#L66).

### Findings

- **F-L18 (Low)** — `scope_allow`, `scope_deny`, and `attack_techniques` are created `nullable=True`
  while the SQLModel fields are non-optional `list[str]`. A NULL from any non-app writer becomes a
  500 at read time (`ScopePolicy(allow=None)` → ValidationError;
  `list(row.attack_techniques)` → TypeError). Should be `nullable=False` with a `server_default`.
- **F-L25 (Low)** — no `ondelete` behaviour on any FK. Deleting an engagement is currently
  impossible through the API (which is deliberate — PX-EVIDENCE append-only), so this is latent, but
  the schema does not express the intent. A `RESTRICT`/`NO ACTION` declaration would make the
  append-only posture structural rather than incidental.
- **F-L26 (Low)** — `title`, `target`, `url`, `remediation`, and the three `evidence_*` columns are
  unbounded `AutoString` (→ `VARCHAR` with no length / `TEXT`). `evidence_tool_output` stores the
  full raw response envelope for **every** finding, so a page with five missing headers stores five
  copies of the same body. Storage grows fast, and there is no length cap on adapter output.
  Deduplicating evidence into its own table keyed by the sha256 would be the natural fix and would
  align with the seal already being computed.
- ✅ Timezone-aware timestamps on all five datetime columns.
- ✅ The unique constraint is at the correct `(engagement_id, display_id)` grain, and is explicitly
  tested rather than assumed.
- ✅ Single revision, linear history, no branches.
