# Backend audit — 00 Overview

**Repo:** `/Users/mac/Projects/mine/provx/backend`
**Audited:** 2026-07-19 · every file under `app/`, `alembic/`, `tests/` read line by line.
**Stage:** pre-alpha walking skeleton. 4 HTTP routes, 1 passive adapter, Postgres persistence, HTML report.

---

## 1. Stack and versions

| Layer | Choice | Constraint (`pyproject.toml`) | Pinned in `requirements.lock` |
|---|---|---|---|
| Language | Python | `>=3.12` | image is `python:3.12.13-slim` |
| Web framework | FastAPI | `>=0.111` | `fastapi==0.139.2`, `starlette==1.3.1` |
| ASGI server | uvicorn[standard] | `>=0.30` | `uvicorn==0.51.0`, `uvloop==0.22.1`, `httptools==0.8.0` |
| ORM / models | SQLModel over SQLAlchemy | `>=0.0.22` | `sqlmodel==0.0.39`, `SQLAlchemy==2.0.51` |
| Migrations | Alembic | `>=1.13` | `alembic==1.18.5`, `Mako==1.3.12` |
| DB drivers | asyncpg (prod), aiosqlite (tests) | `>=0.29` / `>=0.20` | `asyncpg==0.31.0`, `aiosqlite==0.22.1` |
| Async bridge | greenlet | `>=3` | `greenlet==3.5.3` (explicit — SQLAlchemy no longer declares it) |
| Templating | Jinja2 | `>=3.1` | `Jinja2==3.1.6`, `MarkupSafe==3.0.3` |
| Settings | pydantic-settings | `>=2.3` | `pydantic==2.13.4`, `pydantic-settings==2.14.2` |
| Shared contract | `provx-sdk` (monorepo path install) | unpinned | deliberately **absent** from the lock |
| HTTP client | httpx | dev extra only | `httpx==0.28.1` |

`app.__version__ = "0.0.0"` ([`app/__init__.py:5`](../../backend/app/__init__.py#L5)).

**Note (F-L3):** `httpx` is declared only under `[project.optional-dependencies].dev`
([`pyproject.toml:29`](../../backend/pyproject.toml#L29)), yet the runtime scan path imports it via
`provx_sdk.adapters.security_headers`. It is in the lock so the image works, but a
`pip install provx-backend` from `pyproject.toml` alone would produce a runtime `ImportError` on
the first scan.

### Tooling config

- **ruff** — `target-version = py312`, `line-length = 100`, `select = ["E","F","I","UP","B"]`.
  Declared identically in [`backend/pyproject.toml:41`](../../backend/pyproject.toml#L41) and root
  [`ruff.toml`](../../ruff.toml) (duplication is deliberate and documented in both files).
  `flake8-bugbear.extend-immutable-calls` whitelists `fastapi.Depends/Query/Path/Body` — the correct
  handling of B008 vs. the FastAPI DI idiom.
- **mypy** — `strict = True`, `python_version = 3.12`,
  `mypy_path = backend:packages/adapters/src` ([`mypy.ini`](../../mypy.ini)).
- **pytest** — root [`pytest.ini`](../../pytest.ini): `asyncio_mode = auto`,
  `pythonpath = . backend packages/adapters/src`, `testpaths = backend/tests packages/adapters/tests lab/tests`.
  `backend/pyproject.toml` also carries a narrower `testpaths = ["tests"]` for a backend-only run.

---

## 2. Folder layout under `app/`

```
app/
├── __init__.py            package marker; holds __version__ = "0.0.0"
├── main.py                FastAPI app object, 2 exception handlers, /health and /
├── config.py              typed Settings (pydantic-settings) + cached get_settings()
├── db.py                  async engine, sessionmaker, get_session() FastAPI dependency
├── api/
│   ├── __init__.py        docstring only
│   ├── engagements.py     the four business routes + row→response projection helpers
│   └── schemas.py         request/response Pydantic models + the ErrorResponse envelope
├── models/
│   ├── __init__.py        re-exports the SDK contract types
│   ├── findings.py        re-export shim → provx_sdk.findings (back-compat import path)
│   └── tables.py          SQLModel tables: Engagement, Target, Scan, FindingRow
├── services/
│   ├── __init__.py        docstring only
│   ├── scan_runner.py     the scan pipeline: scope gate → probe → seal → dedup → persist
│   ├── report.py          Jinja environment (autoescape on) + render_report()
│   └── retest.py          documented NotImplementedError stub
└── templates/
    └── report.html.j2     the HTML findings report + the PX-HUMAN "unvalidated" banner
```

Plus `alembic/` (env.py + one revision + script.py.mako + README), `tests/` (7 files),
`Dockerfile`, `docker-entrypoint.sh`, `alembic.ini`, `pyproject.toml`, `requirements.lock`,
`README.md`, `.dockerignore`.

---

## 3. Entry point and bootstrap flow

1. Container starts → `ENTRYPOINT ["provx-entrypoint"]`
   ([`Dockerfile`](../../backend/Dockerfile)) → [`docker-entrypoint.sh`](../../backend/docker-entrypoint.sh).
2. `set -eu`; `alembic upgrade head` runs **before** the server
   ([`docker-entrypoint.sh:8`](../../backend/docker-entrypoint.sh#L8)). Schema is owned by Alembic,
   never `create_all`; a failed migration aborts start-up rather than serving a wrong schema.
3. `exec "$@"` → `uvicorn app.main:app --host 0.0.0.0 --port 8000`.
4. [`app/main.py:30`](../../backend/app/main.py#L30) constructs the `FastAPI` object and includes the
   engagements router. There is **no lifespan / startup hook** — the DB engine is created lazily on
   first use through the `lru_cache`d `get_engine()`.

**Note (F-L6):** migrations and the server are separate process steps in the same container, so a
multi-replica deploy would race `alembic upgrade head`. Harmless for the single-container skeleton;
needs a leader gate before any real deployment.

---

## 4. Environment variables

Read by the app ([`app/config.py:21`](../../backend/app/config.py#L21)):

| Var | Type | Default | Effect |
|---|---|---|---|
| `APP_ENV` | str | `"production"` | Gates whether internal error detail reaches a client. Fails **closed** — unset or unrecognized is treated as production (PX-ERRORS). Debug set: `local, development, testing, staging`. |
| `DATABASE_URL` | str | `postgresql+asyncpg://provx:provx@db:5432/provx` | Coerced to an async driver by `Settings.async_database_url`. |
| `HTTP_TIMEOUT` | float | `10.0` | Forwarded to `adapter.probe(..., timeout=)`. |

Declared in [`.env.example`](../../.env.example) but **not consumed by backend code**:

| Var | Status |
|---|---|
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | consumed by the `db` service only — correct |
| `REDIS_URL` | injected into the backend container by compose; no code reads it. Declared scaffolding (arq is a later phase). |
| `SECRET_KEY` | injected into the backend container; no code reads it. Nothing is signed or encrypted yet. |
| `SAFE_MODE` | injected into the backend container; **no code reads it**. Advertised in `.env.example` as an "org-wide safe-mode lock… forces safety regardless of engagement mode" — it currently does nothing. See finding **F-H3**. |
| `BACKEND_PORT`, `FRONTEND_PORT`, `PROVX_API_BASE_URL` | compose / frontend only |
| `AI_ENABLED`, `AI_PROVIDER`, `AI_MODEL`, `AI_API_KEY` | not read anywhere. Consistent with PX-AI-OPTIONAL — there is no AI code path in the backend at all. Verified by grep: zero LLM imports. |

`Settings.model_config` sets `env_file=None`, so the app never parses `.env` itself; the environment
must be populated externally (compose does). `extra="ignore"` means the unread vars above are
silently dropped rather than raising.

---

## 5. Docker / compose

[`backend/Dockerfile`](../../backend/Dockerfile):

- Base `python:3.12.13-slim`, exact patch pin; deliberately not digest-pinned, with the rationale
  (arm64/amd64 parity) written into the header. Reasonable, and flagged as a pre-1.0 item.
- Build context is the **repo root**, not `backend/`, so `packages/adapters` can be copied to
  `/opt/provx-sdk` and installed with `--no-deps`. That install is what registers the
  `provx.adapters` entry points `provx_sdk.registry.load_adapter` discovers at runtime.
- `requirements.lock` installed first for layer caching. **No `--require-hashes`** (F-L7).
- Drops root: `useradd --create-home --uid 10001 appuser` + `USER appuser`. Good.
- `HEALTHCHECK` polls `/health` over `urllib`.

[`docker-compose.yml`](../../docker-compose.yml):

- `backend` waits on `db` and `redis` `service_healthy`; the healthcheck is duplicated at the compose
  level on purpose so the frontend's `service_healthy` gate does not depend on an image detail.
- `frontend` deliberately gets **no `env_file`** — only `PROVX_API_BASE_URL`. Correct secret
  hygiene (PX-SECRETS), and the comment says so.
- `db` publishes `5432:5432` and `redis` publishes `6379:6379` to the host, Redis with no password
  — see **F-M6**.
- Lab targets (`lab-missing-headers`, `lab-hardened`, `accuracy`) sit behind the `lab` profile on an
  `internal: true` network with no published ports. Good PX-AUTHZ posture.

---

## 6. Database / ORM configuration

- **Engine:** `create_async_engine(settings.async_database_url, echo=False, future=True)` under
  `lru_cache(maxsize=1)` ([`app/db.py:22`](../../backend/app/db.py#L22)). `echo=False` is a
  deliberate PX-SECRETS decision — SQL logging would put scan targets and evidence into stdout.
- **Sessions:** `async_sessionmaker(..., class_=AsyncSession, expire_on_commit=False)`;
  `get_session()` is an async-generator dependency yielding one session per request.
- **URL coercion:** `Settings.async_database_url` rewrites `postgresql://`, `postgresql+psycopg://`,
  `postgresql+psycopg2://` and `sqlite://` to their async equivalents, so a sync DSN in `.env` fails
  with a clear config error rather than a missing-module traceback from inside engine creation.
- **Schema ownership:** Alembic only. `SQLModel.metadata.create_all` appears **only** in the test
  fixture ([`tests/conftest.py:47`](../../backend/tests/conftest.py#L47)) — never in app code.
- **Tables:** `engagement`, `target`, `scan`, `finding`. One revision `b1428574732c`, `down_revision = None`.
- **Timestamps:** every datetime column is built by `_timestamp_column()` → `DateTime(timezone=True)`,
  and every default is `datetime.now(UTC)`. Timezone-aware end to end, which is a PX-EVIDENCE
  prerequisite.

---

## 7. Modules index

| File | Covers |
|---|---|
| [`module_core.md`](module_core.md) | `app/main.py`, `app/config.py`, `app/db.py`, `app/__init__.py` |
| [`module_api.md`](module_api.md) | `app/api/engagements.py`, `app/api/schemas.py`, `app/api/__init__.py` |
| [`module_models.md`](module_models.md) | `app/models/tables.py`, `app/models/findings.py`, `app/models/__init__.py` |
| [`module_services.md`](module_services.md) | `app/services/*`, `app/templates/report.html.j2` |
| [`module_alembic.md`](module_alembic.md) | `alembic.ini`, `alembic/env.py`, revision `b1428574732c` |
| [`01_ARCHITECTURE.md`](01_ARCHITECTURE.md) | request lifecycle, scan pipeline, auth, cross-cutting concerns |
| [`99_FINDINGS.md`](99_FINDINGS.md) | consolidated findings ordered by severity |
