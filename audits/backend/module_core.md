# Module — core (`app/main.py`, `app/config.py`, `app/db.py`, `app/__init__.py`)

**Path:** `/Users/mac/Projects/mine/provx/backend/app/`
**Purpose:** the ASGI application object, global error handling, typed configuration, and database
engine/session wiring. Everything that is process-wide rather than request-specific.

---

## Files

| File | Purpose | Exported symbols |
|---|---|---|
| [`app/__init__.py`](../../backend/app/__init__.py) | Package marker. | `__version__ = "0.0.0"` |
| [`app/main.py`](../../backend/app/main.py) | FastAPI app, exception handlers, meta routes. | `app`, `handle_http_exception`, `handle_unexpected_exception`, `health`, `root`, `logger` |
| [`app/config.py`](../../backend/app/config.py) | Typed settings loaded once from env. | `DEBUG_ENVIRONMENTS`, `Settings`, `get_settings` |
| [`app/db.py`](../../backend/app/db.py) | Engine, sessionmaker, request-scoped session dependency. | `get_engine`, `get_sessionmaker`, `get_session` |

---

## `app/main.py`

### App construction — [lines 30-35](../../backend/app/main.py#L30)

```python
app = FastAPI(title="Provx API", version=__version__,
              description="Governed automated security validation - control plane.")
app.include_router(engagements_router)
```

No middleware, no lifespan, no dependency overrides, no `docs_url`/`openapi_url` restriction —
`/docs` and `/openapi.json` are publicly served in all environments.

### Endpoints

| Method | Path | Request | Response model | Status | Notes |
|---|---|---|---|---|---|
| `GET` | `/health` | — | `dict[str, str]` (no declared model) | 200 | `{"status","service","version"}`. Used by the Dockerfile and compose healthchecks. `def`, not `async def` → threadpool. |
| `GET` | `/` | — | `dict[str, str]` | 200 | Static pointer to `/docs`. |

Neither meta route declares a `response_model` (B-FA-07). Trivial and self-describing, so Low at
most — but they are the two routes in the file, so the deviation is visible. Also, `/health`
publishes the application version unauthenticated; negligible today at `0.0.0`.

### Functions

| Signature | Description |
|---|---|
| `async handle_http_exception(request: Request, exc: HTTPException) -> JSONResponse` | Normalizes handled errors into the `ErrorResponse` envelope. If `exc.detail` is a dict containing `error_code`, it is splatted into `ErrorResponse(**detail)`; otherwise `error_code="http_error"` and `message=str(detail)`. Preserves `exc.status_code`. |
| `async handle_unexpected_exception(request: Request, exc: Exception) -> JSONResponse` | Logs the real failure with `logger.exception`, returns 500 with a fixed generic message. `detail=repr(exc)` is included **only** when `get_settings().is_debug_env`. |
| `health() -> dict[str, str]` | Liveness probe. |
| `root() -> dict[str, str]` | Service banner. |

### Findings

- **F-M3 (Medium)** — [`main.py:38`](../../backend/app/main.py#L38): the handler is registered for
  `fastapi.exceptions.HTTPException`, which is a *subclass* of `starlette.exceptions.HTTPException`.
  Starlette raises the **parent** class for unmatched routes (404) and method-not-allowed (405), and
  Starlette dispatches handlers by the raised class's MRO against the registered key. Those
  responses therefore bypass this handler entirely and return FastAPI's default
  `{"detail":"Not Found"}`, breaking the "stable error envelope" the module docstring promises. Fix:
  register for `starlette.exceptions.HTTPException` (it catches both, since FastAPI's subclasses it).
- **F-M4 (Medium)** — no `RequestValidationError` handler, so every 422 returns FastAPI's default
  body including an `input` field echoing submitted values. Outside the documented contract
  (PX-ERRORS consistency).
- **F-L5 (Low)** — `handle_http_exception` calls `ErrorResponse(**detail)` on any dict containing
  `error_code`. `ErrorResponse` is `extra="forbid"`, so a route raising a detail dict with an extra
  key would make the *error handler itself* raise a `ValidationError` inside error handling. No
  current caller does this (`ENGAGEMENT_NOT_FOUND` is the only structured detail), but it is a sharp
  edge in exactly the code that must never fail.
- **F-L9 (Low)** — `/docs`, `/redoc` and `/openapi.json` are unconditionally public. Given F-C1
  (no auth) this is consistent rather than additive, but should be gated on `is_debug_env` when auth
  lands.
- ✅ **PX-ERRORS / B-FA-06 / S-13 satisfied** on the 500 path. `repr(exc)` — which can carry SQL
  fragments, DSNs and driver internals — is correctly gated, and the gate fails closed.
- ✅ **PX-AI-OPTIONAL** — the module docstring states no AI runs here, and that is factually true of
  the whole backend.

---

## `app/config.py`

### `Settings(BaseSettings)` — [line 21](../../backend/app/config.py#L21)

`model_config = SettingsConfigDict(env_file=None, extra="ignore")`

| Field | Type | Default | Validation |
|---|---|---|---|
| `app_env` | `str` | `"production"` | none (free string; membership tested via `is_debug_env`) |
| `database_url` | `str` | `postgresql+asyncpg://provx:provx@db:5432/provx` | none |
| `http_timeout` | `float` | `10.0` | none — no `gt=0` bound |

| Property | Description |
|---|---|
| `is_debug_env -> bool` | `app_env.strip().lower() in DEBUG_ENVIRONMENTS` where the set is `{local, development, testing, staging}`. Fails closed for unknown values. |
| `async_database_url -> str` | Rewrites a sync DSN prefix to its async equivalent (`postgresql://`, `+psycopg`, `+psycopg2` → `+asyncpg`; `sqlite://` → `sqlite+aiosqlite://`), first match wins, otherwise returns unchanged. |

`get_settings()` is `lru_cache(maxsize=1)`; the test suite calls `.cache_clear()` explicitly.

### Findings

- ✅ B-FA-05 satisfied — one typed settings object, no scattered `os.getenv` anywhere in `app/`
  (verified by search: `os.getenv`/`os.environ` appear only in `tests/`).
- ✅ The default `database_url` embeds `provx:provx`, which is a *development* placeholder, not a
  committed production secret. Acceptable, though a fail-fast on a missing `DATABASE_URL` in
  production would be safer than silently falling back to a guessable local DSN (**F-L10**).
- **F-L11 (Low)** — `http_timeout` has no lower/upper bound. `HTTP_TIMEOUT=0` or a negative value
  reaches httpx unchecked. `Field(gt=0, le=120)` costs one line.
- **F-H3 relates here** — `Settings` has no `safe_mode` field, which is why the `SAFE_MODE` env var
  compose injects is silently ignored (`extra="ignore"`). See `99_FINDINGS.md`.

---

## `app/db.py`

| Function | Signature | Description |
|---|---|---|
| `get_engine` | `() -> AsyncEngine` | `lru_cache(maxsize=1)`. `create_async_engine(settings.async_database_url, echo=False, future=True)`. `echo=False` is a deliberate PX-SECRETS choice, documented inline — SQL logging would emit scan targets and evidence to stdout. |
| `get_sessionmaker` | `() -> async_sessionmaker[AsyncSession]` | `lru_cache(maxsize=1)`. Binds the engine, `class_=AsyncSession`, `expire_on_commit=False`. |
| `get_session` | `() -> AsyncIterator[AsyncSession]` | FastAPI dependency. `async with get_sessionmaker()() as session: yield session`. Exiting the context closes the session, rolling back anything uncommitted — this is what makes the mid-scan failure path safe (see `01_ARCHITECTURE.md` §B-FA-04). |

### Findings

- ✅ Schema ownership is Alembic-only; no `create_all` in app code.
- ✅ `expire_on_commit=False` is the correct choice given routes read ORM attributes after commit.
- **F-L12 (Low)** — no connection-pool configuration (`pool_size`, `max_overflow`,
  `pool_pre_ping`, `pool_recycle`). SQLAlchemy defaults apply. `pool_pre_ping=True` in particular is
  near-mandatory against Postgres behind a connection killer or a container restart, and its absence
  surfaces as intermittent 500s.
- **Note** — `get_session` has no `try/except` wrapper and does not call `rollback()` explicitly.
  This is correct: `AsyncSession.__aexit__` closes the session and discards the transaction. No
  finding.
