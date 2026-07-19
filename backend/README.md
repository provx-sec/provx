# Provx backend

FastAPI control plane for Provx — the API, scan orchestration, findings pipeline, and
the safety/scope engine. Python 3.12.

> **Status: Phase 1 skeleton.** Currently a minimal FastAPI app exposing `GET /health`
> and `GET /`. The data model, engagements, scanning, and findings pipeline land in
> later phases (see [`../docs/ROADMAP.md`](../docs/ROADMAP.md) and
> [`../docs/PenForge-Local_Build_Blueprint.md`](../docs/PenForge-Local_Build_Blueprint.md)).

## Run with Docker (recommended)

From the repo root:

```bash
docker compose up --build backend
```

The API is served at http://localhost:8000 (`/health`, and `/docs` for the OpenAPI UI).

## Run locally

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
uvicorn app.main:app --reload
```

## Checks

```bash
ruff check . && ruff format --check .
mypy .
pytest
```

These map to the `lint`, `types`, and `unit-fixtures` CI gates.
