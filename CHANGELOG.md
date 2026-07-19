# Changelog

All notable changes to Provx are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Repository scaffold and governance (Phase 1): monorepo structure
  (`backend/`, `frontend/`, `packages/adapters/`, `packages/client/`, `lab/`,
  `wordlists/`, `.github/`).
- Apache-2.0 `LICENSE` and `NOTICE`.
- Community health files: `README.md`, `CONTRIBUTING.md` (DCO sign-off, adapter
  cookbook, Definition of Done), `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1),
  `SECURITY.md`, `RESPONSIBLE_USE.md`, `GOVERNANCE.md`, `SUPPORT.md`, `CODEOWNERS`.
- GitHub templates: `.github/PULL_REQUEST_TEMPLATE.md` (Definition of Done checklist)
  and issue forms for bug, feature, new-adapter, and detection-issue.
- Label taxonomy in `labels.yml`.
- Path-filtered CI skeleton in `.github/workflows/ci.yml` with stub gates: `dco`,
  `lint`, `types`, `unit-fixtures`, `accuracy`, `secrets-deps` (passing no-ops).
- `docker-compose.yml` (independently building `backend`/`frontend` services plus
  `db` and `redis`), `Makefile` skeleton, `.gitignore`, and `.env.example`.
- Service skeletons: FastAPI backend (`GET /health`) and Next.js frontend placeholder.
- Deterministic-core scaffolding (models/interfaces/one example/tests, no engine):
  - `workflows/` with the `web-baseline.yaml` example playbook and a documented playbook
    schema in `docs/PLAYBOOK_SCHEMA.md`.
  - Playbook plugin type in the `provx-sdk` package (`provx_sdk.playbook` models +
    `provx_sdk.loader` load/validate stub, alongside the `ToolAdapter` interface) —
    no execution engine.
  - Extended `Finding` model plus `RiskAcceptance` and a documented `retest()` stub in
    `backend/app` (Pydantic only; EPSS/confidence/status lifecycle; no DB logic).
  - Tests for the playbook loader and the Finding model; the `unit-fixtures` CI gate now
    runs `pytest` for real (root `pytest.ini`). `accuracy` stub references
    `lab/expected.yml` (empty ruleset placeholder).
- Reaffirmed identity in docs/README: deterministic and auditable core; **AI is an
  optional advisor, off by default**.
- `docs/PROVX_RULES.md` — the PX safety/engineering rules (incl. **PX-DSL**: the future
  playbook evaluator must be a restricted/allowlisted evaluator; `eval()`/`exec()` are
  forbidden). Cross-linked from `CONTRIBUTING.md` and `docs/PLAYBOOK_SCHEMA.md`.
- Walking skeleton, end to end: `POST /engagements` runs a scope-gated scan through the
  `security_headers` adapter (discovered as an entry-point plugin), normalizes the
  results into Findings sealed with SHA-256, and persists them to PostgreSQL via
  SQLModel and Alembic. Findings are readable as a list, an HTML report, and a Next.js
  Server Component page. Scans run inline; there is no job queue yet.
- Scoped HTTP egress boundary — `provx_sdk.fetch.fetch_within_scope`, the single outbound
  HTTP path, which re-checks engagement scope on every redirect hop (PX-EGRESS).
- Scan-time safety gate in `backend/app/services/safety.py`, enforcing the org-wide
  `SAFE_MODE`, the engagement's `mode`, and the adapter's `safety` class before any
  adapter runs (PX-ACTIVE).
- Lab targets for the accuracy harness: a vulnerable target (`lab/positive`) and a clean
  one (`lab/clean`), with `lab/expected.yml` populated as the scoring oracle.

### Changed

- `Finding` now has a UUID `id` (database primary key) plus a per-engagement human
  `display_id` (`PVX-0001`, resets per engagement). The `PF-` convention is dropped.
- Renamed the plugin SDK package `provx-adapters` → `provx-sdk` (import `provx_adapters`
  → `provx_sdk`); it hosts both tool adapters and playbooks. Directory stays
  `packages/adapters/`.
- Promoted the `dco`, `lint` (ruff), and `types` (mypy, strict) CI gates from stubs to
  real checks on `backend/` and `packages/` (root `ruff.toml` + `mypy.ini`); the existing
  scaffold passes them cleanly. `secrets-deps` remains a stub until the tools are wired.
- Promoted `accuracy` from a stub to a real gate: it scores TP/FP/FN with `lab/harness.py`
  against the vulnerable (`lab/positive`) and clean (`lab/clean`) targets, and fails the
  build on a regression.
- Scoped the CI triggers to the paths each gate covers and added a concurrency group so
  superseded runs on the same ref are cancelled.

### Fixed

- Redirects escaped engagement scope: only the initial URL was checked, so a redirect
  could send a request to an out-of-scope host. Scope is now re-checked on every hop
  (PX-SCOPE, PX-EGRESS).
- `SAFE_MODE` was inert — the setting was read and then discarded, so it appeared wired
  while enforcing nothing. It is now enforced at the scan gate.
- Evidence is attributed to the adapter that produced it, rather than to the engagement.
- Scans against dangerous or overly broad target ranges are denied.
- Stripped leaked local filesystem paths from the CI workflow definitions.

[Unreleased]: https://github.com/provx-sec/provx/commits/main
