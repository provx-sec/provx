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
  - Playbook plugin type in `packages/adapters` (`provx_adapters.playbook` models +
    `provx_adapters.loader` load/validate stub, alongside the `ToolAdapter` interface) —
    no execution engine.
  - Extended `Finding` model plus `RiskAcceptance` and a documented `retest()` stub in
    `backend/app` (Pydantic only; EPSS/confidence/status lifecycle; no DB logic).
  - Tests for the playbook loader and the Finding model; the `unit-fixtures` CI gate now
    runs `pytest` for real (root `pytest.ini`). `accuracy` stub references
    `lab/expected.yml` (empty ruleset placeholder).
- Reaffirmed identity in docs/README: deterministic and auditable core; **AI is an
  optional advisor, off by default**.

[Unreleased]: https://github.com/darkusolomon1/provx/commits/main
