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

[Unreleased]: https://github.com/darkusolomon1/provx/commits/main
