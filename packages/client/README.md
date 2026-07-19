# @provx/client

A typed TypeScript client for the Provx API, consumed by the [frontend](../../frontend/)
and available to third-party integrations and CI tooling.

> **Status: Phase 1 skeleton.** No client surface yet. Once the backend exposes a stable
> OpenAPI schema, this package will hold a generated + hand-wrapped client so the UI and
> external automation share one source of truth.

## Intended shape

- Generated from the backend's OpenAPI schema (`/openapi.json`).
- Thin ergonomic wrappers for common flows (engagements, scans, findings, reports).
- Published for use in CI/CD security gates (see [`docs/ROADMAP.md`](../../docs/ROADMAP.md)
  §6, the `POST /scan` API milestone).
