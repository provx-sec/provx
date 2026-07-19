<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Solomon Nii Amu Darku
-->

# Provx

**Open-source, governed automated security validation — web, API & infra in one console. Safe by default.**

Provx is a self-hosted, pluggable platform for running continuous, *authorized*
security validation between your paid human pentests — without breaking anything and
without being locked to one AI vendor. The machine proposes findings; a human always
confirms before anything is reported as real.

> **Provx runs fully without AI.** The engine is deterministic and auditable — a
> workflow/playbook that encodes pentest methodology as reproducible rules. AI is an
> **optional advisor** you switch on (bring your own key, cloud or local); it enriches
> the deterministic core but never replaces it. Provx is not another autonomous AI
> hacker — it's the governed, reproducible alternative.
> See [`docs/DETERMINISTIC_CORE_and_NonAI_Strengths.md`](docs/DETERMINISTIC_CORE_and_NonAI_Strengths.md)
> and [`docs/POSITIONING_and_STRATEGY.md`](docs/POSITIONING_and_STRATEGY.md).

> [!IMPORTANT]
> **Status: Phase 2 — walking skeleton (pre-alpha).** The thinnest end-to-end slice works:
> create an engagement with a scoped target, run one passive `security_headers` check
> through the SDK's adapter plugin, and get deduplicated findings in PostgreSQL, in the UI,
> and in an HTML report. A lab with a vulnerable and a clean target gates accuracy on
> TP/FP/FN in CI.
>
> Still absent **by design**: authentication, the job queue, the playbook execution engine,
> Active mode, exploitation, and any AI feature. See
> [`docs/ROADMAP.md`](docs/ROADMAP.md) §4 for the MVP scope and
> [`docs/KNOWN_ISSUES.md`](docs/KNOWN_ISSUES.md) for defects that are known and deferred.

> [!NOTE]
> **A note on the name.** Some planning documents in [`docs/`](docs/) refer to the
> project as *Provex* or *PenForge*. The canonical name is **Provx**; those older
> names are superseded.

---

## Why Provx

- **Deterministic brain.** A workflow/playbook engine decides what to run next from
  discovered facts — reproducible and auditable (compliance-grade), not delegated to a
  non-deterministic agent. Findings intelligence (dedup, EPSS prioritization,
  risk-acceptance, retest) is all deterministic too.
- **Safe by default.** Passive mode does recon and vulnerability assessment only.
  Intrusive checks require *Active* mode; exploitation requires per-finding human
  approval and runs sandboxed, non-destructive by default.
- **Human-in-the-loop.** Nothing is presented as "true" on its own. Every finding
  carries a confidence level and moves through a validation lifecycle before it can
  enter a client report.
- **Pluggable everything.** Tools, use-cases, report templates, and AI providers are
  plugins. The core stays small; the ecosystem grows.
- **AI is optional, never required.** The platform is fully usable with zero AI. When
  enabled, you pick the provider (cloud, local, or free) and bring your own key.
- **Honest about limits.** Automated results must be human-verified; no scanner finds
  everything, and every report says so.

See [`RESPONSIBLE_USE.md`](RESPONSIBLE_USE.md) before running Provx against anything.

---

## Quickstart

> Requires [Docker](https://docs.docker.com/get-docker/) and Docker Compose.

```bash
git clone <your-fork-url> provx
cd provx
cp .env.example .env        # then edit values as needed
docker compose up --build
```

The API is at `http://localhost:8000` (interactive docs at `/docs`) and the web console at
`http://localhost:3000`. Database migrations are applied on start.

A first run, end to end:

```bash
# 1. create an engagement with one in-scope target
curl -X POST localhost:8000/engagements -H 'content-type: application/json' \
  -d '{"name":"Demo","scope_allow":["example.com"],"targets":["https://example.com"]}'

# 2. run the passive check, then read the findings
curl -X POST localhost:8000/engagements/<id>/scan
curl localhost:8000/engagements/<id>/findings

# 3. open the report, or view it in the console
open http://localhost:3000/engagements/<id>
```

Common tasks are wrapped in the [`Makefile`](Makefile): `make up`, `make down`,
`make logs`, `make test`, `make lint`, and `make accuracy` (the TP/FP/FN gate).

---

## Repository layout

This is a **single monorepo** (the open-core). Future commercial features live in a
separate private repository, so community contributions to the core never need
relicensing.

| Path | What lives here |
|---|---|
| [`workflows/`](workflows/) | Deterministic YAML playbooks — the engine's brain |
| [`backend/`](backend/) | FastAPI control plane, findings pipeline, deterministic services |
| [`frontend/`](frontend/) | Next.js + Tailwind web console |
| [`packages/adapters/`](packages/adapters/) | Plugin SDK: tool adapters, playbook loader, and the scoped HTTP egress boundary |
| [`packages/client/`](packages/client/) | Generated/typed API client |
| [`lab/`](lab/) | Intentionally-vulnerable + clean targets for the accuracy harness |
| [`wordlists/`](wordlists/) | Discovery / fuzzing wordlists |
| [`docs/`](docs/) | Planning docs, architecture, and the contributor standard |
| [`audits/`](audits/) | Per-repo code audit: file-by-file findings, severity, fixes |
| [`.github/`](.github/) | Issue/PR templates and path-filtered CI |

---

## Architecture & roadmap

- **Start here (canonical decisions):** [`docs/00_README_docs_index.md`](docs/00_README_docs_index.md).
- **The deterministic core & why AI is optional:** [`docs/DETERMINISTIC_CORE_and_NonAI_Strengths.md`](docs/DETERMINISTIC_CORE_and_NonAI_Strengths.md).
- **Positioning & strategy:** [`docs/POSITIONING_and_STRATEGY.md`](docs/POSITIONING_and_STRATEGY.md).
- **Playbook schema:** [`docs/PLAYBOOK_SCHEMA.md`](docs/PLAYBOOK_SCHEMA.md).
- **The standard we hold every contribution to:** [`docs/ROADMAP.md`](docs/ROADMAP.md)
  (North Star, Definition of Done, Safety Contract, architecture diagrams).
- **The full feature map:** [`docs/Provx_Build_Blueprint.md`](docs/Provx_Build_Blueprint.md).
- **How accuracy is measured (human-in-the-loop + oracles):**
  [`docs/VALIDATION_and_REFERENCE_SYSTEMS.md`](docs/VALIDATION_and_REFERENCE_SYSTEMS.md).
- **How the project is run:** [`docs/PROJECT_SETUP_PLAYBOOK.md`](docs/PROJECT_SETUP_PLAYBOOK.md).

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) — it covers the DCO sign-off, the adapter
cookbook (add a tool in one file), and the Definition of Done every PR must meet.
Questions go to Discussions ([`SUPPORT.md`](SUPPORT.md)); conduct is governed by the
[Contributor Covenant](CODE_OF_CONDUCT.md).

## Security

To report a vulnerability **in Provx itself**, follow [`SECURITY.md`](SECURITY.md) —
please do not open a public issue.

## License

[Apache-2.0](LICENSE) — Copyright 2026 Solomon Nii Amu Darku ("SNAD"). See [`NOTICE`](NOTICE).
