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
> **Status: Phase 1 — governance scaffold (pre-alpha).** This repository currently
> contains the project's structure, governance, and CI skeleton only. There is **no
> feature code yet** — that is by design (see [`docs/START_HERE_Master_Checklist.md`](docs/START_HERE_Master_Checklist.md)).
> The first "walking skeleton" slice lands next.

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

Once the walking-skeleton code lands, the API will be at `http://localhost:8000` and
the web UI at `http://localhost:3000`. Today the compose file builds the service
skeletons so you can verify the topology end to end.

Common tasks are wrapped in the [`Makefile`](Makefile): `make up`, `make down`,
`make logs`, `make build`.

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
| [`packages/adapters/`](packages/adapters/) | Plugin SDK: tool adapters + playbook loader |
| [`packages/client/`](packages/client/) | Generated/typed API client |
| [`lab/`](lab/) | Intentionally-vulnerable + clean targets for the accuracy harness |
| [`wordlists/`](wordlists/) | Discovery / fuzzing wordlists |
| [`docs/`](docs/) | Planning docs, architecture, and the contributor standard |
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
