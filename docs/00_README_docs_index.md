# Provx — Docs Index & Canonical Decisions

*Read this first. It states what's locked and which doc owns what, so nothing conflicts. Drop the whole set into the repo's `docs/` folder.*

---

## Canonical decisions (the current truth)

- **Name:** **Provx** (repo/CLI `provx`). Older drafts say *PenForge* (a reference tool studied) or *Provex* — both **superseded**.
- **Identity:** governed, deterministic, auditable security validation — **AI is optional, never required**. Not an autonomous AI hacker.
- **License / model:** Apache-2.0 core, **open core** (paid edges later in a private repo). Contributions via **DCO**.
- **Repo:** free GitHub **org**, **single monorepo**, isolation via workspaces + path-filtered CI.
- **Stack:** Python 3.12 + FastAPI · Next.js · PostgreSQL · Docker Compose · all OSS. AI behind a provider abstraction (LiteLLM), off by default, local option.
- **Core brain:** deterministic **workflow/playbook engine** + findings intelligence (dedup, EPSS, risk-acceptance, retest). AI is an optional advisor on top.
- **Interfaces:** **UI + CLI + API**, one FastAPI core, three front-ends. The CLI is a first-class, **free** interface (a thin client over `packages/client`) with full governance parity — no gate bypass. Both UI and CLI are free; monetize scale, never the core.
- **Free-only dependencies (PX-FREE):** the core depends only on free/OSS Apache-compatible packages and wrapped tools. Paid tools/APIs are optional, bring-your-own-key integrations only — never required by the free core.

## The doc set (and what each owns)

| Doc | Owns | Status |
|---|---|---|
| `00_README_docs_index.md` (this) | Canonical decisions + precedence | current |
| `POSITIONING_and_STRATEGY.md` | Who Provx is for; how it differs from Strix/PentAGI; free-now/paid-later | current |
| `DETERMINISTIC_CORE_and_NonAI_Strengths.md` | The deterministic engine as the brain; borrowed non-AI ideas; AI-optional | current |
| `COMPETITIVE_HARVEST_and_CLI.md` | What to borrow from existing tools; the free-usage levers; the first-class **CLI** decision (one API, three front-ends) | current |
| `COMPETITOR_LANDSCAPE_CATALOG.md` | Full competitor/tool landscape reference (wrap / borrow / differentiate / avoid); feeds the rolling roadmap | current |
| `REPOSITORY_STRATEGY.md` | Org + monorepo + isolation | current |
| `Provx_Build_Blueprint.md` | Full feature/architecture catalog (the menu) | current (rebranded) |
| `ROADMAP.md` | Phases, cadence, contributor standard, DoD | current — see note ▼ |
| `PROJECT_SETUP_PLAYBOOK.md` | How to set up repo/governance | current |
| `VALIDATION_and_REFERENCE_SYSTEMS.md` | QA, human-in-the-loop, oracle benchmarking | current |
| `START_HERE_Master_Checklist.md` | The ordered control checklist | current |
| `BOOTSTRAP_with_ClaudeCode.md` | Claude Code + gh setup runbook | current |
| `PROVX_RULES.md` | **Canonical source of the PX safety/engineering rules.** Cite by ID; mirrored into `.claude/rules.md` | current |
| `PLAYBOOK_SCHEMA.md` | The deterministic playbook YAML schema | current |
| `KNOWN_ISSUES.md` | Defects and residual risks that are known, reproduced, and deliberately deferred — the counterpart to [`../audits/`](../audits/) | current |

## Precedence when docs disagree

1. This index → 2. `POSITIONING` / `DETERMINISTIC_CORE` (identity & AI-optional) → 3. everything else.

**ROADMAP note:** where the roadmap lists an **AI Autopilot**, treat it as an **optional module**. The headline is the **deterministic workflow engine + findings intelligence**; AI enriches but is never required. (The roadmap's principles already say "AI optional, never required" — this just settles ordering.)

**Blueprint note:** the blueprint is a **superset menu** to build *from*, prioritized by the roadmap — not a spec to build all at once. Any "AI engine/analyst/autopilot" there = optional module.
