# workflows/ — the deterministic brain

This directory holds Provx's **deterministic playbooks**: declarative YAML that encodes
pentest methodology as auditable rules. The workflow engine evaluates these rules against
facts discovered during a scan to decide *where to go next* — the same judgement a manual
pentester applies ("an open login form means test auth + session"), but **reproducible
and auditable**, not delegated to a non-deterministic AI agent.

> **The workflow engine is Provx's brain. AI is an optional advisor, off by default.**
> See [`../docs/DETERMINISTIC_CORE_and_NonAI_Strengths.md`](../docs/DETERMINISTIC_CORE_and_NonAI_Strengths.md).

## Why deterministic

- **Auditable** — a human can read the exact logic that ran.
- **Reproducible** — same input, same output, every time (compliance-grade).
- **Safety-aware** — `active_only` steps never run in passive/test mode.
- **Composable** — playbooks hand off to sub-workflows (web → api → infra).
- **Contributor-friendly** — add methodology by writing a YAML playbook, no core code.

## Files

- [`web-baseline.yaml`](web-baseline.yaml) — the worked example (a baseline web
  methodology). Matches the illustration in `DETERMINISTIC_CORE` §3.

## Schema

The playbook schema is documented in
[`../docs/PLAYBOOK_SCHEMA.md`](../docs/PLAYBOOK_SCHEMA.md). It is **enforced** by the
Pydantic models in `provx_adapters.playbook`, loaded and validated by
`provx_adapters.loader` (in [`../packages/adapters/`](../packages/adapters/)).

> **Status: scaffolding.** Playbooks load and validate today. The engine that *evaluates*
> the `when` / `if` expressions and runs steps is added in a later phase — no execution
> logic exists yet.
