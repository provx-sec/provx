# Provx Playbook Schema

A **playbook** is a deterministic YAML file that encodes pentest methodology as auditable
rules (see [`DETERMINISTIC_CORE_and_NonAI_Strengths.md`](DETERMINISTIC_CORE_and_NonAI_Strengths.md)
§3). The workflow engine evaluates these rules against discovered facts to decide which
checks to run next — no AI involved.

This document is the human-readable schema. It is **enforced** by the Pydantic models in
`provx_adapters.playbook` and loaded/validated by `provx_adapters.loader`. If this doc and
the models ever disagree, the models are authoritative.

> **Scaffolding status:** playbooks currently *load and validate*. The engine that
> *evaluates* the `when` / `if` expression strings and executes steps is not implemented
> yet. Expressions are stored verbatim as opaque strings; validation only checks structure
> and that expressions are non-empty.

## Top-level fields

| Field | Type | Required | Description |
|---|---|---|---|
| `workflow` | string | yes | Unique playbook name (e.g. `web-baseline`). |
| `on_discovery` | list of DiscoveryRule | yes (≥1) | Rules evaluated against discovered facts. |
| `routing` | list of RoutingRule | no | Post-finding routing to deterministic validators / sub-workflows. |

## DiscoveryRule

| Field | Type | Required | Description |
|---|---|---|---|
| `when` | string | yes | Condition over discovered facts (e.g. `"service.http == true"`). Opaque expression string — not evaluated yet. |
| `run` | list of string | yes (≥1) | Use-case IDs to run when `when` holds. These are **passive/safe** by default. |
| `active_only` | list of string | no | Intrusive use-case IDs that run **only in Active mode**. Never run in passive/test. |

## RoutingRule

| Field | Type | Required | Description |
|---|---|---|---|
| `if` | string | yes | Condition over a produced finding (e.g. `"finding.type == 'cors_misconfig'"`). Opaque expression string. |
| `then_validate` | list of string | yes (≥1) | Deterministic validator(s) to corroborate the finding before human review. |

> Note: `if` is a reserved word in Python, so the model exposes it as the field alias
> `if` while using the attribute name `if_` internally.

## Safety rules (enforced by the engine, later)

- Steps listed under `active_only` **must not** run unless the engagement is in Active
  mode. This mirrors the `△` intrusive gating in the Safety Contract
  ([`ROADMAP.md`](ROADMAP.md) §8).
- Everything under `run` must be safe (non-destructive) in passive/test mode.
- Scope is enforced at the adapter boundary before any step executes.

## Example

See [`../workflows/web-baseline.yaml`](../workflows/web-baseline.yaml):

```yaml
workflow: web-baseline
on_discovery:
  - when: "service.http == true"
    run: [fingerprint, tech_detect, security_headers, tls]
  - when: "form.login_detected == true"
    run: [csrf, cookie_flags]
    active_only: [auth_bypass, default_creds]
  - when: "path == '/api/docs' or swagger_detected"
    run: [api_discovery]
routing:
  - if: "finding.type == 'cors_misconfig'"
    then_validate: [active_options_probe]
```
