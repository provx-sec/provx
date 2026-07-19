# Provx Rules (PX) — non-negotiable engineering & safety rules

These **PX rules** are the hard constraints every contribution is held to. They distill the
Safety Contract ([`ROADMAP.md`](ROADMAP.md) §8), the deterministic-core principles
([`DETERMINISTIC_CORE_and_NonAI_Strengths.md`](DETERMINISTIC_CORE_and_NonAI_Strengths.md)),
and [`../RESPONSIBLE_USE.md`](../RESPONSIBLE_USE.md) into short, citable rules. A PR that
violates a PX rule is not merged, however good it otherwise is.

Cite them by ID in reviews and PRs (e.g. "blocked by PX-DSL").

---

## Safety

### PX-SCOPE — scope is enforced at the boundary
Every target and request is checked against the engagement's allow/deny scope **at the
adapter boundary, before any tool runs**. Scope is never trusted from an upstream caller.
An out-of-scope action is skipped and logged, never executed.

### PX-PASSIVE — passive/test mode is read-only
In passive mode, no check may create, modify, or delete state on a target. If a check
cannot guarantee that, it is `intrusive` and does not run in passive mode.

### PX-ACTIVE — intrusive work is gated to Active mode
Intrusive checks and any `active_only` playbook steps run **only** when the engagement is
explicitly in Active mode with recorded authorization. They are gated and logged.

### PX-EXPLOIT — exploitation is human-approved and non-destructive
Exploitation requires **per-finding human approval**, runs sandboxed, produces
non-destructive proof only, and writes a full replay trail. Scanning never auto-exploits.

### PX-SECRETS — protect our own secrets
Never log secrets, credentials, tokens, or session material. Store them encrypted at rest.
Every state-changing action is written to the append-only audit log.

### PX-AUTHZ — authorized use only
Provx runs only against systems the operator owns or is explicitly authorized to test. No
feature is accepted whose only sensible use is unauthorized attack (e.g. target-less mass
exploitation). See [`../RESPONSIBLE_USE.md`](../RESPONSIBLE_USE.md).

---

## Deterministic core

### PX-DSL — no `eval`/`exec` in the playbook engine
Playbook `when` / `if` expressions are **untrusted input**. The evaluator that runs them
(not built yet) **MUST** be a restricted, allowlisted evaluator. `eval()`, `exec()`,
`compile()`+exec, `pickle`, and any equivalent dynamic code execution are **FORBIDDEN** —
evaluating an untrusted expression through them is a remote-code-execution vulnerability.

The locked design for the future evaluator:

- A **fixed operator set**: comparisons (`==`, `!=`, `<`, `<=`, `>`, `>=`, `in`) and
  boolean `and` / `or` / `not`.
- Operands drawn only from a **known facts namespace** (e.g. `service.http`,
  `form.login_detected`, `finding.type`) — resolved from a typed facts object.
- **No function calls, no attribute traversal beyond whitelisted facts, no imports, no
  arbitrary Python.**

Until the evaluator exists, expressions are stored verbatim and validated for structure
only (see [`PLAYBOOK_SCHEMA.md`](PLAYBOOK_SCHEMA.md)).

### PX-DETERMINISM — the engine is deterministic and auditable
Core decisions (what to run next, dedup, prioritization) come from transparent rules and
formulas, reproducible for the same input. Prioritization uses a defensible formula
(severity + CVSS + EPSS + asset criticality), not an opaque judgement call.

### PX-AI-OPTIONAL — AI is an optional advisor, never required
Provx must be fully usable with AI **off**. Every AI-assisted feature has a deterministic
fallback (default playbooks, template remediation text, EPSS ranking). AI is bring-your-own
-key, provider-swappable, and every AI-assisted output is labelled as such. No code path may
hard-depend on an LLM.

---

## Quality

### PX-FIXTURE — adapters ship fixtures
Every tool adapter ships a recorded raw-output fixture plus the expected normalized
findings, so a tool changing its output format fails CI, not users.

### PX-ATTACK — findings carry ATT&CK mapping
Findings are de-duplicated and carry a severity + CVSS and **≥1 MITRE ATT&CK technique ID**.
"MITRE ATT&CK" is a display label; the stored value is the technique ID string (e.g.
`T1190`).

### PX-HUMAN — the machine proposes, a human confirms
No finding is presented as "true" on its own. Findings carry a confidence level and move
through the validation lifecycle before entering a client report
([`VALIDATION_and_REFERENCE_SYSTEMS.md`](VALIDATION_and_REFERENCE_SYSTEMS.md)).
