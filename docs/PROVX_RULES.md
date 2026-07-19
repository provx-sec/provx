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

### PX-EGRESS — all outbound HTTP goes through the scoped fetch boundary
Every outbound HTTP request is made by `provx_sdk.fetch.fetch_within_scope`. Constructing an
`httpx.AsyncClient`, a `requests` session, or any other HTTP client outside
`provx_sdk/fetch.py` is a violation, as is passing `follow_redirects=True` — a client that
follows redirects itself carries the request off-scope *after* the gate passed.

This is the mechanically checkable form of [[PX-SCOPE]]: scope is only enforced at the
boundary if there is exactly one boundary. One function to audit means reviewing it reviews
the platform's entire egress.

*Detect:* `httpx.AsyncClient(`, `httpx.Client(`, `requests.`, or `follow_redirects=True`
anywhere outside `packages/adapters/src/provx_sdk/fetch.py`.

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

## Quality & evidence

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

### PX-EVIDENCE — evidence is hashed, timestamped, and append-only
Findings are only defensible if their evidence can be shown unaltered since capture, and a
mutable audit log can be rewritten to hide activity. Hash every evidence artifact (tool output,
screenshots, proofs) with SHA-256 and record a capture timestamp **at capture time**. Store
evidence and the audit log **append-only** — no update or delete paths; a correction is a new
entry referencing the prior one. Every state-changing action writes an audit entry. Reinforces
[PX-SECRETS](#px-secrets--protect-our-own-secrets).

### PX-LICENSE — respect upstream tool licenses
Absorbing GPL/AGPL source into Provx would relicense the project; the open-core model depends on
keeping copyleft tools at arm's length. Never copy, vendor, or bundle the source of
GPL/AGPL/custom-licensed tools (sqlmap, nmap, OpenVAS) into the codebase, and never wrap a
copyleft tool as a linked library. Invoke external tools **only as separate subprocesses** (mere
aggregation). Keep the AGPL/copyleft boundary out of any closed edition, and keep the SPDX
license-compatibility check in CI. See [PX-DSL](#px-dsl--no-evalexec-in-the-playbook-engine) for
the engine boundary.

### PX-FREE — free & open-source dependencies and wrapped tools only
Provx's promise is a genuinely free, self-hostable platform: a paid/proprietary dependency,
or a wrapped tool that needs a paid license, breaks that promise. Do not add a dependency
under a non-free/proprietary license, and do not wrap a tool that requires a paid license
(Nessus, Burp Suite Pro, paid Shodan/Censys API, Cobalt Strike) as a **required** part of
the free core, or ship a core feature that only works via a paid third-party SaaS/API.
Use free, OSI-approved, Apache-compatible packages (verified by the SPDX license-compatibility
check in CI). Paid tools/APIs may exist **only** as optional integrations the user configures
with their own key/license — never required by, or bundled into, the free core. AI providers
are optional, bring-your-own-key, with a free local (Ollama) option. Reinforces
[PX-LICENSE](#px-license--respect-upstream-tool-licenses) (the tool-license boundary, also in
[`DETERMINISTIC_CORE_and_NonAI_Strengths.md`](DETERMINISTIC_CORE_and_NonAI_Strengths.md) §6) and
[PX-AI-OPTIONAL](#px-ai-optional--ai-is-an-optional-advisor-never-required).

### PX-ERRORS — user-safe errors, gated on APP_ENV
Stack traces and internal details in a client-facing response leak infrastructure information
and look unprofessional in a security product. Return a generic, user-safe message plus a stable
error code to clients, and log the real exception server-side. Expose stack traces or internal
detail **only** when `APP_ENV` is `dev`/`local`; never leave `debug=True` reachable outside
dev/local. Reinforces the baseline error-handling rules (S-13, B-FA-06) with an explicit
`APP_ENV` gate.
