# Provx — Deterministic Core & Non-AI Strengths (AI-Optional by Design)

*Strix and PentAGI put AI at the center and can't run without it. Provx does the opposite: a **deterministic engine is the brain**, and AI is an **optional advisor** you can switch on. This doc captures the strong ideas borrowed from the non-AI, manual-pentester world so Provx is powerful with the AI turned completely off.*

---

## 1. The principle

A manual pentester doesn't need a language model to know that an open SMB port means "run SMB enumeration," or that a login form means "test auth + session." That knowledge is a **methodology** — and methodology can be encoded as **deterministic, auditable rules**, not delegated to a non-deterministic agent.

> **The workflow/decision engine is Provx's brain. AI is a bolt-on advisor, off by default.**

This is also *why* Provx is more trustworthy for compliance: deterministic runs are reproducible and auditable; agent runs are neither.

---

## 2. Strong ideas borrowed from the deterministic world

| Idea | Borrowed from | Provx feature | Lane it strengthens |
|---|---|---|---|
| **Declarative, auditable YAML workflows** with conditional routing ("if service X → run checks Y") | Osmedeus | The deterministic decision engine (§3) | Governed / reproducible |
| Sandboxed execution + secure credential handling in the engine | Osmedeus | Safe scan runners | Safe-by-default |
| **Reusable "scan engines"/profiles** + project/engagement spaces | reNgine | Engagement + saved scan profiles | Consultant workflow |
| Scheduled + periodic scans; dedup endpoints by title+content-length | reNgine | Continuous scans + dedup heuristic | Continuous validation |
| Parallel service enumeration → **structured surface map by service type** | AutoRecon | Recon phase output model | Determinism / speed |
| **Intelligent dedup**: 3 tools → 1 finding w/ 3 references | DefectDojo | Findings pipeline | Signal quality |
| **EPSS prioritization** (rank by real exploit probability, not just CVSS) | DefectDojo | Finding prioritization | Actionability |
| **Risk-acceptance workflow** (sign-off + expiration + audit trail) | DefectDojo | Governance layer | Audit / compliance |
| **Retest loop**: push to Jira/GitHub, auto-close on next scan confirming fix | DefectDojo | Verify/retest + integrations | Remediation |
| **Deterministic validators** confirm exploitability via non-destructive checks | XBOW | Corroboration before human review | False-positive control |

None of these needs AI. All of them make Provx stronger than a bare scanner.

---

## 3. The deterministic decision engine (how "where to go next" works without AI)

Encode methodology as auditable YAML the way Osmedeus does — a **playbook** of rules the engine evaluates against discovered facts:

```yaml
# example: web-baseline.yaml  (illustrative)
workflow: web-baseline
on_discovery:
  - when: "service.http == true"
    run: [fingerprint, tech_detect, security_headers, tls]
  - when: "form.login_detected == true"
    run: [csrf, cookie_flags]
    active_only: [auth_bypass, default_creds]     # gated to Active mode
  - when: "path == '/api/docs' or swagger_detected"
    run: [api_discovery]                          # hand off to API workflow
routing:
  - if: "finding.type == 'cors_misconfig'"
    then_validate: [active_options_probe]         # deterministic validator
```

Properties that matter:
- **Auditable** — a human can read the exact logic that ran (unlike an agent's opaque reasoning).
- **Reproducible** — same input, same output, every time (compliance-grade).
- **Safety-aware** — `active_only` steps never run in passive/test mode.
- **Composable** — workflows call sub-workflows (web → api → infra), mirroring how a pentester pivots.
- **Contributor-friendly** — a community member adds methodology by writing a YAML playbook, no core code.

This engine *is* the codified "manual pentester knows where to go." Ship a curated set of default playbooks mapped to OWASP WSTG / API Top 10 / PTES.

---

## 4. Findings intelligence — all without AI

- **Intelligent dedup** (DefectDojo model): the same issue from three tools becomes one finding with three evidence references — no alert fatigue.
- **Deterministic prioritization**: severity + CVSS **+ EPSS** (probability of real-world exploitation) + asset criticality → an ordered, defensible fix list. This replaces "ask the AI what's important" with a transparent formula.
- **Risk-acceptance workflow**: mark a finding accepted with a reason, an owner, and an **expiration date** → permanent audit trail. Pure governance value.
- **Retest / verify loop**: re-run a single finding after a fix; if it's gone, auto-close the linked Jira/GitHub issue. Deterministic, satisfying, and it's what buyers pay Picus/DefectDojo for.

---

## 5. AI as an optional advisor (what turning it ON adds)

With AI enabled (BYO key, cloud or local Ollama), it *augments* — never replaces — the deterministic core:
- **Suggests** a next workflow or an edge case the playbooks didn't cover.
- **Triages/explains** a finding in plain language and drafts remediation text.
- **Reasons** about remediation dependencies (patch the medium that closes the critical).

Hard rule: with AI **off**, every one of these has a deterministic fallback (default playbooks, template remediation text, EPSS ranking). Provx must be fully useful with zero AI. AI is the turbo, not the engine.

---

## 6. Interop & respecting the ecosystem

- **Speak the standards**: import/export **SARIF**, and support **DefectDojo** import so Provx slots into existing pipelines instead of walling itself off.
- **Credit upstream** (as Strix does for LiteLLM/Caido/Nuclei): a visible ACKNOWLEDGEMENTS section for every wrapped tool.
- **Tool licenses — the one real constraint on monetizing later** (not legal advice; get a lawyer before a paid launch):
  - Permissive wrapped tools (nuclei, httpx, ZAP, Osmedeus-style engines) → fine to build on and around.
  - **GPL tools** (sqlmap, OpenVAS) and **nmap's custom license** → safe to **invoke as separate subprocesses** (mere aggregation); do **not** copy their source into Provx or bundle/redistribute them into a proprietary artifact. A hosted SaaS that merely *runs* them server-side generally does not trigger GPL distribution (AGPL is the exception — avoid wrapping AGPL tools into the closed edition).
  - Keep the **SPDX license-compatibility check** in CI (already stubbed) so nothing incompatible sneaks into the core.

**On the ethics you raised:** monetizing hosting + your own proprietary features is legitimate open-core *because* (1) the core stays genuinely free and open, (2) you credit and don't closed-source what the community built, and (3) you charge for **your** added value (hosting, SSO, multi-tenant, compliance packs, support) — not for others' code. That's exactly what you described, and it's the honest, accepted model (DefectDojo Pro, Sn1per Pro, Strix Cloud all do it).

---

## 7. What to add to the plan

- New top-level concept: **`workflows/`** — the deterministic YAML playbooks (the brain). Add a "playbook" plugin type alongside tool-adapters.
- Findings pipeline gains: **EPSS** enrichment, **risk-acceptance** state + audit trail, **retest/verify** action.
- Reporting/ops gains: **SARIF** + **DefectDojo** export, optional **Jira/GitHub** issue push with auto-close.
- ROADMAP reframe: the **deterministic workflow engine + findings intelligence** are the headline; **AI Advisor** is an explicitly optional module.
- README: state plainly — *"Provx runs fully without AI. The engine is deterministic and auditable; AI is an optional advisor you bring your own key for."*

*Bottom line: Strix is the AI-first extreme; Provx is the deterministic, auditable, governed alternative that happens to support AI. The non-AI world (Osmedeus, reNgine, DefectDojo, AutoRecon) already proved every piece of that core — you're assembling proven ideas into a governed whole, not inventing risk.*
