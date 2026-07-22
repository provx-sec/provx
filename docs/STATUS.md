# Provx — STATUS (living plan-of-record tracker)

*The single source of truth for "where are we vs. the plan." Update this file as part of EVERY PR's Definition of Done. If it's not here, it's not tracked. Do not trust memory (human or AI) over this file.*

**Last updated:** branch `feat/report-hardening` (client-ready HTML report) · **Current phase:** Phase 2 — Web module (✅ complete) · **Target milestone:** v0.1 (ready to tag)

---

## Roadmap phase status

| Phase | Scope | State |
|---|---|---|
| 0 — Foundations | Compose, Postgres, auth-less skeleton, scope engine, governance | ✅ done |
| 1 — Engagements & scope | Engagement CRUD, scope allow/deny, targets, walking skeleton | ✅ done |
| **2 — Web module (MVP)** | **Passive adapters → findings pipeline → report** | **✅ done** |
| 3 — Reporting | Branding, HTML→PDF/Word, dashboard | ⏳ partial (client-ready HTML ✅; PDF/Word + dashboard still to do) |
| 4 — API module | OWASP API Top 10 | ⛔ not started |
| 5 — Infra & AD | nmap/BloodHound, approval-gated exploitation | ⛔ not started |
| 6 — Exploitation + AI | Approval queue, optional AI advisor | ⛔ not started |
| 7 — Expansion | CLI, mobile-static, cloud, integrations, multi-tenant | ⛔ not started |

## Phase 2 breakdown (the current floor — finish before Phase 3+)

| Item | State | Notes |
|---|---|---|
| Adapter: security_headers | ✅ | walking skeleton |
| Adapter: tls_transport | ✅ | PR #9 |
| Adapter: cookie_flags | ✅ | PR #9 |
| Adapter: cors | ✅ | PR #9, passive-only (active reflection deferred) |
| Adapter: wellknown | ✅ | PR #9 |
| Egress hardening (redirect/scope/evidence) | ✅ | earlier + #9 |
| Evidence redaction + encryption at rest | ✅ | #9 (redaction) + #10 (encryption) |
| **Findings dedup + validate/in-report lifecycle** | ✅ | `feat/findings-pipeline`: deterministic cross-adapter dedup (rule_id+target+location) keeping every evidence ref; validation lifecycle + transition/in-report endpoints; FP suppression + regression intent |
| HTML report hardening (severity order, ATT&CK, machine-vs-validated) | ✅ | `feat/report-hardening` (PR TBD): 7 documented sections (exec summary + posture, scope/RoE, methodology, findings summary, detailed findings, ATT&CK coverage, remediation roadmap); deterministic Critical→Info ordering; classification/branding from config; sealed evidence *reference* only (hash + capture time, never raw); machine-vs-validated split + PX-HUMAN banner kept. **Completes v0.1.** |
| Authenticated scanning | ⛔ | NEW capability class — after pipeline is complete (post-v0.1) |

## Open issues / known issues (tracked, deferred deliberately)

| ID | What | Blocks | Land with |
|---|---|---|---|
| KI-002 | display_id race (fails safe via unique constraint) | nothing | when convenient |
| KI-003 | dangerous-range check = IP literals only; DNS-rebinding needs pinned-resolution transport | user-supplied scope | auth |
| SDK-004 | Evidence inline-seal design (envelope vs inline field) | nothing | adapter #6 / auth |
| KI-004 residuals | body-content redaction, URL-userinfo, KMS key vs SECRET_KEY-derived | real credentials | auth |
| — | Vitest frontend test runner (report-proxy guard has no regression test) | nothing | v0.5 |
| — | Second adapter proves pattern | — | ✅ done |
| — | accuracy-gate last-wins (KI-001) | — | ✅ resolved |

## Definition of Done — every PR must

- [ ] Feature + fixtures + lab accuracy pair (if it emits findings)
- [ ] All gates green in CI (ruff, mypy --strict, pytest, tsc, accuracy, dco)
- [ ] Rules respected (PX-*, safety tags, PX-EGRESS, PX-SECRETS, PX-EVIDENCE)
- [ ] **This STATUS.md updated** — move the item, note the PR, adjust phase state
- [ ] KNOWN_ISSUES.md updated if anything deferred
- [ ] Branch → PR → green CI → squash-merge (never direct to main)

## Testing ladder (what exists, what's next)

- **Unit / fixture:** ✅ every adapter (recorded input → expected findings)
- **Accuracy / lab:** ✅ every adapter (TP/FP/FN vs lab positive+clean, per-adapter)
- **Integration (no-stub):** ✅ redirect/scope/evidence path · ✅ findings pipeline (`test_findings_pipeline.py`: 2 adapters → overlap → one finding w/ 2 evidence refs → validate / mark-FP / toggle in-report → report + list reflect each)
- **Frontend:** ⛔ no runner yet (Vitest — v0.5)
- **Oracle/benchmark (OWASP Benchmark + ZAP/Nuclei diff):** ⛔ v0.5

*Rule: finish the current layer before adding a new one. Never build a capability whose output flows into an unfinished pipeline. Right now the findings pipeline is that unfinished layer — it goes next.*
