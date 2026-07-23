# Provx — STATUS (living plan-of-record tracker)

*The single source of truth for "where are we vs. the plan." Update this file as part of EVERY PR's Definition of Done. If it's not here, it's not tracked. Do not trust memory (human or AI) over this file.*

**Last updated:** main @ `b80b5a9` (PR #14, 2026-07-23) · **Current phase:** Phase 2 — Web module (⏳ NOT complete — multi-adapter `/scan` gap, see breakdown) · **Milestone:** v0.1.0 TAGGED (annotated tag at `9522dfa` / PR #12). Note: the tag predates this reconciliation — the multi-adapter gap below was found after tagging.

---

## Roadmap phase status

| Phase | Scope | State |
|---|---|---|
| 0 — Foundations | Compose, Postgres, auth-less skeleton, scope engine, governance | ✅ done |
| 1 — Engagements & scope | Engagement CRUD, scope allow/deny, targets, walking skeleton | ✅ done |
| **2 — Web module (MVP)** | **Passive adapters → findings pipeline → report** | **⏳ NOT done** — all 5 adapters + pipeline + report landed, but `/scan` exposes only `security_headers`; see MULTI-ADAPTER SCAN row |
| 3 — Reporting | Branding, HTML→PDF/Word, dashboard | ⏳ partial (client-ready HTML ✅; PDF/Word + dashboard still to do) |
| 4 — API module | OWASP API Top 10 | ⛔ not started |
| 5 — Infra & AD | nmap/BloodHound, approval-gated exploitation | ⛔ not started |
| 6 — Exploitation + AI | Approval queue, optional AI advisor | ⛔ not started |
| 7 — Expansion | CLI, mobile-static, cloud, integrations, multi-tenant | ⛔ not started |

## Phase 2 breakdown (one gap left: multi-adapter `/scan` exposure)

| Item | State | Notes |
|---|---|---|
| Adapter: security_headers | ✅ | walking skeleton |
| Adapter: tls_transport | ✅ | PR #9 |
| Adapter: cookie_flags | ✅ | PR #9 |
| Adapter: cors | ✅ | PR #9, passive-only (active reflection deferred) |
| Adapter: wellknown | ✅ | PR #9 |
| Egress hardening (redirect/scope/evidence) | ✅ | earlier + #9 |
| Evidence redaction + encryption at rest | ✅ | #9 (redaction) + #10 (encryption) |
| **Findings dedup + validate/in-report lifecycle** | ✅ | PR #11 (`feat/findings-pipeline`): deterministic cross-adapter dedup (rule_id+target+location) keeping every evidence ref; validation lifecycle + transition/in-report endpoints; FP suppression + regression intent |
| HTML report hardening (severity order, ATT&CK, machine-vs-validated) | ✅ | PR #12 (`feat/report-hardening`): 7 documented sections (exec summary + posture, scope/RoE, methodology, findings summary, detailed findings, ATT&CK coverage, remediation roadmap); deterministic Critical→Info ordering; classification/branding from config; sealed evidence *reference* only (hash + capture time, never raw); machine-vs-validated split + PX-HUMAN banner kept. **Completes v0.1.** |
| **Authenticated scanning (explicit creds)** | ✅ | PR #13 (`feat/authenticated-scanning`): write-only encrypted `credential` table (bearer/cookie/custom header), decrypted only in-memory at scan time; credential injected at the **single** egress boundary and attached only to in-scope hops (SSRF guard, not just ordering); injected header covered by `SENSITIVE_HEADERS` redaction so a reflected copy is sealed as `<redacted:...>`; best-effort body-secret redaction. Adapters unchanged (auth rides on `ScopePolicy`→`fetch`). Proven by a **no-stub** integration test (401→200; credential authenticates; absent from sealed evidence/finding/report/Provx logs; off-scope redirect stopped and credential-free). Closes KI-004 request-side residuals. Form-login/SSO/MFA/session-record deferred (KI-006). **Test hardening (PR #14, `fix/auth-test-hardening`):** the no-stub integration test now proves body redaction end-to-end (via the body-sealing `wellknown` adapter), the `extra_sensitive` custom-header path (parametrized across bearer/cookie/custom-header), and isolates the redirect scope re-check with a non-dangerous off-scope hostname; the finding/report/Provx-log absence checks are relabelled honestly as **regression guards** (those surfaces carry no evidence by construction), and third-party wire-debug logging is documented as KI-007. |
| **MULTI-ADAPTER SCAN (`/scan` runs all registered adapters)** | ⏳ **NOT done** | Verified 2026-07-23 against the code: `POST /engagements/{id}/scan` hardcodes `DEFAULT_ADAPTER = "security_headers"` (`backend/app/services/scan_runner.py`), the endpoint never passes an adapter name, and `ScanRequest` (`extra="forbid"`) offers no selection field — so the product surface runs **1 of 5** shipped adapters. The SDK's "run all" primitive (`provx_sdk.registry.load_adapters()`) exists but has no backend caller. A web module that exposes 1 of 5 adapters isn't done — this row is why Phase 2 is ⏳. |

## Open issues / known issues (tracked, deferred deliberately)

| ID | What | Blocks | Land with |
|---|---|---|---|
| KI-002 | display_id race (fails safe via unique constraint) | nothing | when convenient |
| KI-003 | dangerous-range check = IP literals only; DNS-rebinding needs pinned-resolution transport | user-supplied scope | still open — auth landed **without** API RBAC / user-supplied scope, so its urgency trigger isn't reached yet |
| SDK-004 | Evidence inline-seal design (envelope vs inline field) | nothing | adapter #6 / auth |
| KI-004 residuals | request-side `Authorization`/`Cookie` + custom-header ✅ covered by boundary redaction; body-content ✅ best-effort (`redact_body`); URL-userinfo + KMS key still open | real credentials | ⏳ partly closed by `feat/authenticated-scanning` |
| KI-006 | form-login/SSO/MFA/CSRF/session-record deferred; explicit creds only in v0.2 | nothing | when a real form-login need appears |
| KI-007 | third-party httpx/httpcore wire-debug logging echoes a reflected credential before Provx redaction; Provx's own loggers stay clean | logs, only if wire-debug is enabled | operational note — don't enable wire-debug in production |
| KI-008 | body redaction (`fetch.redact_body`) is exercised in production only by body-sealing adapters — today only `wellknown` seals bodies and the live `/scan` path never runs it, so redaction is effectively cold in production | nothing now; becomes hot-path when `/scan` goes multi-adapter | multi-adapter scan work — re-verify redaction end-to-end then |
| — | Vitest frontend test runner (report-proxy guard has no regression test) | nothing | v0.5 |
| — | Second adapter proves pattern | — | ✅ done |
| — | accuracy-gate last-wins (KI-001) | — | ✅ resolved |

## Definition of Done — every PR must

- [ ] Feature + fixtures + lab accuracy pair (if it emits findings)
- [ ] All gates green in CI (ruff, mypy --strict, pytest, tsc, accuracy, dco)
- [ ] Rules respected (PX-*, safety tags, PX-EGRESS, PX-SECRETS, PX-EVIDENCE)
- [ ] **This STATUS.md updated** — move the item, note the PR, adjust phase state
- [ ] STATUS.md header + PR refs reconciled (no "TBD" left behind)
- [ ] KNOWN_ISSUES.md updated if anything deferred
- [ ] Branch → PR → green CI → squash-merge (never direct to main)

## Testing ladder (what exists, what's next)

- **Unit / fixture:** ✅ every adapter (recorded input → expected findings)
- **Accuracy / lab:** ✅ every adapter (TP/FP/FN vs lab positive+clean, per-adapter)
- **Integration (no-stub):** ✅ redirect/scope/evidence path · ✅ findings pipeline (`test_findings_pipeline.py`: 2 adapters → overlap → one finding w/ 2 evidence refs → validate / mark-FP / toggle in-report → report + list reflect each) · ✅ **authenticated scanning** (`test_integration_authenticated.py`: real loopback server requiring a bearer token — 401 unauth → 200 authed; credential authenticates the request; credential value absent from sealed evidence / finding / report / Provx logs; off-scope redirect stopped and credential-free — no egress or persistence stub)
- **Frontend:** ⛔ no runner yet (Vitest — v0.5)
- **Oracle/benchmark (OWASP Benchmark + ZAP/Nuclei diff):** ⛔ v0.5

*Rule: finish the current layer before adding a new one. Never build a capability whose output flows into an unfinished pipeline. The findings pipeline is ✅ — the unfinished layer is now multi-adapter `/scan` exposure. It goes next.*
