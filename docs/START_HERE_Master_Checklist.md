# Provex — Master Start-Here Checklist

*Your single control document. Work top to bottom, tick each box, and don't start a phase until the previous phase's **GATE** is met. When you've done as much as you can, fill in the **Status Report** at the bottom and send this file back — I'll check it, catch any loopholes, and tell you exactly what's next.*

**Success definition (what we're aiming at):** a free, governed scanner that someone can run for real testing and get results good enough to compare with the paid tools — safe by default, human-verified, and honest about its limits.

---

## How the five docs fit together

| Doc | Role | You act on it… |
|---|---|---|
| Build Blueprint | *What* to build (full feature map) | Reference throughout |
| ROADMAP.md | The standard, phases, cadence, diagrams | Reference + update as you go |
| **PROJECT_SETUP_PLAYBOOK.md** | *How* to set up the repo | **Executed by Phase 1 below** |
| VALIDATION_and_REFERENCE_SYSTEMS.md | QA, human-in-the-loop, oracles | Baseline in Phase 2; rest built with code |
| **THIS checklist** | The ordered control doc | Work top to bottom |

**Order:** Phase 0 → Phase 1 (admin) → Phase 2 (validation baseline) → Phase 3 (first code). Do not jump to Phase 3.

---

## Decisions locked (confirm or change these first)

| Decision | Value | Status |
|---|---|---|
| Name | **Provex** (proposed) | [ ] confirmed / [ ] changed to: ____ |
| Domain + trademark | check `.io`/`.dev` + basic TM search | [ ] done |
| License / model | **Apache-2.0**, open core (paid features later in a private repo) | [ ] confirmed |
| Contributions | **DCO** sign-off (not heavy CLA) | [ ] confirmed |
| Backend | **Python 3.12 + FastAPI** + PostgreSQL + Redis/arq | [ ] confirmed |
| Frontend | **Next.js** (React) + Tailwind | [ ] confirmed |
| Packaging | **Docker Compose** | [ ] confirmed |
| AI | provider-abstracted (LiteLLM), **off by default**, local option | [ ] confirmed |
| Dependencies | **open-source only**; a package is fine if it speeds dev + license is compatible | [ ] confirmed |

*Note on Next.js: it's heavier to self-host than a plain static SPA, but you already know it well, so the dev-speed win is worth it. Keep it as a static/SSR frontend served alongside the FastAPI API.*

---

## PHASE 0 — Accounts & decisions (½ day)

- [ ] Confirm the name (or pick an alternate) and do the domain + trademark check.
- [ ] Confirm every row in "Decisions locked" above.
- [ ] Create/choose the GitHub account that will own the repo (org later, not now).
- [ ] Set up GitHub Sponsors / Open Collective account (so `FUNDING.yml` works from day one).

**GATE 0:** every decision above is ticked. → proceed to Phase 1.

---

## PHASE 1 — Repository & governance (2–3 days) — *executes the Playbook*

### 1a. Repository
- [ ] Create public repo `provex` with `README.md`, `.gitignore`, `LICENSE = Apache-2.0`.
- [ ] Add topics: `security`, `penetration-testing`, `vulnerability-scanner`, `security-validation`, `devsecops`, `self-hosted`, `open-source`.
- [ ] Enable Issues, Discussions, Projects; disable Wiki.

### 1b. Community health files (from Playbook A3)
- [ ] `README.md` (what it is + `docker compose up` quickstart + status)
- [ ] `CONTRIBUTING.md` (DCO, adapter cookbook, DoR/DoD)
- [ ] `CODE_OF_CONDUCT.md` (Contributor Covenant)
- [ ] `SECURITY.md` (how to report a vuln in Provex itself)
- [ ] `RESPONSIBLE_USE.md` (authorized-use-only)
- [ ] `GOVERNANCE.md` (who decides, how maintainers/roadmap change)
- [ ] `SUPPORT.md`, `CHANGELOG.md`
- [ ] `CODEOWNERS`
- [ ] `.github/FUNDING.yml`

### 1c. Project board (GitHub Projects v2)
- [ ] Create project "Provex Roadmap".
- [ ] Add fields: Status, Area, Priority, Effort, Milestone, Type.
- [ ] Create 3 views: Board (by Status), Roadmap/timeline (by Milestone), Good-first-issues.

### 1d. Milestones (map 1:1 to roadmap)
- [ ] `v0.1 MVP`, `v0.5 Depth`, `v1.0 Full`, `v2.0 Reach` — each with due date + one-line exit criterion.

### 1e. Labels, ownership, protection
- [ ] Add label taxonomy (`labels.yml`): type / area / priority / good-first-issue / needs-fixture / needs-accuracy-review / safety-review.
- [ ] `CODEOWNERS` (you own everything for now).
- [ ] Protect `main`: require PR + passing CI + 1 review + DCO; no direct pushes; linear history.

### 1f. Templates & CI skeleton
- [ ] `.github/PULL_REQUEST_TEMPLATE.md` (the DoD checklist).
- [ ] `.github/ISSUE_TEMPLATE/` (bug, feature, new-adapter, detection-issue).
- [ ] `.github/workflows/ci.yml` with gate stubs: dco, lint, types, unit-fixtures, **accuracy**, secrets-deps (can be no-ops that pass until filled in).

**GATE 1:** a fully governed **empty** repo — health files present, board + milestones + labels live, `main` protected, CI runs (even if stubs). No feature code yet, and that's correct. → proceed to Phase 2.

---

## PHASE 2 — Validation baseline (1–2 days) — *so we test for loopholes from day one*

- [ ] Create `lab/` with **positive** targets (deliberately vulnerable): e.g. OWASP Juice Shop, DVWA, VAmPI (API).
- [ ] Add **clean/baseline** targets (should produce zero findings) for false-positive testing.
- [ ] Add an `expected.yml` manifest per lab target (what should / should not be found).
- [ ] Wire the **accuracy harness** into CI: run checks vs lab, score True-Positive / False-Positive / False-Negative, fail PRs that add FPs or miss known vulns.
- [ ] Add the **OWASP Benchmark** as an accuracy oracle to track a real TP/FP score per release.
- [ ] Note the **oracle diff** plan (ZAP / Nuclei / OpenVAS on same targets) for later comparison.

**GATE 2:** the harness runs green on an empty ruleset and is ready to judge the first real check. → proceed to Phase 3.

---

## PHASE 3 — First code: the walking skeleton (week 1–2)

Thin end-to-end slice only (ROADMAP §3). Not the MVP yet.

- [ ] One engagement + one in-scope target (scope allow-check works).
- [ ] ONE adapter (httpx or nuclei) runs within scope.
- [ ] Output normalized into a Finding (severity + 1 ATT&CK tag).
- [ ] Finding stored in PostgreSQL.
- [ ] Finding visible in the Next.js UI.
- [ ] Export a basic HTML report.
- [ ] The adapter ships a **fixture test** and passes the **accuracy gate** on its lab case.

**GATE 3:** a stranger can `docker compose up`, run that one scan authenticated-or-not, see a de-duplicated finding, and export a report — on a fresh machine, following only the README. → the architecture is proven; everything after is "add more adapters/use-cases" per the roadmap.

---

## The ongoing discipline (every PR / weekly / monthly)

- [ ] Every PR: DoD checklist ticked, fixture added, accuracy gate green, DCO signed.
- [ ] Weekly: triage the board, merge green PRs, patch-release if security-relevant.
- [ ] Monthly: minor release + changelog; review automated content/dependency updates.
- [ ] Each step: re-run the oracle diff, look for loopholes, fix regressions before adding new features.

---

## Status Report — fill this in before sending back

- **Furthest phase completed:** _____ (0 / 1 / 2 / 3)
- **Currently working on:** _______________________________
- **Boxes I could NOT complete (and why):** _______________________________
- **Blockers / things I don't understand:** _______________________________
- **Loopholes or worries I spotted:** _______________________________
- **What I want you to do next:** _______________________________

*Send this back with the boxes ticked and I'll verify it, flag anything missing or risky, and hand you the exact next task set.*
