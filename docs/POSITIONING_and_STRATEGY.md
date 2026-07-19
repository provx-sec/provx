# Provx — Positioning & Strategy (Decision Record)

*Written after reviewing Strix (39k★, funded, autonomous AI pentester) and PentAGI (18k★). This locks what Provx **is**, who it's **for**, and how it stays defensible instead of dying as a clone. Goal: a free-now project that doubles as a serious portfolio piece and has a real (if long-shot) path to adoption/payment later.*

---

## 1. The one-line identity

> **Provx is governed, deterministic security validation you can run safely in production — human-approved, auditable, and useful with or without AI.**

We are **not** building "autonomous AI hackers." That lane is taken and well-funded. We build the disciplined, safe, engagement-and-compliance-oriented platform those tools deliberately are not.

Tagline: **"Prove your security. Safely."**

---

## 2. How Provx differs from the leaders (this is the whole strategy)

| Dimension | Strix / PentAGI (AI-autonomous leaders) | **Provx (our lane)** |
|---|---|---|
| Core identity | Autonomous AI agents that exploit | **Governed orchestration; human approves exploitation** |
| AI | **Required** (won't run without an LLM; burns tokens every run) | **Optional** — fully usable with zero AI; AI only enriches |
| Determinism | Non-deterministic agent runs | **Reproducible, deterministic** results (compliance-grade) |
| Primary user | Individual developers, bug-bounty, CI | **Pentest consultants + internal security/compliance teams** |
| Workflow | Point at a repo/URL, let it hack | **Engagement model**: scope, RoE, approval queue, branded reports |
| Production safety | Built to exploit | **Safe-by-default**; passive/active + per-finding approval |
| Auditability | Hard to reproduce an agent run | **Forensic evidence trail** (chain-of-custody, reproducible) |
| Cost to run | LLM tokens per run = ongoing $ | **Cheap** — deterministic OSS tools; AI optional |

If a feature we plan already exists identically in Strix and isn't in the right column, it's not our differentiator — don't lead with it.

---

## 3. Who Provx is for (and who it isn't)

**For:**
- Small pentest firms / consultants who need an engagement workflow + client-ready, compliance-tagged reports without a five-figure license.
- Internal security/compliance teams in regulated or budget-limited orgs (finance, health, gov, education) who need **reproducible** results and **safe-for-production** behavior.
- **Air-gapped / no-AI / privacy-first** environments that can't send code or traffic to an LLM and can't run token-hungry agents.

**Not for (Strix's turf — don't chase it):**
- Individual devs who just want to YOLO-scan a repo in CI with an AI agent.
- People who want autonomous exploitation with zero governance.

---

## 4. Why this lane fits *you* specifically

- Your **MSc** is on multi-tenant educational-platform security → multi-tenancy, governance, and audit are literally your research area.
- Your **Digital Forensics** background → the evidence-integrity / chain-of-custody edge is native to you and rare in this space.
- Result: the repositioned Provx is **more** aligned with your academic and professional identity than a generic AI-hacker clone would be. It strengthens your portfolio *and* your dissertation story.

---

## 5. The free-now, paid-later model (open core)

- **Now / forever free (Apache-2.0 core):** the whole scanner, engagement model, governance, findings, reports, plugin SDK, self-hosted deploy. This is what drives adoption, contributors, and portfolio value.
- **Paid later (separate, private):** hosted SaaS, SSO/SAML, true multi-tenant management, premium compliance report packs (SOC2/ISO/PCI), priority support/SLA. Exactly the edges Strix charges for — never the core.
- **Honest economics:** conversion is low (~1–5% for hosted, <0.1% enterprise); revenue, if any, is a multi-year build. Don't quit anything for it. Treat money as a *possible* later outcome, not the plan.

---

## 6. Honest expectations (say it plainly)

- **Portfolio / learning value: near-certain.** A governed, multi-tenant, auditable Python/Next.js security platform is a strong artifact regardless of adoption.
- **Adoption value: plausible if disciplined.** Requires staying narrow, shipping something *excellent* in the niche, good docs, and time. Broad "beat Strix" ambition = failure.
- **Payment value: long shot, years out, edges-only.** Fine as an aspiration; wrong as a near-term driver.

The discipline that makes all three work is the same: **narrow lane, excellent execution, free core, honest scope.**

---

## 7. What this changes in the existing docs

- **Blueprint** (still named "PenForge"): rebrand to Provx, and reframe intro from "one-stop pentest platform" → "governed, deterministic, AI-optional validation."
- **ROADMAP:** demote "AI Autopilot" from headline to an *optional* module; promote governance, determinism, audit trail, and the consultant/engagement workflow to the front. Keep AI clearly optional.
- **README (when generated):** lead with the differentiators in §2, and explicitly say "not another autonomous AI hacker."
- **START_HERE checklist:** add this positioning as a locked decision.

*Bottom line: Strix existing is good news — it proves the market and hands you a clear map of the ground to avoid. Provx wins by being the safe, reproducible, auditable, AI-optional alternative for people running real engagements — not by out-hacking a funded AI-agent company.*
