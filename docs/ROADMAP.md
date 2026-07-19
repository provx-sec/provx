# PenForge — Roadmap & Contributor Standard

*The governed, open-source automated security validation platform. Web · API · AD/Infra in one console. Safe enough to run against a test environment without changing anything; exploitation only ever runs on explicit human approval.*

This document is the **standard we hold every contribution to** and the **map of where we're going**. If you're contributing, read the "Definition of Done" and the "Safety Contract" first — a PR that violates them will not be merged no matter how clever it is.

---

## 1. North Star (what "good" means here)

We are **not** trying to out-feature Pentera or NodeZero. Those are 100-person teams. Our wedge is the thing none of the open-source tools and none of the paid tools give away for free:

> **A safe-by-default, governed, pluggable pentest platform that a small team or consultant can run continuously between their paid human pentests — without breaking anything and without being locked to one AI vendor.**

Four principles every feature must serve:

1. **Solve a real problem** — not add a checkbox for attention. If it doesn't help someone find, understand, or fix a real vuln, it doesn't ship.
2. **Safe by default** — passive mode does nothing destructive. Intrusive checks need Active mode; exploitation needs per-finding approval. We advise running against **test environments**, and even then the tool must not change state unless explicitly approved.
3. **Pluggable everything** — tools, use-cases, report templates, and AI providers are all plugins. The core stays small; the ecosystem grows.
4. **AI is optional, never required** — the platform is fully usable with no AI at all. When AI is on, the user picks the provider (cloud, local, or free) and brings their own key.

---

## 2. Definition of Done (every contribution)

A change is "done" only when **all** of these are true. This is the bar contributors sign up to:

- **Safety.** Any new check is tagged `passive` or `intrusive`. Intrusive checks are gated to Active mode and never run in passive/test. No check writes/deletes/modifies target state unless it is an approval-gated exploit.
- **Signal quality.** New findings are de-duplicated, carry a severity + CVSS, and map to at least one MITRE ATT&CK technique. No noisy "info" spam without value.
- **Tested.** Every tool adapter ships with a fixture (sample raw output) + a parser test, so a tool changing its output format is caught by CI, not by users.
- **Documented.** A new use-case/adapter/provider updates its plugin manifest and one line of docs. Undocumented features are considered incomplete.
- **Platform security respected.** No secret is logged. Credentials/tokens/sessions are encrypted at rest. Every state-changing action is written to the audit log.
- **Responsible use.** No feature that only makes sense for unauthorized attacks (e.g. built-in target-less mass exploitation).

---

## 3. Where to start — Step 0 and the Walking Skeleton

### Step 0 — Lock ownership before code (½ day, do this first)
This is the one that bites people later. Decide now, because you cannot retrofit it once outside PRs arrive:

- **License model: Open Core.** Core repo under **Apache-2.0** (permissive + patent grant, corporate-legal-friendly). Keep future paid features (SSO, multi-tenant, hosted SaaS, advanced reporting) in a **separate private repo** — that way community contributions to the core never need to be relicensed, and you keep the money-makers.
- **Contributions: DCO, not a heavy CLA.** A `Signed-off-by` line per commit. Low friction; keeps copyright with authors; enough for open core.
- **Trademark the name "PenForge."** The trademark is often what you actually license commercially. Cheap insurance.
- **Ship a `RESPONSIBLE_USE.md` + `SECURITY.md`** from commit #1 (offensive tooling = real liability).

### Step 1 — The Walking Skeleton (the actual first code)
Do **not** build the MVP feature list yet. Build the thinnest possible end-to-end slice that proves the architecture works, then thicken it:

```mermaid
flowchart LR
  A[Create 1 engagement + 1 in-scope target] --> B[Run ONE adapter: httpx or nuclei]
  B --> C[Normalize output into a Finding]
  C --> D[Store in PostgreSQL]
  D --> E[Show finding in UI]
  E --> F[Export a basic HTML report]
```

When that one slice works — scope check, adapter, normalized finding, storage, UI, report — everything else is "add more adapters and use-cases." Ship this in week 1–2.

---

## 4. The Base (v0.1 MVP)

The minimum that is genuinely useful and credible. Scope is deliberately narrow.

**In scope for MVP:**
- Engagement management: client, scope (allow/deny), targets, rules of engagement.
- Operating mode: passive/active toggle + the intrusive gate.
- **Web module only**, curated safe use-cases first: `fingerprint`, `tech_detect`, `content_discovery`, `security_headers`, `cors`, `tls`, `misconfig`, plus nuclei-driven CVE/exposure checks. Add intrusive input-validation checks (`sqli`, `xss`, …) behind Active mode.
- Authenticated scanning: form/cookie/bearer/header (basic).
- Findings pipeline: normalize → **dedup** → CVSS → ATT&CK tag → store.
- Findings UI: list, filter, details, validate, "in report" toggle.
- Branded report: HTML + PDF (exec summary, findings, ATT&CK coverage, remediation).
- **Multi-LLM abstraction with AI OFF by default** (analyst = optional triage/summary).
- Platform security: RBAC, encrypted secrets, audit log.
- Plugin contract v0 (tool adapter + use-case interface) — even if only 3 adapters exist.
- One-command bring-up: `docker compose up`.

**Explicitly OUT of MVP (say no in writing so you don't half-build them):** API module, AD/Infra, exploitation runners, cloud/K8s, mobile, scheduling, integrations, attack-path graphs. They come later — see roadmap.

---

## 5. Architecture

```mermaid
flowchart TB
  subgraph Frontend
    UI[Web UI - React/Vite + Tailwind]
  end
  subgraph ControlPlane
    API[FastAPI]
    SEC[RBAC / Secrets Vault / Audit Log]
  end
  subgraph Execution
    Q[Job Queue - arq + Redis]
    W[Scan Workers - sandboxed]
    ADP[Tool Adapters - plugins]
  end
  UI --> API
  API --> SEC
  API --> DB[(PostgreSQL + pgvector)]
  API --> Q --> W --> ADP
  ADP --> T1[nuclei]
  ADP --> T2[httpx]
  ADP --> T3[nmap]
  ADP --> T4[...community plugins]
  W --> NORM[Findings pipeline: normalize / dedup / CVSS / ATT&CK]
  NORM --> DB
  API --> AI[AI layer - provider abstraction]
  API --> REP[Report engine - HTML / PDF / Word / Markdown / ATT&CK layer]
```

### Multi-LLM (and no-AI) — a first-class design goal

```mermaid
flowchart LR
  APP[AI features: triage, methodology, autopilot] --> ABS[Provider abstraction - LiteLLM]
  ABS --> A[Anthropic Claude]
  ABS --> O[OpenAI]
  ABS --> G[Google Gemini]
  ABS --> F[Free / hosted models]
  ABS --> L[Local: Ollama / vLLM - stays in your perimeter]
  ABS --> N[None: full platform works with zero AI]
```

Rules: AI is **opt-in**, **bring-your-own-key**, provider-swappable in one setting, and every AI-assisted output is clearly labelled as such. A local model option is mandatory for regulated/air-gapped users — never force traffic to a third-party model.

### Safe scan lifecycle

```mermaid
flowchart LR
  E[Engagement + scope + mode] --> S[Pick module + use-cases]
  S --> GATE{In scope? Passive vs Active?}
  GATE -- blocked --> STOP[Skip - logged]
  GATE -- allowed --> RUN[Run adapters]
  RUN --> FIND[Findings: dedup + CVSS + ATT&CK]
  FIND --> VAL[Validate / include in report]
  FIND --> EXP{Confirmed exploit path?}
  EXP -- no --> REP[Report as VA finding]
  EXP -- yes --> APPR[Approval queue - Active only]
  APPR -- reject --> REP
  APPR -- approve --> SBX[Sandboxed, non-destructive proof-of-exploit]
  SBX --> REP
```

### Plugin/adapter model (how contributors extend without touching core)

```mermaid
flowchart LR
  DEV[Contributor] --> M[Adapter manifest: name, category, passive/intrusive, tool]
  M --> BUILD[build_command scope+auth+use-cases]
  M --> PARSE[parse_output -> normalized Finding]
  M --> TEST[fixture + parser test]
  BUILD --> REG[Auto-registered via entry point]
  PARSE --> REG
  TEST --> CI[CI gate]
  REG --> CORE[Core discovers plugin - no core edits]
```

---

## 6. Roadmap (v0.1 → v2.0)

Dates are **solo-dev estimates** and will move — they signal sequence and standard, not promises.

```mermaid
gantt
  title PenForge phased roadmap (indicative)
  dateFormat YYYY-MM
  section Foundation
  Step 0 license + repo governance      :2026-08, 15d
  Walking skeleton                       :2026-08, 20d
  section v0.1 - MVP (Web)
  Web module + findings + report + multi-LLM :2026-09, 3M
  Platform security (RBAC/secrets/audit)     :2026-09, 2M
  section v0.5 - Depth
  API module (OWASP API Top 10)          :2026-12, 2M
  Retest / verify + scan-to-scan diffing :2027-01, 1M
  Scheduling + CLI/REST for CI gates     :2027-02, 1M
  section v1.0 - Full pentest
  AD/Infra module + approvals + exploit sandbox :2027-03, 3M
  AI Autopilot + analyst + remediation deps     :2027-05, 2M
  Compliance mappings (PCI/OWASP/ISO)           :2027-06, 1M
  section v2.0 - Reach
  Attack-path graph (AD) + mobile-static (MobSF) :2027-08, 3M
  Integrations (Jira/Slack) + cloud/K8s (opt-in) :2027-10, 3M
```

**Milestone gates (a version isn't "done" until):**
- **v0.1** — a stranger can `docker compose up`, scan a lab target authenticated, get a de-duplicated finding list and a branded PDF, with AI off, on a fresh machine, following only the README.
- **v0.5** — API coverage + one-click retest + diff between two scans + a working `POST /scan` API usable in CI.
- **v1.0** — all three modules, approval-gated safe exploitation with replay log, autopilot within scope/mode, compliance-tagged reports. This is the "credible product" line.
- **v2.0** — attack-path graph, mobile static, integrations, optional cloud.

---

## 7. Release train & update cadence (the "always current" standard)

The whole point of this section: **staying current is mostly automated, not manual.** Here's the contract.

| Cadence | Who/what | What happens |
|---|---|---|
| **Continuous (automated)** | CI bots | Pull latest **Nuclei templates**, **CVE/CISA KEV**, exploit-DB refresh into the content layer. Dependency + wrapped-tool version bumps via Renovate/Dependabot. Nightly build + smoke test against the lab. |
| **Weekly (manual, light)** | Maintainer | Triage new issues/PRs, merge green ones, cut a patch release if security-relevant. Review the automated content diffs. |
| **Monthly (minor release)** | Maintainer + contributors | New adapters/use-cases, bug-fix batch, roadmap check-in, changelog. |
| **Quarterly (feature release)** | Team | A roadmap milestone (e.g. API module, then AD). Public roadmap update. |
| **Yearly (major + hygiene)** | Team | Major version, external security review of PenForge itself, license/governance review, dependency license audit. |

**Content-freshness policy:** detection/exploit content is versioned separately from the app, so a template/CVE update is a data pull, never a code release. Target: newly disclosed high-profile CVEs detectable within days of a public Nuclei template existing — because we ride the community feed, we inherit its speed instead of racing it.

---

## 8. Safety Contract (non-negotiable)

1. **Passive/test = read-only.** No check may create, modify, or delete data on a target in passive mode. If a check can't guarantee that, it's `intrusive`.
2. **Intrusive = Active + authorized.** Gated, logged, and only on engagements explicitly set to Active with rules of engagement recorded.
3. **Exploitation = per-finding human approval, sandboxed, non-destructive proof only** by default. Full replay trail written.
4. **Scope is enforced before every action** — allow/deny checked at the adapter boundary, not trusted upstream.
5. **The platform protects its own secrets** — encrypted creds/tokens/sessions, RBAC, complete audit log. A leaky security tool is a catastrophe.
6. **We advise test environments.** Production is possible by design (non-destructive) but never the recommended default.

---

## 9. Contributor on-ramp

- `CONTRIBUTING.md` (DCO sign-off, how to add an adapter in one file), `ARCHITECTURE.md` (this doc's diagrams), `RESPONSIBLE_USE.md`, `SECURITY.md`.
- Labelled **good first issues**: "add adapter for X", "add use-case Y", "add report template Z", "add LLM provider W".
- A **plugin cookbook**: copy the template adapter, fill `manifest` + `build_command` + `parse_output` + a fixture test, open a PR. No core changes needed.
- Public roadmap board so contributors see the standard and where help is wanted.

---

*Everything here is a living standard. We add options, providers, adapters, and ideas — but we never compromise the Safety Contract or ship noise for attention. Bigger space, more ideas, one discipline.*
