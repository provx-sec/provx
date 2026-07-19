# Provx — Complete Build Blueprint

**Governed automated security validation — web, API & infra in one console.**
*Deterministic and auditable at the core; safe operating modes; approval-gated exploitation; client-ready reporting. AI is an **optional** advisor, never required.*

> **Canonical identity.** This is **Provx** (older drafts said *PenForge*/*Provex* — superseded). Read alongside `POSITIONING_and_STRATEGY.md` (how Provx differs from AI-first tools like Strix) and `DETERMINISTIC_CORE_and_NonAI_Strengths.md` (the deterministic engine is the brain; AI is optional). Where this document mentions an "AI engine/analyst/autopilot," treat it as an **optional module** per those two docs.
>
> **Purpose.** A top-to-bottom feature and architecture map for Provx — the superset of capabilities to draw from, informed by studying a reference tool (27 screenshots) plus market analysis. Items are marked **OBSERVED** (seen in the reference) or **TO-BUILD / STANDARD** (expected for completeness). A gap analysis at the end compares against commercial ASV platforms.
>
> **Scope note.** Authorized/defensive tooling only. Every capability assumes explicit authorization, in-scope targets, and the safety gates in Section 6.

---

## 0. Repository & baseline (canonical)

Provx ships as **one monorepo** (see `REPOSITORY_STRATEGY.md`) served locally during dev; PostgreSQL datastore; Docker Compose bring-up. AI is optional and off by default.

```
provx/
├── backend/            # FastAPI control plane + orchestration + report engine
├── frontend/           # Next.js UI
├── packages/
│   ├── adapters/       # tool-adapter plugin SDK (publishable)
│   └── client/         # thin API client others can install standalone
├── workflows/          # deterministic YAML playbooks (the "brain")
├── lab/                # intentionally-vulnerable + clean targets (accuracy benchmark)
├── wordlists/          # discovery / fuzzing wordlists
├── docs/               # these planning docs
├── docker-compose.yml  # one-command bring-up
├── Makefile
└── README.md
```

**Core sections (nav):** Dashboard · Engagements · Scans · Findings · Approvals · Reports · (optional) AI Advisor · User management · Configurations.

*The feature catalog below was validated against a reference implementation; it is the menu Provx builds from, prioritized by the roadmap — not a spec to build all at once.*

---

## 1. Product concept & design principles

1. **One platform, many asset classes.** Combine what people normally buy as separate tools (web app scanner, API scanner, infra/AD scanner) into a single console. Planned expansion: **wireless testing** and **PCI segmentation testing**.
2. **Safe by default.** Passive mode does recon + VA only. Intrusive checks and exploitation require an explicit mode switch and, for exploitation, per-finding approval. The platform must be safe to point at production without breaking it.
3. **Find first, exploit only on approval.** Scans *find* and validate vulnerabilities; they never auto-exploit. Exploitation is a separate, human-gated step.
4. **AI as an operator and an analyst.** An autopilot can plan → run → chain an assessment within scope/mode and write the report. A separate analyst assists with triage, methodology, prioritization, and request/response analysis.
5. **Client-ready output.** Branded, classification-marked reports in multiple formats, with CVSS and MITRE ATT&CK mapping and a remediation roadmap.
6. **Runs offline.** External tools are pre-installed into the container so a scan works without internet; internet is only needed to *install/update* tooling.

---

## 2. System architecture

### 2.1 Runtime (OBSERVED + inferred)

| Layer | Choice (observed / inferred) | Notes |
|---|---|---|
| Delivery | Docker Compose, `Makefile` targets | one-command `make up` / `docker compose up` |
| Datastore | PostgreSQL (`postgresql+psycopg`) | engagements, scans, findings, approvals, users, settings |
| Backend | Python service on `:8000` (FastAPI or Flask) | REST API + task orchestration + report/AI engines |
| Task execution | async workers / job queue *(to build)* | long-running scans, progress %, cancel/control |
| Frontend | server-rendered or SPA at `:8000` | the console in the screenshots |
| AI | Anthropic Claude API (`claude-sonnet-4-6`) | key + enable flag stored in settings |
| Tool layer | external binaries baked into the image | nmap, nuclei, httpx, etc. (Section 7) |
| Lab | `lab/` vulnerable apps + `wordlists/` | safe practice targets |

### 2.2 Suggested component breakdown (`backend/`)

```
backend/
├── api/              # HTTP routes for each nav section
├── core/             # config, auth, RBAC, SAFE_MODE, scope engine
├── engagements/      # scope rules, targets, creds, RoE, mode
├── scanning/         # scan lifecycle, progress, control (pause/cancel)
├── modules/
│   ├── web/          # web use-cases (Section 5.1)
│   ├── api/          # API use-cases (Section 5.2)
│   └── infra_ad/     # infra + Active Directory (Section 5.3)
├── tools/            # wrappers/adapters per external binary + install/health
├── findings/         # normalize → dedupe → CVSS/ATT&CK enrichment
├── exploitation/     # approval queue + gated exploit runners
├── ai/               # autopilot orchestrator + analyst endpoints
├── reporting/        # HTML/PDF/Word/Markdown + ATT&CK layer export
└── users/            # accounts, roles
```

---

## 3. Data model (core entities)

- **Engagement** — client name, mode (passive/active), scope rules, targets, credentials/auth, rules of engagement, authorization reference, status.
- **ScopeRule** — value (IP/CIDR/host/`*.wildcard`/URL) + `ALLOW`/`DENY`.
- **Target** — host/ip/url, type (infra/web/api), active flag, "exclude from scope" flag, source (manual/import/enumeration).
- **Credential/AuthProfile** — login URL, username, password; or bearer token / cookie string / header lines / recorded session; auth type.
- **Scan** — engagement, selected module(s), selected test IDs, authenticated flag, status, progress %, targets snapshot, control state.
- **Finding** — title, affected target, severity + CVSS, module, MITRE technique(s), validated flag, "in report" flag, description, evidence (structured), remediation, stable ID (e.g. `PF-001`).
- **ExploitCandidate / Approval** — finding ref, exploit path, status (pending/approved/rejected), gated on ACTIVE mode.
- **Report** — engagement ref, branding, classification, format, generated artifact.
- **User** — username, role, credentials.
- **Settings** — AI key/model/enabled, report branding, SAFE_MODE lock, tool install status.

---

## 4. Engagement management (OBSERVED)

Everything needed to define *what* you're allowed to test and *how*.

- **Create / select engagement**; each shows scope, targets, and mode.
- **Operating mode toggle — Passive / Active.** *"Active — intrusive checks & exploits permitted."*
- **Engagement details & credentials:**
  - Login URL (for authenticated scanning), Username, Password.
  - **Alternative authentication** dropdown — *Form login (URL + user + pass)*, plus `bearer: token` · `cookie: k=v; k2=v2` · `header: Name: value` · `session: cookie/header lines`.
  - **Form login is best-effort** — auto-detects fields + CSRF, falls back to JSON/SPA logins.
  - **Record session** — capture a live login when SSO/MFA/captcha defeats form login.
  - **Rules of engagement** free-text (e.g. *"Prod — nothing destructive. Deep testing allowed."*).
  - **Save details.**
- **Bulk import scope & targets** — paste a `TARGETS.md` block or any list of URLs / IPs / CIDRs / `*.wildcards`. Hosts and CIDRs become scope rules + targets; wildcards become scope you can enumerate. **Import** + **Enumerate subdomains (wildcards)**.
- **Scope list** — add `IP / CIDR / host / *.domain` as **Allow** or **Deny**.
- **Targets list** — add `host / ip / url`; typed (host/…); shows "N/N target(s) active for scanning"; grouped (e.g. *Infra (1)*); per-target **exclude from scope** / remove.
- **Report shortcuts** on the engagement: HTML report · Markdown · PDF · ATT&CK layer.

### Scope engine (build carefully — this is the safety spine)
- Every request/target is checked against ALLOW/DENY before any tool runs.
- Wildcard `*.example.com` → optional subdomain enumeration → new in-scope targets.
- CIDR expansion for infra targets.
- "Exclude from scope" overrides even if a target was auto-added.

---

## 5. The three test models + full use-case catalogues

At scan creation you **Choose your test model(s)** — select one, two, or all three:

- **Web Pentest** — *OWASP web-app testing — recon, config, auth, session, injection, crypto, client-side.*
- **API Pentest** — *OWASP API Top 10 — BOLA, broken auth/JWT, mass assignment, BFLA, SSRF, injection.*
- **AD & Infra Pentest** — *Network recon, service/NSE checks, vuln assessment, exploitation, and full Active Directory.*

**Convention throughout:** *"Tests (none = safe default sweep; △ = needs ACTIVE mode)."* The `△` marks intrusive checks that only run when the engagement is in Active mode. Each module screen also exposes free-text **targets** and an optional **nuclei severity** filter, plus **Select all** / **Clear**.

### 5.1 Web Pentest — full use-case matrix (OBSERVED, verified across passes)

| Group | Use-cases (`△` = intrusive / ACTIVE-only) |
|---|---|
| **Information gathering** | `fingerprint` · `tech_detect` · `content_discovery` · `backup_files` · `spider` |
| **Configuration & deployment** | `security_headers` · `http_methods` · `cors` · `admin_panels` · `exposures` · `misconfig` |
| **Identity & authentication** | `default_creds △` · `auth_bypass` · `user_enum` |
| **Session management** | `cookie_flags` · `csrf` |
| **Input validation** | `sqli △` · `blind_sqli △` · `xss △` · `stored_xss △` · `command_injection △` · `ssti △` · `ssrf △` · `lfi △` · `xxe △` · `ldap_injection △` · `xpath_injection △` · `crlf △` · `shellshock △` · `open_redirect` · `host_header` |
| **Cryptography / transport** | `tls` · `https_redirect` · `csp_eval` · `sensitive_http` |
| **Client-side** | `clickjacking` · `dom_xss` |
| **Bug-bounty recon** (JS, healthcheck, GraphQL, takeover, 403 bypass) | `js_analysis` · `healthcheck` · `wellknown` · `graphql` · `waf_detect` · `subdomain_takeover` · `bypass_403` |

### 5.2 API Pentest — use-case catalogue (TO-BUILD; mirror OWASP API Top 10 2023)

The model description names BOLA, broken auth/JWT, mass assignment, BFLA, SSRF, injection. Build the full API matrix to match Web's depth:

| Group | Use-cases |
|---|---|
| **Discovery** | `swagger_openapi_detect` · `graphql_introspection` · `endpoint_extraction_from_js` · `api_versioning` · `hidden_params` |
| **Authorization** | `bola_idor △` (API1) · `bfla △` (API5 function-level) · `object_property_level_auth △` (API3) |
| **Authentication** | `broken_auth △` (API2) · `jwt_attacks △` (alg=none, weak secret, kid abuse) · `api_key_leakage` · `token_replay △` |
| **Data / mass assignment** | `mass_assignment △` (API6) · `excessive_data_exposure` (API3) · `unrestricted_resource_consumption △` (API4 rate/limits) |
| **Injection & SSRF** | `api_sqli △` · `nosql_injection △` · `command_injection △` · `ssrf △` (API7) · `xxe △` |
| **Config & inventory** | `security_misconfig` (API8) · `improper_inventory` (API9 shadow/deprecated) · `cors_api` · `verbose_errors` |
| **Business logic** | `workflow_abuse △` · `unsafe_consumption_of_apis △` (API10) |

### 5.3 AD & Infra Pentest — use-case catalogue (TO-BUILD; match "recon → VA → exploitation → full AD")

| Group | Use-cases |
|---|---|
| **Network recon** | `host_discovery` · `port_scan` · `service_version` · `os_detect` · `nse_safe_scripts` |
| **Service/VA checks** | `smb_enum` · `snmp_enum` · `rdp_checks` · `ftp_checks` · `ssh_checks` · `db_service_checks` · `tls_service_checks` · `cve_mapping` |
| **Credential attacks** | `default_creds △` · `password_spray △` · `brute_force △` · `credential_stuffing △` |
| **Active Directory — enum** | `null_session` · `user_group_enum` · `ldap_enum` · `kerberos_userenum` · `smb_share_enum` · `gpo_enum` · `bloodhound_collect` |
| **Active Directory — attack (`△`)** | `asrep_roast △` · `kerberoast △` · `llmnr_nbtns_poison △` · `ntlm_relay △` · `pass_the_hash △` · `dcsync △` · `adcs_esc △` · `delegation_abuse △` |
| **Exploitation** | `exploit_known_cve △` · `lateral_movement △` · `privilege_escalation △` (all approval-gated) |

### 5.4 Planned additional models (user roadmap — TO-BUILD)

- **Wireless testing** — SSID/AP discovery, encryption assessment (WEP/WPA2/WPA3), rogue-AP / evil-twin detection, handshake capture + offline crack `△`, client deauth `△`, PMKID. *(Requires monitor-mode NIC; keep strictly lab/authorized.)*
- **PCI segmentation testing** — prove CDE isolation: from each network segment, attempt reachability to the Cardholder Data Environment; assert that only permitted paths succeed. Produce a segmentation matrix (segment → CDE: expected vs. actual) suitable for a PCI DSS 11.4.5 / 11.4.6 evidence pack.

---

## 6. Safety & governance model (OBSERVED — do not cut corners here)

This is what lets the tool touch production without breaking things.

1. **Per-engagement Passive/Active mode.** Passive = *safe, non-intrusive (recon, scanning, VA only)*. Active = *intrusive checks & exploitation permitted (requires authorization)*.
2. **`△` intrusive gating.** Any `△` use-case is skipped unless the engagement is Active.
3. **VA-only scanning.** *"Scans only find these — active exploitation runs only after you approve it here."* Scanning never exploits.
4. **Approval-gated exploitation.** Exploit candidates go to the Approvals queue; running an exploit requires (a) Active mode and (b) explicit **Approve exploit**, else **Reject** keeps it as a VA finding.
5. **Org-wide SAFE_MODE lock.** A global switch (seen "OFF — per-engagement mode active") that, when ON, forces safety org-wide regardless of engagement settings.
6. **Scope enforcement** on every action (Section 4 engine).
7. **Rules of engagement** captured per engagement and surfaced in the report.
8. **Autopilot boundary.** *"Every action stays within scope & mode"* — the AI operator inherits, and cannot exceed, these gates.

---

## 7. Scanning engine & external tool orchestration (OBSERVED + inferred)

**Attack tooling** is managed under Configurations: shows `installed 15/17 · 2 missing`, **Install all missing**, **Recheck**. *"External tools the attack modules orchestrate … the container needs internet for the install."* Tools are baked into the image so scans run offline.

**Observed tools (with categories):**

| Category | Tool | Role |
|---|---|---|
| INFRA / WEB | `nmap` | infra recon, NSE scripts & credential checks |
| WEB / API | `nuclei` | web tech/exposure/injection templates, API injection |
| WEB | `httpx` | web probing / fingerprinting (ProjectDiscovery) |
| WEB | `feroxbuster` | web content discovery |
| WEB | `dalfox` | XSS detection |
| WEB | `testssl` | TLS/SSL assessment |
| WEB | `sqlmap` | web/API SQL injection |
| WEB / BUG BOUNTY | `trufflehog` | JS-bundle secret detection (700+ detectors) |
| WEB / BUG BOUNTY | `gitleaks` | JS-bundle secret detection (extra regex) |
| ACTIVE DIRECTORY | *(header shown; 2 tools missing in demo)* | — |

**Likely/needed AD & Infra tools to complete the set (TO-BUILD):** `netexec`/`crackmapexec`, `impacket` suite (secretsdump, GetNPUsers, GetUserSPNs, ntlmrelayx), `bloodhound` + `SharpHound`/`bloodhound.py`, `kerbrute`, `enum4linux-ng`, `responder`, `ldapsearch`/`windapsearch`, `certipy` (ADCS), `evil-winrm`. **Web/recon extras worth adding:** `katana` (crawl), `subfinder`/`amass` (subdomain enum for wildcards), `dnsx`, `naabu` (fast port scan), `gau`/`waybackurls`, `ffuf`, `wpscan` (if WordPress), `nikto`.

**Orchestration requirements:**
- A **tool adapter** per binary: build the command from selected use-cases + scope + auth, run it, capture stdout/artifacts, health-check its presence/version.
- **Module → tool mapping** so selecting a use-case picks the right tool(s).
- **Install/health page** with per-tool status (`installed` / missing) + one-click install + recheck.
- **Progress + control**: live progress %, and a per-scan control (pause/cancel).
- **Authenticated vs unauthenticated** toggle at scan time (uses the engagement's saved login).
- **Change models** at scan time (which of the 3 models to include).

---

## 8. Findings & vulnerability assessment (OBSERVED)

**Findings list:** filter by engagement, search (name/target/CVE), severity filter, status filter, page size. Columns: **Finding · Criticality · Validated · In report (toggle) · Details · Validate.**

**Finding record (from report detail):**
- Stable ID (`PF-001…`), title, affected target.
- **Severity + CVSS** (e.g. *Medium · CVSS 5.5*).
- **Module** (web/api/infra).
- **MITRE ATT&CK** technique(s) (e.g. `Active Scanning (T1595)`, `Exploit Public-Facing Application (T1190)`).
- **Validated** flag.
- **Description**, structured **Evidence** (e.g. `acao: https://evil.example`; `status/server/x_powered_by/final_url`; crawl `param_urls`/`forms`; nuclei `template`/`tags`), **Remediation**.

**Pipeline to build:** normalize raw tool output → dedupe across tools/targets → enrich (CVSS score, ATT&CK mapping) → assign stable ID → allow manual **Validate** and **in-report** inclusion toggle.

---

## 9. Exploitation & approvals (OBSERVED)

**Exploitation Approvals** page: *"Vulnerabilities with a confirmed exploit path. Scans only find these — active exploitation runs only after you approve it here."* Table: **Vulnerability · Target · Severity · CVE · Status · Action** with **Approve exploit** / **Reject**; shows "N pending approval · N exploitable". Approving runs the gated exploit (Active mode required); rejecting keeps it as a VA finding.

**Build:** a candidate is created only when a scan confirms an exploitable path; approval triggers a sandboxed, scope-checked exploit runner that records proof and upgrades the finding to *validated/exploited* — never destructive by default.

---

## 10. AI engine (OBSERVED)

### 10.1 AI Autopilot (on the engagement)
*"Let Claude plan, run, and chain the assessment (incl. exploitation), then write the report. Every action stays within scope & mode."* Controls: **rounds** (e.g. 4), **auto-exploit** checkbox, **Run Autopilot**. Build it as an orchestration loop that can only call the same scope/mode/approval-gated actions a human can.

### 10.2 AI Analyst (dedicated page)
- **AI settings** — Anthropic API key, model (`claude-sonnet-4-6`), Enabled flag, Save.
- **Analyse engagement findings** — pick engagement → **Analyse with Claude** (triage, correlate, prioritize).
- **Methodology advisor** — target + asset type (e.g. *web application*) + optional context (stack, auth type, notes) → **Generate test plan**.
- **HTTP request/response analyzer** — paste request (+ optional response) → **Analyse request/response**.

### 10.3 Remediation-dependency prioritization (design the analyst to do this)
Model the user's key requirement: reason about *fix dependencies*, not just severity. If patching a **Medium** also closes a **Critical** (e.g. a config change that removes the exploit precondition), the analyst should recommend the dependency fix first and mark the dependent findings as "resolved-by". Output an ordered roadmap: *fix X first → also closes A, B; skip separate fix for A/B.*

---

## 11. Reporting (OBSERVED)

**Branding & settings:** tester company, website, contact, email, classification (e.g. CONFIDENTIAL), primary/accent colour, client logo, tester logo, Save. *"Client name is taken from each engagement."*

**Generate report:** pick a completed engagement → download **PDF / Word / HTML** (engagement page also offers **Markdown** and **ATT&CK layer** JSON for the Navigator).

**Report structure (11-page demo):** cover (classification banner, client) → **1. Executive summary** (scan count, finding counts by severity, overall risk posture, severity-definition table) → **2. Scope & rules of engagement** (client, in-scope, out-of-scope, testing models, mode, authorization) → **3. Methodology** (industry-standard, ATT&CK-mapped) → **4. Findings summary** (`PF-xxx`, finding, affected, severity, status) → **5. Detailed findings** (per-finding target/severity+CVSS/module/ATT&CK/validated/description/evidence/remediation) → **6. MITRE ATT&CK coverage** (tactic → technique → ID → finding count) → **7. Remediation roadmap** (severity → priority window → recommended per-`PF` actions).

---

## 12. Users, dashboard & configuration (OBSERVED)

- **User management** *(page not shown — build RBAC: admin/operator/viewer; per-engagement access)*.
- **Dashboard** — counters (engagements, total/completed/running-queued scans, critical+high, validated), **findings by severity** bars, **Top ATT&CK techniques** (technique → count), **recent scans** (id/module/status/progress), **engagement risk** list, Refresh.
- **Configurations** — deployment info (version, DB, SAFE_MODE lock, signed-in user), per-engagement mode toggles, attack-tooling install/health.

---

## 13. Lab & practice environment (OBSERVED)

`lab/` ships intentionally-vulnerable targets (the demo "Vul Bank"/"Gye Nyame Bank" banking apps on `:2000`/`:4000`) and `wordlists/` for discovery/fuzzing. Keep the lab isolated on an internal Docker network so the platform can be exercised end-to-end safely and used for learning/regression before you point it at real internal apps.

---

## 14. Gap analysis — features to add vs. commercial ASV platforms

Beyond faithful replication, these are standard in mature ASV / continuous-validation products (Pentera, Cymulate, Horizon3 NodeZero, RidgeBot) and worth adding:

- **Scheduling & continuous validation** — recurring scans, drift detection, and **scan-to-scan diffing** (new / fixed / regressed findings).
- **Attack-path chaining & visualization** — graph exploited hops (BloodHound-style) to show blast radius, not just isolated findings.
- **Retest / remediation-verification workflow** — mark fixed → re-run just that finding → track SLA and MTTR.
- **Asset inventory & tagging** — persistent asset DB across engagements with ownership/criticality tags.
- **Evidence capture** — request/response and **screenshot** attachments per finding (auto for web).
- **Cloud & container coverage** — AWS/Azure/GCP posture checks, S3/bucket exposure, IAM misconfig; Docker/Kubernetes checks.
- **Detection/BAS validation** — safe "did the SOC/EDR catch it?" checks to validate blue-team coverage, mapped to ATT&CK (you already emit ATT&CK layers).
- **Phishing / social-engineering simulation** — optional, authorized, template-based.
- **Integrations** — Jira/ServiceNow ticket creation, Slack/email notifications, webhooks; **REST API + CLI** for automation and CI/CD security gates.
- **Multi-tenancy & audit** — tenant isolation, full audit log of every action (who ran what, when) — directly aligned with your multi-tenant-platform research and essential for a shippable product.
- **Compliance mappings** — tag findings to OWASP/PCI DSS/ISO 27001/NIST so reports double as compliance evidence (pairs with the PCI segmentation model).
- **False-positive management** — accept-risk / mute / re-classify with justification, carried across scans.

---

## 15. Phased build roadmap (so no step is skipped)

**Phase 0 — Foundations**
Docker Compose + Postgres + backend skeleton + auth/RBAC + `.env`; data model (Section 3); scope engine + SAFE_MODE (Section 6); lab targets + wordlists.

**Phase 1 — Engagements & scope**
Engagement CRUD, mode toggle, credentials/auth (form/bearer/cookie/header + record session), bulk import + wildcard subdomain enumeration, scope/target management.

**Phase 2 — Web module (MVP scanner)**
Tool adapters (httpx, nuclei, feroxbuster, dalfox, testssl, sqlmap, trufflehog/gitleaks), full web use-case matrix (5.1), authenticated scanning, progress/control, findings pipeline (normalize/dedupe/CVSS/ATT&CK), findings UI + validate + in-report toggle.

**Phase 3 — Reporting**
Branding settings; PDF/Word/HTML/Markdown + ATT&CK-layer export; the 7-section report; `PF-xxx` IDs; dashboard counters/charts.

**Phase 4 — API module**
Full API matrix (5.2): discovery, BOLA/BFLA/object-property auth, JWT, mass assignment, injection/SSRF, inventory/config, business logic.

**Phase 5 — Infra & Active Directory**
nmap orchestration + service VA + CVE mapping; AD enum + BloodHound collection; AD attacks (`△`) and infra exploitation (approval-gated); complete the AD tool set.

**Phase 6 — Exploitation & approvals + AI**
Approval queue + gated exploit runners; AI Analyst (findings analysis, methodology advisor, HTTP analyzer, remediation-dependency prioritization); AI Autopilot (rounds, auto-exploit, within scope/mode) + report authoring.

**Phase 7 — Expansion & hardening**
Wireless model; PCI segmentation model; scheduling/continuous validation + scan diffing; retest workflow; integrations (Jira/Slack/webhooks) + REST API/CLI; cloud/container coverage; multi-tenancy + audit log; compliance mappings.

---

## Appendix A — Observed vs. to-build (quick index)

**Directly observed:** all 9 nav sections; engagement scope/targets/creds/mode/RoE/bulk-import/subdomain-enum; the 3-model chooser + descriptions; the **full Web use-case matrix**; passive/active + `△` gating; VA-only scanning; approval-gated exploitation; findings schema (CVSS+ATT&CK+evidence+remediation) + validate/in-report; AI settings + Analyst (3 tools) + Autopilot (rounds/auto-exploit); report branding + PDF/Word/HTML/Markdown/ATT&CK-layer + 7-section structure; dashboard; Configurations (deployment, per-engagement mode, tool install/health with 9 named tools); repo layout; lab + wordlists.

**Inferred / to-build (marked in-text):** full **API** matrix; full **Infra/AD** matrix + AD tool set; User-management page internals; wireless + PCI-segmentation models; task-queue/progress internals; and the Section 14 gap-analysis features.

*Reviewed across the full set of 27 screenshots (multiple passes) plus the walkthrough narrative; observed items reflect exactly what is on screen, inferred items are flagged as such.*
