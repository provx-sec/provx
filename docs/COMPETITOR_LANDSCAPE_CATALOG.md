# Provx — Competitor & Tool Landscape (Reference Catalog)

*The full field — free, open-source, and paid — so you can survey features and decide what to wrap, borrow, differentiate from, or ignore. Not a to-do list: a map. Tags per entry:*

- 🔧 **WRAP** — free OSS engine Provx orchestrates (a building block, not a rival)
- 📋 **BORROW** — a feature or model idea worth adopting
- ⚔️ **DIFFERENTIATE** — a competitor; hold the governed / free-UI / deterministic / auditable lane
- 🚫 **AVOID** — don't try to replicate (incumbent moat or out of scope)

**The 2026 consensus** (multiple analyst sources): annual pentests are seen as insufficient, autonomous agents are taking breadth + continuous coverage, but the accepted model is that **humans own validation, judgment, and regulatory sign-off** — and agentic systems still hallucinate, false-positive exploits, and lack transparent decision-making. That gap (transparency + governance + validation) is Provx's opening.

---

## A. Open-source — all-in-one / orchestration platforms (closest in shape to Provx)

| Tool | Cost | What it is | Provx relevance |
|---|---|---|---|
| **Sn1per (Community)** | Free CLI (paid UI/Pro/Ent) | Recon→scan→exploit→report; 90+ integrations, 600+ exploits | ⚔️ + 📋 borrow the edition/quota **monetization mechanic**; beat it by keeping the **UI free** |
| **Osmedeus** | Free (MIT) | Declarative **YAML workflow engine**, sandboxed, dedup, REST+UI | 📋 the model for your deterministic **playbook engine** |
| **reNgine** | Free (GPL) | Recon framework, "scan engines," projects, scheduled scans | 📋 engagement/profile + scheduling ideas |
| **Faraday** | Free core (paid ent) | Aggregates 80+ tools, dedups, agents for distributed scans | 📋 normalization; distributed agents much later |
| **Nettacker (OWASP)** | Free | Automated recon + vuln scanning, modular | 📋 modular scan orchestration reference |
| **Rengine/AutoRecon** | Free | Parallel service enumeration → structured surface map | 📋 the "map first" recon pattern |

## B. Open-source — engines & scanners (the free building blocks you WRAP)

| Tool | Role | Provx |
|---|---|---|
| **Nmap** (+ **Masscan**/**Naabu**) | Port/service/OS discovery; NSE scripts | 🔧 infra recon |
| **Nuclei** | Template scanner; 9,000+ templates, **AI template-gen from a CVE/PoC**, CISA KEV mapping, CI-native | 🔧 core web/CVE detection |
| **httpx / katana** | Probing/fingerprinting; crawling (ProjectDiscovery) | 🔧 web recon |
| **OWASP ZAP** | Free web scanner + proxy; scriptable, CI-friendly, good passive mode | 🔧 web (and an accuracy **oracle**) |
| **sqlmap** | DB/SQLi detection + exploitation (low-noise engine) | 🔧 injection (GPL → subprocess only) |
| **Wapiti** | Black-box web scanner; 2026 adds SSTI + JWT fuzzing | 🔧 optional web adapter |
| **feroxbuster / gobuster** | Content discovery (DirBuster is deprecated) | 🔧 discovery |
| **dalfox** | XSS detection | 🔧 web |
| **testssl.sh** | TLS/SSL assessment | 🔧 transport |
| **trufflehog / gitleaks** | Secret detection in JS/bundles/repos | 🔧 bug-bounty recon |
| **BloodHound** (+ SharpHound) | AD attack-path graphing | 🔧 AD (wrap, don't rebuild) |
| **Metasploit Framework** | Exploit/payload library (open-source core) | 🔧 approval-gated exploitation only |
| **Nikto** | Web-server checks | 🔧 optional |
| **Wireshark** | Packet analysis | 🚫 out of Provx scope |
| **OpenVAS / Greenbone (Community)** | Closest OSS to Nessus; network+endpoint VA, Community Feed | 🔧/⚔️ heavy; wrap selectively, and an **oracle** |

## C. Open-source — SAST / SCA / cloud / containers (adjacent; wrap later)

| Tool | Role | Provx |
|---|---|---|
| **Semgrep** | SAST with PR "guardrails" that block insecure commits | 📋 CI-gate pattern; optional adapter |
| **Trivy** | All-in-one: containers, IaC, repos, AWS; fast | 🔧 later (cloud/container phase) |
| **ScoutSuite / Prowler** | Cloud posture (AWS/Azure/GCP) | 🔧 later, optional |
| **Dependency-Track** | SBOM / continuous component risk | 📋 later; interop |
| **Garak / PyRIT** | Test **LLMs** (prompt injection etc.); Garak is OSS | 🚫 different category (AI-app testing) |

## D. Open-source — vulnerability management / aggregation

| Tool | Role | Provx |
|---|---|---|
| **DefectDojo** | Gold-standard OSS DevSecOps hub: ingests 200+ tools, **intelligent dedup**, **EPSS**, **engagement tracking**, compliance mapping, risk-acceptance | 📋 borrow dedup/EPSS/risk-acceptance/retest; **interop via SARIF import/export** |
| **Faraday** | (see A) normalization hub | 📋 |

## E. Open-source — AI-native agents (the OSS AI wave)

| Tool | Notes | Provx |
|---|---|---|
| **PentAGI** | ~14.7k★, most polished OSS multi-agent, Docker-sandboxed, 200+ tools, multi-LLM | ⚔️ AI-first; you're deterministic-first/AI-optional |
| **PentestGPT** | Academic gold standard (USENIX 2024), reasoning loop, Docker, BYO-LLM | ⚔️/📋 good "reasoning advisor" reference for your optional AI |
| **Shannon** | Highest benchmark (~96% on XBOW's suite) but white-box | ⚔️ research-grade |
| **SILENTCHAIN** | Sn1per's AI layer; local-model support | 📋 confirms local-LLM demand |

## F. Commercial — autonomous pentest / ASV

| Tool | Cost | Notes | Provx |
|---|---|---|---|
| **Pentera** | $$$$ | Agentless internal pentest, safe exploits + cleanup, replay trail, EASM | ⚔️ the enterprise benchmark; you're the free/governed alt |
| **Horizon3 NodeZero** | $$$$ | Active-adversary attack-path chaining, cloud/K8s/identity, fix verification | ⚔️ most-cited; don't chase breadth |
| **RidgeBot (Ridge Security)** | $$$ | Continuous automated pentest, lower price | ⚔️/📋 pricing reference |

## G. Commercial — Breach & Attack Simulation (BAS)

| Tool | Notes | Provx |
|---|---|---|
| **Cymulate · SafeBreach · AttackIQ · Picus · XM Cyber** | Validate defensive controls ("did detection fire?"); threat-content teams; Picus "1-Click Verify" | 🚫 different product (control validation); 📋 borrow the **retest/verify** idea only |

## H. Commercial — agentic AI pentest (the 2026 wave)

| Tool | Notes | Provx |
|---|---|---|
| **XBOW** | Hundreds of agents + **deterministic validators**; findings surface only after controlled validation; force-multiplier framing | ⚔️/📋 borrow "validate before surfacing" |
| **Terra Security** | Agent swarms + **human-in-the-loop** portal (approve/override); business-context prioritization; continuous | ⚔️/📋 their human-oversight model echoes your governance |
| **Penligent** | Agentic; orchestrates 200+ tools in one workflow | ⚔️ |
| **Escape** | Exploitability proof, multi-step chains, API-focused, dev-friendly reports | ⚔️ |
| **Aikido Security** | Dev-workflow agentic; chains findings into attack paths | ⚔️ |
| **CodeAnt AI** | Offensive + defensive with shared code intelligence ("pre-informed agents") | ⚔️ |
| **HackerAI / Penti** | Guided/assistant agentic tools | ⚔️ |

## I. Commercial — DAST / web-API scanners

| Tool | Notes | Provx |
|---|---|---|
| **Burp Suite Pro** | Industry standard for **manual** web testing; automated scanner has FPs, misses business logic | ⚔️/🔧 users bring their own; optional import |
| **Invicti (Netsparker) / Acunetix** | Automated DAST, proof-based scanning | ⚔️ |
| **StackHawk** | Continuous runtime DAST in CI (complements, not replaces, deep tests) | 📋 CI-runtime framing |
| **Nessus (Tenable)** | Top VA scanner; free for individuals, paid for teams | 🚫 paid; optional user-configured integration only |

## J. Commercial — PTaaS (human / hybrid) & EASM

| Tool | Notes | Provx |
|---|---|---|
| **Cobalt · Synack** | Human pentesters-as-a-service on a platform | 🚫 different model (people) |
| **Astra Security** | Hybrid AI + human-validated; compliance mapping (SOC2/ISO/PCI/HIPAA/GDPR) | 📋 compliance-mapping framing |
| **Hadrian · FireCompass** | Agentic **external** attack-surface management | ⚔️ EASM; not your v1 |
| **Intruder · Pentest-Tools.com · Hexway** | SMB-friendly scanning / self-hosted PTaaS-lite | ⚔️/📋 SMB packaging ideas |

## K. Specialized — mobile & LLM-app testing (separate disciplines)

| Tool | Notes | Provx |
|---|---|---|
| **MobSF** | Free all-in-one mobile static+dynamic (iOS/Android), MASVS-mapped | 🔧 the cheap **mobile-static** path (later) |
| **NowSecure · Ostorlab · Zimperium · Corellium** | Commercial mobile (device farms, dynamic) | 🚫 heavy; out of scope |
| **Garak · PyRIT · General Analysis** | Testing AI apps/agents (prompt injection, MCP) | 🚫 different category |

---

## What this map tells you (vision, not scope-creep)

1. **Your building blocks are all free** (Section B/C) — you never pay to wrap nmap/nuclei/ZAP/sqlmap/BloodHound/MobSF. Enforced by rule **PX-FREE**.
2. **Your best feature ideas are already proven and mostly free to adopt** — Osmedeus's YAML engine, DefectDojo's dedup/EPSS/risk-acceptance/retest + SARIF, Sn1per's pricing mechanic, XBOW/Terra's "validate + human-approve before surfacing."
3. **The whole field validates your wedge:** the 2026 consensus is autonomous-for-breadth + **human-for-validation-and-sign-off**. Nobody in the *free* tier combines governed safety + free UI + deterministic auditability + compliance framing. That's the gap.
4. **What to avoid:** BAS/control-validation, human-PTaaS, dark-web/threat-intel feeds, mobile-dynamic, LLM-app testing, and 90+-integration breadth. Incumbent moats or different products.

## How to use this over time (feeds the rolling roadmap)

- **v0.x (now):** wrap a handful of Section-B engines; ship the deterministic engine + findings + report + free UI/CLI.
- **v0.5:** DefectDojo-style findings intelligence + SARIF; CI diff-scoping.
- **v1.0:** governed AD/infra (wrap BloodHound/Metasploit, approval-gated); optional AI advisor (PentestGPT-style reasoning); compliance mappings (Astra-style).
- **later:** mobile-static (MobSF), cloud (Trivy/ScoutSuite/Prowler) — only if demand appears.

*Revisit this catalog each roadmap cycle: new entrants appear monthly (Terra, Penligent, CodeAnt all launched around early 2026). The categories are stable; the names churn. Stay in the free-governed-deterministic-auditable lane and borrow proven pieces — don't chase the breadth race.*
