# Provx — Competitive Harvest & the CLI

*What to borrow from the tools already out there (so we don't reinvent), how Provx improves on each, the levers that keep Provx genuinely free, and the decision to ship a first-class CLI alongside the UI.*

---

## 1. The rule of borrowing

Borrow **proven mechanics and free building blocks**; never chase **breadth** — that's incumbent territory we'd lose. Every borrowed idea must serve Provx's wedge: *free, governed, deterministic, auditable, safe-for-production.*

---

## 2. The harvest (source → borrow → how Provx improves it)

| Source | What to borrow | How Provx improves / differentiates | Priority |
|---|---|---|---|
| **Sn1per** | Edition split (free core → self-serve Pro → Enterprise) + **asset/workspace quota as the paid lever** | Keep the **UI free** (Sn1per charges for it); monetize scale/hosting, not basic use | Model — now |
| **Sn1per** | Free **CLI** for terminal users | Ship CLI **and** UI free, both over one API (§4) | Feature — near |
| **Sn1per** | Workspaces (logical grouping of assets) | Map to our **engagement** model (already have it) | Align — now |
| **Sn1per** | Mobile static (ReverseAPK) | Add via **MobSF** wrapper later, governed | Later |
| **Strix** | **CI/CD diff-scoping** (scan only changed scope in a PR) | Deterministic + governed; great for the CI gate | Feature — mid |
| **Strix** | Multi-LLM via LiteLLM + local models | Already planned; AI stays **optional** | Have it |
| **Strix** | PoC validation before surfacing a finding | Our **deterministic validators** + human confirm | Have it |
| **DefectDojo** | Intelligent dedup · EPSS prioritization · risk-acceptance audit trail · retest + auto-close | Core of our findings pipeline; ties to audit lane | Feature — near |
| **DefectDojo** | **SARIF** import/export; tool-normalization | Interop, not walled garden | Feature — near |
| **Osmedeus / reNgine** | Auditable **YAML workflow/playbook engine**; scan profiles; scheduling | Our deterministic "brain" (already the plan) | Have it |
| **Faraday** | Normalize many tools → one de-duplicated report; agents for distributed scans | Normalization now; distributed agents much later | Mixed |
| **OWASP Benchmark** | Accuracy scorecard (TP/FP/FN) | Our CI accuracy gate / oracle | Have it |

Most of the "near" items are things a small team can wrap cheaply because the hard part already exists as free OSS.

---

## 3. The free-usage levers (what makes Provx genuinely free — and adoptable)

These are *why* someone picks Provx over a paywalled tier:

1. **Both CLI and UI are free.** Sn1per's Community is CLI-only; the Web UI/scheduling/reports are paid. Provx gives the governed **UI + CLI + API** free.
2. **No asset/scan caps in the free core.** Monetize *scale and convenience* (hosted SaaS, SSO, multi-tenant, compliance packs, support) — never basic scanning.
3. **Standalone CLI install** (`pipx install provx`) — use it without deploying the whole stack. Lowest-friction on-ramp.
4. **Ride free community content** (Nuclei templates, CISA KEV) — "updates" cost you nothing and stay current automatically.
5. **Wrap free OSS engines** (nmap, nuclei, ZAP, sqlmap) — zero per-tool license cost; invoke as subprocesses (see rule PX-LICENSE).

Net: the free tier is genuinely useful and uncrippled; the paid edges are scale/hosting/compliance — the Sn1per pricing *mechanic* without the "UI behind a paywall" downside.

---

## 4. The CLI — a first-class interface (decision)

Terminal-first users are a real audience, and the CLI is also how Provx plugs into CI/CD and headless/air-gapped environments. Good news: it's **nearly free to build** because of the monorepo design.

### Architecture: one API, three front-ends
```
                 ┌──────────────┐
   Web UI  ─────▶ │              │
   CLI     ─────▶ │  FastAPI API │ ──▶ deterministic engine, findings, reports
   Scripts ─────▶ │  (one core)  │
                 └──────────────┘
```
The CLI is a **thin wrapper over `packages/client`** (the API client that already exists in the monorepo). UI and CLI both call the same API → **feature parity for free**, no duplicated logic, no drift. Everything the UI can do, the CLI can do, because both are just callers.

### Command shape (maps to the domain)
```
provx engagement create --name "Acme" --scope acme.com --mode passive
provx scan run --engagement acme --module web --auth cookie
provx findings list --engagement acme --severity high --json
provx playbook run web-baseline --target https://app.acme.com
provx approve <finding-id>        # exploitation still gated + audited
provx report generate --engagement acme --format pdf
```

### Non-negotiables for the CLI
- **Governance parity, not a bypass.** The CLI is a client of the API, so it inherits *every* safety gate — scope, passive/active, approval-gated exploitation. There is no "CLI backdoor" around the rules.
- **Machine-friendly output**: `--json` and **SARIF** output, meaningful **exit codes** (non-zero on failure/policy breach) so it drops into CI pipelines and pre-commit/PR gates.
- **Local or remote**: point the CLI at a local instance or a remote Provx server (`--server`), with token auth.
- **Deterministic-first**: works fully with **no AI**; AI advisor is an opt-in flag.
- **Standalone installable** (`pipx install provx`) so people can start from the terminal without the UI stack.

### Why this is a differentiator, not just parity
Sn1per gives a free CLI but charges for the UI; Strix is CLI/CI-first but AI-required. Provx offers a **free governed CLI *and* free governed UI over one API**, deterministic by default — the terminal guru and the report-writing consultant use the *same* tool, same rules, same evidence trail.

---

## 5. What NOT to borrow (stay out of incumbent territory)

- **A threat-intel / dark-web feed operation** — that's a content-team moat; we ride free community feeds instead.
- **90+ integrations on day one** — breadth is a trap; grow the adapter list as contributors arrive.
- **Autonomous exploitation as the headline** — Strix/Sn1per own "attacker's view"; ours is governed/safe.
- **Paid commercial-tool integrations early** (Nessus, Burp Pro) — they require *users'* paid licenses; start with free OSS engines.

---

## 6. Where this slots in

- **CLI:** build a minimal `provx` CLI right after the walking-skeleton API exists (a single `provx scan` + `provx findings list` over `packages/client`), then grow with the API. Add a `packages/cli` (or `cli/`) now as an empty placeholder so the structure is reserved.
- **Findings intelligence** (dedup/EPSS/risk-acceptance/retest) and **SARIF export:** the v0.5 "depth" phase.
- **CI diff-scoping:** with the CLI + API, once scanning is real.
- **Monetization mechanics** (edition split + quota lever): document now, implement only when there's adoption.

*Bottom line: we assemble proven, mostly-free pieces into a governed whole, keep the CLI and UI both free over one API, and monetize scale — not basic use. That's how we stay useful and non-redundant next to a 10-year incumbent, without burning ourselves out building their breadth.*
