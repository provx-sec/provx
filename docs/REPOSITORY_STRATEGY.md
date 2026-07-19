# Provx — Repository Strategy (Decision Record)

*Why Provx is a single monorepo inside a free GitHub org — not many repos — and when that changes.*

---

## Decision

- **A free GitHub Organization**, with you as sole owner. It's a neutral home for the name/trademark and gives Teams + CODEOWNERS-by-team later. Free for public repos.
- **One monorepo** (`provx`) inside it. Isolation comes from **workspaces + path-filtered CI + independent packaging**, not from splitting repos.

## Why monorepo (for our stage)

The instinct "don't jam two apps in one folder" is right; the fix is *internal* isolation, not many repos. A monorepo is one repository holding cleanly-separated packages/services (same model as Yarn workspaces).

| | Monorepo (chosen) | Many repos (rejected for now) |
|---|---|---|
| "Push one update" across parts | **one atomic PR** | N coordinated PRs + version matrix |
| Admin overhead (CI, labels, governance) | **once** | ×N |
| Cross-cutting schema change (e.g. Finding model) | **trivial** | painful |
| "Install only the API/client" | via **published package** | native but heavy |
| Per-part CI isolation | **path-filtered workflows** | native |
| Best when | few devs, coupled parts, early | many teams, loose coupling, mature |

Provx is a solo dev with tightly-coupled parts at the start → textbook monorepo. Premature polyrepo is over-engineering (against our own rules).

**Key point:** your goal of *"we push one update"* is **easier** in a monorepo. Splitting repos would force multi-repo coordination — the opposite of what you want.

## Structure (isolation inside one repo)

```
provx/                    # one repo, in the org
├── backend/    (FastAPI — the API; publishes OpenAPI spec)
├── frontend/   (Next.js — independent build)
├── packages/
│   ├── adapters/  (tool-adapter plugin SDK — publishable to PyPI)
│   └── client/    (thin API client — installable standalone)
├── workflows/   (deterministic YAML playbooks)
├── lab/  ├── wordlists/  ├── docs/
├── .github/workflows/    # path-filtered: backend change → backend CI only
└── docker-compose.yml    # each service builds & runs independently
```

## "Someone only wants the API" — solved by packaging, not repos

- Publish the **OpenAPI spec** + a small **client library** (`packages/client`) to PyPI/npm → anyone `pip install`s it without cloning the frontend.
- The API runs as its **own Docker Compose service** independently.
- API docs live on their own page.

They consume the API without ever touching the frontend — from the monorepo.

## When to split later (extract only when a piece earns it)

Break out a piece **only** when it has a genuinely independent life:
- **Community plugin/adapter repos** (like `nuclei-templates` is separate from `nuclei`).
- A widely-adopted **client SDK**.
- The **private enterprise/paid** repo (already planned separate — that's the open-core boundary).

"Start monorepo, extract when there's a real reason" is standard and reversible; merging many repos back is painful.
