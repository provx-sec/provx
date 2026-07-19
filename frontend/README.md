# Provx frontend

The Provx web console — [Next.js](https://nextjs.org) (App Router) + Tailwind CSS +
TypeScript.

> **Status: Phase 1 skeleton.** A single placeholder page. The console (engagements,
> scans, findings, approvals, reports, AI analyst) is built out in later phases — see
> [`../docs/PenForge-Local_Build_Blueprint.md`](../docs/PenForge-Local_Build_Blueprint.md) §12.

> **Framework note:** the ROADMAP architecture diagram mentions "React/Vite", but the
> locked decision (Master Checklist) is **Next.js**, which is what this app uses.

## Run with Docker (recommended)

From the repo root:

```bash
docker compose up --build frontend
```

Served at http://localhost:3000.

## Run locally

```bash
cd frontend
npm install
npm run dev
```

## Checks

```bash
npm run lint        # eslint
npm run typecheck   # tsc --noEmit
```

These map to the `lint` and `types` CI gates.
