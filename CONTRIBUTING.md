# Contributing to Provx

Thank you for helping build a safe, governed, open security-validation platform.
This guide is the practical companion to the standard in
[`docs/ROADMAP.md`](docs/ROADMAP.md) and the workflow in
[`docs/PROJECT_SETUP_PLAYBOOK.md`](docs/PROJECT_SETUP_PLAYBOOK.md). If a PR is clever
but violates the **Safety Contract** or the **Definition of Done**, it will not be
merged — so please read those first.

Before contributing offensive tooling, also read
[`RESPONSIBLE_USE.md`](RESPONSIBLE_USE.md) and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

---

## 1. Ground rules

- **Branching — GitHub Flow.** `main` is always releasable. Work on short-lived
  branches named `type/short-desc`, e.g. `adapter/nuclei-graphql`, `fix/scope-check`.
- **Conventional Commits.** Prefix commit subjects with `feat:`, `fix:`, `docs:`,
  `chore:`, `test:`, `refactor:`, etc. This drives the automated changelog and version
  bumps.
- **Semantic Versioning** (`MAJOR.MINOR.PATCH`).
- **Open or claim an issue first** for anything non-trivial, so work isn't duplicated
  and scope/safety are agreed up front.

---

## 2. Developer Certificate of Origin (DCO) — required

Provx uses the [DCO](https://developercertificate.org/) instead of a heavy CLA. You
keep the copyright to your contribution; the sign-off certifies you have the right to
submit it under Apache-2.0.

**Every commit must be signed off.** Add the trailer automatically with `-s`:

```bash
git commit -s -m "feat(adapter): add httpx web-probe adapter"
```

This appends a line to the commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

Use your real name and an email you can be reached at. The `dco` CI gate fails any PR
with an unsigned commit. To fix an existing branch:

```bash
git rebase --signoff main    # sign off every commit on the branch
git push --force-with-lease
```

---

## 3. The contribution flow

```
Open/claim issue → Definition of Ready met? → branch + code + tests + fixture
  → open PR (fill the DoD checklist, sign off) → CI gates → CODEOWNER review
  → squash-merge to main → auto changelog + version → next release
```

### Definition of Ready (before work starts)
An issue is *Ready* only when it has: a clear problem statement, acceptance criteria,
an **Area** label, a **safety classification** (`passive` / `intrusive`), and — for a
detection or adapter — a note on **how accuracy will be tested** (lab target + expected
findings).

### Definition of Done (before merge) — the PR checklist
A change is *done* only when **all** of these are true (the PR template enforces them):

- [ ] **Safety** — tagged `passive` or `intrusive`; intrusive gated to Active mode and
      never runs in passive/test; no check writes/deletes/modifies target state unless
      it is an approval-gated exploit.
- [ ] **Signal quality** — findings de-duplicated; each carries a severity + CVSS and
      maps to **≥1 MITRE ATT&CK technique**; no low-value "info" spam.
- [ ] **Tested** — a **fixture test** is included (recorded raw tool output → expected
      normalized findings), so a tool changing its output format fails CI, not users.
- [ ] **Accuracy gate passes** — no new false positives on clean lab targets; catches
      the intended vuln in the lab.
- [ ] **Documented** — plugin manifest and one line of docs updated.
- [ ] **Platform security** — no secret logged; state-changing actions audit-logged.
- [ ] **DCO** — every commit signed off.

---

## 4. Adapter cookbook — add a tool in one place

Extending Provx should not require touching the core. A tool adapter is a small,
self-contained plugin that is auto-registered via an entry point. The recipe:

1. **Copy the template adapter** into `packages/adapters/` (a starter template ships
   with the walking skeleton).
2. **Fill the manifest** — `name`, `category` (web/api/infra-ad/…), safety class
   (`passive` / `intrusive`), and the external tool it wraps.
3. **Implement `build_command`** — turn the selected use-cases + scope + auth into the
   exact command to run. Enforce scope at this boundary; never trust it upstream.
4. **Implement `parse_output`** — normalize the tool's raw output into `Finding`
   objects (severity, CVSS, ≥1 ATT&CK technique, evidence, remediation).
5. **Add a fixture test** — commit a recorded sample of the tool's raw output plus the
   expected normalized findings. This is mandatory (see DoD).
6. **Open a PR** — fill the DoD checklist, sign off. No core edits needed; the core
   discovers your plugin automatically.

See [`packages/adapters/README.md`](packages/adapters/README.md) for the current
contract and [`docs/ROADMAP.md`](docs/ROADMAP.md) §5 for the plugin model diagram.

---

## 5. Local development

```bash
cp .env.example .env
docker compose up --build      # brings up backend, frontend, db, redis
make help                      # list available tasks
```

Each service (`backend/`, `frontend/`) builds and runs independently via its own
Dockerfile, so you can iterate on one without the others.

### Before you push
- **Backend:** `ruff` (lint/format) + `mypy` (types) + `pytest` (unit + fixtures).
- **Frontend:** `eslint` + `prettier` + `tsc`.
- Run the **accuracy harness** against `lab/` if you touched a check or adapter.

CI runs these as **path-filtered gates** — a backend-only change runs the backend
gates, and so on. All gates must be green to merge.

---

## 6. Good first contributions

Look for `good-first-issue` and `help-wanted` labels. Common newcomer wins: "add
adapter for X", "add use-case Y", "add report template Z", "add LLM provider W". The
label taxonomy lives in [`labels.yml`](labels.yml).

---

## 7. License of contributions

By contributing, you agree that your contributions are licensed under
[Apache-2.0](LICENSE), and your DCO sign-off records that you have the right to do so.
No copyright assignment is required.
