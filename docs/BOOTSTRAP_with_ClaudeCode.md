# Provx — Bootstrap Runbook (Claude Code + GitHub CLI)

*How to stand up the whole repo — license, governance files, labels, milestones, branch protection, and the project board — mostly automated, so you're not clicking through everything by hand. Claude Code writes the files and runs the commands; you approve each step.*

---

## 0. Install once (10–15 min)

- **Node.js 18+** (only needed for the npm install method): `node --version`.
- **GitHub CLI (`gh`)**: install, then `gh auth login` (choose GitHub.com → HTTPS → login via browser).
- **Claude Code**: native installer (recommended) or `npm install -g @anthropic-ai/claude-code`. Verify with `claude --version` and `claude doctor`. Requires a paid Claude plan (Pro/Max/Team) or Anthropic Console API credits — the free plan doesn't include it. Docs: `code.claude.com/docs/en/setup`.
- Put the five planning docs (blueprint, ROADMAP, PROJECT_SETUP_PLAYBOOK, VALIDATION, START_HERE checklist) into a local folder `provx/docs/` — Claude Code will read them as the source of truth.

---

## 1. The Apache-2.0 license — the simple truth

You do **not** register, apply for, pay for, or ask permission for Apache-2.0. It's a public license you simply *include* in the repo. That's the whole thing.

**What you provide:**
1. A file named `LICENSE` at the repo root containing the **full, verbatim** Apache-2.0 text (from `apache.org/licenses/LICENSE-2.0.txt`).
2. Fill the one placeholder in the appendix: `Copyright 2026 <Your name or "The Provx Contributors">`.
3. *(Optional, good practice)* a `NOTICE` file, and a short license header at the top of source files (the Apache appendix gives the boilerplate).

**Three ways to add it — pick one:**
- **Easiest:** when you create the repo, choose the Apache-2.0 template (web UI "Add a license", or `gh repo create ... --license apache-2.0`). GitHub drops the `LICENSE` file in for you.
- **Claude Code:** tell it "add an Apache-2.0 LICENSE file with copyright 2026 <name> and a NOTICE file."
- **Manual:** copy the text from the URL above into `LICENSE`.

**Note on contributors:** with Apache-2.0 + DCO, each contributor keeps their copyright but licenses their contribution under Apache-2.0; the `Signed-off-by` line records it. That's all you need for open core — no copyright assignment.

---

## 2. Let Claude Code scaffold + write the governance (the big time-saver)

In the `provx/` folder, run `claude`, then paste a prompt like this:

```
Read everything in ./docs. This is an open-source, Apache-2.0, open-core project
called Provx (a governed automated security validation platform).

Scaffold the repository to match those docs:
1. Create the folder structure: backend/, frontend/, docs/, lab/, wordlists/, .github/
2. Add an Apache-2.0 LICENSE (copyright 2026 <MY NAME>) and a NOTICE file.
3. Generate these governance files, consistent with docs/ROADMAP.md and
   docs/PROJECT_SETUP_PLAYBOOK.md: README.md, CONTRIBUTING.md (DCO sign-off +
   adapter cookbook + Definition of Done), CODE_OF_CONDUCT.md (Contributor
   Covenant), SECURITY.md, RESPONSIBLE_USE.md, GOVERNANCE.md, SUPPORT.md,
   CHANGELOG.md, CODEOWNERS.
4. Add .github/PULL_REQUEST_TEMPLATE.md (the DoD checklist) and
   .github/ISSUE_TEMPLATE/ forms for bug, feature, new-adapter, detection-issue.
5. Add labels.yml with our label taxonomy, and .github/workflows/ci.yml with
   stub jobs: dco, lint, types, unit-fixtures, accuracy, secrets-deps (passing no-ops
   for now).
6. Add a sensible .gitignore for Python + Node, and a docker-compose.yml + Makefile
   skeleton.
Initialize git and stage everything, but do not push yet — show me the tree first.
```

Claude Code writes all of it. Review the tree, ask it to fix anything, then move on.

---

## 3. Create the GitHub repo + push (Claude Code runs `gh`)

Tell Claude Code, or run yourself:

```bash
# from inside the provx/ folder, with the initial commit made
gh repo create provx --public \
  --description "Governed open-source automated security validation — web, API & infra. Safe by default." \
  --source . --remote origin --push
```

Then set topics:

```bash
gh repo edit --add-topic security --add-topic penetration-testing \
  --add-topic vulnerability-scanner --add-topic security-validation \
  --add-topic devsecops --add-topic self-hosted --add-topic open-source
```

---

## 4. Labels, milestones, branch protection (Claude Code runs `gh`)

**Labels** (either loop `gh label create`, or add a labels-sync Action reading `labels.yml`):

```bash
gh label create "type:adapter"        --color 1D76DB --description "New tool adapter" --force
gh label create "needs-fixture"       --color FBCA04 --description "Missing test fixture" --force
gh label create "needs-accuracy-review" --color D93F0B --description "Accuracy gate must confirm" --force
gh label create "safety-review"       --color B60205 --description "Touches intrusive/exploit path" --force
gh label create "good-first-issue"    --color 7057FF --description "Good for newcomers" --force
# ...ask Claude Code to generate the full set from labels.yml
```

**Milestones** (via the API):

```bash
for m in "v0.1 MVP" "v0.5 Depth" "v1.0 Full" "v2.0 Reach"; do
  gh api repos/{owner}/provx/milestones -f title="$m" >/dev/null
done
```

**Branch protection on `main`** — the fiddly one; easiest in the web UI (Settings → Branches → Add rule): require a PR, require status checks to pass, require 1 approval, require linear history, no direct pushes. Or have Claude Code do it via `gh api --method PUT repos/{owner}/provx/branches/main/protection` with the JSON body.

---

## 5. GitHub Projects board — step by step

The board is visual and one-time, so the **web UI is the simplest path**:

1. Go to `github.com`, click your avatar → **Projects** → **New project**.
2. Choose the **Board** template → name it **"Provx Roadmap"** → **Create**.
3. **Add custom fields** (Project menu → **Settings** → **+ New field**), all single-select:
   - **Status**: Backlog · Ready · In progress · In review · Blocked · Done
   - **Area**: core · web · api · infra-ad · ai · report · platform-sec · docs · ci
   - **Priority**: P0 · P1 · P2 · P3
   - **Effort**: XS · S · M · L · XL
   - **Type**: feature · bug · adapter · use-case · docs · chore
4. **Create 3 views** (**+ New view**): a **Board** grouped by Status, a **Table**, and a **Roadmap** (timeline — needs a Date or Iteration field).
5. **Link the repo**: in the project, **+ Add item** → type `#` to pull in issues from `provx`. New issues you create can be auto-added.

**CLI alternative (optional, Claude Code can do it):** grant the project scope once with `gh auth refresh -s project`, then `gh project create --owner "@me" --title "Provx Roadmap"`, and `gh project field-create …` for the fields. Check `gh project --help` for exact flags — the web UI is honestly faster for a one-time board.

---

## 6. Seed the first issues (Claude Code runs `gh`)

Turn the walking-skeleton tasks (START_HERE Phase 3) into issues:

```bash
gh issue create --title "Walking skeleton: scope allow-check for one target" \
  --body "See docs/ROADMAP.md §3" --label "type:feature,area:core" --milestone "v0.1 MVP"
gh issue create --title "Adapter: run httpx within scope, normalize to Finding" \
  --label "type:adapter,needs-fixture,area:web" --milestone "v0.1 MVP"
# ...one per skeleton step; then drag them onto the board.
```

---

## Division of labor

| Claude Code does | You do by hand |
|---|---|
| Write all governance/community files from our docs | Confirm the name + buy the domain |
| Add the Apache-2.0 LICENSE + NOTICE | Trademark check (later, if monetizing) |
| Create the repo, push, set topics | Click through the Projects **board** (or let it try via `gh project`) |
| Create labels, milestones, first issues | Approve each `gh` command it proposes |
| Draft `ci.yml`, templates, `.gitignore`, compose/Makefile | Review the generated files for tone/accuracy |
| Set branch protection via `gh api` | (or set protection in the Settings UI) |

**One habit:** review what Claude Code proposes before you let it push — it's fast, but the governance wording and the license copyright line are worth a human read. After this runbook, Phase 1 of your master checklist is essentially done.
