---
name: x-implement
description: Canonical provx work command. Phase 0 = parse + clarify + scope-lock (uses PROMPT_GENERATOR.md framework). Phase 1 = implement scoped changes. Phase 2 = self-check + auto-fix critical violations + report. Auto-fires on PG / PG: prefix or PROMPT_GENERATOR.md mention.
argument-hint: "<task description> [--repo <name>] [--plan-only] [--skip-prompt] [--no-check] [--auto] [--dry-run]"
allowed-tools: [Read, Edit, Write, Glob, Grep, Bash]
---

# /x-implement — The provx canonical work command

You are doing work in the provx project. This is the **single canonical entry point** for any non-trivial coding task. It runs in **3 phases**:

| Phase | What happens | Skip flag |
|---|---|---|
| **Phase 0** | Parse + clarify + scope-lock (PROMPT_GENERATOR.md framework + ambiguity scoring) | `--skip-prompt` |
| **Phase 1** | Implement the scoped changes | `--plan-only` (stops after Phase 0) |
| **Phase 2** | Self-check + auto-fix critical violations + report | `--no-check` |

Never skip a phase silently. Each phase must complete (or be explicitly skipped via flag) before moving to the next.

## Triggers

This skill fires on:
1. **Explicit invocation** — `/x-implement <task>`
2. **PG shorthand** — message starts with `PG` or `PG:` (case-insensitive). Defaults to **plan-only** (`--plan-only` is implied) — the user reads the brief, then types "go" to proceed with Phase 1+2.
3. **Reference** — message mentions `PROMPT_GENERATOR.md` or `@.ai/PROMPT_GENERATOR.md` → fires `/x-implement --plan-only`
4. **Auto-trigger** — `/x-prompt <task>` is an alias that calls this skill with `--plan-only`

## Input sources (task description)

The task description can arrive in two ways — always check BOTH before proceeding:

1. **Inline (short tasks)** — `/x-implement fix the login bug --repo backend`. Everything in `$ARGUMENTS` that isn't a recognised flag IS the task description.
2. **Prior message (long/detailed tasks)** — The user types their full description as a normal chat message, then on the next message types `/x-implement` (possibly with flags only, e.g. `--repo backend`). In this case `$ARGUMENTS` is empty or flag-only; **use the most recent user message from conversation context as the task description**.

**Decision rule**: After stripping all recognised flags from `$ARGUMENTS`, if the remaining text is empty or under ~15 words, look at the conversation history above for the user's most recent message that reads like a task description. That message IS the task. Do not ask the user to repeat themselves.

---

## Argument parsing

Parse `$ARGUMENTS` for:

- **Task description** (everything that isn't a flag) — what to do; if absent/short, see "Input sources" above
- `--repo <name>` — restrict to one detected repo (direct child of `/Users/mac/Projects/mine/provx` containing `.git/`). If absent, infer from the task.
- `--plan-only` — run Phase 0 only, then STOP. Output the locked scope contract for the user to review/share/copy.
- `--skip-prompt` — skip Phase 0 entirely. Use only for trivial tasks (typo, rename, one-line fix).
- `--no-check` — skip Phase 2. Print a warning at the top.
- `--no-tests` — skip Phase 1.5 (test scaffolding). Default is OFF — tests ARE required. Only use for pure visual UI iteration on a screen you've already tested, or for trivial fixes.
- `--auto` — when invoked via PG, skip the confirmation step at the end of Phase 0 and proceed directly to Phase 1+2. Without `--auto`, plan-only mode requires user confirmation.
- `--dry-run` — explain what each phase WOULD do, don't touch files.

**PG default**: `PG <task>` is equivalent to `/x-implement <task> --plan-only`. If the user wants to skip the confirmation step and just go: `PG <task> --auto` is equivalent to `/x-implement <task>` (full Phase 0 → Phase 1 → Phase 2).

---

## Phase 0 — Parse + Clarify + Scope-lock

This is the planning phase. Goal: convert a messy task description into a locked scope contract that Phase 1 must stay inside.

### Step 0.1 — Read the foundation files

Read in this order (unless `--skip-prompt`):

1. `/Users/mac/Projects/.ai/PROMPT_GENERATOR.md` — fresh, every time (the framework you'll apply)
2. `/Users/mac/Projects/mine/provx/CLAUDE.md` — project anchor
3. `/Users/mac/Projects/mine/provx/.claude/rules.md` — full rules file
4. Memory files at `/Users/mac/.claude/projects/-Users-mac-Projects-mine-provx/memory/` (already loaded into your context — re-reference consciously):
   - `project_scope.md`
   - `project_features.md`
   - `project_audits.md`
   - `project_vendors.md`
   - `feedback_seniority_and_workflow.md`

If you skip this step (because `--skip-prompt`), say so explicitly: "⚠ Skipping Phase 0 — no scope-lock will be enforced." Then go straight to Phase 1.

### Step 0.2 — Parse the task

Apply STEP 1 of PROMPT_GENERATOR.md ("Intelligent Parsing"). Extract from the user's input:

- 📋 **Instructions** — action verbs (add, change, fix, optimize, implement, create, remove)
- 🔒 **Constraints** — restrictions (don't use X), standards (SOLID, TypeScript), limits (under 200ms), best practices, technology choices
- 🎯 **Expectations** — success criteria, test scenarios, performance targets, UX requirements
- 🏗️ **Context clues** — tech mentions, current state, project details, the affected screen/endpoint

### Step 0.3 — Detect repo(s) and existing context

Look for which repo(s) the task touches. Detected repos are direct children of `/Users/mac/Projects/mine/provx` that contain a `.git/` directory. Map task keywords to repo names using the project's CLAUDE.md as the source of truth (stacks per repo live there).

Multi-repo tasks must list ALL relevant repos. If unclear, this counts toward the ambiguity score.

For each affected repo, look up:
- **Audit findings** that touch this code area: `/Users/mac/Projects/mine/provx/audits/<repo>/99_FINDINGS.md` and the relevant module/section/feature MDs
- **Spec sections** that document this feature: `/Users/mac/Projects/mine/provx/specs/`
- **Existing similar code** (rule Q-11 — reuse before create): `Glob` for files with similar names, `Grep` for similar function names
- **i18n infrastructure** (rule W-04): detect if the project is multilingual by checking for any of:
  - Flutter: `l10n.yaml`, `lib/l10n/*.arb`, `flutter_localizations` + `intl` in `pubspec.yaml`
  - Next.js / React: `next-intl` / `next-i18next` / `i18next` in `package.json`, `messages/`, `locales/`, `app/[locale]/`
  - Laravel: `lang/<locale>/` directories
  - Nuxt / Vue: `@nuxtjs/i18n` / `vue-i18n`, `locales/*.json`, `i18n.config.*`
  - React Native: `i18next` / `react-i18next`, `locales/*.json`
  - Django: `LocaleMiddleware`, `locale/*/LC_MESSAGES/*.po`

  **If i18n IS configured** AND the task introduces new user-facing strings: the scope contract MUST include "add keys to EVERY locale file + consume via the i18n function" as an explicit Phase 1 step and acceptance criterion. Brand / proper nouns (app name, "Google", "Apple", etc.) are exempt. See W-04 + stack-specific rule (M-FL-13 for Flutter).

  **If i18n is NOT configured** and the user is ADDING multilingual support: treat it as a foundational scope-expansion — stop and confirm scope with the user before proceeding (it touches `MaterialApp`, `pubspec.yaml`, and every screen with user-facing text).

### Step 0.4 — Score ambiguity (OPINIONATED — this controls whether to ask questions)

Score the parsed task on 4 axes. **If ANY axis is below threshold, ask a question about THAT specific axis.** Don't ask vague questions.

| Axis | Score 3 (clear) | Score 2 (mostly clear) | Score 1 (ambiguous) | Score 0 (unknown) |
|---|---|---|---|---|
| **SCOPE** (which files/repos) | Specific file paths or function names mentioned | Specific feature + repo identified | Feature mentioned but multi-repo | "fix the thing", "improve performance" |
| **CONSTRAINTS** (what NOT to do) | Explicit constraints listed | Some constraints listed; rest can be inferred from rules.md | No constraints, all inferred from defaults | Task contradicts a rule (P-01 escrow, etc.) |
| **SUCCESS CRITERIA** (how to know it's done) | Explicit acceptance criteria | Implied by the action verb (e.g. "fix bug X" → bug X no longer reproduces) | Vague (e.g. "make it better") | Subjective with no measurable signal |
| **PRIOR ART** (does similar code exist) | Confirmed via Glob/Grep | Likely exists, easy to find | Unclear if exists | Can't tell without significant search |

**Decision rule:**
- All 4 axes ≥ 2 → **NO questions**, proceed to scope contract directly
- 1 axis at 1 → **ONE targeted question** about that axis
- 2+ axes at 1, OR any axis at 0 → **2-3 targeted questions** + STOP for answers
- Any axis at 0 AND task contradicts a rule → **REFUSE the task**, explain the rule, ask for an alternative interpretation

**Hard rule: max 3 questions.** If you have more than 3, the task is too vague — ask the user to add detail rather than firing 5 questions.

### Step 0.5 — Cross-reference rules (rule collision check)

Walk the parsed Instructions + Constraints against `.claude/rules.md`. Specifically check:

- **P-rules** (product scope): Does the task add escrow (P-01)? Commission math (P-02)? Subscription UI (P-03)? iOS code (P-04)? — these are HARD blocks. If the task asks for any of these, STOP and refuse.
- **A-rules** (auth): Does the task touch login/tokens/role checks? Apply A-01 through A-09.
- **S-rules** (security): Does the task involve secrets/env/proxies?
- **X-rules** (audit-derived): Does the task touch code that the audit flagged broken? Reference the finding.
- **Q-rules** (quality): Will the implementation need tests (Q-10), need to reuse existing code (Q-11), need to avoid over-comments (Q-12)?
- **S-13** (error UX): Will the task add new error paths? Then env-gated user-friendly errors are required.
- **PERF-rules** (performance / Web Vitals): Does the task touch ANY frontend page, route, component, image, font, provider, dependency, or loading state? Then performance is in scope and must be designed in NOW, not checked afterward. Apply the PERF rules from the project's frontend rule module (e.g. PERF-01 no opacity-0 on the LCP element, PERF-02 loading states need a real contentful element for FCP, PERF-03 above-fold image priority, PERF-04/05 don't ship heavy or disabled-feature deps in the shared/root bundle — code-split them, PERF-06 font preload discipline, PERF-07 loading-state streaming, PERF-08 cache public SSR data, PERF-09 verify the production bundle before deploy). Performance applies to EVERY surface, not just routes a Lighthouse / Speed-Insights report flagged.

**List the rules that will apply** in the scope contract. The user should see which rules constrain the implementation.

### Step 0.6 — Output the scope contract

This is the deliverable of Phase 0. It's a structured brief the user explicitly accepts. Once accepted, **Phase 1 is FORBIDDEN from going outside it**.

Format:

```markdown
## 📐 SCOPE CONTRACT — Phase 0 lock

### Task summary
<one paragraph: what the user asked for, in clear language>

### Parsed input
- 📋 **Instructions**:
  - [Item 1]
  - [Item 2]
- 🔒 **Constraints**:
  - [User-stated constraint 1]
  - [Inferred constraint from rules.md: e.g. "A-03 — JWT in HttpOnly cookies, not localStorage"]
- 🎯 **Expectations**:
  - [Success criterion 1]
- 🏗️ **Context**:
  - Repo(s): [...]
  - Affected files (predicted): [...]
  - Existing similar code: [...]

### Rules that will apply
| Rule | Why it applies |
|---|---|
| `<id>` <title> | <one-line reason> |

### PG principles applied (from PROMPT_GENERATOR.md + senior baseline)
ALWAYS list these explicitly, so the user can see the skill is enforcing them:
- Senior architect / full-stack / UI-UX / DBA / security baseline (Google/Apple-level judgment)
- SOLID + DRY, no over-engineering, no premature abstraction
- Reuse before create (Q-11) — grep codebase first; new helpers go in shared locations
- No over-comments (Q-12) — explain WHY not WHAT
- ISO 27001 + OWASP Top 10 awareness
- Env-gated user-friendly errors (S-13) — no raw server / SQL / stack / third-party errors in production UI
- Tests run with `--env=testing` / `APP_ENV=testing` / `.env.testing` (Q-10)
- Performance / Web Vitals designed in for any frontend change (PERF rules) — LCP element paints immediately, loading states are FCP-contentful, no heavy/disabled deps in the shared bundle, verify the production bundle before deploy. Do it right while implementing, not as a post-hoc fix.
- Read context (CLAUDE.md + rules + memory + audit) before writing code (W-01)

### Audit / spec references
- Audit: [<file>](<audit-md-link>) — <one-line>
- Spec: [<file>](<spec-md-link>) — <one-line>

### Ambiguity score
| Axis | Score | Note |
|---|---|---|
| Scope | X / 3 | <if not 3, why> |
| Constraints | X / 3 | <if not 3, why> |
| Success | X / 3 | <if not 3, why> |
| Prior art | X / 3 | <if not 3, why> |

### Out of scope (explicitly excluded)
- [Things this task will NOT touch]
- [Refactors that won't happen]
- [Adjacent files left alone]

### Acceptance criteria
- [ ] [Specific testable criterion 1]
- [ ] [Specific testable criterion 2]
- [ ] Matching test file(s) exist for each new unit of behavior (W-02 + M-FL-12) — OR `--no-tests` was explicitly passed and justified
- [ ] Tests run via the project's testing env (Q-10): `NODE_ENV=testing` / `APP_ENV=testing` / `flutter test --dart-define=ENV=testing` / etc.
- [ ] All affected files pass `/x-check`

### What I'll do in Phase 1
1. [Concrete step 1 with file path]
2. [Concrete step 2 with file path]
3. [Concrete step 3 with file path]
4. **Scaffold tests** (Phase 1.5) for each new feature/widget/endpoint (unless `--no-tests` is set). Path the project's convention: `test/**/*_test.dart` (Flutter), `__tests__/*.test.ts` (Node), `tests/Feature/**Test.php` (Laravel), etc.

### What I'll do in Phase 2
- Read every file modified in Phase 1
- Apply every rule's Detect pattern from `.claude/rules.md`
- **Check W-02 + M-FL-12**: every new feature file has a matching test file (unless `--no-tests` was set and justified)
- Auto-fix critical (S-/A-/X-/P-) violations introduced by my work
- Report Medium violations that need structural changes
- Re-run detection after each fix to verify it resolved
```

### Step 0.7 — Wait for confirmation OR proceed

Three behaviors based on flags:

1. **`--plan-only`** — Output the scope contract. **STOP**. Print: "Phase 0 complete. Plan-only mode — Phase 1 + 2 not run. Reply 'go' to proceed, or refine the scope above and re-invoke."
2. **`--auto`** — Output the scope contract. **Immediately proceed** to Phase 1 without waiting.
3. **Default (no flag)** — Output the scope contract. **Ask one yes/no question**: "Scope locked. Proceed with Phase 1?" Wait for confirmation. If the user says no, refine and re-output the contract.

If the user typed `PG <task>`, assume `--plan-only` was set unless they ALSO typed `--auto`.

---

## Phase 1 — Implement (scope-locked)

This is the doing phase. **You are forbidden from going outside the scope contract from Phase 0.**

### Step 1.1 — Confirm the contract is loaded

Re-state the scope contract back briefly: "Implementing per scope contract: <one-line summary>. Files in scope: [list]. Files out of scope: [list]."

### Step 1.2 — Read every file you'll modify, in full

Use the Read tool. Don't edit a file you haven't read.

### Step 1.3 — Make the changes

Edit / Write per the contract. Stay scoped. Apply the rules:

- **Q-11 reuse before create** — search for existing helpers before adding new ones
- **Q-12 don't over-comment** — comments only where the WHY isn't obvious
- **S-13 user-friendly errors** — env-gate any new error paths
- **All rules from the contract's "Rules that will apply" table**

### Step 1.4 — Scope drift detection

If during implementation you discover you NEED to touch a file that wasn't in the scope contract:

1. **STOP immediately.** Do not silently widen scope.
2. Ask the user: "I need to also modify `<file>` because <reason>. This is outside the original scope contract. Should I (a) include it, (b) skip it and adjust my approach, or (c) abort?"
3. Wait for the answer before proceeding.

This is non-negotiable. Scope creep without explicit re-negotiation is the #1 way AI implementations go wrong.

### Step 1.5 — Scaffold tests (REQUIRED unless `--no-tests`)

W-02 requires tests accompany new features. This step is NOT optional. For each new unit of behavior added in Step 1.3:

- **New widget** (Flutter, `lib/features/**`, `lib/shared/widgets/**`): add `test/.../<widget>_test.dart` with at least 1 happy-path `testWidgets` check (renders without throwing + key label present). Run via `flutter test --dart-define=ENV=testing test/...`.
- **New endpoint / handler / service** (backend): add a unit or integration test covering the happy path AND one error path (validation failure, unauthorized, not-found). Use the project's testing runner with the correct env flag (Q-10).
- **New React/Next.js component or page**: add `__tests__/<name>.test.tsx` with a render-without-crash + one interaction assertion. Use the project's test runner (vitest/jest) with `NODE_ENV=testing`.

If `--no-tests` was passed: state in the report WHY tests are deferred (e.g. "pure visual iteration on existing tested widget — no behavior change"). Acceptable reasons:
- Typo / comment / variable rename with no behavior change
- Pure visual styling tweak on a screen already covered by widget tests
- Asset swap / pubspec change

NOT acceptable reasons: "it's simple", "I'll add them later", "the user didn't ask for tests". The user asking for a feature implies asking for a working + tested feature.

### Step 1.6 — Smoke test

For non-trivial changes, run a fast type-check or lint via Bash if the repo has one. Pick the appropriate command per stack (examples — use what the detected repo actually supports):
- Node (TS): `cd <repo> && pnpm typecheck 2>&1 | tail -20` (or `yarn typecheck`, `npm run typecheck`)
- Flutter: `cd <repo> && flutter analyze --no-fatal-infos 2>&1 | tail -20`
- PHP/Laravel: `cd <repo> && ./vendor/bin/phpstan analyse 2>&1 | tail -20` (if configured)

Fix any type errors introduced by your changes before proceeding. If tests were added in Step 1.5, also run them: `flutter test --dart-define=ENV=testing <path>` / `pnpm test <path>` / etc.

### Step 1.7 — Inline-comment self-audit (MANDATORY before Phase 2)

Phase 2's Q-12 sweep keeps catching inline comment patterns the user has asked me to stop introducing. By the time Phase 2 fires it's too late — the offending block is already on screen and the user has to point at it. This step pulls the audit forward so the model deletes the over-comment itself, every run, before any test command or report goes out.

Run this BEFORE Phase 2:

1. **Look at your own diff** for new `//` or `/* */` blocks (one-liners and multi-line) you added in Step 1.3:
   ```bash
   git diff -U0 -- <paths I touched> | grep -E '^\+\s*(//|/\*|\*)' | head -50
   ```
2. **For each new comment, ask: does this belong inline, in the symbol's docblock, or nowhere?** Use this decision rule (mirrors `.claude/rules.md` Q-12):

   | Comment shape | Verdict | Action |
   |---|---|---|
   | Preamble above an `if` / call / guard explaining policy ("The X is authoritative…", "Soft gate: …", "Dedicated alert when …") | **Over-comment** | Delete; if the text is genuinely useful, move it into the enclosing function's docblock |
   | Paraphrase of the next line ("// loop through users") | **Over-comment** | Delete |
   | Per-change narration ("// now also check Y", "// added to fix …") | **Over-comment** | Delete (git history records it) |
   | Linter / type-checker / static-analysis suppression + brief reason | **Keep** | Required for the suppression |
   | Cross-reference / TODO / FIXME / single short WHY the code can't say | **Keep** if concise | Keep as-is |

3. **Apply the deletions** in the same turn — don't wait for Phase 2 to catch them. Then re-run the diff check; the only `^\+\s*(//|/\*)` lines remaining should match the "Keep" rows above.

4. **Phase 2 still runs Q-12** as a backstop. But by then your diff should already pass. If Phase 2 finds a new inline block, that's a regression in this step — treat it as a process bug, fix it, and remember to delete the next one at Step 1.7 instead.

This is a behavioral gate, not a metrics gate: the goal is that the user never has to point at an inline block comment again.

---

## Phase 2 — Self-check + auto-fix

Same as the original `/x-implement` Phase 2. Audit YOUR OWN work against every rule in `.claude/rules.md`. Auto-fix critical violations. Report the rest.

### Step 2.1 — Determine the file set

`git status --porcelain` in each affected repo. Filter to scannable code files (exclude lockfiles, generated files, binaries).

### Step 2.2 — Read the rules fresh

Read `.claude/rules.md` again. The user may have added rules between Phase 0 and Phase 2.

### Step 2.3 — Audit each file against EVERY rule

For each modified file:
1. Read in full
2. For each rule: apply the Detect pattern, record violations with file:line + rule ID + snippet + fix text
3. Don't shortcut. Don't stop after one violation per file.

**Performance (PERF rules) is mandatory when the change touches frontend.** For any modified page / route / component / image / font / provider / dependency / loading state, walk the PERF rules: LCP element not hidden by `opacity:0`, loading states FCP-contentful, above-fold image prioritized, no heavy/disabled-feature dep added to the shared/root bundle, loading-state streaming on client-gated routes. **If the change added a dependency, a top-level/provider import, or a heavy component, run the production build (PERF-09) and confirm no heavy dep leaked into the guest/shared first-load bundle and per-route bundle size didn't regress — this is the gate before any deploy.** This is a safety net; the real fix is to design these in during Phase 1, not patch them here. Auto-fix PERF violations you introduced; report structural ones as follow-ups.

**Q-12 is mandatory on every file you wrote or edited.** For each new/modified non-trivial or exported function, method, or class, verify it has a concise doc comment (purpose + `@param`/`@returns` in the language's convention) and that line-level comments stay minimal (WHY, not WHAT). Never run only the Q-13 character scan and call the self-check done — Q-12 is a semantic check with no regex, so it must be walked deliberately, every time.

**Q-13 is mandatory on every file you wrote or edited.** Run this Python one-liner over the modified set as part of Step 2.3 (BSD `grep` on macOS can't do Unicode classes):

```bash
python3 -c '
import re, sys
pat = re.compile(r"[–—…‘’“”​‌‍﻿]")
hits = 0
for f in sys.argv[1:]:
  for i, line in enumerate(open(f, encoding="utf-8"), 1):
    if pat.search(line):
      hits += 1
      print(f"{f}:{i}: {line.rstrip()[:120]}")
print(f"Q-13 hits: {hits}")
' <modified-files>
```

Then grep the same files for `&mdash;`, `&ndash;`, `&hellip;` (these render literally when they live in JS string literals). Also walk the AI-tell vocabulary list in `.claude/rules.md` (uniquely sensitive, critically, leverage, robust, tapestry, …) against every file you wrote or edited.

False positive watch: ignore matches in comments/markdown/test fixtures unless the rule explicitly applies.

**Q-12 over-commenting is mandatory on every file you wrote or edited — scan it on EVERY run, same status as Q-13.** Read your own added/changed comments and confirm: (1) no symbol is documented twice (per-field JSDoc on an interface/props AND a duplicate `@param` block on its function — pick one); (2) no `/** */` or `//` on self-explanatory fields/props/enum members whose name already says it; (3) no per-line comments paraphrasing the next line / a comment on nearly every line; (4) no essay docblocks where 1–2 lines suffice; (5) non-trivial exported functions/classes still have ONE concise doc comment. Auto-fix over-commenting (collapse to one concise doc + WHY-only inline notes) the same way you auto-fix Q-13. Bias check: when you add a comment, ask "does the code already say this?" — if yes, delete it.

### Step 2.4 — Fix violations

- **Critical / High** (S-, A-, X-, P-, Q-12, Q-13, security-touching Q-): **fix immediately** by re-reading the rule's Fix text and applying it. Re-run detection to verify the fix resolved the violation. Retry up to 2x.
- **Medium** (style Q-, stack-specific B-/M-/W-): fix if it's a one-line change. If it requires structural changes, REPORT only.
- **Soft / aspirational** (Q-04, M-04): REPORT only.

**Q-13 specifics:** swap em-dash for comma / period / colon / semicolon based on intent; swap smart quotes for straight quotes in JS string literals; delete zero-width and BOM characters; rewrite AI-tell vocabulary in plain English. The character fix is always Critical-tier (auto-fix). The prose rewrite is Critical when the file is user-facing copy (legal pages, marketing pages, dialog descriptions, tile descriptions), Medium otherwise (internal comments / docblocks).

### Step 2.5 — Stay-in-scope guarantee

If during Phase 2 you find PRE-EXISTING violations in files you DIDN'T touch in Phase 1, **ignore them**. `/x-implement` only checks YOUR new/modified work. The user has `/x-check` for the broader sweep.

### Step 2.6 — Report

Output:

```markdown
## /x-implement report

### Phase 0 — Scope contract
**Task**: <one-line>
**Repos**: [...]
**Files in scope**: [list]

### Phase 1 — Implementation
**Files changed** (N):
- [<file>:<lines>](<absolute-path>) — <one-line what>

<2-4 bullet summary of decisions made. WHY at decision points.>

### Phase 2 — Self-check
**Rules applied**: <total>
**Violations found**: <count>
**Violations auto-fixed**: <count>
**Violations reported (need decision)**: <count>
**Q-13 chars stripped**: <count> (em-dash, en-dash, ellipsis, smart quotes, zero-width, BOM, `&mdash;`/`&ndash;`/`&hellip;` entities)

#### ✅ Auto-fixed (N)
| Rule | File | Fix applied |
|---|---|---|
| `<id>` <title> | [file:line](path#L<n>) | <fix> |

#### ⚠ Reported (need your decision) (N)
| Severity | Rule | File | Why not auto-fixed |
|---|---|---|---|

### Acceptance criteria check
- [x] <criterion from contract>
- [ ] <criterion from contract — not met because Y>

### Next steps
- [ ] Review the auto-fixes: `git diff <repo>/<file>`
- [ ] Run the smoke test command
- [ ] Commit when ready
```

---

## Constraints (hard rules for this skill)

- **You MUST complete all 3 phases** unless explicitly skipped via `--skip-prompt`, `--plan-only`, or `--no-check`. Don't shortcut.
- **Phase 0 is ALWAYS run** unless `--skip-prompt` is passed. Even for tasks you think are obvious, run Phase 0 — the ambiguity scoring will tell you whether to ask questions or just proceed.
- **The scope contract is binding**. Once accepted (or auto-accepted), Phase 1 cannot widen it without an explicit re-negotiation.
- **`PG` defaults to plan-only**. The user wants to read the brief before execution. They'll type "go" or call you again with `--auto` to proceed.
- **Max 3 clarifying questions** in Phase 0. If you have more, the input was too vague; ask the user to add detail rather than firing 5 questions.
- **Don't editorialize**. Report what the rules and the parsed input say, not your opinions.
- **Don't auto-fix structural changes**. If a rule fix needs a DB migration, a new file, or a new package, REPORT it.
- **Use markdown links** for every file:line reference: `[file:line](abs-path#Ln)`.
- **Don't read files you don't need**. Phase 0 reads the foundation files; Phase 1 reads only the in-scope files.

## Why this skill exists

The user asked for ONE command that:
1. Asks the right questions before implementing (no scope creep, no ambiguity)
2. Cross-references all the project context (rules, audit, spec, memory)
3. Executes the work scoped tightly
4. Self-checks the work against the rules
5. Reports clearly

This is that command. It's the canonical entry point for any non-trivial work in provx.

`/x-prompt <task>` is a thin alias that calls this with `--plan-only`. Same skill, different default flag.

## Argument

User-provided task and flags: $ARGUMENTS
