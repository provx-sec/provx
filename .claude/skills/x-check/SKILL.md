---
name: x-check
description: Audit uncommitted/staged changes against the project rules — file-by-file, line-by-line. Reports violations with clickable file:line links. Default = all detected repos, all severities.
argument-hint: "[--repo <name>|all] [--staged-only] [--severity critical|high|all]"
allowed-tools: [Read, Glob, Grep, Bash]
---

# /x-check — Audit uncommitted changes against project rules



You are auditing uncommitted/changed files in the provx project against the master rule file. **Be exhaustive and pedantic** — the user explicitly wants line-by-line, character-by-character checking. Skipping anything is a failure of the command.

## Inputs

- **Rule source**: `/Users/mac/Projects/mine/provx/.claude/rules.md` — read fresh on every invocation
- **Repos to scan** (parse from $ARGUMENTS, default = all detected): auto-detect by listing direct child directories of `/Users/mac/Projects/mine/provx` that contain a `.git/` directory. The `--repo <name>` flag may reference any such directory.
- **Argument**: $ARGUMENTS (parse for `--repo`, `--staged-only`, `--severity`)

## Steps

### 1. Determine the file set

For each target repo:
1. Run `git status --porcelain` to get a machine-readable status. (Use the Bash tool, not Grep.)
2. Parse the output:
   - Lines starting with `M ` / `A ` / `D ` / `R ` → **staged** changes
   - Lines starting with ` M` / ` A` / ` D` / `??` → **unstaged + untracked** changes
3. If `--staged-only` was passed, take only staged. Otherwise take ALL modified + staged + untracked.
4. **Exclude** files matching: `*.lock`, `*.lockb`, `pubspec.lock`, `package-lock.json`, `*.g.dart`, `*.freezed.dart`, `*.png`, `*.jpg`, `*.svg`, `*.ico`, `node_modules/**`, `.next/**`, `build/**`, `.dart_tool/**`, `.gradle/**`. These are generated or binary, not worth checking.
5. If the file set is empty after filtering, **say so explicitly** and stop with a clean exit message: "No relevant changed files in `<repo>`."

### 2. Read the rules

Read `/Users/mac/Projects/mine/provx/.claude/rules.md` in full. Build a mental index of rules by category. If `--severity` was passed, filter rules:
- `critical` → only rules with severity hints like "Critical CVE-equivalent", "Critical finding", "broken", "bypass", etc. in the Why field
- `high` → critical + high (rules touching auth, secrets, payments)
- `all` → everything (default)

### 3. For each changed file, read it and check it against EVERY rule

This is the core of the command. Be exhaustive.

For each file in the file set:
1. **Read** the file in full with the Read tool.
2. **For every rule** in the rules file (or filtered set):
   - Re-read the rule's `**Detect:**` section.
   - Apply the detection pattern to the file content. The patterns are described in plain English — use grep-like logic, regex, or semantic reasoning as appropriate.
   - If the detection pattern matches, record a violation with:
     - File path + line number(s)
     - Rule ID + title
     - The matching code snippet (1–3 lines max)
     - The rule's `**Fix:**` text
3. Don't shortcut. If a rule says "any reference to `escrow`, `escrow_status`, `release_escrow`, ...", grep for ALL of those tokens, not just the first one. Don't give up after finding one violation per file — report all of them.
4. Watch for false positives. If the file is the audit MD, the spec MD, the rules MD itself, or a memory file, the strings will appear there legitimately — skip those. Code files (`*.ts`, `*.tsx`, `*.dart`, `*.kt`, `*.swift`, `*.sql`) are the targets.

**Q-13 sub-pass (mandatory):** the character + entity scan skips Markdown (`.md`/`.markdown`, including all `docs/**/*.md`) per Q-13's "Scope" in `.claude/rules.md` - those are prose docs with a deliberate house style, so mirror the pre-commit hook and exclude them from the two scans below. For every **non-markdown** file in the set, run the Python Unicode scan from `.claude/rules.md` Q-13 (BSD `grep` on macOS can't do Unicode classes), then grep `&mdash;|&ndash;|&hellip;`. Then, on all files regardless of type, look for AI-tell vocabulary (`uniquely sensitive`, `critically,`, `leverage`, `robust`, `tapestry`, `delve`, `seamlessly`, "It's worth noting that…", triplet-rhythm lists). Report Q-13 violations under Critical and include the offending line for each hit. Over-commenting (Q-12) is a Critical/blocking finding too, scanned every run: flag (a) the same params documented twice — per-field JSDoc on an interface/props AND a duplicate `@param` block; (b) `/** */` or `//` on self-explanatory fields/props/enum members; (c) comments that narrate the next line or a comment on nearly every line; (d) essay docblocks where 1-2 lines suffice; AND (e) non-trivial or exported functions/classes missing a concise doc comment. The character set is always Critical; AI-tell prose in user-facing copy (legal, marketing, dialog/tile descriptions) is Critical; AI-tell prose in internal comments/docblocks is Medium.

### 4. Report

Output structure:

```
## /x-check report — <timestamp>

**Repos checked**: <list of detected repos>
**Files checked**: N
**Rules applied**: M (<filter>)
**Violations found**: K

---

### 🔴 Critical (N)

#### `<file:line>` — `<rule-id>` <rule-title>
```<lang>
<offending code snippet>
```
**Fix**: <rule fix text>

---

### 🟡 High (N)
... same shape ...

### 🟢 Medium / Low (N)
... same shape ...

---

## Summary by file

| File | Violations | Top severity |
|---|---|---|
| `<file>` | N | Critical |

## Summary by rule

| Rule | Violations | Files |
|---|---|---|
| `<id>` <title> | N | a, b, c |

## Clean files

(if any) — list files that had no violations.
```

## Constraints

- **Use markdown links** for every file:line reference: `[file.ts:42](/Users/mac/Projects/mine/provx/<repo>/<path>#L42)` so the user can click through.
- **Don't truncate**: if there are 100 violations, list 100. Don't say "and 50 more".
- **Don't editorialize**: report what the rules say, not your opinions.
- **Don't auto-fix**: this command is read-only. If the user wants fixes, they'll ask in a follow-up.
- **Branch context**: at the start, also report which branch each repo is on (`git branch --show-current`) and warn if any repo is NOT on `dev-snad` (the user's working branch).
- If a repo has uncommitted changes that LOOK like in-progress work (lots of additions, no deletions), say so in the summary — the user might want to commit before running the check.
- **Time budget**: this command can be slow for large diffs. That's expected. Don't apologize, just do the work.

## Argument parsing

User-provided arguments: $ARGUMENTS

Examples:
- `/x-check` → all repos, all changes, all severities
- `/x-check --repo backend` → backend only
- `/x-check --staged-only` → only staged changes
- `/x-check --severity critical` → only critical-level rules
- `/x-check --repo <name> --severity high` → one repo, high+critical
