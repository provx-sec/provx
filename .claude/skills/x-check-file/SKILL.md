---
name: x-check-file
description: Audit a single file against the project rules — line-by-line, character-by-character. Resolves the path against detected repos automatically.
argument-hint: "<file-path> [--severity critical|high|all]"
allowed-tools: [Read, Glob, Grep, Bash]
---

# /x-check-file — Audit a single file against project rules

You are auditing ONE file against the master rule file. Same logic as `/x-check` but scoped to a single path. Be exhaustive, line-by-line, no shortcuts.

## Inputs

- **Rule source**: `/Users/mac/Projects/mine/provx/.claude/rules.md` — read fresh on every invocation
- **Target file**: parsed from $ARGUMENTS (the first non-flag argument)
- **Severity filter**: optional `--severity critical|high|all` (default: all)

## Steps

### 1. Resolve the file path

The user may provide:
- An absolute path: `/Users/mac/Projects/mine/provx/<repo>/<path-to-file>`
- A relative path from project root: `<repo>/<path-to-file>`
- A relative path from one of the repos: `src/...` (you'll need to guess which repo)

Resolution logic:
1. If absolute, use as-is.
2. If it starts with a detected repo name (direct child of `/Users/mac/Projects/mine/provx` containing `.git/`), prefix with `/Users/mac/Projects/mine/provx/`.
3. Otherwise, try each detected repo in turn. Use the first one where the file exists.
4. If you can't resolve it, ask the user which repo and stop.

### 2. Read the file

Use the Read tool. If it's larger than 2000 lines, read it in chunks. Don't skip any lines.

### 3. Read the rules

Read `/Users/mac/Projects/mine/provx/.claude/rules.md` in full. Apply the severity filter if provided (see /x-check for the filter logic).

### 4. Apply EVERY rule line-by-line

For each rule:
- Re-read its `**Detect:**` section.
- Search the file content for the pattern (regex, token, semantic).
- Record every violation with file:line link.

Don't shortcut. If a rule has 5 forbidden tokens, search for all 5. If a rule has a regex pattern, apply it.

**Q-13 sub-pass (mandatory):** run the Python Unicode scan from `.claude/rules.md` Q-13 against the file (BSD `grep` on macOS can't do Unicode classes). Also grep `&mdash;|&ndash;|&hellip;`. Also walk the AI-tell vocabulary list (`uniquely sensitive`, `critically,`, `leverage`, `robust`, `tapestry`, `delve`, `seamlessly`, "It's worth noting that…"). Report every hit under Critical with the offending line.

**Watch for false positives**: if the file is a markdown doc / spec / audit / rule file itself, the strings appear legitimately — but the user is asking about a code file, so this is unlikely. Still, if the file is `.md` and you're getting hundreds of "violations", suggest the user meant a different file.

### 5. Report

Output structure:

```
## /x-check-file report — <file-path>

**File**: [<file>](<absolute-path>)
**Lines**: N
**Rules applied**: M (<severity filter>)
**Violations found**: K

---

### 🔴 Critical (N)

#### Line <num>: <rule-id> <rule-title>
```<lang>
<line content>
```
**Fix**: <rule fix text>

---

### 🟡 High (N)
... same shape ...

### 🟢 Medium / Low (N)
... same shape ...

---

## Violations by rule

| Rule | Lines |
|---|---|
| `<id>` <title> | 42, 87, 103 |

## Clean rules

Number of rules that found NO violations in this file: X / M total.

If the file has zero violations, end with: "✅ Clean — no rule violations found."
```

## Constraints

- One file = one focused report. Don't expand scope beyond what the user asked.
- Use markdown links: `[file.ts:42](<absolute-path>#L42)`.
- Don't auto-fix.
- Don't truncate the violation list.
- If the file doesn't exist, say so and stop. Don't guess at similar filenames.

## Argument parsing

User-provided arguments: $ARGUMENTS

Examples:
- `/x-check-file <repo>/src/auth/auth.service.ts`
- `/x-check-file <repo>/lib/services/dio_client.service.dart --severity critical`
- `/x-check-file /Users/mac/Projects/mine/provx/<repo>/src/middleware.ts`
