---
name: x-audit
description: Deep audit of one or all repos — reads every source file line-by-line, documents every function/route/component, writes structured MDs to audits/. Same depth as a senior code review.
argument-hint: "[--repo <name>] [--output <path>] [--quick]"
allowed-tools: [Read, Write, Glob, Grep, Bash, Agent]
---

# /x-audit — Deep file-by-file codebase audit

You are running a comprehensive, line-by-line audit of one or all repos in this project. The output is a set of structured markdown files written to an `audits/` folder. Same rigor as a senior engineer's code review — every file, every function, every route, every schema field documented.

## Inputs

- **Audit prompt template**: `/Users/mac/Projects/.ai/claude-kit/templates/audit-prompt.md` — read fresh
- **Project root**: `/Users/mac/Projects/mine/provx` (or current working directory)
- **Argument**: $ARGUMENTS (parse for `--repo`, `--output`, `--quick`)

## Argument parsing

- `--repo <name>` — audit only this repo (e.g. `--repo backend`). If absent, audit ALL detected repos.
- `--output <path>` — write audit MDs here instead of `<project>/audits/<repo>/`. Default: `<project>/audits/<repo>/`.
- `--quick` — skip the per-module/section/feature deep-dive files. Only produce `00_OVERVIEW.md`, `01_ARCHITECTURE.md`, and `99_FINDINGS.md`. Faster but less detailed.

## Steps

### Step 1 — Detect repos

If `--repo` was provided, use that single repo. Otherwise, scan the project root for repos:

1. Run `ls` at the project root
2. Look for indicators:
   - `package.json` in root → single-repo Node project
   - `pubspec.yaml` in root → single-repo Flutter project
   - `composer.json` in root → single-repo PHP project
   - Subdirectories with their own `package.json` / `pubspec.yaml` / `composer.json` / `go.mod` / etc. → multi-repo
3. For each detected repo, identify:
   - **Path** (absolute)
   - **Stack** (framework + language, not just language)
   - **Source directory** (`src/`, `app/`, `lib/`, etc.)
   - **Test directory** (`test/`, `tests/`, `__tests__/`, `spec/`)
   - **Source file count** (`find <src-dir> -type f | wc -l`)
   - **Key config files** (package.json, tsconfig.json, pubspec.yaml, composer.json, drizzle.config.ts, nest-cli.json, next.config.js, nuxt.config.ts, etc.)

4. Present the detected repos as a table and confirm: "I'll audit these repos. Correct?"

### Step 2 — Determine the TOP_FOLDER_TYPE per repo

| Stack | TOP_FOLDER_TYPE |
|---|---|
| NestJS / Express / Fastify | `module` |
| Laravel | `feature` (or `module` if using modular structure) |
| Django | `app` |
| Next.js / Nuxt / SvelteKit | `section` |
| React / Vue / generic SPA | `section` |
| Flutter | `feature` |
| React Native | `feature` |
| Go | `package` |
| Other | `module` (generic) |

### Step 3 — Create output directories

```bash
mkdir -p <project>/audits/<repo>/
```

For each detected repo.

### Step 4 — Read the audit prompt template

Read `/Users/mac/Projects/.ai/claude-kit/templates/audit-prompt.md` in full. This template contains the full audit instructions with placeholders.

### Step 5 — Launch audit agents

For each repo, launch a **`general-purpose` agent** (NOT Explore — Explore can't write files) with the substituted audit prompt.

**Substitutions per repo:**
- `{{REPO_NAME}}` → the repo's short name (e.g. `backend`, `mobile`)
- `{{REPO_PATH}}` → absolute path
- `{{STACK_DESCRIPTION}}` → e.g. "NestJS + Drizzle + TypeScript"
- `{{SOURCE_COUNT}}` → the source file count from Step 1
- `{{SOURCE_DIR}}` → main source directory
- `{{TEST_DIR}}` → test directory
- `{{AUDIT_OUTPUT_PATH}}` → the output path from Step 3
- `{{KEY_CONFIG_FILES}}` → comma-separated config files from Step 1
- `{{TOP_FOLDER_TYPE}}` → from Step 2

**If there are multiple repos**: launch ALL agents **in parallel** (in the background). Tell the user: "Audit launched for N repos in parallel. I'll notify you as each completes."

**If there's only one repo**: launch the agent in the foreground (the user sees progress).

### Step 6 — Wait for completion + write the cross-repo index

After all audit agents complete:

1. Verify the audit MDs exist on disk (`ls <project>/audits/<repo>/`)
2. Write `<project>/audits/README.md` with:
   - A table linking each repo's audit folder
   - Source file counts + finding counts per repo
   - The top 5 critical findings across all repos
   - Cross-cutting themes (patterns that appear in multiple repos)
3. **Tell the user** the audit is complete with a summary:

```
## Audit complete

| Repo | Source files | Audit docs | Top severity |
|---|---|---|---|
| <repo1> | N | M | Critical / High / Medium |
| <repo2> | N | M | ... |

**Top 5 critical findings:**
1. ...
2. ...
3. ...
4. ...
5. ...

Audit MDs written to: <project>/audits/
Cross-repo index: <project>/audits/README.md
```

### Step 7 — Update memory (if memory folder exists)

If `/Users/mac/.claude/projects/-Users-mac-Projects-mine-provx/memory/` exists:
1. Create or update `project_audits.md` with the audit summary
2. Update `MEMORY.md` index if the audit file is new

## Constraints

- **Use `general-purpose` agents, NOT `Explore` agents** — Explore is read-only and cannot write the audit MD files.
- **Read EVERY source file.** The user explicitly wants line-by-line coverage. Don't skip "boring" files.
- **Don't modify code.** The audit READS files and WRITES audit MDs. It does not change any source code.
- **Use markdown links** for every code reference: `[file.ts:42](../../<repo>/<src>/file.ts#L42)`.
- **Findings must be actionable.** "Missing input validation on email field" ✓. "Could be better" ✗.
- **If `--quick` was passed**, only produce 3 files per repo (00_OVERVIEW, 01_ARCHITECTURE, 99_FINDINGS). Skip the per-module/section/feature deep-dive MDs.
- **Don't truncate.** If there are 100 findings, list 100.

## Example invocations

```
/x-audit                                    # audit all detected repos, full depth
/x-audit --repo backend                     # audit only the backend repo
/x-audit --quick                            # fast mode — overview + architecture + findings only
/x-audit --repo mobile --output /tmp/audit  # audit mobile, write to /tmp
```

## Argument

User-provided flags: $ARGUMENTS
