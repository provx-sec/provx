---
name: x-rules
description: List all provx project rules from .claude/rules.md, organized by category. Optional filter by category letter (P/A/S/D/Q/B/M/W/X) or name.
argument-hint: "[category-letter-or-name]"
allowed-tools: [Read, Glob, Grep]
---

# /x-rules — List project rules

You are listing the provx project rules. The single source of truth is `/Users/mac/Projects/mine/provx/.claude/rules.md`. Read it fresh — do NOT rely on memory of past invocations, the file may have been edited.

## Steps

1. **Read** `/Users/mac/Projects/mine/provx/.claude/rules.md` in full.
2. **Parse** the rules. Each rule has the format:
   - Category-letter prefix: `P-` (Product), `A-` (Auth), `S-` (Security), `D-` (Data/Privacy), `Q-` (Quality), `B-` (Backend), `M-` (Mobile), `W-` (Admin Web), `X-` (Audit-derived).
   - Each rule has: `### <ID> — <title>`, `**Status:**`, `**Why:**`, `**Detect:**`, `**Fix:**`.
3. **Filter** by category if `$ARGUMENTS` was provided. The argument is a single letter or category name. Examples:
   - `/x-rules` → list all rules grouped by category
   - `/x-rules P` → only product rules
   - `/x-rules security` → only security rules (`S-` prefix)
   - `/x-rules audit` → only audit-derived rules (`X-` prefix)
4. **Output** as a markdown table per category with columns: `ID | Title | Status | One-line summary`. Skip the long Why/Detect/Fix sections — those are in the source file. Use markdown links: `[ID](/Users/mac/Projects/mine/provx/.claude/rules.md#<anchor>)` so the user can click through to the full text.
5. **End with**: rule count + `Last updated` field from the file + a one-line reminder of how to add new rules ("edit `.claude/rules.md` and add your rule to the appropriate category — `/x-check` will pick it up next run").

## Constraints

- Be exhaustive: list EVERY rule, never truncate. The whole point is the user gets a quick overview.
- Use the actual rule IDs from the file — don't make up IDs.
- If the file has been updated since the last invocation in this conversation, use the new content (re-read).
- If a category has 0 rules after filtering, say "no rules in this category" rather than omitting the category header.
- Output is for the user to read in their terminal — keep it scannable, not chatty.

## Argument

User-provided filter (optional): $ARGUMENTS
