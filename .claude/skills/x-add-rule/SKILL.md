---
name: x-add-rule
description: Append a new rule to .claude/rules.md in the right category, with auto-numbering and full Why/Detect/Fix template
argument-hint: "<category-letter> <one-line description>"
allowed-tools: [Read, Edit, Bash]
---

# /x-add-rule — Add a new rule to the master rule file

You are adding a new rule to `/Users/mac/Projects/mine/provx/.claude/rules.md`. Use this when the user says "add a rule for X" or describes a new constraint they want enforced going forward.

## Inputs

- **Rule source**: `/Users/mac/Projects/mine/provx/.claude/rules.md`
- **User input**: $ARGUMENTS — first token is the category letter, rest is a one-line description

## Steps

### 1. Parse the category

Map the first token to a category:
- `P` → Product / Scope rules (section 1)
- `A` → Auth & Authorization rules (section 2)
- `S` → Security rules (section 3)
- `D` → Data & Privacy rules (section 4)
- `Q` → Code quality rules (section 5)
- `B` → Backend-specific rules (section 6)
- `M` → Mobile-specific rules (section 7)
- `W` → Admin dashboard-specific rules (section 8)
- `X` → Audit-derived rules (section 9)

If the user provides a full word ("product", "security"), match it to the letter. If unclear, ask.

### 2. Read the rules file + find the next number

1. Read `/Users/mac/Projects/mine/provx/.claude/rules.md`.
2. Find all existing rule IDs in the target category. They look like `### P-01`, `### S-12`, etc.
3. Pick the next sequential number. E.g. if `S-01` through `S-12` exist, the new rule is `S-13`.

### 3. Draft the new rule

Use the standard template:

```
### <NEW-ID> — <short title>
**Status:** ACTIVE
**Why:** <reason — what would break or what was a past incident>
**Detect:** <how to spot this in code — file patterns, regex, semantic checks>
**Fix:** <what to do instead>
```

The user gave you a one-line description. **Don't just paste it**. Expand it into the 4 fields:
- **Title**: 5-10 words, action-oriented ("No X in production", "Always use Y", "Z must be encrypted")
- **Why**: 1-2 sentences. Reference the source if relevant (audit finding, product spec feature, the user's instruction).
- **Detect**: be specific. What strings, what file types, what semantic patterns? Without a clear detect, the `/x-check` command can't enforce it.
- **Fix**: the corrective action. Specific enough that another dev knows what to do.

If any of the 4 fields is unclear from the user's input, **ASK before writing**. Don't guess.

### 4. Insert into the file

Use the Edit tool to insert the new rule at the END of the target category section, right before the next category's `## ` header (or before "## How to extend this file" if it's the last category).

Be careful with the Edit tool's `old_string` — pick a unique anchor that won't have any whitespace ambiguity.

### 5. Update the "Last updated" field

Find the `**Last updated:**` line near the top and update it to today's date.

### 6. Confirm

Output:
```
✅ Added rule <NEW-ID> — <title> to category <name>.
File: [.claude/rules.md](/Users/mac/Projects/mine/provx/.claude/rules.md)
Run /x-check to verify it picks up your existing code.
```

## Constraints

- **Never delete** existing rules — that's `/x-deprecate-rule` (not yet built — for now, do it manually).
- **Never renumber** existing rules — IDs are stable forever.
- **Never invent the user's intent**. If the description is too vague to write a good Detect/Fix, ask.
- **One rule per command invocation**. If the user wants 3 rules, do them one at a time so they can confirm each.

## Input sources

The rule description can arrive in two ways — always check BOTH:

1. **Inline** — `/x-add-rule S api keys must never appear in mobile asset files`. First token is the category letter, rest is the description.
2. **Prior message** — The user types their full description as a normal chat message, then types `/x-add-rule` (possibly with just the category letter). In this case `$ARGUMENTS` is empty or just one token; **use the most recent user message from conversation context as the description**.

**Decision rule**: If `$ARGUMENTS` (after extracting the category letter) is empty or under ~8 words, look at the conversation history above for the user's most recent message that describes the rule. That message IS the description.

## Argument parsing

$ARGUMENTS

Examples:
- `/x-add-rule S api keys must never appear in mobile asset files`
- `/x-add-rule product all currency display uses GH₵ symbol not GHS or USD`
- `/x-add-rule M no print statements in widget build methods`
