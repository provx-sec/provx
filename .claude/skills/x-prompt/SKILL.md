---
name: x-prompt
description: Plan-only entry point for the canonical /x-implement command. Runs Phase 0 (parse + clarify + scope-lock via PROMPT_GENERATOR.md framework), then STOPS. Use this when you want a structured brief without execution — e.g. for sharing with a teammate, pasting into a ticket, or reviewing before committing to the work.
argument-hint: "<task description>"
allowed-tools: [Read, Glob, Grep, Bash]
---

# /x-prompt — Plan-only alias for /x-implement

This skill is a thin wrapper around `/x-implement <task> --plan-only`. It exists for the **planning-without-doing** use case.

## What it does

When invoked, this skill is equivalent to running `/x-implement <task> --plan-only`. That means:

- **Phase 0 runs** — read foundation files, parse the messy task, score ambiguity, ask up to 3 targeted clarifying questions if needed, cross-reference rules (including the PERF / Web Vitals rules for any frontend work, so performance is designed in from the brief, not bolted on later), output the scope contract
- **Phase 1 + Phase 2 do NOT run** — no implementation, no self-check, no file edits

The output is a **scope contract** the user can:
- Review before deciding to proceed
- Share with a teammate for sign-off
- Paste into a ticket or PR description
- Refine and re-invoke if anything looks wrong

## When to use this vs `/x-implement`

| You want | Use |
|---|---|
| Plan AND execute the work in one go | `/x-implement <task>` |
| Plan only — review the brief first, decide later | `/x-prompt <task>` (or `PG <task>` shorthand) |
| Plan AND auto-execute without confirmation | `/x-implement <task> --auto` |
| Skip planning entirely (trivial fix) | `/x-implement <task> --skip-prompt` |

The shorthand **`PG <task>`** in any message is equivalent to `/x-prompt <task>` — it auto-fires this skill. To skip the confirmation step and run all 3 phases, type `PG <task> --auto` instead.

## Steps

1. **Read** `/Users/mac/Projects/mine/provx/.claude/skills/x-implement/SKILL.md` in full to load the canonical instructions.
2. **Apply** the `/x-implement` skill's instructions with `--plan-only` set.
3. **Execute Phase 0 only** per those instructions.
4. **Stop** at the end of Phase 0 with the message: "Phase 0 complete. Plan-only mode — Phase 1 + 2 not run. Reply 'go' (or call `/x-implement <task>`) to proceed, or refine the scope above and re-invoke."

## Why this is a thin alias instead of duplicating the logic

If both files contained the full Phase 0 logic, they'd drift apart. The single source of truth is `x-implement/SKILL.md`. This file is just an entry point that signals "run with `--plan-only` set".

When the user invokes `/x-prompt`, you literally read the `x-implement` SKILL.md file and follow its instructions, with the `--plan-only` flag treated as set. Don't try to re-implement Phase 0 here.

## Input sources (task description)

The task description can arrive in two ways — always check BOTH:

1. **Inline (short tasks)** — `/x-prompt fix the login bug`. Everything in `$ARGUMENTS` IS the task description.
2. **Prior message (long/detailed tasks)** — The user types their full description as a normal chat message, then on the next message types `/x-prompt` with no args. In this case `$ARGUMENTS` is empty; **use the most recent user message from conversation context as the task description**.

**Decision rule**: If `$ARGUMENTS` is empty or under ~15 words, look at the conversation history above for the user's most recent message that reads like a task description. That message IS the task. Do not ask the user to repeat themselves.

## Argument

User-provided task: $ARGUMENTS
