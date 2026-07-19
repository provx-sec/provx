# packages/cli — reserved (not built yet)

Placeholder reserving the structure for the Provx **CLI**. No code lives here yet.

The CLI will be a **thin wrapper over [`packages/client`](../client/)** (the `provx_sdk`
API client). Provx exposes **one API, three front-ends** — Web UI, CLI, and scripts — all
clients of the same FastAPI core, so the UI and CLI reach feature parity with no duplicated
logic.

## Principles (when it is built)

- **Governance parity, not a bypass** — as an API client the CLI inherits every safety gate:
  scope (PX-SCOPE), passive/active (PX-PASSIVE / PX-ACTIVE), approval-gated exploitation
  (PX-EXPLOIT). There is no CLI backdoor around the rules.
- **Machine-friendly** — `--json` and SARIF output, plus meaningful exit codes (non-zero on
  failure/policy breach) so it drops into CI pipelines and PR gates.
- **Local or remote** — target a local instance or a remote server (`--server`) with token auth.
- **Zero-AI by default** — deterministic; the AI advisor is an opt-in flag (PX-AI-OPTIONAL).
- **Standalone install** — `pipx install provx`, usable without deploying the full stack.
- **Free** — both the UI and CLI ship free (see the monetization mechanic in
  [`../../docs/ROADMAP.md`](../../docs/ROADMAP.md) §6) and depend only on free/OSS packages (PX-FREE).

## Timing

Built **after** the walking-skeleton API exists — a minimal `provx scan` + `provx findings list`
over `packages/client` first, then grown alongside the API. See
[`../../docs/ROADMAP.md`](../../docs/ROADMAP.md) §5 (Interfaces) and
[`../../docs/COMPETITIVE_HARVEST_and_CLI.md`](../../docs/COMPETITIVE_HARVEST_and_CLI.md).
