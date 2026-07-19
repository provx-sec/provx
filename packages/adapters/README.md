# provx-adapters

Pluggable **tool adapters** for Provx. An adapter wraps one external security tool (for
example `nuclei`, `httpx`, `nmap`) and normalizes its raw output into Provx `Finding`
objects. Adapters are the primary way contributors extend Provx **without touching the
core** — the core discovers them via the `provx.adapters` entry-point group.

> **Status: Phase 1 skeleton.** The adapter base class, the `Finding` model, and the
> starter template land with the walking skeleton. This directory currently defines the
> package and the plugin contract so the structure is in place.

## The adapter contract

Every adapter provides four things (see [`../../docs/ROADMAP.md`](../../docs/ROADMAP.md) §5):

1. **Manifest** — `name`, `category` (web / api / infra-ad / …), safety class
   (`passive` / `intrusive`), and the external tool it wraps.
2. **`build_command`** — build the command from selected use-cases + scope + auth.
   **Scope is enforced here**, at the adapter boundary — never trusted from upstream.
3. **`parse_output`** — normalize raw tool output into `Finding`s (severity, CVSS,
   ≥1 MITRE ATT&CK technique, evidence, remediation).
4. **Fixture test** — a recorded sample of the tool's raw output plus the expected
   normalized findings. **Required** — a tool changing its output format must fail CI,
   not users.

## Adding an adapter

Follow the cookbook in [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md#4-adapter-cookbook--add-a-tool-in-one-place):
copy the template, fill the manifest + `build_command` + `parse_output`, add a fixture
test, and open a PR. Register the adapter under `[project.entry-points."provx.adapters"]`
in [`pyproject.toml`](pyproject.toml).

## Safety

Adapters are subject to the [Safety Contract](../../docs/ROADMAP.md) and
[`RESPONSIBLE_USE.md`](../../RESPONSIBLE_USE.md). Intrusive checks must be tagged and are
gated to Active mode; nothing an adapter does may change target state outside an
approval-gated exploit.
