# provx-sdk

Provx's **deterministic plugin SDK** (distribution name `provx-sdk`, import package
`provx_sdk`; it lives in `packages/adapters/`). It defines the two plugin types that extend Provx
**without touching the core**, both discovered via entry-point groups:

1. **Tool adapters** (`provx.adapters`) — wrap one external security tool (e.g. `nuclei`,
   `httpx`, `nmap`) and normalize its raw output into Provx `Finding` objects.
2. **Playbooks** (`provx.playbooks`) — declarative YAML methodology that the deterministic
   workflow engine evaluates to decide what to run next (the "brain"). See
   [`../../workflows/`](../../workflows/) and [`../../docs/PLAYBOOK_SCHEMA.md`](../../docs/PLAYBOOK_SCHEMA.md).

Both plugin types are deterministic and auditable. **No AI lives here** — AI is an
optional advisor layered on elsewhere, off by default.

> **Status: scaffolding.** The playbook models (`provx_sdk.playbook`) and
> loader/validator (`provx_sdk.loader`) exist and are tested. The tool-adapter base
> class is an interface stub (`provx_sdk.plugins.ToolAdapter`); the `Finding` model,
> the starter adapter template, and the execution engine land with the walking skeleton.

## Layout

```text
packages/adapters/
├── src/provx_sdk/
│   ├── plugins.py    # ToolAdapter + PlaybookPlugin interface stubs
│   ├── playbook.py   # Pydantic playbook schema (models)
│   └── loader.py     # load + validate playbook YAML (no engine)
└── tests/            # fixture test: loads workflows/web-baseline.yaml
```

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
