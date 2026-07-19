# provx_sdk + lab — Overview

**Audited:** 2026-07-19 · **Scope:** `packages/adapters/` (the `provx-sdk` distribution) and `lab/` (the accuracy gate).
**Status:** pre-alpha. Version `0.0.0`. Audited against [`docs/PROVX_RULES.md`](../../docs/PROVX_RULES.md) and [`.claude/rules.md`](../../.claude/rules.md).

These two trees are audited together because they are coupled: `lab/` has no manifest of its own, no dependencies of its own, and no adapter of its own. It imports `provx_sdk` and exists solely to prove the SDK's one shipped adapter is accurate.

---

## 1. Distribution & dependencies

From [`pyproject.toml`](../../packages/adapters/pyproject.toml):

| Field | Value |
|---|---|
| Distribution name | `provx-sdk` (import name `provx_sdk`) |
| Version | `0.0.0` |
| Python | `>=3.12` |
| License | Apache-2.0, declared inline (`license = { text = "Apache-2.0" }`) |
| Build backend | `hatchling`, wheel packages `src/provx_sdk` (src-layout) |

**Runtime dependencies — three, all permissive, all PX-FREE clean:**

| Package | Constraint | License | Used by |
|---|---|---|---|
| `httpx` | `>=0.27` | BSD-3-Clause | `adapters/security_headers.py` only |
| `pydantic` | `>=2` | MIT | `findings`, `scope`, `playbook`, `evidence` |
| `pyyaml` | `>=6` | MIT | `loader.py` only |

Optional `dev` extra: `pytest>=8.2`.

Observations:
- All three are OSI-approved and Apache-2.0 compatible. **PX-FREE and PX-LICENSE are satisfied** — no copyleft source is vendored, and the one external tool named (`httpx`) is a permissive Python library, not a wrapped GPL binary.
- Constraints are **floors with no ceilings** (`>=2` on Pydantic in particular). A Pydantic 3.x release would be accepted by the resolver and would break `field_validator`/`ConfigDict`. There is no lockfile in `packages/adapters/` — the only lock in the repo is [`backend/requirements.lock`](../../backend/requirements.lock), which pins the SDK's deps only for the backend image. See [99_FINDINGS.md](99_FINDINGS.md) `SDK-013`.
- `pyyaml` is a dependency of the whole SDK but is imported by exactly one module (`loader.py`). Not a defect; noted for future extras-splitting.
- **`lab/` declares no dependencies at all.** It imports `provx_sdk` and `yaml` and is type-checked and linted only because [`Makefile`](../../Makefile) and [`ci.yml`](../../.github/workflows/ci.yml) name the `lab` path explicitly. There is no `lab/pyproject.toml`. See `SDK-014`.

---

## 2. Package layout

```
packages/adapters/
├── pyproject.toml
├── src/provx_sdk/
│   ├── __init__.py                    # curated public surface, __all__ of 24 names
│   ├── findings.py                    # THE shared platform contract
│   ├── scope.py                       # PX-SCOPE enforcement primitive
│   ├── evidence.py                    # PX-EVIDENCE seal primitive
│   ├── plugins.py                     # the two plugin Protocols
│   ├── registry.py                    # entry-point adapter discovery
│   ├── playbook.py                    # playbook Pydantic schema
│   ├── loader.py                      # YAML -> Playbook
│   └── adapters/
│       ├── __init__.py
│       └── security_headers.py        # the one shipped adapter
└── tests/
    ├── fixtures/
    │   ├── security_headers_missing.json
    │   └── security_headers_hardened.json
    ├── test_findings_validation.py
    ├── test_scope.py
    ├── test_registry.py
    ├── test_playbook_loader.py
    └── test_security_headers_adapter.py
```

Every source file carries an `SPDX-License-Identifier: Apache-2.0` header and a copyright line. Every module uses `from __future__ import annotations`. This consistency is genuinely good and should be treated as a house standard.

Notably **absent from `tests/`: there is no `test_evidence.py` and no `test_plugins.py`.** `evidence.py` — a PX-EVIDENCE primitive — has zero direct unit tests in this package. See `SDK-009`.

---

## 3. The two plugin types

Provx's extension story is that a third party installs a package and the platform picks it up **with no core edit**. Two plugin types are declared in [`plugins.py`](../../packages/adapters/src/provx_sdk/plugins.py), both as `@runtime_checkable` `Protocol`s:

| Plugin type | Protocol | Entry-point group | Concrete implementation today |
|---|---|---|---|
| Tool adapter | `ToolAdapter` | `provx.adapters` | `SecurityHeadersAdapter` |
| Playbook | `PlaybookPlugin` | `provx.playbooks` | none — group is declared but commented out |

`ToolAdapter` declares four class attributes (`name`, `category`, `safety`, `tool`) and three methods (`build_command`, `probe`, `parse_output`). `PlaybookPlugin` declares exactly one attribute, `workflow`.

> **Protocol caveat.** `@runtime_checkable` `isinstance()` checks verify **method and attribute *names* only** — never signatures, never types. [`test_registry.py:17`](../../packages/adapters/tests/test_registry.py#L17) asserts `isinstance(load_adapter("security_headers"), ToolAdapter)`, which passes for any object that happens to have those seven names. It is a spelling check, not a contract check. See `SDK-010`.

---

## 4. Entry points & discovery

Declared in [`pyproject.toml:22-27`](../../packages/adapters/pyproject.toml#L22):

```toml
[project.entry-points."provx.adapters"]
security_headers = "provx_sdk.adapters.security_headers:SecurityHeadersAdapter"

[project.entry-points."provx.playbooks"]
# web_baseline = "provx_sdk.playbook:Playbook"  # loaded from workflows/*.yaml
```

Discovery flow, in [`registry.py`](../../packages/adapters/src/provx_sdk/registry.py):

1. `load_adapters()` calls `importlib.metadata.entry_points(group="provx.adapters")`.
2. For each entry: `entry.load()()` — imports the module, resolves the attribute, **and instantiates it** with no arguments.
3. Keys the result by `adapter.name` — the instance attribute, **not** the entry-point key.
4. `load_adapter(name)` builds the whole dict, then indexes it; a `KeyError` becomes `AdapterNotFoundError`.

Three consequences worth naming up front:

- **The dict key comes from the adapter, not the manifest.** An adapter whose `name` attribute disagrees with its entry-point key is silently reachable under the wrong name. Two adapters declaring the same `name` silently overwrite each other, last-wins, in entry-point iteration order — which is *not* a guaranteed order. This is the opposite of `load_playbooks_dir`, which explicitly refuses duplicates (`loader.py:58`). The inconsistency is the finding. See `SDK-005`.
- **`entry.load()` executes arbitrary third-party code** at discovery time, for every installed adapter, whether or not the caller wanted it. That is inherent to entry points, but it means installing an adapter package is a trust decision equivalent to installing any dependency.
- **`load_adapter` is O(all adapters) per call** and re-imports/re-instantiates on every invocation — no caching. Minor today (one adapter); it means adapters must keep `__init__` side-effect-free.

The `provx.playbooks` group is **declared but empty**. Playbooks are loaded from `workflows/*.yaml` via `loader.py`, and there is no `load_playbook_plugins()` counterpart to `load_adapters()`. This is declared scaffolding, consistent with the commented-out line.

---

## 5. The lab: layout and how the gate runs

```
lab/
├── __init__.py                        # empty; makes `lab.harness` importable
├── expected.yml                       # index / schema documentation ONLY
├── harness.py                         # the gate
├── positive/missing-headers/
│   ├── expected.yml                   # oracle: 5 checks MUST fire
│   ├── nginx.conf                     # sends no security headers
│   └── index.html
├── clean/hardened/
│   ├── expected.yml                   # oracle: expect_none
│   ├── nginx.conf                     # sends all 5 headers
│   └── index.html
└── tests/
    ├── __init__.py
    └── test_harness.py                # 7 tests, all drive score_target directly
```

**The oracle lives next to each target.** [`lab/expected.yml`](../../lab/expected.yml) is *not* loaded by anything — it documents the per-target schema and lists the two manifests by path. `harness.py` finds manifests by globbing `*/*/expected.yml`. The index file and the glob can therefore drift apart with no error; see `SDK-007`.

**Two targets, deliberately paired:**

| Target | Compose service | `kind` | Oracle |
|---|---|---|---|
| `http://lab-missing-headers` | `lab-missing-headers` | `positive` | 5 `expect` entries, each `min_severity: low` |
| `http://lab-hardened` | `lab-hardened` | `negative` | `expect_none: true` |

The hardened target is the **false-positive tripwire** — its `nginx.conf` sets all five headers with `always`, so any finding at all means the adapter has started crying wolf.

### How the gate executes

**Makefile** ([`Makefile`](../../Makefile), `accuracy` target):

```make
accuracy:
	$(COMPOSE) --profile lab up -d lab-missing-headers lab-hardened
	$(COMPOSE) --profile lab run --rm accuracy; \
		status=$$?; $(COMPOSE) --profile lab down; exit $$status
```

The exit-status capture-then-teardown idiom is correct — `down` cannot mask a gate failure. Good.

**docker-compose** ([`docker-compose.yml`](../../docker-compose.yml)): three services behind `profiles: [lab]`, so a plain `docker compose up` never starts them. All three sit on the `lab` network, declared `internal: true`, and **publish no ports to the host**. The `accuracy` service reuses the `provx-backend` image with `entrypoint: ["python", "/app/lab/harness.py"]` and mounts `./lab:/app/lab:ro`.

This containment design is the right answer to PX-AUTHZ: deliberately-vulnerable targets exist, but they are unroutable from outside the compose network and unstartable without an explicit profile flag. Credit where due.

> One gap: the `accuracy` container inherits the `lab` network only. It cannot reach the internet — good. But `harness.py` itself applies **no `ScopePolicy`** (see [module_lab.md](module_lab.md) and `SDK-002`), so that containment is enforced by Docker, not by Provx. If the harness is ever run outside compose — and `main()` accepts `--lab-root`, inviting exactly that — nothing stops it probing whatever a manifest names.

**CI** ([`.github/workflows/ci.yml`](../../.github/workflows/ci.yml), job `accuracy`): gated on `needs.changes.outputs.backend|adapters|lab == 'true'`, checks out, and runs `make accuracy`. It is a **real gate**, not a stub — the workflow header says so and the body confirms it. Note it does *not* pin or cache anything and rebuilds the backend image each run.

Other CI jobs touching this audit's scope: `backend-lint` (ruff check + format on `backend packages/adapters lab`), `backend-types` (`mypy` strict on `backend/app packages/adapters/src/provx_sdk lab`), `unit-fixtures` (`pytest -q` with the SDK **pip-installed**, not just on `PYTHONPATH`, so entry-point discovery resolves the way it does at runtime — a genuinely thoughtful detail).

---

## 6. Modules index

| Module | LOC | Public surface | PX rules it carries | Audit |
|---|---|---|---|---|
| [`findings.py`](../../packages/adapters/src/provx_sdk/findings.py) | 195 | `Severity`, `Confidence`, `Module`, `FindingStatus`, `Evidence`, `Finding`, `FindingDraft`, `RiskAcceptance`, `validate_attack_techniques` | PX-ATTACK, PX-HUMAN, PX-DETERMINISM | [module_findings.md](module_findings.md) |
| [`scope.py`](../../packages/adapters/src/provx_sdk/scope.py) | 69 | `OutOfScopeError`, `target_host`, `ScopePolicy` | **PX-SCOPE** | [module_scope.md](module_scope.md) |
| [`evidence.py`](../../packages/adapters/src/provx_sdk/evidence.py) | 32 | `EvidenceSeal`, `seal` | **PX-EVIDENCE** | [module_evidence.md](module_evidence.md) |
| [`plugins.py`](../../packages/adapters/src/provx_sdk/plugins.py) | 82 | `ToolAdapter`, `PlaybookPlugin` | PX-LICENSE, PX-FIXTURE | [module_plugins_registry.md](module_plugins_registry.md) |
| [`registry.py`](../../packages/adapters/src/provx_sdk/registry.py) | 38 | `AdapterNotFoundError`, `load_adapters`, `load_adapter` | — | [module_plugins_registry.md](module_plugins_registry.md) |
| [`playbook.py`](../../packages/adapters/src/provx_sdk/playbook.py) | 83 | `PlaybookValidationError`, `DiscoveryRule`, `RoutingRule`, `Playbook` | **PX-DSL**, PX-ACTIVE | [module_playbook_loader.md](module_playbook_loader.md) |
| [`loader.py`](../../packages/adapters/src/provx_sdk/loader.py) | 74 | `load_playbook`, `load_playbooks_dir`, `find_workflows_dir` | PX-DSL | [module_playbook_loader.md](module_playbook_loader.md) |
| [`adapters/security_headers.py`](../../packages/adapters/src/provx_sdk/adapters/security_headers.py) | 158 | `RECON_TECHNIQUE`, `HeaderRule`, `RULES`, `encode_response`, `SecurityHeadersAdapter` | PX-PASSIVE, PX-DETERMINISM, PX-FIXTURE, PX-SCOPE | [module_adapters.md](module_adapters.md) |
| [`lab/harness.py`](../../lab/harness.py) | 154 | `Manifest`, `Score`, `load_manifests`, `check_id`, `score_target`, `run`, `report`, `main` | PX-DETERMINISM, PX-SCOPE | [module_lab.md](module_lab.md) |

---

## 7. Declared scaffolding — explicitly NOT counted as defects

Per the audit brief and the modules' own docstrings, the following are absent **by design** at this stage and are not reported in [99_FINDINGS.md](99_FINDINGS.md):

- **The playbook expression evaluator.** PX-DSL mandates that `when`/`if` be stored verbatim and structure-validated only until a restricted allowlisted evaluator exists. `playbook.py` does exactly that, and its module docstring reproduces the locked design. **This is correct current behavior.** I confirmed by grep that there is no `eval`, `exec`, `compile`, or `pickle` anywhere in the SDK.
- **The workflow execution engine** — nothing decides which adapter runs when; the caller names it.
- **Additional adapters** — one passive adapter is the whole roster.
- **EPSS enrichment** — the `Finding.epss` field exists and is documented as a prioritization input; nothing populates it.
- **SARIF export** — no reporting layer in this package.
- **`provx.playbooks` entry-point consumption** — group declared, no loader.

---

*Continue to [01_ARCHITECTURE.md](01_ARCHITECTURE.md) for the design rationale, or jump to [99_FINDINGS.md](99_FINDINGS.md) for the ranked findings.*
