# `plugins.py` + `registry.py` — the extension mechanism

Two files, audited together: `plugins.py` declares *what* a plugin must look like, `registry.py` *finds* them. Together they are the "install a package, get an adapter, no core edit" promise.

---

# Part 1 — `plugins.py`

**File:** [`packages/adapters/src/provx_sdk/plugins.py`](../../packages/adapters/src/provx_sdk/plugins.py) · 82 lines
**PX rules carried:** PX-LICENSE (the subprocess boundary), PX-FIXTURE (the purity contract), PX-SCOPE (the caller precondition).

`FindingDraft` is imported under `if TYPE_CHECKING:` ([line 21](../../packages/adapters/src/provx_sdk/plugins.py#L21)) — the Protocol module has no runtime dependency on the models. Combined with `from __future__ import annotations`, this is correct modern practice and keeps the interface layer free-standing.

## 1.1 `ToolAdapter` — [line 26](../../packages/adapters/src/provx_sdk/plugins.py#L26)

`@runtime_checkable class ToolAdapter(Protocol)`.

### Attributes

| Attribute | Declared type | Documented values | Assessment |
|---|---|---|---|
| `name` | `str` | e.g. `"httpx"` | the registry dict key — see `SDK-005` |
| `category` | `str` | `"web" \| "api" \| "infra-ad" \| ...` | ❌ **not** `Module` |
| `safety` | `str` | `"passive" \| "intrusive"` | ❌ **safety-critical, unconstrained** |
| `tool` | `str` | e.g. `"httpx"` | the external binary wrapped |

**`safety: str` is the significant problem.** PX-PASSIVE and PX-ACTIVE both key off this value: *"In passive mode, no check may create, modify, or delete state on a target. If a check cannot guarantee that, it is `intrusive` and does not run in passive mode."* The gate that eventually implements this will compare `adapter.safety` against a mode. As a bare `str`:

- `"passive"`, `"Passive"`, `"pasive"`, and `""` are all equally valid to the type checker.
- A typo'd `"pasive"` will not equal `"intrusive"` — so depending on how the gate is written (`if safety == "intrusive": block` vs `if safety != "passive": block`), a typo either **silently permits an intrusive adapter in passive mode** or silently blocks a safe one. The fail-open variant is the natural way to write that check.
- mypy strict, which CI runs, cannot catch any of it.

`Literal["passive", "intrusive"]` or a `Safety` `StrEnum` makes the typo a CI failure instead of a safety incident. This should be fixed **before** the passive/active gate is written, not after. **`SDK-006`** (medium).

**`category: str` has already drifted.** The docstring lists `"infra-ad"`, but `Module` ([`findings.py:71`](../../packages/adapters/src/provx_sdk/findings.py#L71)) defines `INFRA = "infra"`. The adapter-metadata vocabulary and the finding vocabulary disagree, with one adapter written and one module implemented. `category: Module` would have made them the same vocabulary by construction.

### `build_command(self, *, targets: list[str], use_cases: list[str]) -> list[str]` — [line 42](../../packages/adapters/src/provx_sdk/plugins.py#L42)

Keyword-only (the bare `*`), which is right for a two-list signature where positional order would be easy to swap.

The docstring carries the PX-LICENSE rationale: *"Copyleft tools may only be invoked as separate subprocesses (rule PX-LICENSE), so this stays the path for external binaries."*

**Returning `list[str]` rather than `str` is the load-bearing choice.** It steers every implementer toward `subprocess.run(argv, shell=False)`, which is simultaneously:
- the **license boundary** — a separate process is mere aggregation, so wrapping sqlmap/nmap/OpenVAS cannot relicense Provx; and
- the **injection boundary** — a hostile target name like `example.com; rm -rf /` is one argv element, never a shell token.

One design decision serving both constraints. This is the best idea in the file.

### `async probe(self, target: str, *, timeout: float = 10.0) -> str` — [line 51](../../packages/adapters/src/provx_sdk/plugins.py#L51)

The in-process counterpart. Docstring: *"Exactly one of the two is live for any given adapter"* and *"The caller MUST have cleared the target against engagement scope before calling this (rule PX-SCOPE) — this is the method that touches the network."*

Two findings, both covered in depth elsewhere:

- **The "exactly one" invariant is unenforced prose.** An adapter implementing both, or neither, satisfies the Protocol identically. See `SDK-010` below.
- **Delegating the scope check to the caller contradicts PX-SCOPE**, which says scope *"is never trusted from an upstream caller"*. The method that touches the network is precisely the boundary that should own the check. Passing `policy: ScopePolicy` into `probe()` would make it structural — and would simultaneously fix the redirect bypass, since the policy would then be available at each hop. See [module_scope.md](module_scope.md) §5 and `SDK-001` / `SDK-002`.

The signature has no return-size bound and no way to pass proxy/redirect settings; see [module_adapters.md](module_adapters.md).

### `parse_output(self, raw: str) -> list[FindingDraft]` — [line 63](../../packages/adapters/src/provx_sdk/plugins.py#L63)

Two contracts stated in the docstring, both correct and both important:

1. **Drafts, not Findings** — *"`display_id` is a per-engagement sequence the persistence layer allocates, so an adapter is not in a position to assign one."* Reinforced structurally by `FindingDraft` lacking the field under `extra="forbid"`.
2. **Purity** — *"Implementations MUST be pure and deterministic — the same raw input yields the same drafts every time, which is what a recorded fixture asserts in CI (rule PX-FIXTURE)."*

Splitting the impure network call (`probe`) from the pure transform (`parse_output`) is the structural precondition that makes fixture testing meaningful at all. Without it, PX-FIXTURE could not be enforced without a live network. The one shipped adapter honors it — verified line by line in [module_adapters.md](module_adapters.md) §4.

## 1.2 `PlaybookPlugin` — [line 76](../../packages/adapters/src/provx_sdk/plugins.py#L76)

```python
@runtime_checkable
class PlaybookPlugin(Protocol):
    workflow: str
```

One attribute. The docstring points to `provx_sdk.playbook.Playbook` as the concrete model and names the `provx.playbooks` entry-point group.

This Protocol is currently **unused**: nothing loads the `provx.playbooks` group (the entry-point declaration is commented out, and `registry.py` only knows `provx.adapters`), and `Playbook` does not declare itself as implementing it. It is a placeholder marking where playbook plugins will attach. Consistent with declared scaffolding — noted, not filed.

## 1.3 The Protocol enforcement gap (`SDK-010`)

`@runtime_checkable` `isinstance()` checks verify **the presence of names**. Not signatures. Not types. Not arity. Not return types.

[`test_registry.py:17`](../../packages/adapters/tests/test_registry.py#L17):

```python
def test_loaded_adapter_satisfies_the_tool_adapter_protocol() -> None:
    assert isinstance(load_adapter("security_headers"), ToolAdapter)
```

This passes for any object carrying the seven names `name`, `category`, `safety`, `tool`, `build_command`, `probe`, `parse_output` — regardless of what they do. An adapter whose `parse_output` takes three positional arguments and returns `None`, or whose `safety` is the integer `7`, passes this assertion. The test is a spelling check presented as a contract check, and its name overstates what it verifies.

Static checking helps only if the adapter opts in. `SecurityHeadersAdapter` does **not** declare `class SecurityHeadersAdapter(ToolAdapter)` — it is a bare class relying on structural typing. mypy therefore never verifies it against the Protocol, because nothing in the codebase annotates it as one: `load_adapters()` returns `dict[str, ToolAdapter]` built from `entry.load()()`, which is `Any`, so the assignment is unchecked.

**Fixes, cheapest first:**
1. Add `_: ToolAdapter = SecurityHeadersAdapter()` in a test module — mypy strict then verifies the full signature match at CI time, for free.
2. Constrain `safety` and `category` to `Literal`/enum types (`SDK-006`) so the values are checked too.
3. Add a conformance test asserting **behavior**: exactly one of `build_command`/`probe` raises `NotImplementedError`; `parse_output` is idempotent; `name` is non-empty and matches its entry-point key.

**Severity: medium.** The gap is invisible today (one adapter, written by the same author) and becomes a real problem the moment a third-party adapter is installed — which is the entire purpose of this mechanism.

---

# Part 2 — `registry.py`

**File:** [`packages/adapters/src/provx_sdk/registry.py`](../../packages/adapters/src/provx_sdk/registry.py) · 38 lines

Docstring states the goal: *"Adapters are found through the `provx.adapters` entry-point group, never imported by name from the backend. That is what makes a third-party adapter a drop-in."*

Confirmed by grep: nothing in `backend/` imports `SecurityHeadersAdapter` directly. `scan_runner.py` calls `load_adapter(adapter_name)` with a string. The indirection is real, not aspirational.

## 2.1 `ADAPTER_GROUP` / `AdapterNotFoundError`

`ADAPTER_GROUP = "provx.adapters"` — a module constant matching the `pyproject.toml` declaration. Two places that must agree with nothing checking; a packaging test could assert the built distribution advertises this exact group.

`AdapterNotFoundError(LookupError)` — correct base class (`KeyError` is a `LookupError`, so callers can catch either).

## 2.2 `load_adapters() -> dict[str, ToolAdapter]` — [line 24](../../packages/adapters/src/provx_sdk/registry.py#L24)

```python
discovered: dict[str, ToolAdapter] = {}
for entry in entry_points(group=ADAPTER_GROUP):
    adapter = entry.load()()
    discovered[adapter.name] = adapter
return discovered
```

### ❌ The dict key comes from the adapter, not the manifest (`SDK-005`)

`discovered[adapter.name]` keys on the **instance attribute**, while the entry-point key (`security_headers = ...` in `pyproject.toml`) is discarded. Two consequences:

1. **A mismatch is silent.** An adapter registered as `security_headers` whose `name` attribute says `"sec_headers"` is reachable only as `sec_headers`. `load_adapter("security_headers")` raises `AdapterNotFoundError` while the package is correctly installed — a confusing failure with no diagnostic pointing at the mismatch.
2. **Duplicate names silently overwrite, last-wins.** Two installed packages both declaring `name = "nmap"` produce one entry. Which one survives depends on `entry_points()` iteration order, which follows `sys.path`/metadata discovery order and is **not a stable, documented guarantee**. So *which adapter actually runs* can differ between machines, between CI and local, and after an unrelated `pip install` reorders site-packages.

That second point is a **PX-DETERMINISM violation in the discovery layer**. The engine's promise is that the same input reproduces the same result; here the same engagement config can silently select a different adapter — and therefore produce different findings — depending on install order. In an adversarial framing it is worse: installing any package that declares `provx.adapters` with a colliding `name` **silently replaces** a trusted adapter, with no error and no log line.

**The inconsistency is the tell.** [`loader.py:58`](../../packages/adapters/src/provx_sdk/loader.py#L58) handles the identical situation for playbooks and refuses it explicitly:

```python
if pb.workflow in playbooks:
    raise PlaybookValidationError(f"duplicate workflow name {pb.workflow!r} ...")
```

with the comment *"Silently overwriting a workflow would let one file replace another's methodology without a trace — not acceptable for a deterministic, auditable engine."* That reasoning applies verbatim to adapters. The same author wrote both files and got it right once.

**Fix:** raise on duplicate `name`; and either key by the entry-point name, or validate `entry.name == adapter.name` and raise on mismatch.

**Severity: medium.**

### Other observations

- **`entry.load()()` executes third-party code at discovery time** — every installed adapter is imported *and instantiated*, whether or not the caller wants it. Inherent to entry points, but it means adapter `__init__` must be side-effect-free, and installing an adapter package is a trust decision equal to any dependency. Worth stating in the adapter-author docs.
- **No error isolation.** One adapter raising in `__init__` or at import aborts the whole loop, so a single broken third-party package makes **every** adapter undiscoverable, including the built-in one. A `try/except` per entry that logs and skips would contain the blast radius — with the caveat that silently skipping a security adapter is its own hazard, so it must log loudly. **`SDK-038`** (low).
- **No caching.** Every call re-runs metadata discovery, re-imports, and re-instantiates.
- **The declared return type is a lie mypy cannot see.** `entry.load()` returns `Any`, so `dict[str, ToolAdapter]` is asserted, never verified. Nothing checks the loaded object is a `ToolAdapter` at all — a `ValueError` at `adapter.name` is the first symptom. An `isinstance(adapter, ToolAdapter)` check here would at least catch missing names (with the §1.3 caveat that it only checks names).

## 2.3 `load_adapter(name: str) -> ToolAdapter` — [line 33](../../packages/adapters/src/provx_sdk/registry.py#L33)

```python
try:
    return load_adapters()[name]
except KeyError as exc:
    raise AdapterNotFoundError(f"no adapter named {name!r} is installed") from exc
```

- **`from exc`** preserves the exception chain — correct, and consistent with `loader.py`.
- **The message is user-safe** — names the requested adapter, leaks no paths, no tracebacks, no internals. PX-ERRORS clean.
- **Builds the entire registry to fetch one entry**, importing and instantiating every installed adapter as a side effect of asking for one. O(n) imports per lookup, with no cache.

---

# Verdict

| Aspect | Verdict |
|---|---|
| Entry-point indirection (no direct backend import) | ✅ **real** — verified by grep |
| `build_command` returns argv | ✅ **excellent** — PX-LICENSE and injection safety in one choice |
| `probe`/`parse_output` purity split | ✅ **correct** — precondition for PX-FIXTURE |
| `TYPE_CHECKING` import of `FindingDraft` | ✅ correct |
| Keyword-only args on `build_command`/`probe` | ✅ correct |
| `AdapterNotFoundError` chaining + safe message | ✅ correct |
| `safety`/`category` as bare `str` | ❌ `SDK-006` — safety-critical value with no type constraint |
| Protocol checks names only; adapter not statically verified | ❌ `SDK-010` |
| Duplicate `name` silently overwrites, order-dependent | ❌ `SDK-005` — PX-DETERMINISM issue; `loader.py` gets this right |
| Scope check delegated to caller | ❌ `SDK-002` — contradicts PX-SCOPE's own wording |
| "Exactly one of build_command/probe" unenforced | ❌ part of `SDK-010` |
| No error isolation across adapters | ❌ `SDK-038` |

The mechanism is well-conceived — the indirection is genuine, and the `build_command`/`probe` split encodes a real license constraint into a type signature. The weaknesses are all the same shape: **invariants documented in prose that the type system could enforce instead** (`safety` values, one-of-two implementation, unique names). At one first-party adapter none of them bite. Every one of them bites on the first third-party adapter, which is the mechanism's whole purpose.
