# `playbook.py` + `loader.py` — the deterministic playbook schema

Two files: `playbook.py` defines the schema, `loader.py` reads YAML into it. Together they are the "brain" — the auditable methodology that decides what runs next, **without AI**.

> **Read the scaffolding boundary first.** PX-DSL requires that `when`/`if` expressions be *stored verbatim and structure-validated only* until a restricted allowlisted evaluator exists. **These modules do exactly that, and that is correct current behavior — not a gap.** The absence of an evaluator and of an execution engine is declared scaffolding and is **not** reported as a defect anywhere in this audit.

---

# Part 1 — `playbook.py`

**File:** [`packages/adapters/src/provx_sdk/playbook.py`](../../packages/adapters/src/provx_sdk/playbook.py) · 83 lines
**PX rules carried:** PX-DSL, PX-ACTIVE.

## 1.1 The PX-DSL security posture

The module docstring ([lines 14-19](../../packages/adapters/src/provx_sdk/playbook.py#L14)) is the strongest piece of security documentation in the repo:

> *"SECURITY — rule PX-DSL: when the evaluator is built, it MUST be a restricted, allowlisted evaluator. `eval()` / `exec()` and any equivalent dynamic code execution are FORBIDDEN — evaluating an untrusted playbook expression with them is a remote code execution hole. The planned design is a fixed operator set (comparisons + boolean `and`/`or`/`not`) over a known **facts namespace** only: no function calls, no attribute traversal beyond whitelisted facts, no imports."*

This is exactly right, and the placement matters: the warning lives in the file a future contributor opens when they sit down to *write* the evaluator. That is the moment the mistake gets made, and it is the moment they will read this.

**Verified by grep across the whole SDK and lab:** no `eval`, no `exec`, no `compile`, no `pickle`, no `__import__`, no `yaml.load` without `safe_`. **PX-DSL is fully satisfied.**

`when` and `if_` are typed `str` and validated for non-emptiness only. Nothing parses them, nothing tokenizes them, nothing evaluates them. Expressions like `"path == '/api/docs' or swagger_detected"` are carried as opaque strings. Correct.

## 1.2 `PlaybookValidationError` — [line 27](../../packages/adapters/src/provx_sdk/playbook.py#L27)

`ValueError` subclass. The single error type for every playbook failure — unreadable file, bad YAML, wrong shape, schema violation, duplicate name. One `except` clause catches all playbook problems, and Pydantic's `ValidationError` never leaks to callers. Good boundary hygiene.

## 1.3 `_non_empty(value, field_name)` — [line 31](../../packages/adapters/src/provx_sdk/playbook.py#L31)

```python
if not value or not value.strip():
    raise ValueError(f"{field_name} must be a non-empty expression string")
return value
```

Shared by all three validators (rule Q-11, reuse before create). Rejects `""`, `"   "`, `"\n"`. **Returns the original `value`, not the stripped one** — deliberate and correct: PX-DSL says store *verbatim*, so whitespace is preserved for the future evaluator and for the audit trail. Normalizing here would quietly alter recorded methodology.

## 1.4 `DiscoveryRule` — [line 37](../../packages/adapters/src/provx_sdk/playbook.py#L37)

`model_config = ConfigDict(extra="forbid")`

| Field | Type | Default | Constraint |
|---|---|---|---|
| `when` | `str` | **required** | `_check_when` → `_non_empty` |
| `run` | `list[str]` | **required** | `Field(min_length=1)` |
| `active_only` | `list[str]` | `[]` | none |

Docstring states the PX-ACTIVE semantics: *"`run` steps are passive/safe; `active_only` steps are intrusive and gated to Active mode — they never run in passive/test."*

- **`min_length=1` on `run`** — a rule that fires and does nothing is a config error, correctly rejected. Tested at [`test_playbook_loader.py:36`](../../packages/adapters/tests/test_playbook_loader.py#L36).
- **`active_only` defaults to `[]`** — the safe default. A playbook is passive unless it explicitly opts into intrusive steps. Correct direction: forgetting the field yields the *safer* behavior.
- **Separate fields, not a flag on each step.** The intrusive set is structurally distinct from the safe set, so a gate cannot accidentally read the wrong one. Better than `[{step: x, intrusive: true}]`, where a missing flag would default to permissive.

**Gaps:**
- **No step-name validation.** `run: [fingerprint, tech_detect]` accepts any string. Nothing checks these correspond to installed adapters or known checks, so a typo (`securty_headers`) is a silent no-op — a check that never runs and never reports that it did not. In a compliance tool, a silently-skipped check is worse than a loud failure. Cross-validating against `load_adapters()` at load time is the fix (accepting the coupling). **`SDK-039`** (medium).
- **`run` and `active_only` may overlap.** A step in both lists is ambiguous — is it gated or not? No validator forbids it, and a permissive resolution would run an intrusive step in passive mode. Cheap to reject. **`SDK-040`** (low).
- **Empty strings allowed inside the lists.** `run: [""]` satisfies `min_length=1` (list length, not element content).

## 1.5 `RoutingRule` — [line 56](../../packages/adapters/src/provx_sdk/playbook.py#L56)

`model_config = ConfigDict(extra="forbid", populate_by_name=True)`

| Field | Type | Alias | Constraint |
|---|---|---|---|
| `if_` | `str` | `if` | `_check_if` → `_non_empty` |
| `then_validate` | `list[str]` | — | `Field(min_length=1)` |

The `if_`/`if` alias handles the Python-keyword collision, with the reason in a comment ([line 61](../../packages/adapters/src/provx_sdk/playbook.py#L61)): *"`if` is a Python keyword; expose it as the YAML alias while using `if_` internally."* The YAML stays natural (`if:`), the Python stays legal. `populate_by_name=True` allows both spellings when constructing in Python — convenient for tests, and the alias is what the YAML uses.

**Interaction worth noting:** `extra="forbid"` + `populate_by_name=True` means both `if` and `if_` are accepted from YAML. A playbook written with `if_:` would load silently despite the documented schema saying `if:`. Harmless, mildly inconsistent with the strictness elsewhere.

Docstring: *"Post-finding routing to a deterministic validator or sub-workflow."* — the PX-HUMAN validation pipeline's declarative half. `then_validate` has the same unvalidated-name gap as `run` (`SDK-039`).

## 1.6 `Playbook` — [line 71](../../packages/adapters/src/provx_sdk/playbook.py#L71)

`model_config = ConfigDict(extra="forbid")`

| Field | Type | Default | Constraint |
|---|---|---|---|
| `workflow` | `str` | **required** | `_check_workflow` → `_non_empty` |
| `on_discovery` | `list[DiscoveryRule]` | **required** | `Field(min_length=1)` |
| `routing` | `list[RoutingRule]` | `[]` | none |

- **`min_length=1` on `on_discovery`** — a playbook that discovers nothing is meaningless. Correct.
- **`routing` optional** — not every playbook needs post-finding routing. Correct.
- **`extra="forbid"` on all three models** — a typo'd key (`on_discovry:`) fails loudly instead of silently disabling the whole rule set. For a methodology file, this is the single most valuable config choice, and it is applied consistently.

**Gaps:**
- **No `version` field.** [`lab/expected.yml`](../../lab/expected.yml) manifests carry `version: 1`; playbooks do not. When the schema evolves there is no way to distinguish an old playbook from a malformed one. **`SDK-041`** (low).
- **`workflow` has no format constraint** — `"my workflow!! 🎉"` is a valid name, and it is used as a dict key in `load_playbooks_dir` and as a plugin identifier. A slug pattern (`^[a-z0-9-]+$`) would be appropriate.
- **No duplicate detection within a playbook** — two `on_discovery` rules with an identical `when` are accepted. Ambiguous once an evaluator exists.

## 1.7 The worked example

[`workflows/web-baseline.yaml`](../../workflows/web-baseline.yaml) validates against this schema and demonstrates the intended shape: three discovery rules, one routing rule, `active_only: [auth_bypass, default_creds]` on the login rule with an inline `# gated to Active mode` comment. Its header restates that the execution engine is not implemented. The example is honest about its own status.

---

# Part 2 — `loader.py`

**File:** [`packages/adapters/src/provx_sdk/loader.py`](../../packages/adapters/src/provx_sdk/loader.py) · 74 lines

Docstring: *"This is loading and validation ONLY — there is no execution engine."*

## 2.1 `load_playbook(path) -> Playbook` — [line 21](../../packages/adapters/src/provx_sdk/loader.py#L21)

Four guarded stages, each converting a distinct failure into `PlaybookValidationError`:

| Stage | Guard | Line |
|---|---|---|
| Read | `except OSError` | [30](../../packages/adapters/src/provx_sdk/loader.py#L30) |
| Parse | `except yaml.YAMLError` | [35](../../packages/adapters/src/provx_sdk/loader.py#L35) |
| Shape | `if not isinstance(data, dict)` | [38](../../packages/adapters/src/provx_sdk/loader.py#L38) |
| Schema | `except ValidationError` | [43](../../packages/adapters/src/provx_sdk/loader.py#L43) |

**`yaml.safe_load` — [line 34](../../packages/adapters/src/provx_sdk/loader.py#L34).** The critical line. `yaml.load()` with the default loader deserializes arbitrary Python objects and is a well-known RCE primitive; `safe_load` restricts to plain scalars/lists/dicts. A playbook is untrusted input under PX-DSL, so this is the same threat PX-DSL addresses, at the parser rather than the evaluator. **Correct, and it is the difference between a config loader and a remote-code-execution hole.**

**The `isinstance(data, dict)` check is a genuine catch.** `yaml.safe_load` returns whatever the document is — a list, a bare string, or `None` for an empty file. Without this guard, `Playbook.model_validate("just a string")` produces a confusing Pydantic error about the wrong thing. Tested at [`test_playbook_loader.py:50`](../../packages/adapters/tests/test_playbook_loader.py#L50).

**Error handling quality:** every raise uses `from exc`, preserving the chain. Messages name the file path and, for schema failures, embed the full Pydantic error. That is correct for a **developer/operator-facing** loader — playbooks are authored by the operator, so a precise error is the useful thing. PX-ERRORS governs *client-facing* responses; if a playbook is ever uploaded through the API, the raw Pydantic error must not be echoed to the client. Flagging for the future, not a current violation.

**`encoding="utf-8"` is explicit** on `read_text` — reproducible across platforms and locales, consistent with `evidence.seal`.

**Minor:** no file-size bound. `read_text` on a pathological YAML file (or a YAML bomb — `safe_load` prevents object construction but not billion-laughs alias expansion) will consume memory. Low risk since playbooks are operator-authored and local. **`SDK-042`** (low).

## 2.2 `load_playbooks_dir(directory) -> dict[str, Playbook]` — [line 47](../../packages/adapters/src/provx_sdk/loader.py#L47)

```python
for file in sorted([*d.glob("*.yaml"), *d.glob("*.yml")]):
    pb = load_playbook(file)
    if pb.workflow in playbooks:
        raise PlaybookValidationError(f"duplicate workflow name {pb.workflow!r} in {d} ({file.name})")
    playbooks[pb.workflow] = pb
```

**Two things done right, and one of them is the standout in this audit.**

**`sorted(...)` — PX-DETERMINISM.** `Path.glob` yields in filesystem order, which varies by OS and filesystem. Sorting makes iteration order deterministic across machines, so error-reporting order and any order-sensitive downstream behavior reproduce identically. Small line, real property.

*(Note: `sorted()` over the concatenation sorts by full path, so `a.yml` sorts before `b.yaml` — a single interleaved sequence rather than all `.yaml` then all `.yml`. Deterministic either way.)*

**Duplicate detection — [line 58](../../packages/adapters/src/provx_sdk/loader.py#L58).** With the comment:

> *"Silently overwriting a workflow would let one file replace another's methodology without a trace — not acceptable for a deterministic, auditable engine."*

This is precisely the right instinct, correctly reasoned, and it is **the same situation `registry.py` gets wrong** — `load_adapters()` silently last-wins on duplicate adapter names in non-deterministic iteration order (`SDK-005`). Same author, same repo, same hazard: resolved here, missed there. The comment above is the argument for fixing the registry.

**Minor gaps:**
- **Non-recursive.** Only top-level `*.yaml`/`*.yml`; a playbook in a subdirectory is silently ignored. Same class of silent-omission bug as `load_manifests` in the lab harness (`SDK-007`), and worth the same treatment.
- **Case-sensitive glob** on case-sensitive filesystems — `.YAML` is skipped.
- **No empty-directory signal** — a directory with no playbooks returns `{}` rather than raising, so a misconfigured path is indistinguishable from an empty one.

## 2.3 `find_workflows_dir(start=None) -> Path` — [line 66](../../packages/adapters/src/provx_sdk/loader.py#L66)

```python
here = Path(start) if start is not None else Path(__file__).resolve()
for parent in [here, *here.parents]:
    candidate = parent / "workflows"
    if candidate.is_dir():
        return candidate
raise PlaybookValidationError("could not locate a 'workflows/' directory")
```

Walks upward from this file to find the repo's `workflows/`. The docstring is admirably honest about its status: *"Convenience for tests and tooling; not used by any engine."*

- `.resolve()` on the default handles symlinks correctly.
- Raises rather than returning `None` — no `Optional` for callers to forget.
- Correctly scoped as a **test/tooling** helper. Upward directory-walking is fragile in production (it can escape a package root and find an unrelated `workflows/` in a parent directory, and behaves differently installed-in-site-packages vs. in a source checkout). Labelling it as tooling-only is the right call; it should not migrate into runtime code.

Used by [`test_playbook_loader.py:15`](../../packages/adapters/tests/test_playbook_loader.py#L15) to locate `web-baseline.yaml` — legitimate, since a test needs the repo root regardless of cwd.

---

## 3. Test coverage

[`test_playbook_loader.py`](../../packages/adapters/tests/test_playbook_loader.py) — 6 tests:

| Test | Covers |
|---|---|
| `test_web_baseline_parses` | the real playbook loads; `active_only` steps present; `if` alias works |
| `test_missing_required_field_raises` | `run` omitted → `min_length=1` |
| `test_empty_workflow_name_raises` | `_non_empty` on whitespace |
| `test_non_mapping_yaml_raises` | the `isinstance(data, dict)` guard |
| `test_load_missing_file_raises` | the `OSError` guard |
| `test_duplicate_workflow_name_raises` | duplicate detection in `load_playbooks_dir` |

Good coverage of the guard rails, and `test_web_baseline_parses` doubles as a fixture test pinning the real methodology file — including the load-bearing assertion that `auth_bypass` and `default_creds` are `active_only` ([lines 27-29](../../packages/adapters/tests/test_playbook_loader.py#L27)), which is a PX-ACTIVE regression guard.

**Not covered:**
- Malformed YAML syntax → the `yaml.YAMLError` branch is never exercised.
- Empty file → `safe_load` returns `None`, caught by the `isinstance` guard, but untested.
- `extra="forbid"` — no test asserts an unknown key is rejected, despite this being the most valuable config choice in the schema.
- `_non_empty` on `when` and `if_` (only `workflow` is tested).
- `find_workflows_dir` failure path.
- `load_playbooks_dir` on a non-directory / empty directory.
- **A test asserting no `eval`/`exec` appears in the module** — a grep-based guard would make PX-DSL an enforced CI gate rather than a documented intention. Given that the docstring calls this out as the file's central risk, this is the highest-value missing test here. **`SDK-043`** (low, high leverage).

---

## 4. Verdict

| Aspect | Verdict |
|---|---|
| PX-DSL: expressions stored verbatim, never evaluated | ✅ **correct** — the mandated behavior |
| No `eval`/`exec`/`compile`/`pickle` anywhere | ✅ **verified by grep** |
| `yaml.safe_load`, never `yaml.load` | ✅ **critical, and correct** |
| Security rationale documented where the mistake would be made | ✅ **best security doc in the repo** |
| `sorted()` glob for deterministic order | ✅ PX-DETERMINISM |
| Duplicate workflow names rejected with reasoning | ✅ **exemplary** — and the argument for fixing `SDK-005` |
| `extra="forbid"` on all schema models | ✅ correct |
| `active_only` as a separate field defaulting to `[]` | ✅ safe-by-default (PX-ACTIVE) |
| Error chaining + path-naming messages | ✅ correct |
| Step names unvalidated → typo = silent skipped check | ❌ `SDK-039` |
| `run`/`active_only` overlap permitted | ❌ `SDK-040` |
| No schema `version` field | ❌ `SDK-041` |
| No file-size bound on YAML | ❌ `SDK-042` |
| No CI guard asserting PX-DSL compliance | ❌ `SDK-043` |

These two files are the **best-executed pair in the SDK**. The security posture is right, documented at the point of risk, and verified. The duplicate-name reasoning in `loader.py` is the standard the rest of the codebase should be held to — starting with `registry.py`.
