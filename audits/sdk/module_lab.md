# `lab/` — the accuracy gate

**Files:** [`lab/harness.py`](../../lab/harness.py) (154 lines), [`lab/tests/test_harness.py`](../../lab/tests/test_harness.py) (101 lines), two target directories, one index file.
**PX rules carried:** PX-DETERMINISM, PX-HUMAN, PX-FIXTURE, PX-AUTHZ. **Violated:** PX-SCOPE.

The gate exists to make an empirical claim: *these checks find what we say they find, and nothing else.* Its docstring states the stakes: *"a PR that starts crying wolf on the clean target — or stops catching a known issue — fails CI rather than users."*

Every behavioral claim below was **executed against the real code**.

---

## 1. Module constants

```python
LAB_ROOT = Path(__file__).resolve().parent
SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
```

`LAB_ROOT` uses `.resolve()` — symlink-safe, cwd-independent. Correct.

**`SEVERITY_ORDER` is a hand-maintained duplicate of `Severity`'s declaration order, in a different package** ([`findings.py:52`](../../packages/adapters/src/provx_sdk/findings.py#L52)). Two lists that must agree, with nothing checking. Adding `Severity.NONE` to the SDK without updating this list makes `SEVERITY_ORDER.index()` raise `ValueError` mid-run; reordering it silently inverts every severity comparison in the gate — the gate would still pass, while comparing the wrong way.

The root cause is that `StrEnum` provides no ordering, so every consumer invents one (see [module_findings.md](module_findings.md) §3). The fix belongs in the SDK: an ordered enum, or a `SEVERITY_ORDER` exported from `findings.py` as the single source of truth (rule Q-11). **`SDK-017`** (medium).

---

## 2. `Manifest` — [line 32](../../lab/harness.py#L32)

`@dataclass` with five fields:

| Field | Type | Default | Source key |
|---|---|---|---|
| `path` | `Path` | required | — |
| `target` | `str` | required | `target` |
| `kind` | `str` | required | `kind`, defaulting to `"positive"` |
| `expect` | `list[dict[str, Any]]` | `[]` | `expect` |
| `expect_none` | `bool` | `False` | `expect_none` |

A plain `@dataclass`, not a Pydantic model — even though the SDK already depends on Pydantic and every other schema in the repo uses it. The consequence is that **the manifest schema is unvalidated**: no `extra="forbid"`, no type coercion, no required-field errors. Every finding in §7 traces back to this choice. **`SDK-055`** (medium) — `Manifest` should be a Pydantic model with `extra="forbid"`, which would convert all of the silent failures below into loud ones.

### `expected_ids` property — [line 42](../../lab/harness.py#L42)

```python
return {str(item["id"]) for item in self.expect}
```

Returns a **set**, correct for membership testing and set difference. `item["id"]` is unguarded — a manifest entry missing `id` raises `KeyError` with no indication of which file. **A set also silently deduplicates**: an oracle listing the same check twice collapses to one, so a copy-paste error in a manifest is invisible.

### `min_severity(check_id)` method — [line 46](../../lab/harness.py#L46)

```python
for item in self.expect:
    if str(item["id"]) == check_id and "min_severity" in item:
        return Severity(str(item["min_severity"]))
return None
```

Linear scan returning the **first** match. Correct given unique ids; with a duplicated id carrying different floors, the first silently wins. `Severity(...)` raises `ValueError` on a typo (`"lo"`) — the failure is loud, but it happens deep in scoring rather than at load, so the message does not name the file.

---

## 3. `Score` — [line 53](../../lab/harness.py#L53)

```python
target: str
true_positives: set[str]
false_positives: set[str]
false_negatives: set[str]

@property
def passed(self) -> bool:
    return not self.false_positives and not self.false_negatives
```

Three sets and a derived verdict. Clean, and the right model: TP is not part of the pass condition (it is derivable from expected minus FN), so gating on it would be redundant. Sets give free dedup and the set-difference operation FN needs.

---

## 4. `check_id(draft)` — [line 84](../../lab/harness.py#L84)

```python
evidence = draft.evidence
if evidence is None or not evidence.matched_rule:
    raise ValueError(f"finding {draft.title!r} has no matched_rule to score against")
return evidence.matched_rule
```

### ❌ What happens with a finding that has no `matched_rule`? It **crashes the run.** — `SDK-012`

This was the specific question asked, and the answer is: the gate does not score it, does not report it, and does not fail gracefully. It raises `ValueError`, which propagates through `score_target` → `run` → `asyncio.run` in `main()`, uncaught. The process dies with a traceback.

The consequences:

- **`report()` never runs.** No scorecard is printed. Other targets already scored are discarded. A developer sees a Python traceback instead of a TP/FP/FN table, with no indication which *target* was being scored.
- **The exit code is accidentally correct.** An uncaught exception exits 1, so `make accuracy` still fails and CI still blocks. The gate fails safe — by luck of Python's default, not by design. `main()` has no `try/except` and its `return 0 if report(scores) else 1` is never reached.
- **The root cause is a contract mismatch, not a harness bug.** `Evidence.matched_rule` is typed `str | None` and documented as optional ([module_findings.md](module_findings.md) §4), while the gate treats it as mandatory. The SDK permits what the harness forbids.

A finding with no `matched_rule` is genuinely unscoreable, so raising is defensible in principle — but it should be caught at the `score_target` or `run` boundary and turned into a **loud FAIL for that target** with the target named, so the scorecard still prints and other targets still score. Better still: make the requirement structural by having the SDK guarantee `matched_rule` on any draft intended for scoring.

**Severity: medium.**

---

## 5. `score_target(manifest, drafts)` — [line 92](../../lab/harness.py#L92)

```python
found = {check_id(draft): draft for draft in drafts}
expected = manifest.expected_ids
result = Score(target=manifest.target)

for found_id, draft in found.items():
    if found_id not in expected:
        result.false_positives.add(found_id); continue
    floor = manifest.min_severity(found_id)
    if floor is not None and SEVERITY_ORDER.index(draft.severity) < SEVERITY_ORDER.index(floor):
        result.false_positives.add(f"{found_id} (below {floor.value})"); continue
    result.true_positives.add(found_id)

result.false_negatives = expected - set(found)
return result
```

The core logic is right: unexpected → FP, expected-but-weak → FP with a distinguishing label, expected-and-strong → TP, expected-but-absent → FN via set difference.

### ❌ The `found` dict silently collapses duplicates — and makes the gate order-dependent — `SDK-003`

`found = {check_id(draft): draft for draft in drafts}` builds a dict keyed by `matched_rule`. **A dict comprehension keeps the LAST value for a repeated key.** Two findings sharing a `matched_rule` on one target become one, and the survivor depends on list position.

This is not theoretical. I executed it against an oracle of `{id: "a:b", min_severity: "high"}`:

| Drafts (in order) | TP | FP | **Gate verdict** |
|---|---|---|---|
| `a:b`@HIGH, then `a:b`@INFO | `{}` | `{"a:b (below high)"}` | **FAIL** |
| `a:b`@INFO, then `a:b`@HIGH | `{"a:b"}` | `{}` | **PASS** |

**The same set of findings produces opposite gate verdicts depending on list order.** That is a **PX-DETERMINISM violation inside the tool built to enforce determinism** — the harness's own docstring opens by invoking reproducibility, and the scorer is the one place in the repo that fails it.

Two distinct defects, one line:

1. **Data loss.** Findings vanish from scoring without a warning. An adapter reporting the same check on three URL paths of one target has two silently discarded — the gate under-counts and cannot detect it.
2. **Order dependence.** Only the surviving draft's severity is checked against the floor, so which draft is evaluated is positional.

Today `SecurityHeadersAdapter` emits each rule at most once per target, so the bug is dormant — and `parse_output`'s guaranteed ordering means it is currently *stable*. It activates the moment any adapter reports a check more than once per target, which is normal for path-scoped, parameter-scoped, or port-scoped checks.

**Fix:** group instead of overwrite — `defaultdict(list)` keyed by `matched_rule`, then apply the severity floor to the **strongest** (or all) drafts in each group, and surface the instance count in the report. That is both deterministic and more informative.

**Severity: medium** (latent today; a correctness bug in the correctness gate).

### Other observations

- **`expected - set(found)`** — `set(found)` on a dict yields its keys. Correct, if slightly implicit; `found.keys()` reads better.
- **FP entries are heterogeneous strings.** A plain FP is `"a:b"`; a below-floor FP is `"a:b (below high)"`. Convenient for printing, but the set now mixes identities with human-readable annotations, so it cannot be compared or aggregated programmatically. A structured `Score` (id + reason) would be cleaner.
- **A below-floor finding is classified FP, not FN.** Arguable — the check *did* fire — but the effect is right: it fails the gate loudly and distinguishably. Tested at [`test_harness.py:84`](../../lab/tests/test_harness.py#L84).
- **`SEVERITY_ORDER.index()` raises `ValueError`** for any severity not in the list — same fragility as §1.

### ❌ `expect_none` is parsed and never read — `SDK-008`

`Manifest.expect_none` is loaded from YAML, stored on the dataclass, exposed as a field — and **never referenced by `score_target` or anything else**. Confirmed by grep: the only occurrences are the field declaration, the `load_manifests` assignment, and a test constructor.

Negative targets pass **as an emergent side effect**: `expect` is empty → `expected` is an empty set → every finding falls into the `not in expected` branch → FP → fail. The behavior is correct; the mechanism is accidental.

Verified: a manifest with `kind="negative"` and **`expect_none=False`** scores identically to one with `expect_none=True`. The flag is inert.

Why this matters:
- **A typo in the manifest is silent.** `expect_none: ture` → `bool("ture")` → `True`; `expect_nome: true` → the key is ignored entirely. Neither is caught, and neither changes behavior — so the operator's *intent* is never validated.
- **`kind` is equally inert.** Nothing in the scoring path reads it. A `kind: negative` manifest that also lists `expect` entries would silently behave as a positive target. The only thing that reads `kind` is a test assertion ([`test_harness.py:97`](../../lab/tests/test_harness.py#L97)).
- Config that looks load-bearing but is not misleads whoever writes the next manifest.

**Fix:** either enforce it (`if manifest.expect_none and manifest.expect: raise` — a manifest cannot be both; and assert `expect_none` is `True` for `kind: negative`) or delete both fields and document that an empty `expect` *is* the negative case. Enforcing is better: the redundancy is a useful cross-check on operator intent, once actually checked.

**Severity: medium.**

---

## 6. `load_manifests(root)` — [line 67](../../lab/harness.py#L67)

```python
for path in sorted(root.glob("*/*/expected.yml")):
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    manifests.append(Manifest(
        path=path,
        target=str(data["target"]),
        kind=str(data.get("kind", "positive")),
        expect=list(data.get("expect") or []),
        expect_none=bool(data.get("expect_none", False)),
    ))
```

**Correct:** `sorted()` for deterministic order (PX-DETERMINISM), `yaml.safe_load` not `yaml.load` (consistent with `loader.py`), explicit `encoding="utf-8"`, `or {}` handling an empty file, `or []` handling `expect:` with a null value.

Verified against the real tree: finds both manifests, `clean/hardened` before `positive/missing-headers`.

### ❌ The glob silently misses misplaced manifests — `SDK-007`

`*/*/expected.yml` matches **exactly two directory levels**. Therefore:

| Location | Found? |
|---|---|
| `lab/positive/missing-headers/expected.yml` | ✅ |
| `lab/clean/hardened/expected.yml` | ✅ |
| `lab/positive/expected.yml` (one level) | ❌ **silently skipped** |
| `lab/positive/web/xss/expected.yml` (three levels) | ❌ **silently skipped** |
| `lab/positive/missing-headers/expected.yaml` (`.yaml`) | ❌ **silently skipped** |
| `lab/positive/missing-headers/Expected.yml` (case) | ❌ **silently skipped** |

**A misplaced manifest is not an error — it is an absence.** And an absent manifest is an absent test: the target is never probed, its expected findings are never checked, and **no FN is ever recorded** because the oracle that would have declared them is not loaded. The gate reports `pass` with fewer targets and nobody notices, because nothing asserts how many targets there should be.

That is the dangerous shape: a safety gate whose failure mode is quietly testing less. It compounds with `SDK-057` below.

**Fix:** use `rglob("expected.yml")` (depth-agnostic), and/or cross-validate against the manifest list in [`lab/expected.yml`](../../lab/expected.yml) — which exists, lists both paths, and **is currently never read by any code** (it is documentation only). Reading it and asserting that every listed path was loaded, and every loaded path was listed, converts silent omission into a hard failure and gives that file a purpose.

**Severity: medium.**

### ❌ Would a typo'd `kind:` be caught? **No.** — `SDK-056`

Traced:

- **`kind: postive`** (typo) → `data.get("kind", "positive")` returns `"postive"`. Stored verbatim. **Nothing validates it against a known set**, and — as established in §5 — **nothing in the scoring path reads `kind` at all**. Scoring is unaffected; the typo is invisible.
- **`knid: negative`** (typo'd key) → `.get("kind", "positive")` falls back to `"positive"`. A clean target is now labelled positive with an empty `expect`, so every finding on it is an FP. Behavior happens to stay correct, by accident.
- The **only** thing that would notice is [`test_harness.py:98`](../../lab/tests/test_harness.py#L98), `assert kinds == {"positive", "negative"}` — which fires on a typo, but with the unhelpful message that a set comparison failed, and only because the suite happens to assert on the real on-disk manifests.

Similarly unvalidated: `version` (declared `version: 1` in both manifests, **never read**), and any unknown key, which is silently ignored — the `Manifest` dataclass has no `extra="forbid"` equivalent.

**Only `target` is effectively required** — `data["target"]` raises `KeyError`, unguarded and without naming the file.

**Fix:** make `Manifest` a Pydantic model with `extra="forbid"`, `kind: Literal["positive", "negative"]`, and `version: int`. Every failure above becomes a load-time error naming the file. **`SDK-055`.**

---

## 7. `run(root, adapter_name)` — [line 112](../../lab/harness.py#L112)

```python
adapter = load_adapter(adapter_name)
scores: list[Score] = []
for manifest in load_manifests(root):
    raw = await adapter.probe(manifest.target)
    scores.append(score_target(manifest, adapter.parse_output(raw)))
return scores
```

### ❌❌ No scope check whatsoever — `SDK-002`

**`run()` never constructs a `ScopePolicy` and never calls `is_in_scope`.** Confirmed by grep: `ScopePolicy` appears in `backend/`, in `provx_sdk/`, and in `test_scope.py` — **nowhere in `lab/`**.

`manifest.target` comes straight from a YAML file and goes straight into `adapter.probe()`, which performs the network request. PX-SCOPE requires the check *"at the adapter boundary, before any tool runs"*, and states scope *"is never trusted from an upstream caller."* Here there is no check at any layer.

The `probe()` docstring — *"The caller MUST have cleared the target against engagement scope before calling this"* — is a contract this caller silently breaks. **Two callers of `probe()` exist: `scan_runner` (compliant) and `harness` (not).** A 50% compliance rate on the platform's central safety rule, achieved in the first two callers, is the strongest possible argument that the check belongs *inside* `probe()` rather than in a docstring.

Containment today is **Docker's**, not Provx's: the `accuracy` service runs on the `internal: true` `lab` network with no route off it. That is good defense in depth — but it is not the tool being safe. And `main()` exposes `--lab-root`, explicitly inviting the harness to be run outside compose against an arbitrary directory of manifests. Do that, and a manifest naming any host on the internet is probed, unchecked.

Fixing `SDK-001` by moving `ScopePolicy` into `probe()` fixes this simultaneously.

**Severity: medium** (contained by Docker today; the design defect is the same one as `SDK-001`).

### Other issues

- **No exception handling.** A `ConnectError` on target 1 aborts before target 2 is scored — no partial results, no scorecard. Combined with `SDK-051` (the adapter has no error handling either), an unreachable lab container produces a raw traceback instead of a useful failure. **`SDK-051`**.
- **Default timeout used.** `adapter.probe(manifest.target)` omits `timeout`, taking the adapter's `10.0` default. Not configurable from the CLI.
- **Sequential probing** — fine for two targets, and arguably correct: sequential is deterministic, concurrent scoring would need care to stay so.
- **`adapter.probe` / `adapter.parse_output` are unchecked calls** on a `ToolAdapter` Protocol that guarantees names only (`SDK-010`).
- **Only one adapter is scored per run** (`--adapter`, default `security_headers`). As adapters multiply, the gate needs to score all of them, or CI needs a matrix. Today's single adapter makes this invisible.

---

## 8. `report(scores)` — [line 122](../../lab/harness.py#L122)

```python
if not scores:
    print("accuracy gate: no lab manifests found", file=sys.stderr)
    return False
```

**The empty-scores guard is the right instinct and deserves credit** — it is precisely the "gate that silently tests nothing" failure mode, and it is caught and turned into a failure with a message on stderr. Good.

But it only catches the case where **zero** manifests load. It does not catch **some** manifests failing to load — which is exactly what `SDK-007` produces. If one of two manifests is misplaced, `scores` has one entry, `report` prints a one-row table, every score passes, and the gate returns `True`. **`SDK-057`** (medium): assert a minimum expected target count, or cross-check against `lab/expected.yml`.

The rest is clean: aligned column output, per-target verdict, and **`sorted()` on both FP and FN detail loops** ([lines 135, 137](../../lab/harness.py#L135)) so diagnostic output is deterministic and diffable across runs — a small touch that reflects the same care as `sorted()` in `load_manifests`.

Minor: the scorecard goes to stdout while the empty-scores error goes to stderr — inconsistent, though defensible (data vs. error). `f"{score.target:<34}"` truncates nothing but misaligns for targets longer than 34 characters.

---

## 9. `main()` — [line 143](../../lab/harness.py#L143)

```python
parser.add_argument("--lab-root", type=Path, default=LAB_ROOT)
parser.add_argument("--adapter", default="security_headers")
args = parser.parse_args()
scores = asyncio.run(run(args.lab_root, args.adapter))
return 0 if report(scores) else 1
```

Clean CLI. `type=Path` for correct coercion; sensible defaults; `raise SystemExit(main())` under `__main__` propagates the exit code correctly, which is what `make accuracy` and CI depend on.

- **No `try/except`.** Any exception from `run()` — `ValueError` from `check_id` (`SDK-012`), `KeyError` from a malformed manifest, `ConnectError` from an unreachable target, `AdapterNotFoundError` from a bad `--adapter` — produces a traceback rather than a diagnosed failure. All exit 1, so the gate fails safe, but the operator experience is poor and the failure is unattributed. Wrapping in a handler that prints a clear message and returns 1 costs four lines.
- **`--lab-root` accepts any path**, which combined with `SDK-002` means an arbitrary manifest directory can drive arbitrary network requests.
- **No `--verbose`/`--json`** — the scorecard is human-only, so CI cannot machine-consume results or trend accuracy over time.

---

## 10. The lab targets and their oracles

### `lab/positive/missing-headers/` — the recall test

[`nginx.conf`](../../lab/positive/missing-headers/nginx.conf): a minimal server block sending **no** security headers. Its comment states the authorization posture: *"Authorized, self-contained testing only; this target is never exposed off the lab network"* — consistent with PX-AUTHZ and with the `internal: true` network.

[`expected.yml`](../../lab/positive/missing-headers/expected.yml): `kind: positive`, five `expect` entries — one per rule in `RULES` — each with `min_severity: low`.

**The oracle exactly mirrors the adapter's five rules**, and the ids use the `adapter:check` form the adapter emits. Complete coverage of the current ruleset: deleting or breaking any single rule produces an FN and fails CI. This is PX-FIXTURE working as intended.

*(Note the coupling: every `min_severity` is `low`, matching every rule's `LOW` severity. If a rule is ever raised to `medium`, the floor still passes — floors catch downgrades, not upgrades. Correct, and worth knowing.)*

### `lab/clean/hardened/` — the precision test

[`nginx.conf`](../../lab/clean/hardened/nginx.conf): all five headers, each with the `always` directive so they are emitted on error responses too — a correct nginx detail that many hardening guides miss.

[`expected.yml`](../../lab/clean/hardened/expected.yml): `kind: negative`, `expect_none: true`, no `expect` list.

**This is the false-positive tripwire and the most important idea in `lab/`.** Optimizing for recall alone is trivial — report everything, get zero FNs. This target makes that strategy fail immediately. The two targets together pin precision *and* recall, and neither can be gamed without failing the other.

**Its blind spot** (see `SDK-046` in [module_adapters.md](module_adapters.md)): the hardened target sets *correct* header values, and the adapter only checks presence. A third target sending **present-but-worthless** values — `Content-Security-Policy: default-src *`, `Strict-Transport-Security: max-age=0`, `X-Content-Type-Options: yes` — would currently score as clean, exposing the value-validation gap. That target is the highest-value addition to the lab. **`SDK-058`** (medium).

### `lab/expected.yml` — the index

Documents the per-target schema and lists both manifest paths. **Read by nothing.** As noted in §6, wiring it in as the authoritative manifest list would fix `SDK-007` and `SDK-057` in one change and give the file a job.

---

## 11. Test coverage — `lab/tests/test_harness.py`

Seven tests, and the suite's stated philosophy is right: *"The gate is only worth having if it actually fails when it should, so these drive the scorer directly with synthetic findings rather than over the network."* **Testing that a gate FAILS correctly is the thing most teams skip**, and five of the seven tests do exactly that.

| Test | Covers |
|---|---|
| `test_expected_finding_scores_as_a_true_positive` | happy path |
| `test_missing_expected_finding_is_a_false_negative` | FN detection |
| `test_unexpected_finding_is_a_false_positive` | FP detection |
| `test_any_finding_on_a_clean_target_fails_the_gate` | the tripwire |
| `test_clean_target_with_no_findings_passes` | the tripwire's happy path |
| `test_finding_below_the_severity_floor_does_not_count_as_a_hit` | the severity floor |
| `test_lab_manifests_on_disk_load_and_cover_both_cases` | real manifests load; both kinds present |

The last test is the most valuable: it exercises `load_manifests` against the **real on-disk tree** and asserts a real check id is present, so it catches manifest corruption. Note it asserts `len(manifests) >= 2` — a lower bound, which does not catch one manifest going missing if a third is ever added.

### Coverage gaps — every one maps to a finding

| Gap | Finding |
|---|---|
| **Two findings sharing a `matched_rule`** — the dict-overwrite / order-dependence bug | `SDK-003` |
| **A finding with no `matched_rule`** — `check_id` raising | `SDK-012` |
| **`expect_none` semantics** — no test proves the flag does anything (it does not) | `SDK-008` |
| **A misplaced manifest** — no test that a wrong-depth manifest is caught | `SDK-007` |
| **Malformed manifest** — missing `target`, typo'd `kind`, unknown keys, bad `min_severity` | `SDK-055`, `SDK-056` |
| **`run()`** — completely untested; no test of the probe→score pipeline | `SDK-002`, `SDK-051` |
| **`report()`** — no test of output or of the empty-scores guard | `SDK-057` |
| **`main()`** — no test of exit codes, the one thing CI depends on | — |
| **Scope enforcement** — no test asserts the harness respects scope (it does not) | `SDK-002` |

`score_target` is well covered. `load_manifests` is thinly covered. **`run`, `report`, and `main` have zero coverage** — including the exit-code path that is the gate's entire contract with CI.

---

## 12. Verdict

| Aspect | Verdict |
|---|---|
| Positive/negative target pairing | ✅ **the strongest idea in `lab/`** — pins precision and recall together |
| Matching on `matched_rule`, not title | ✅ correct — stable machine identity |
| Severity floors catching downgrades | ✅ thoughtful |
| `sorted()` in `load_manifests` and in `report` | ✅ PX-DETERMINISM |
| `yaml.safe_load` | ✅ correct |
| Empty-scores guard in `report` | ✅ right instinct, incomplete |
| Tests that assert the gate FAILS correctly | ✅ **the right testing philosophy** |
| Lab containment: `internal` network, no ports, profile-gated | ✅ **correct PX-AUTHZ posture** |
| Makefile exit-status capture before teardown | ✅ correct |
| Oracle mirrors the adapter's ruleset exactly | ✅ complete for the current rules |
| `found` dict collapses duplicates → **order-dependent verdicts** | ❌ `SDK-003` — PX-DETERMINISM violated *in the determinism gate* |
| No `ScopePolicy` anywhere in the harness | ❌ `SDK-002` — PX-SCOPE violated |
| `expect_none` and `kind` parsed but never read | ❌ `SDK-008` |
| Glob silently misses misplaced manifests | ❌ `SDK-007` |
| `report` cannot detect partial manifest loss | ❌ `SDK-057` |
| `check_id` crashes the run instead of failing a target | ❌ `SDK-012` |
| `Manifest` unvalidated (plain dataclass) | ❌ `SDK-055`, `SDK-056` |
| `SEVERITY_ORDER` duplicates the SDK enum | ❌ `SDK-017` |
| `run`/`report`/`main` untested | ❌ coverage gap |
| No present-but-worthless-value target | ❌ `SDK-058` |

The gate's **design** is right — the positive/negative pairing, the stable identity, the severity floors, and a test suite that verifies failure rather than success are all correct choices that many teams get wrong.

Its **implementation** has a theme: **silent reduction in what is tested.** A misplaced manifest disappears, a duplicate finding disappears, a typo'd `kind` does nothing, `expect_none` does nothing, and partial manifest loss still reports `pass`. Each is individually minor; together they mean the gate can quietly verify less than it claims while continuing to print `pass`. For a component whose entire purpose is to be the thing you trust, that is the failure mode that matters most — and the cheapest fix (making `Manifest` a validated Pydantic model and reading `lab/expected.yml` as the authoritative list) closes most of them at once.
