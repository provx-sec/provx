# `findings.py` — the platform-wide Finding contract

**File:** [`packages/adapters/src/provx_sdk/findings.py`](../../packages/adapters/src/provx_sdk/findings.py) · 195 lines
**Imports:** `re`, `uuid`, `datetime`, `enum`, `pydantic` — stdlib + Pydantic only, deliberately.
**PX rules carried:** PX-ATTACK, PX-HUMAN, PX-DETERMINISM.

This is the canonical shared type for the entire platform. Adapters produce it, the backend persists it, reports render it. Every field below is a contract other code depends on.

---

## 1. Module-level constants

### `DISPLAY_ID_PATTERN` — [line 33](../../packages/adapters/src/provx_sdk/findings.py#L33)

```python
DISPLAY_ID_PATTERN = r"^PVX-\d{4,}$"
```

Preceded by a three-line comment explaining `{4,}` rather than `{4}`: four digits is a zero-padded **minimum, not a cap**. An engagement exceeding 9999 findings keeps counting (`PVX-10000`) rather than emitting a label the contract would reject.

The reasoning is exactly right, and it is the kind of thing that is almost always discovered in production instead. A scanner that legitimately exceeds four digits must not be able to write a record that later fails to load. The allocator [`display_id_for()`](../../backend/app/services/scan_runner.py#L36) uses `f"PVX-{sequence:04d}"`, whose format spec is also a minimum width — the two agree past the boundary. Verified by [`test_findings_validation.py:70`](../../packages/adapters/tests/test_findings_validation.py#L70), which parametrizes `PVX-0001`, `PVX-9999`, `PVX-10000`, `PVX-123456`.

Anchored `^…$`. In Python `re`, `$` also matches immediately before a trailing newline — so `"PVX-0001\n"` would pass. Pydantic's `pattern=` uses `re.search` with the anchors as written, so this quirk applies. Trivial in practice (nothing constructs a display_id with a newline), but `\Z` is the airtight form. Filed as informational, `SDK-016`.

### `ATTACK_TECHNIQUE_PATTERN` — [line 34](../../packages/adapters/src/provx_sdk/findings.py#L34)

```python
ATTACK_TECHNIQUE_PATTERN = r"^T\d{4}(\.\d{3})?$"
```

Matches `T1190` and sub-techniques `T1190.001`. Correctly **rejects** tactic IDs (`TA0001`) — a common conflation, and the test suite pins it explicitly.

---

## 2. `validate_attack_techniques(techniques: list[str]) -> list[str]` — [line 37](../../packages/adapters/src/provx_sdk/findings.py#L37)

Shared validator, applied identically at every boundary that accepts techniques. The docstring names the reason: *"so the rule is enforced identically at each boundary, rather than only where a finding is finally assembled (rule PX-ATTACK)."*

```python
for technique in techniques:
    if not re.match(ATTACK_TECHNIQUE_PATTERN, technique):
        raise ValueError(...)
return techniques
```

**PX-ATTACK check — are technique IDs validated everywhere they enter?** Yes. Both `Finding` and `FindingDraft` register the identical `@field_validator("attack_techniques")` delegating to this one function ([lines 141-144](../../packages/adapters/src/provx_sdk/findings.py#L141) and [167-170](../../packages/adapters/src/provx_sdk/findings.py#L167)). Those are the only two models carrying techniques. **No boundary is missed.**

This is the single-source-of-truth pattern done right, and it satisfies rule Q-11 (reuse before create). Two duplicated regexes would drift; one function cannot.

Notes:
- `re.match` anchors at the start only; the pattern's own `^…$` supplies the rest. Redundant but harmless.
- The error message includes the offending value with `{technique!r}` and an example of the correct form — good operator ergonomics, and it does not leak internals (PX-ERRORS clean).
- **Returns the list unchanged** — no normalization, no dedup, no sorting. `["T1190", "T1190"]` is accepted as-is. Whether duplicate techniques should collapse is a product decision; today they do not. Noted, not filed.
- **Empty list is valid.** PX-ATTACK requires *"≥1 MITRE ATT&CK technique ID"*, and both models default to `Field(default_factory=list)`. A `Finding` with zero techniques constructs fine. The `Finding` docstring hedges: *"At least one is expected once a finding is final."* The rule is aspirational at the type level. This is defensible for a *draft*, but `Finding` is the final form and PX-ATTACK is unconditional. See `SDK-015`.

---

## 3. Enums

All four are `StrEnum` (Python 3.11+), so members compare equal to their string values and serialize to plain strings in JSON. Correct choice for a wire contract.

### `Severity` — [line 52](../../packages/adapters/src/provx_sdk/findings.py#L52)

| Member | Value |
|---|---|
| `INFO` | `"info"` |
| `LOW` | `"low"` |
| `MEDIUM` | `"medium"` |
| `HIGH` | `"high"` |
| `CRITICAL` | `"critical"` |

Declared low-to-high, but **`StrEnum` does not provide ordering** — `Severity.LOW < Severity.HIGH` is a `TypeError`. Consumers must supply their own ordering, and `lab/harness.py` does exactly that with a hand-maintained `SEVERITY_ORDER` list ([`harness.py:29`](../../lab/harness.py#L29)) that duplicates the declaration order. Two lists that must agree, in two packages, with nothing checking. See `SDK-017`.

### `Confidence` — [line 62](../../packages/adapters/src/provx_sdk/findings.py#L62)

`HIGH` / `MEDIUM` / `LOW`. Declared **high-to-low** — the reverse of `Severity`. Harmless today since nothing orders confidence, but the inconsistency is a trap for whoever writes the second `*_ORDER` list.

Docstring ties it to PX-HUMAN: low-confidence findings can be filtered so noise is opt-in.

### `Module` — [line 71](../../packages/adapters/src/provx_sdk/findings.py#L71)

`WEB` / `API` / `INFRA`. Matches the roadmap's module split. Note `ToolAdapter.category` is a bare `str` documented as `"web" | "api" | "infra-ad" | ..."` — **`"infra-ad"` is not a `Module` value** (`Module.INFRA` is `"infra"`). The adapter-metadata vocabulary and the finding vocabulary already disagree, before either has a second implementation. See `SDK-006`.

### `FindingStatus` — [line 79](../../packages/adapters/src/provx_sdk/findings.py#L79)

`NEW` → `TRIAGED` → `VALIDATED` / `FALSE_POSITIVE` / `ACCEPTED_RISK` / `FIXED` / `REGRESSION`.

This is the PX-HUMAN lifecycle: *the machine proposes, a human confirms*. Seven states, no transition rules — any state can be set to any other. A state machine belongs here eventually; at scaffolding stage the enum alone is appropriate.

---

## 4. `Evidence` — [line 92](../../packages/adapters/src/provx_sdk/findings.py#L92)

`model_config = ConfigDict(extra="forbid")`

| Field | Type | Default | Notes |
|---|---|---|---|
| `raw_request` | `str \| None` | `None` | never populated by the one shipped adapter |
| `raw_response` | `str \| None` | `None` | never populated |
| `tool_output` | `str \| None` | `None` | populated — the full raw envelope |
| `matched_rule` | `str \| None` | `None` | populated — **the accuracy gate's identity key** |
| `reproduction_cmd` | `str \| None` | `None` | populated — `curl -sSI {target}` |
| `screenshot_path` | `str \| None` | `None` | never populated |

Docstring: *"All fields are optional; an adapter fills in what it captured."*

**Findings on this model:**

- **`matched_rule` being `str | None` is the root of a downstream crash.** It is the identity the entire accuracy gate matches on, yet it is optional, so `harness.check_id` must raise when it is absent — see [module_lab.md](module_lab.md) §4 and `SDK-012`. An optional field that a consumer treats as mandatory is a contract mismatch, not a harness bug.
- **No integrity fields.** No `sha256`, no `captured_at`. PX-EVIDENCE requires hash + capture timestamp; `EvidenceSeal` supplies them but lives *outside* this model, threaded separately through `scan_runner`. Any consumer holding an `Evidence` alone holds unverifiable evidence. `SDK-004`.
- **`screenshot_path` is a path, not content.** A path is not evidence — the file it points to can be swapped after capture with no detectable change. When screenshots land, this needs a companion seal.
- **No size bounds on `tool_output`.** It holds the whole raw envelope; five findings on one target embed five full copies of the same string ([`security_headers.py:152`](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L152)). Correct for auditability, wasteful at scale. `SDK-018`.
- `extra="forbid"` — good, a typo'd field name fails loudly.

---

## 5. `Finding` — [line 106](../../packages/adapters/src/provx_sdk/findings.py#L106)

`model_config = ConfigDict(extra="forbid")`

| # | Field | Type | Default | Constraint |
|---|---|---|---|---|
| 1 | `id` | `uuid.UUID` | `uuid.uuid4()` via `default_factory` | — |
| 2 | `display_id` | `str` | **required** | `pattern=^PVX-\d{4,}$` |
| 3 | `title` | `str` | **required** | none — empty string accepted |
| 4 | `target` | `str` | **required** | none — not URL-validated |
| 5 | `module` | `Module` | **required** | enum |
| 6 | `severity` | `Severity` | **required** | enum |
| 7 | `cvss` | `float \| None` | `None` | `ge=0.0, le=10.0` |
| 8 | `epss` | `float \| None` | `None` | `ge=0.0, le=1.0` |
| 9 | `confidence` | `Confidence` | `MEDIUM` | enum |
| 10 | `status` | `FindingStatus` | `NEW` | enum |
| 11 | `attack_techniques` | `list[str]` | `[]` | `_valid_attack_techniques` validator |
| 12 | `evidence` | `Evidence \| None` | `None` | — |
| 13 | `remediation` | `str \| None` | `None` | — |

**Validator:** `_valid_attack_techniques` ([line 141](../../packages/adapters/src/provx_sdk/findings.py#L141)) → `validate_attack_techniques`.

**What is right:**
- The two-identifier design is documented in the docstring with the per-engagement reset explained. `id` is a UUID PK, never reused; `display_id` is the human label, per-engagement, so two engagements can both hold `PVX-0001`.
- `cvss` bounded `0.0–10.0` and `epss` bounded `0.0–1.0` — the correct scales, and mixing them up is a classic bug that these bounds catch.
- `epss` is present as a *field* with no producer, which is honest scaffolding: PX-DETERMINISM's prioritization formula (severity + CVSS + EPSS + asset criticality) has its slot reserved.
- `default_factory=uuid.uuid4` — a factory, not a shared default. The classic mutable-default bug is avoided; likewise `default_factory=list` on `attack_techniques`.

**What is loose:**
- **`title` and `target` have no constraints.** `Finding(display_id="PVX-0001", title="", target="", ...)` validates. `target` in particular is the field the report attributes the finding to, and it is unvalidated free text — `scope.target_host()` exists and could constrain it. `SDK-019`.
- **`attack_techniques` may be empty** on a *final* `Finding`, contradicting PX-ATTACK's "≥1". `SDK-015`.
- **`cvss` may be `None`** on a final `Finding`, same rule, same gap.
- **Nothing pins severity to CVSS.** `severity=CRITICAL, cvss=0.1` validates. PX-DETERMINISM wants a defensible formula; a cross-field validator is the natural home. Not filed — the formula itself is declared future work.

---

## 6. `FindingDraft` — [line 147](../../packages/adapters/src/provx_sdk/findings.py#L147)

`model_config = ConfigDict(extra="forbid")`

| # | Field | Type | Default | Constraint |
|---|---|---|---|---|
| 1 | `title` | `str` | **required** | none |
| 2 | `target` | `str` | **required** | none |
| 3 | `module` | `Module` | **required** | enum |
| 4 | `severity` | `Severity` | **required** | enum |
| 5 | `cvss` | `float \| None` | `None` | `ge=0.0, le=10.0` |
| 6 | `confidence` | `Confidence` | `MEDIUM` | enum |
| 7 | `attack_techniques` | `list[str]` | `[]` | validator |
| 8 | `evidence` | `Evidence \| None` | `None` | — |
| 9 | `remediation` | `str \| None` | `None` | — |

**Absent versus `Finding`, by design:** `id`, `display_id`, `epss`, `status`.

The docstring gives the rationale: *"An adapter cannot know a finding's `display_id`: that sequence is per-engagement and is allocated when the finding is persisted."* Combined with `extra="forbid"`, an adapter that tries to set one gets a `ValidationError`. The mistake is structurally inexpressible. See [01_ARCHITECTURE.md](01_ARCHITECTURE.md) §2.

### `dedup_key` property — [line 172](../../packages/adapters/src/provx_sdk/findings.py#L172)

```python
@property
def dedup_key(self) -> tuple[str, str]:
    return (self.target, self.title)
```

Deterministic, hashable, order-stable — a tuple, not a set or dict. Correct for PX-DETERMINISM. Consumed by [`scan_runner._existing_dedup_keys`](../../backend/app/services/scan_runner.py#L105), which reconstructs `(row.target, row.title)` from the DB. The two must agree; nothing enforces that they do.

Two substantive concerns:

1. **`title` is prose and it is part of the identity.** Rewording *"Missing X-Frame-Options header"* to *"X-Frame-Options header not set"* silently makes every existing finding a new one — every prior finding reappears as fresh, triage state is stranded, and no test catches it. `matched_rule` (`security_headers:x-frame-options`) is the stable machine identity and already exists on `Evidence`; the accuracy gate correctly uses *that* rather than title. Dedup should follow the gate's lead. `SDK-020`.
2. **The docstring cites the wrong rule** — `"(PX-ATTACK)"`. PX-ATTACK is the ATT&CK-mapping rule; dedup belongs to **PX-DETERMINISM**. PX-ATTACK's text does mention de-duplication in passing, so the confusion is understandable, but a rules-cited-by-ID culture depends on the citations being right. `SDK-021`.

### `to_finding(display_id: str) -> Finding` — [line 177](../../packages/adapters/src/provx_sdk/findings.py#L177)

```python
return Finding(display_id=display_id, **self.model_dump())
```

Promotion is one line. `Finding` re-validates everything — techniques, CVSS bounds, the display_id pattern — so promotion cannot smuggle in an invalid value. `id` and `status` take their defaults; `epss` stays `None` pending enrichment.

The fragility: `**self.model_dump()` means **any field added to `FindingDraft` that does not exist on `Finding` raises at promotion time** under `extra="forbid"`. There is no test asserting `set(FindingDraft.model_fields) <= set(Finding.model_fields)`, so that breakage surfaces at runtime rather than in CI. One assertion would pin it permanently. `SDK-011`.

`model_dump()` also converts nested `Evidence` to a dict, which `Finding` re-validates back into an `Evidence` — a round-trip that works but costs a re-parse. `model_dump()` on enums under Pydantic v2 returns the enum members (not `.value`) by default, so no string-coercion surprise. Correct as written.

---

## 7. `RiskAcceptance` — [line 182](../../packages/adapters/src/provx_sdk/findings.py#L182)

`model_config = ConfigDict(extra="forbid")`

| Field | Type | Default | Notes |
|---|---|---|---|
| `finding_id` | `str` | **required** | see below |
| `owner` | `str` | **required** | unconstrained free text |
| `reason` | `str` | **required** | unconstrained |
| `expires_on` | `date` | **required** | no future-date constraint |
| `created_at` | `datetime` | **required** | **no default** — caller supplies |

Governance record: an owner, a reason, an expiry. Docstring calls it *"a permanent audit-trail record (DefectDojo-style governance)"*.

- **`finding_id: str` is deliberately ambiguous**, and the comment says so: *"Kept as a string for now; the pipeline decides whether it holds the UUID `Finding.id` or the human `display_id` when the DB layer lands."* Honest deferral, correctly flagged in-code. But `display_id` is only unique *per engagement* — if that is the eventual choice, `RiskAcceptance` needs an `engagement_id` too or it is ambiguous across engagements. Worth deciding before the DB layer, not after. `SDK-022`.
- **`created_at` has no default and is not timezone-constrained.** Unlike `EvidenceSeal`, which stamps itself with `datetime.now(UTC)`, this trusts the caller — who may pass a naive datetime, or a backdated one. For a record described as *permanent audit-trail*, self-stamping in UTC is the safer shape. `SDK-023`.
- **`expires_on` is unconstrained** — a risk acceptance can be created already expired, or expiring in the year 3000. A `date`-vs-`created_at` cross-validator is the obvious guard.
- **Nothing enforces append-only.** The model is not `frozen=True`, unlike `EvidenceSeal`. PX-EVIDENCE's append-only requirement covers the audit log; a "permanent audit-trail record" that is freely mutable in memory is at odds with that. `frozen=True` here would cost nothing. `SDK-024`.

---

## 8. Module verdict

| Aspect | Verdict |
|---|---|
| Contract placement (SDK not backend) | **Correct and load-bearing** |
| `display_id` `{4,}` reasoning + allocator agreement | **Excellent** — a real bug avoided by design |
| Draft/Finding split | **Excellent** — mistake made inexpressible |
| PX-ATTACK validation at every boundary | **Complete** — both models, one shared function |
| `extra="forbid"` on all five models | **Correct** |
| No mutable default bugs | **Correct** |
| Import discipline (stdlib + Pydantic only) | **Correct** — should become an enforced rule |
| PX-ATTACK "≥1 technique" on final `Finding` | **Not enforced** (`SDK-015`) |
| `Evidence` carries no integrity fields | **Gap** (`SDK-004`) |
| `dedup_key` keyed on prose `title` | **Fragile** (`SDK-020`) |
| `RiskAcceptance` mutable + caller-stamped | **Weak for an audit record** (`SDK-023`, `SDK-024`) |
| `Severity` has no ordering; consumers duplicate it | **Gap** (`SDK-017`) |
