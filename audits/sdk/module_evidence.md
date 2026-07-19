# `evidence.py` — PX-EVIDENCE integrity primitive

**File:** [`packages/adapters/src/provx_sdk/evidence.py`](../../packages/adapters/src/provx_sdk/evidence.py) · 32 lines — the smallest module in the SDK.
**Rule:** [PX-EVIDENCE](../../docs/PROVX_RULES.md) — *"Hash every evidence artifact with SHA-256 and record a capture timestamp **at capture time**. Store evidence and the audit log **append-only** — no update or delete paths; a correction is a new entry referencing the prior one."*

The rule states the stakes precisely: *"Findings are only defensible if their evidence can be shown unaltered since capture."* This module is the primitive that makes that claim provable.

---

## 1. `EvidenceSeal` — [line 20](../../packages/adapters/src/provx_sdk/evidence.py#L20)

```python
model_config = ConfigDict(extra="forbid", frozen=True)

sha256: str
captured_at: datetime
```

| Field | Type | Constraint |
|---|---|---|
| `sha256` | `str` | **none** — see below |
| `captured_at` | `datetime` | none — but always UTC-aware in practice via `seal()` |

**`frozen=True` is the most important character in this file.** It makes the seal immutable after construction: `stamp.sha256 = "..."` raises a `ValidationError`. PX-EVIDENCE's append-only requirement is expressed in the type system rather than left to reviewer vigilance. A tamper-evidence record that can be silently overwritten is worthless, and this closes that off at the language level. Correct, and notably the *only* model in the SDK that is frozen — `RiskAcceptance`, also described as a permanent audit record, is not (see [module_findings.md](module_findings.md) §7, `SDK-024`).

`extra="forbid"` — a typo'd field fails loudly rather than being silently dropped.

**Gap: `sha256` is an unconstrained `str`.** `EvidenceSeal(sha256="not-a-hash", captured_at=...)` constructs successfully. Since `seal()` is the only producer today this is latent, but the model is public (exported in `__all__`) and the backend imports it directly ([`tables.py:20`](../../backend/app/models/tables.py#L20)) — so a hand-constructed or deserialized-from-DB seal has no format guarantee. A `pattern=r"^[0-9a-f]{64}$"` costs nothing and makes a truncated or mis-encoded digest impossible to represent. **`SDK-031`** (low).

**Gap: `captured_at` does not require timezone-awareness.** `seal()` always supplies UTC, but the model would accept a naive datetime from any other construction path — and naive-vs-aware comparisons raise at runtime while naive timestamps are ambiguous in an audit trail. Pydantic v2 supports `AwareDatetime` for exactly this. **`SDK-032`** (low).

**Design gap: the seal is not bound to what it seals.** `EvidenceSeal` carries a digest and a time, but no reference to *which* artifact — no finding id, no target, no artifact identifier. Binding is positional: `scan_runner` holds `list[tuple[FindingDraft, EvidenceSeal]]` ([line 63](../../backend/app/services/scan_runner.py#L63)) and relies on the tuple pairing surviving the dedup loop. Correct today, but a seal that travels alone means nothing. **`SDK-033`** (low; matters when evidence is exported or re-verified out of band).

---

## 2. `seal(raw: str) -> EvidenceSeal` — [line 29](../../packages/adapters/src/provx_sdk/evidence.py#L29)

```python
digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
return EvidenceSeal(sha256=digest, captured_at=datetime.now(UTC))
```

Two lines, and both are right:

- **SHA-256** — mandated by the rule, and the correct choice for tamper evidence.
- **Explicit `"utf-8"`** — not the platform default. Reproducible across machines and locales, which matters for a digest that must be re-verifiable years later.
- **`datetime.now(UTC)`** — timezone-aware, no naive-datetime ambiguity, no local-timezone drift between the scanner host and the reporting host.
- **Hash and timestamp in a single expression** — the two cannot drift apart. There is no window where an artifact is hashed but not yet stamped.

The function is pure apart from reading the clock, which is inherent to what it does.

**Limitation: `str` only.** The signature takes `str`, so binary artifacts — screenshots, pcaps, binary tool output — cannot be sealed. `Evidence.screenshot_path` already anticipates screenshots. When they land this needs a `bytes` overload or a `seal_bytes()` companion; hashing a path string proves nothing about the file it names. **`SDK-034`** (low today, blocking when screenshots ship).

**Limitation: no streaming.** `raw.encode("utf-8")` materializes the whole artifact in memory before hashing. Fine for header envelopes (~1 KB); a problem for a multi-hundred-megabyte tool dump. Compounds with the unbounded-response issue in [module_adapters.md](module_adapters.md) (`SDK-035`).

---

## 3. PX-EVIDENCE compliance — the two questions

### Q1: Is `seal()` called at capture time? **Yes.**

[`scan_runner.py:74-77`](../../backend/app/services/scan_runner.py#L74):

```python
raw = await adapter.probe(target.url, timeout=timeout)
stamp = seal(raw)
scanned += 1
captured.extend((draft, stamp) for draft in adapter.parse_output(raw))
```

`seal(raw)` is the **immediately next statement** after the probe returns — before parsing, before dedup, before persistence, before anything can transform the artifact. The module docstring states the intent (*"Evidence is sealed the moment a response comes back, not later"*) and the code matches it exactly.

This is the part most implementations get wrong: they seal at persistence time, by which point the artifact has been parsed, re-encoded, and possibly normalized, so the digest attests to processing output rather than to what the tool saw. The docstring here names that exact failure mode — *"so the hash attests to what the tool actually saw rather than to whatever survived later processing"* — and the ordering honors it. **Genuinely well done.**

### Q2: Is the sealed value the same bytes that get stored? **Yes.**

Traced end to end:

1. `probe()` returns `raw`, a `str` from `encode_response()`.
2. `seal(raw)` hashes exactly that string.
3. The **same `raw` object** is passed to `parse_output(raw)`.
4. `parse_output` embeds it verbatim: `Evidence(tool_output=raw, ...)` ([`security_headers.py:152`](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L152)). No re-encoding, no re-serialization, no normalization.
5. `FindingRow.from_draft(draft, ..., stamp=stamp)` persists both together.

The digest attests to the stored bytes. Python `str` round-trips through UTF-8 deterministically, so verification will reproduce the digest — **provided** the storage layer stores the string rather than a re-serialized JSON of the model. That last step is the one link not covered by any test.

**There is no verification path.** Nothing in the codebase re-computes a digest and compares it to a stored seal. The system can *produce* tamper evidence but cannot yet *check* it — and an unexercised verification path is one that will not work when first needed. A `verify(raw, stamp) -> bool` helper plus a round-trip test through the persistence layer is the missing half. **`SDK-036`** (medium).

---

## 4. Where PX-EVIDENCE is not satisfied

### The seal lives outside `Evidence` (`SDK-004`)

`Evidence` ([module_findings.md](module_findings.md) §4) has six fields, none of them `sha256` or `captured_at`. So:

- An `Evidence` object on its own is **unsealed and unverifiable**.
- Integrity exists only at the `FindingRow` layer, and only because `scan_runner` remembered to thread `stamp` through as a parallel value.
- **Any other consumer of the SDK gets unsealed evidence by default.** `lab/harness.py` is exactly that consumer — it calls `adapter.probe()` and `adapter.parse_output()` and never imports `seal`. Confirmed by grep: `seal` appears in `backend/` and in `provx_sdk/__init__.py`, and nowhere in `lab/`.

The correct shape is for sealing to be **impossible to skip** — either `Evidence` carries an optional `seal: EvidenceSeal` field populated at capture, or `probe()` returns a sealed envelope type rather than a bare `str`. As written, PX-EVIDENCE compliance is a property of one caller's discipline rather than of the contract.

**Severity: MEDIUM.** The one live pipeline is compliant; the contract does not make compliance the default.

### One seal covers many findings

`captured.extend((draft, stamp) for draft in adapter.parse_output(raw))` — all five drafts from one target share **one** seal, because they genuinely share one artifact. That is correct. Worth stating explicitly since the DB will store the same digest on five rows, which looks like duplication but is the intended semantics.

### Append-only is a claim, not yet a mechanism

The docstring asserts *"Stored evidence is append-only: a correction is a new record referencing the prior one, never an edit."* `frozen=True` enforces this **in memory**. At the storage layer there is no `UPDATE`/`DELETE` prohibition, no DB-level grant restriction, and no "references the prior one" field anywhere in the models — `FindingRow` has no `supersedes` / `corrects` column. The append-only correction workflow is described but not yet expressible. Reasonable at pre-alpha; flagging so it is not mistaken for done. **`SDK-037`** (low, forward-looking).

---

## 5. Test coverage

**There is no `test_evidence.py` in [`packages/adapters/tests/`](../../packages/adapters/tests/).** A PX-EVIDENCE primitive has **zero direct unit tests** in the package that owns it.

The only coverage is indirect, from the backend: [`backend/tests/test_scan_runner.py:43`](../../backend/tests/test_scan_runner.py#L43) constructs `stamp=seal("raw")`, and [line 84](../../backend/tests/test_scan_runner.py#L84) `test_valid_row_carries_the_evidence_seal` asserts the seal reaches the row. That tests the *wiring*, not the primitive — and it lives in a different package, so `packages/adapters` can be released with a broken `seal()` and its own suite stays green.

Missing tests, all cheap:

| Test | Asserts |
|---|---|
| Known-vector digest | `seal("").sha256 == "e3b0c442...b855` — pins the algorithm and the UTF-8 encoding |
| Determinism | `seal(x).sha256 == seal(x).sha256` |
| Sensitivity | one changed character changes the digest |
| Non-ASCII | `seal("café")` is stable and matches an independently-computed UTF-8 digest |
| Immutability | mutating `stamp.sha256` raises (pins `frozen=True` — the load-bearing config) |
| Awareness | `seal(x).captured_at.tzinfo is not None` |
| Ordering | `captured_at` is within a tight window of `datetime.now(UTC)` |
| **Round-trip verify** | re-hashing the stored `tool_output` reproduces the stored `sha256` |

The last one is the one that matters most — it is the assertion that would catch a future refactor breaking the capture-time guarantee, which is the entire point of the rule.

**`SDK-009`** (medium).

---

## 6. Module verdict

| Aspect | Verdict |
|---|---|
| SHA-256 with explicit UTF-8 | ✅ correct and reproducible |
| Timestamp at capture, UTC-aware | ✅ correct |
| Hash + stamp atomic in one expression | ✅ correct |
| `frozen=True` on the seal | ✅ **the right call** — append-only in the type system |
| `seal()` called at capture time in the live pipeline | ✅ **verified** — immediately after probe, before parse |
| Sealed bytes == stored bytes | ✅ **verified** — same object, no re-encoding |
| Seal stored *outside* `Evidence` | ❌ `SDK-004` — compliance depends on caller discipline |
| No verification path exists | ❌ `SDK-036` |
| No unit tests in this package | ❌ `SDK-009` |
| `sha256` / `captured_at` unconstrained | ❌ `SDK-031`, `SDK-032` |
| `str`-only, no binary, no streaming | ❌ `SDK-034`, `SDK-035` |

Thirty-two lines that get the hard part — *when* to hash — exactly right, wrapped in a contract that does not yet make getting it right unavoidable. The fix is not to the algorithm; it is to move the seal inside `Evidence` so a consumer cannot hold unsealed evidence, and to add the verification half so the guarantee is exercised.
