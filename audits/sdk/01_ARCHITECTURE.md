# provx_sdk + lab — Architecture

The design decisions in this package, why they were made, and where they hold or leak.

---

## 1. The Finding contract lives in the SDK, not the backend

This is the single most consequential structural decision in the repo, and it is the right one.

`Finding`, `FindingDraft`, `Evidence`, `Severity`, `Confidence`, `Module`, `FindingStatus`, and `RiskAcceptance` all live in [`provx_sdk/findings.py`](../../packages/adapters/src/provx_sdk/findings.py). The module docstring states the rationale plainly:

> *"It lives in the SDK (not the backend) so tool adapters can depend on it without depending on the API."*

**The dependency graph this buys:**

```
                  ┌─────────────────┐
                  │  provx_sdk      │   pydantic, httpx, pyyaml
                  │  findings.py    │   (no FastAPI, no SQLModel, no DB)
                  └────────┬────────┘
                           │ imported by
        ┌──────────────────┼──────────────────┬─────────────────┐
        ▼                  ▼                  ▼                 ▼
   backend/app      3rd-party adapter    lab/harness.py    frontend types
   (FastAPI+DB)     (pip-installable)    (accuracy gate)   (via API schema)
```

The arrows all point **inward**. Nothing the SDK depends on knows anything about the platform. That is what makes "install a package, get an adapter, no core edit" actually true — a third-party adapter author `pip install provx-sdk`, imports `FindingDraft`, and never pulls FastAPI, SQLModel, Postgres drivers, or the API surface into their environment.

Had the contract lived in `backend/app/models/`, every adapter would transitively depend on the web framework, and the accuracy harness could not run in a container that has no database. Verified: `lab/harness.py` imports only `provx_sdk.findings` and `provx_sdk.registry`, and the `accuracy` compose service has no `depends_on: db`.

The docstring also constrains imports deliberately — *"Imports are limited to Pydantic + stdlib so the models stay dependency-light."* Confirmed: `findings.py` imports `re`, `uuid`, `datetime`, `enum`, and `pydantic`. Nothing else. That discipline is what keeps the contract portable, and it should be enforced as a rule rather than left to good intentions.

**Where the boundary is respected downstream:** [`backend/app/models/tables.py`](../../backend/app/models/tables.py) defines a separate `FindingRow` persistence model with a `from_draft()` constructor, rather than making `Finding` itself an ORM table. The domain contract and the storage schema are distinct types. This is the correct layering and worth protecting.

---

## 2. FindingDraft → Finding: why adapters cannot assign a display_id

Two identifiers, deliberately separate ([`findings.py:106-120`](../../packages/adapters/src/provx_sdk/findings.py#L106)):

| Identifier | Type | Scope | Assigned by | Reused? |
|---|---|---|---|---|
| `id` | `uuid.UUID` | global | `default_factory=uuid.uuid4` at construction | never |
| `display_id` | `str`, pattern `^PVX-\d{4,}$` | **per engagement** | the persistence layer | yes — across engagements |

`FindingDraft` carries every field of `Finding` **except** `id`, `display_id`, `epss`, and `status`. The promotion is one method:

```python
def to_finding(self, display_id: str) -> Finding:
    return Finding(display_id=display_id, **self.model_dump())
```

**The argument for this split is sound and load-bearing.** `display_id` is a per-engagement counter — engagement A and engagement B both legitimately have a `PVX-0001`. An adapter runs against one target with no knowledge of the engagement, no knowledge of how many findings preceded it, and no transaction to allocate a number in. Any `display_id` an adapter invented would be a guess, and two adapters running concurrently would guess the same one. Making the field structurally absent from `FindingDraft` means the mistake **cannot be expressed**, rather than being caught in review.

This is enforced by construction, not convention: `FindingDraft` sets `extra="forbid"`, so an adapter that tries `FindingDraft(display_id="PVX-0001", ...)` raises a `ValidationError` immediately. Good.

**The allocator** is [`display_id_for()` in `scan_runner.py:36`](../../backend/app/services/scan_runner.py#L36) — `f"PVX-{sequence:04d}"`. Note the `:04d` format spec is a *minimum* width that widens naturally past 9999 (`PVX-10000`), which matches the `\d{4,}` pattern exactly. The `{4,}` quantifier is documented at [`findings.py:30-33`](../../packages/adapters/src/provx_sdk/findings.py#L30) as a zero-padded minimum and not a cap, with the reasoning spelled out: a scanner legitimately exceeding four digits must not write a record that later fails to load. Format and pattern agree at the boundary. Tested at [`test_findings_validation.py:70`](../../packages/adapters/tests/test_findings_validation.py#L70). This is careful work.

**One asymmetry worth flagging:** `Finding` has `epss` and `status`; `FindingDraft` has neither. `epss` is correct to omit — it is enrichment applied later. `status` is also defensible (every draft starts `NEW`). But `to_finding()` does `**self.model_dump()`, so any field added to `FindingDraft` that is *not* on `Finding` will raise at promotion time under `extra="forbid"` — a footgun for a future contributor, with no test pinning the round-trip field-for-field. See `SDK-011`.

---

## 3. The ToolAdapter dual path: build_command vs probe

`ToolAdapter` ([`plugins.py:42-61`](../../packages/adapters/src/provx_sdk/plugins.py#L42)) declares two mutually exclusive ways to collect data:

| | `build_command(*, targets, use_cases) -> list[str]` | `async probe(target, *, timeout=10.0) -> str` |
|---|---|---|
| For | external binaries | in-process Python |
| Returns | argv list for a **subprocess** | raw output envelope |
| Driven by | PX-LICENSE | convenience/performance |
| Unused path raises | — | `NotImplementedError` |

The docstring states the invariant: *"Exactly one of the two is live for any given adapter."*

**Why `build_command` returns a list and not a string is the whole point.** PX-LICENSE forbids absorbing GPL/AGPL source (sqlmap, nmap, OpenVAS) into the codebase or wrapping a copyleft tool as a linked library — doing either would relicense Provx and destroy the open-core model. The only safe relationship is *mere aggregation*: invoke the tool as a separate process. Returning `list[str]` argv rather than a shell string additionally means the eventual runner can use `subprocess.run(argv, shell=False)` and be immune to shell injection from a target name. The license boundary and the injection boundary are enforced by the same design choice. That is elegant.

`SecurityHeadersAdapter` takes the `probe` path and raises from `build_command` with a message that restates the rule ([`security_headers.py:109-117`](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L109)). Pinned by [`test_security_headers_adapter.py:87`](../../packages/adapters/tests/test_security_headers_adapter.py#L87).

**The gap in the design:** the "exactly one is live" invariant is documented prose. Nothing enforces it. An adapter that implements both, or neither, satisfies the `runtime_checkable` Protocol identically — because Protocol `isinstance` checks names, not behavior. There is no `safety`-value validation either: `safety` is typed `str`, so `"passive"`, `"pasive"`, and `"very dangerous"` are equally acceptable to the type system, and PX-PASSIVE/PX-ACTIVE gating will eventually key off that string. Both should become `Literal` types or enums. See `SDK-006` and `SDK-010`.

**And the third method, `parse_output`,** is where determinism is contracted: *"Implementations MUST be pure and deterministic — the same raw input yields the same drafts every time, which is what a recorded fixture asserts in CI (rule PX-FIXTURE)."* The separation of `probe` (impure, network) from `parse_output` (pure, total) is the structural precondition for fixture testing to mean anything, and `SecurityHeadersAdapter` honors it — see [module_adapters.md](module_adapters.md) for the line-by-line purity analysis.

---

## 4. Scope enforcement design — and its two holes

PX-SCOPE: *"Every target and request is checked against the engagement's allow/deny scope at the adapter boundary, before any tool runs. Scope is never trusted from an upstream caller."*

The primitive is [`ScopePolicy.is_in_scope`](../../packages/adapters/src/provx_sdk/scope.py#L61), a three-step pipeline:

```
target URL ──> target_host()  ──> host string (lowercased, no port, no userinfo)
                    │                    │
              OutOfScopeError            ├──> any deny rule matches? ──> False
                    │                    └──> any allow rule matches? ──> that
                    └──> False (fail closed)
```

**Design properties that are right:**

- **Fail-closed on parse failure.** A URL that is not `http`/`https` with a hostname is out of scope, not guessed at.
- **Fail-closed on empty policy.** `ScopePolicy()` with no allow rules permits nothing. The docstring names the reason: *"a misconfigured engagement fails closed rather than scanning the internet."* Tested.
- **Deny evaluated first and unconditionally.** A broad allow can be carved out precisely, and deny cannot be out-voted.
- **Host-based, not URL-based.** Path, query, and fragment are irrelevant to authorization, so they are discarded. Correct — matching on full URLs invites normalization bugs.
- **Userinfo stripped correctly.** `urlsplit("http://example.com@evil.test/").hostname` is `evil.test`, and the policy correctly treats it as `evil.test`. I verified this empirically. Pinned by [`test_scope.py:40`](../../packages/adapters/tests/test_scope.py#L40). Many implementations get this wrong; this one does not.

**Hole 1 — the primitive is not applied at the adapter boundary.** `ScopePolicy` is a value object. `SecurityHeadersAdapter.probe()` accepts no policy, and its docstring pushes the duty to the caller: *"The caller is responsible for having cleared the target against engagement scope first."* PX-SCOPE says scope *"is never trusted from an upstream caller"* — but the current shape does exactly that. `scan_runner.py` happens to call it correctly ([line 66](../../backend/app/services/scan_runner.py#L66)); `lab/harness.py` never calls it at all. Two callers, one compliant.

**Hole 2 — the check is a point-in-time decision about a URL that then changes.** `probe()` sets `follow_redirects=True`. Scope is evaluated against the URL the caller supplied; httpx then follows wherever that URL points. This is the highest-severity finding in the audit and is analyzed in full in [module_scope.md](module_scope.md) §4 and filed as `SDK-001`.

---

## 5. Evidence sealing

PX-EVIDENCE: hash every artifact with SHA-256 and record a capture timestamp **at capture time**; store append-only.

[`evidence.py`](../../packages/adapters/src/provx_sdk/evidence.py) provides the primitive — 32 lines, one frozen model and one function. The design is minimal and correct in isolation:

- `EvidenceSeal` is `frozen=True` — a seal cannot be mutated after construction. This is the append-only property expressed in the type system, and it is exactly right.
- `seal(raw)` hashes and timestamps in a single expression, so the two cannot drift apart.
- `datetime.now(UTC)` — timezone-aware, no naive-datetime ambiguity.

**Is `seal()` called at capture time?** Yes, in the one live pipeline. [`scan_runner.py:74-77`](../../backend/app/services/scan_runner.py#L74):

```python
raw = await adapter.probe(target.url, timeout=timeout)
stamp = seal(raw)
scanned += 1
captured.extend((draft, stamp) for draft in adapter.parse_output(raw))
```

`seal(raw)` is the **immediately next statement** after the probe returns, before parsing, before dedup, before persistence. The module docstring states the intent — *"Evidence is sealed the moment a response comes back, not later"* — and the code matches. This is genuinely well done.

**Is the sealed value the same bytes that get stored?** Yes, with one caveat. `raw` is the exact string `probe()` returned; the same `raw` object is passed to `parse_output`, which embeds it verbatim into `Evidence.tool_output` ([`security_headers.py:152`](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L152)). `FindingRow.from_draft(draft, ..., stamp=stamp)` then persists both. Nothing re-encodes, re-serializes, or normalizes in between. The digest attests to the stored bytes.

The caveat: `seal()` hashes `raw.encode("utf-8")`, and Python `str` round-trips through UTF-8 deterministically, so verification will reproduce the digest — *provided* the storage layer stores the string, not a re-serialized JSON of it. Worth an explicit verify-side test that neither exists today. See `SDK-009`.

**One structural gap:** the seal is stored **beside** the finding, not **inside** `Evidence`. The `Evidence` model has six fields, none of which is `sha256` or `captured_at`. So `Evidence` — the type an adapter builds and a report renders — is unsealed on its own; integrity only exists at the `FindingRow` layer, and only because `scan_runner` remembered to thread `stamp` through. Any second consumer of the SDK gets an unsealed `Evidence`. `lab/harness.py` is precisely that second consumer, and it never seals anything. See `SDK-004`.

---

## 6. The accuracy gate scoring model

PX-DETERMINISM and PX-HUMAN both need a measurable claim: *these checks find what we say they find, and nothing else.* The gate turns that into a number.

**Identity.** A finding is matched to an oracle entry by `Evidence.matched_rule`, formatted `adapter:check` — e.g. `security_headers:x-frame-options`, built at [`security_headers.py:153`](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L153) as `f"{self.name}:{rule.header}"`. **Not** by title, which is prose and will be reworded. Choosing a machine identity over a human string is the correct call and the reason the manifests are stable.

**The three tallies**, per target, from [`score_target`](../../lab/harness.py#L92):

| Tally | Meaning | Computed as |
|---|---|---|
| **TP** | expected and found, at or above the severity floor | `found_id in expected` and severity ≥ `min_severity` |
| **FP** | found but not expected — *or* found but too weak | `found_id not in expected`, or below floor (tagged `"(below low)"`) |
| **FN** | expected but not found | `expected - set(found)` |

`Score.passed` is `not false_positives and not false_negatives`. **TP count is not part of the pass condition** — it is reported for humans, not gated on. That is correct: TP is derivable from expected minus FN, so gating on it would be redundant.

**The severity floor is the subtle part.** A check that fires but downgrades from `low` to `info` is scored as a **false positive**, not a true positive — see [`harness.py:103-104`](../../lab/harness.py#L103). Calling a severity regression an FP rather than an FN is arguable, but the effect is right: it fails the gate, loudly, with a distinguishable label. Pinned by [`test_harness.py:84`](../../lab/tests/test_harness.py#L84).

**The positive/negative pairing is the real design.** Optimizing for recall alone is trivial — report everything, get zero FNs. The `clean/hardened` target exists to make that strategy fail: `expect_none: true` means any finding is an FP. The two targets together pin precision *and* recall, and neither can be gamed without failing the other. This is the correct shape for an accuracy gate and the strongest idea in `lab/`.

**Where the scoring model leaks** — all traced in [module_lab.md](module_lab.md):

- `found` is a **dict keyed by `matched_rule`**, so two findings sharing a rule on one target silently collapse to one, last-wins (`SDK-003`).
- `expect_none` is parsed into `Manifest` and **never read by the scorer** — negative targets pass only as an emergent consequence of `expect` being empty (`SDK-008`).
- `kind` is likewise never read by scoring logic.
- `check_id` **raises** on a finding with no `matched_rule`, crashing the run rather than scoring it (`SDK-012`).
- `load_manifests` globs exactly two levels deep, so a misplaced manifest vanishes silently (`SDK-007`).

---

## 7. Summary of architectural verdicts

| Decision | Verdict |
|---|---|
| Finding contract in SDK, not backend | **Correct.** Keeps the dependency graph pointing inward; makes third-party adapters real. |
| Draft/Finding split for `display_id` | **Correct.** Makes an impossible-to-get-right assignment structurally inexpressible. |
| `{4,}` display_id pattern + `:04d` allocator | **Correct and carefully reasoned.** Format and pattern agree past 9999. |
| `build_command` returns argv, not a shell string | **Correct.** Serves PX-LICENSE and injection-safety with one choice. |
| `probe`/`parse_output` purity split | **Correct.** Precondition for PX-FIXTURE to be meaningful. |
| Scope deny-first, fail-closed, host-based | **Correct primitive.** |
| Scope applied *by callers*, not at the adapter boundary | **Contradicts PX-SCOPE's own wording.** `SDK-002`. |
| Scope checked before a redirect-following fetch | **Defeated.** `SDK-001` — highest severity in this audit. |
| `EvidenceSeal` frozen, sealed at capture | **Correct**, but seal lives outside `Evidence`. `SDK-004`. |
| Positive/negative lab pairing | **Correct and the strongest idea in `lab/`.** |
| `found` dict keyed by `matched_rule` | **Lossy.** `SDK-003`. |
| Playbook expressions stored verbatim, unevaluated | **Correct per PX-DSL.** Declared scaffolding, not a gap. |

---

*Next: the per-module deep dives, starting with [module_findings.md](module_findings.md).*
