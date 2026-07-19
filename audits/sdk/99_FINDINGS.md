# provx_sdk + lab — Findings

**Audited:** 2026-07-19 · **Scope:** `packages/adapters/` + `lab/` · **Stage:** pre-alpha
**Rules:** [`docs/PROVX_RULES.md`](../../docs/PROVX_RULES.md) (PX-*), [`.claude/rules.md`](../../.claude/rules.md) (Q-*, S-*, W-*)

**Total: 58 findings as audited** — 1 High, 13 Medium, 42 Low/Informational, 2 Positive notes.
**Now open: 0 High**, ~9 Medium, 42 Low/Informational (see the status note below).

Declared scaffolding (playbook evaluator, workflow engine, additional adapters, EPSS enrichment, SARIF export) is **excluded by design** and not counted below.


> [!NOTE]
> **Post-audit status (safety-in-motion + cleanup passes).** Findings marked **✅ FIXED**
> below were resolved after this audit was written. They are kept, not deleted: the record of
> what was found — and what it took to close it — is the point of an audit.
>
> Fixed since: `SDK-001` (High), `SDK-002`, `SDK-025`, `SDK-026`, `SDK-027`; `SDK-028` mostly (CIDR rules still unsupported)
>
> Still open, deliberately: see [`docs/KNOWN_ISSUES.md`](../../docs/KNOWN_ISSUES.md).

---

## Severity key

| | Meaning |
|---|---|
| **HIGH** | Defeats a PX safety rule in a reachable way; fix before any real engagement. |
| **MEDIUM** | Correctness, determinism, or contract gap that will bite as the system grows. |
| **LOW** | Robustness, ergonomics, or hardening; safe to schedule. |

---

# HIGH

## `SDK-001` — `follow_redirects=True` defeats the scope check, and mis-attributes sealed evidence — ✅ FIXED

> **✅ Fixed after this audit.** `follow_redirects=False` + per-hop scope re-check in `provx_sdk/fetch.py`; the envelope now records `final_url` so the seal names the responder. Covered by `test_fetch.py` and the no-stub `backend/tests/test_integration_redirect.py`.

**Rules:** PX-SCOPE, PX-EVIDENCE · **Files:** [`security_headers.py:125`](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L125), [`security_headers.py:127`](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L127), [`scan_runner.py:66`](../../backend/app/services/scan_runner.py#L66)

Scope is evaluated against the **configured URL**; httpx then follows up to 20 redirects, **none of which are re-checked**. An in-scope host returning `302 Location: https://evil.test/` causes Provx to fetch an out-of-scope host. The redirect destination is controlled by the scanned host — by definition, a system of uncertain trustworthiness — and open redirects are commonplace, so no server compromise is required.

The destination can be internal: `http://169.254.169.254/latest/meta-data/` (cloud metadata credential theft), `http://127.0.0.1:5432/`, or any host on the scanner's network. **The scanner becomes an SSRF pivot into its own infrastructure.** PX-SCOPE requires an out-of-scope action be *"skipped and logged, never executed"*; here it is executed, unlogged, with no audit entry.

Compounding it, [line 127](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L127) builds the envelope from the requested `target`, never `response.url`. After a redirect the evidence claims one host while the headers came from another — and `seal()` then cryptographically attests to that false attribution, making it **more** convincing, not less. A finding is only defensible if it says where it came from.

**Fix:** (1) set `follow_redirects=False` and treat 3xx as an observation; or (2) pass `ScopePolicy` into `probe()` and re-check every `Location` hop before following, aborting and logging on the first out-of-scope hop; and (3) record `response.url` in the envelope. Fix (2) also resolves `SDK-002`.

Full analysis: [module_scope.md](module_scope.md) §5.

---

# MEDIUM

## `SDK-002` — PX-SCOPE is caller-delegated, and one of two callers ignores it — ✅ FIXED

> **✅ Fixed after this audit.** `lab/harness.py` builds a `ScopePolicy` per manifest; `probe()` now takes a required `policy`, so calling it unscoped is a type error.
**Rules:** PX-SCOPE · **Files:** [`plugins.py:51`](../../packages/adapters/src/provx_sdk/plugins.py#L51), [`harness.py:112`](../../lab/harness.py#L112)

`probe()` accepts no policy and pushes the duty to a docstring. PX-SCOPE says scope *"is never trusted from an upstream caller"*. `scan_runner` complies; **`lab/harness.py` never constructs a `ScopePolicy` at all** — `manifest.target` goes from YAML straight to the network. Containment today is Docker's `internal: true` network, not Provx's. `main()` exposes `--lab-root`, inviting use outside compose. Fix: move the check inside `probe()`.

## `SDK-003` — the accuracy gate's scoring is order-dependent
**Rules:** PX-DETERMINISM · **File:** [`harness.py:94`](../../lab/harness.py#L94)

`found = {check_id(d): d for d in drafts}` — a dict comprehension keeps the **last** value per key. Executed against a `min_severity: high` oracle:

| Drafts in order | Verdict |
|---|---|
| `a:b`@HIGH then `a:b`@INFO | **FAIL** |
| `a:b`@INFO then `a:b`@HIGH | **PASS** |

The same findings produce opposite gate verdicts by list order — a **PX-DETERMINISM violation inside the determinism gate**. Also silently discards duplicate findings. Dormant today (each rule fires once per target); activates on any path/port/parameter-scoped check. Fix: group with `defaultdict(list)`, apply the floor to the strongest, report instance counts.

## `SDK-004` — `Evidence` carries no integrity fields; sealing depends on caller discipline
**Rules:** PX-EVIDENCE · **Files:** [`findings.py:92`](../../packages/adapters/src/provx_sdk/findings.py#L92), [`evidence.py:20`](../../packages/adapters/src/provx_sdk/evidence.py#L20)

`Evidence` has six fields, none `sha256`/`captured_at`. Integrity exists only at `FindingRow`, and only because `scan_runner` threads `stamp` through as a parallel value. Any other consumer holds unsealed evidence — `lab/harness.py` is exactly that consumer and never imports `seal`. Fix: put an optional `seal: EvidenceSeal` on `Evidence`, or have `probe()` return a sealed envelope, so compliance is structural.

## `SDK-005` — duplicate adapter names silently overwrite in non-deterministic order
**Rules:** PX-DETERMINISM · **File:** [`registry.py:29`](../../packages/adapters/src/provx_sdk/registry.py#L29)

`discovered[adapter.name] = adapter` keys on the instance attribute, discarding the entry-point key. Two packages declaring the same `name` collapse to one, last-wins, in `entry_points()` order — which is not a stable guarantee. **The same engagement config can select a different adapter on different machines.** Installing any package with a colliding name silently replaces a trusted adapter. [`loader.py:58`](../../packages/adapters/src/provx_sdk/loader.py#L58) handles the identical case correctly for playbooks, with the reasoning written out. Apply it here.

## `SDK-006` — `safety` and `category` are unconstrained `str`
**Rules:** PX-PASSIVE, PX-ACTIVE · **File:** [`plugins.py:33-40`](../../packages/adapters/src/provx_sdk/plugins.py#L33)

The passive/active gate will key off `adapter.safety`. As a bare `str`, `"pasive"` is valid to mypy strict — and depending on how the gate is written (`!= "passive"` vs `== "intrusive"`), a typo either **silently permits an intrusive adapter in passive mode** or blocks a safe one. Fix with `Literal`/enum **before** the gate is written. Separately, `category`'s documented `"infra-ad"` already disagrees with `Module.INFRA` (`"infra"`).

## `SDK-007` — the manifest glob silently misses misplaced files
**File:** [`harness.py:70`](../../lab/harness.py#L70)

`*/*/expected.yml` matches exactly two levels. A manifest one level up, three levels deep, named `.yaml`, or capitalized is **silently skipped** — and a skipped manifest is a skipped test that records no FN, because the oracle that would declare it never loads. Fix: `rglob`, and cross-validate against [`lab/expected.yml`](../../lab/expected.yml), which lists both paths and is currently read by nothing.

## `SDK-008` — `expect_none` and `kind` are parsed but never read
**File:** [`harness.py:78`](../../lab/harness.py#L78)

Verified: a manifest with `kind="negative"` and **`expect_none=False`** scores identically to `expect_none=True`. Negative targets pass as an emergent side effect of `expect` being empty. `kind` is likewise read by nothing in the scoring path. Config that looks load-bearing but is inert misleads whoever writes the next manifest, and operator intent is never validated. Fix: enforce it (`expect_none` and `expect` are mutually exclusive; `kind: negative` implies `expect_none`) or delete both.

## `SDK-009` — no unit tests for the PX-EVIDENCE primitive
**Rules:** PX-EVIDENCE · **File:** [`evidence.py`](../../packages/adapters/src/provx_sdk/evidence.py)

No `test_evidence.py` exists in `packages/adapters/tests/`. Only indirect wiring coverage from `backend/tests/test_scan_runner.py`, in a different package — so this package can ship a broken `seal()` with a green suite. Missing: known-vector digest, determinism, sensitivity, non-ASCII, `frozen=True` immutability, tz-awareness, and **the round-trip verify** (re-hash stored `tool_output` == stored `sha256`), which is the one that would catch a refactor breaking the capture-time guarantee.

## `SDK-010` — Protocol conformance is checked by name only; the adapter is never statically verified
**File:** [`plugins.py:26`](../../packages/adapters/src/provx_sdk/plugins.py#L26), [`test_registry.py:17`](../../packages/adapters/tests/test_registry.py#L17)

`@runtime_checkable` `isinstance()` verifies name presence — not signatures, arity, or types. The test named `..._satisfies_the_tool_adapter_protocol` passes for any object with the seven names. `SecurityHeadersAdapter` does not declare `(ToolAdapter)` and `entry.load()` returns `Any`, so mypy never checks it either. The "exactly one of `build_command`/`probe`" invariant is unenforced prose. Fix: `_: ToolAdapter = SecurityHeadersAdapter()` in a test gives full mypy signature checking for one line.

## `SDK-012` — a finding without `matched_rule` crashes the gate instead of failing a target
**File:** [`harness.py:88`](../../lab/harness.py#L88)

`check_id` raises `ValueError`, propagating uncaught through `score_target` → `run` → `main()`. **`report()` never runs**, no scorecard prints, already-scored targets are discarded, and the traceback does not name the target. Exit code is accidentally correct (uncaught exceptions exit 1) rather than by design. Root cause is a contract mismatch: `Evidence.matched_rule` is `str | None` while the gate treats it as mandatory. Fix: catch at the `run` boundary, fail that target loudly, keep scoring.

## `SDK-017` — `Severity` has no ordering; consumers duplicate it
**Files:** [`findings.py:52`](../../packages/adapters/src/provx_sdk/findings.py#L52), [`harness.py:29`](../../lab/harness.py#L29)

`StrEnum` provides no comparison, so `harness.py` hand-maintains `SEVERITY_ORDER` duplicating the enum's declaration order, in a different package, with nothing checking. Adding a member makes `.index()` raise mid-run; reordering silently inverts every severity comparison while the gate still passes. Violates Q-11. Fix: export the ordering from `findings.py`.

## `SDK-035` — `probe()` has no response-size limit
**File:** [`security_headers.py:126`](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L126)

`await client.get(target)` reads the **entire body into memory** with no cap, then discards it — only headers are used. A hostile or broken target serving a huge or endless response exhausts scanner memory; with concurrent targets, one host can OOM the process. The adapter needs none of the body. Fix: `client.head()` with a `GET` fallback, or `client.stream()` reading headers and closing. **Best effort-to-value ratio in the file** — eliminates a resource-exhaustion class and makes the adapter faster and more passive.

## `SDK-046` — header **presence** is checked, **validity** is not
**File:** [`security_headers.py:139`](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L139)

`Content-Security-Policy: default-src *; script-src 'unsafe-inline'`, `Strict-Transport-Security: max-age=0` (which *disables* HSTS), `X-Content-Type-Options: yes`, and `X-Frame-Options: ALLOW-FROM ...` all score as **present and fine**. A target with deliberately neutered header values gets a clean bill of health. For a tool selling defensible accuracy, false negatives on value correctness are the more dangerous error — and the lab cannot catch them (see `SDK-058`). Fix: optional `validate: Callable[[str], bool]` per `HeaderRule`.

## `SDK-051` — no exception handling: one unreachable target aborts the whole scan
**Files:** [`security_headers.py:125`](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L125), [`harness.py:116`](../../lab/harness.py#L116), [`scan_runner.py:74`](../../backend/app/services/scan_runner.py#L74)

A `ConnectError`/`TimeoutException` propagates through all three layers uncaught. In `scan_runner` the transaction rolls back, losing every finding from every already-scanned target. In `harness` no scorecard prints. Fix: per-target `try/except` recording the target as unreachable and continuing.

## `SDK-054` — fixture assertions are loose on the fields that carry meaning
**Rules:** PX-FIXTURE · **File:** [`test_security_headers_adapter.py:51-58`](../../packages/adapters/tests/test_security_headers_adapter.py#L51)

The title/order assertion is tight and excellent — exact list equality pins count, titles, and order. But underneath, `cvss` is checked only for being *in range* (changing HSTS 3.7 → 9.8 passes CI silently, altering prioritization output that PX-DETERMINISM says must be defensible), `remediation` only for truthiness (`"x"` passes), and **`matched_rule` is never asserted at all** despite being the identity the entire accuracy gate depends on. Fix: one table-driven field-for-field assertion per rule.

## `SDK-055` / `SDK-056` — the manifest schema is unvalidated; a typo'd `kind:` is not caught
**File:** [`harness.py:32`](../../lab/harness.py#L32), [`harness.py:73`](../../lab/harness.py#L73)

`Manifest` is a plain `@dataclass` — no `extra="forbid"`, no type validation — despite Pydantic already being a dependency and every other schema in the repo using it. Traced: `kind: postive` is stored verbatim and read by nothing; `knid: negative` silently falls back to `"positive"`; `version` is declared in both manifests and never read; unknown keys are ignored; only `target` is effectively required (raising a `KeyError` that does not name the file). Fix: Pydantic model with `extra="forbid"` and `kind: Literal["positive","negative"]` — converts every silent failure into a load-time error naming the file.

## `SDK-057` — `report()` cannot detect partial manifest loss
**File:** [`harness.py:124`](../../lab/harness.py#L124)

The empty-scores guard is the right instinct but only fires at **zero** manifests. With `SDK-007`, one of two manifests going missing yields a one-row table where everything passes and the gate returns `True`. Fix: assert a minimum target count or cross-check `lab/expected.yml`.

## `SDK-058` — the lab has no present-but-worthless-value target
**File:** [`lab/clean/hardened/nginx.conf`](../../lab/clean/hardened/nginx.conf)

The hardened target sets *correct* values, so it cannot expose `SDK-046`. A third target sending `default-src *`, `max-age=0`, and `nosniff: yes` would fail the gate today and pin value validation once implemented. Highest-value addition to the lab.

## `SDK-036` — no evidence-verification path exists
**Rules:** PX-EVIDENCE · **File:** [`evidence.py`](../../packages/adapters/src/provx_sdk/evidence.py)

Nothing re-computes a digest and compares it to a stored seal. The system produces tamper evidence but cannot check it, and an unexercised verification path will not work when first needed. Fix: `verify(raw, stamp) -> bool` plus a round-trip test through persistence.

## `SDK-039` — playbook step names are unvalidated; a typo is a silently skipped check
**File:** [`playbook.py:47`](../../packages/adapters/src/provx_sdk/playbook.py#L47)

`run: [securty_headers]` is accepted. Nothing cross-checks against installed adapters, so the check never runs and never reports that it did not. In a compliance tool a silently-skipped check is worse than a loud failure.

## `SDK-015` — PX-ATTACK's "≥1 technique" is not enforced on a final `Finding`
**Rules:** PX-ATTACK · **File:** [`findings.py:137`](../../packages/adapters/src/provx_sdk/findings.py#L137)

Both models default `attack_techniques` to `[]`, so a `Finding` with zero techniques validates. The docstring hedges (*"expected once a finding is final"*), but PX-ATTACK is unconditional. Defensible on `FindingDraft`; `Finding` is the final form. Same applies to `cvss=None`.

---

# LOW / INFORMATIONAL

## Scope (`scope.py`)

| ID | Finding |
|---|---|
| `SDK-026` ✅ FIXED | **Deny rules do not cover subdomains.** Verified: `a.b.prod.example.com` is **in scope** under `allow=["*.example.com"], deny=["prod.example.com"]`. Allow uses subtree semantics via `*.`; deny is exact-match. An operator writing "deny prod" reasonably expects the tree. Untested, so invisible to CI. *(Borderline HIGH — realistic misconfiguration producing exactly what PX-SCOPE prevents; listed low only because it requires operator misconfiguration rather than attacker action.)* [`scope.py:41`](../../packages/adapters/src/provx_sdk/scope.py#L41) |
| `SDK-027` ✅ FIXED | **No IDN/punycode normalization.** Verified: deny `pröd.example.com` is bypassed by `https://xn--prd-6na.example.com/`, which matches allow and not deny. Allow-side fails closed; deny-side fails open. Fix: IDNA-normalize host and rule. |
| `SDK-028` ✅ MOSTLY FIXED | **No IP-literal normalization.** Deny `127.0.0.1` is not matched by `2130706433`, `0x7f.0.0.1`, `127.1`, or `[::ffff:127.0.0.1]` — all loopback. No CIDR support. Compounds with `SDK-001`. Fix: `ipaddress.ip_address()` normalization + CIDR rules; consider denying private/loopback/link-local by default (`169.254.169.254`). **Status:** normalization done (`_canonical_ip`/`_unmap` fold integer, hex, octal, short and IPv4-mapped-IPv6 forms) and dangerous ranges are denied by default; **CIDR rules are still unsupported** — rules remain exact hosts or `*.` wildcards. |
| `SDK-025` ✅ FIXED | `_matches` lowercases the rule but not the host — safe only because `target_host` pre-lowercases. Undocumented precondition; a second caller gets a silent scope failure. |
| `SDK-029` | `ScopePolicy` is not frozen; `policy.allow.append(...)` works. For an authorization object, `frozen=True` + tuples. |
| `SDK-030` | No scope-rule validation. `allow=["*."]` matches any trailing-dot host; empty-string rules accepted silently. |

## Findings contract (`findings.py`)

| ID | Finding |
|---|---|
| `SDK-011` | `to_finding()` uses `**self.model_dump()`; any `FindingDraft` field absent from `Finding` raises at promotion under `extra="forbid"`. No test asserts the field-set subset relation. One assertion pins it permanently. [`findings.py:179`](../../packages/adapters/src/provx_sdk/findings.py#L179) |
| `SDK-020` | `dedup_key` is `(target, title)` — **prose is part of the identity**. Rewording a title makes every existing finding new, stranding triage state, with no test catching it. `matched_rule` is the stable machine identity and the accuracy gate already uses it. [`findings.py:175`](../../packages/adapters/src/provx_sdk/findings.py#L175) |
| `SDK-021` | `dedup_key` docstring cites `(PX-ATTACK)`; dedup belongs to **PX-DETERMINISM**. A cite-by-ID culture depends on correct citations. |
| `SDK-022` | `RiskAcceptance.finding_id` is deliberately ambiguous (UUID vs `display_id`). If `display_id`, an `engagement_id` is needed — it is only unique per engagement. Decide before the DB layer. |
| `SDK-023` | `RiskAcceptance.created_at` has no default and no tz constraint — caller may pass naive or backdated. `EvidenceSeal` self-stamps in UTC; a "permanent audit-trail record" should too. |
| `SDK-024` | `RiskAcceptance` is not `frozen=True`, unlike `EvidenceSeal`, despite being described as permanent audit trail. |
| `SDK-018` | `Evidence.tool_output` embeds the full envelope per draft — five findings on one target store five copies. Correct for standalone auditability, wasteful; worse with `SDK-035`. |
| `SDK-019` | `title` and `target` are unconstrained; `Finding(title="", target="", ...)` validates. `target` is the attribution field and `scope.target_host()` could constrain it. |
| `SDK-016` | `DISPLAY_ID_PATTERN` uses `$`, which matches before a trailing newline; `\Z` is airtight. |

## Evidence (`evidence.py`)

| ID | Finding |
|---|---|
| `SDK-031` | `sha256: str` unconstrained — `EvidenceSeal(sha256="not-a-hash", ...)` constructs. Add `pattern=r"^[0-9a-f]{64}$"`. |
| `SDK-032` | `captured_at` does not require tz-awareness; use `AwareDatetime`. |
| `SDK-033` | Seal carries no reference to what it seals; binding is positional via tuple pairing. A seal that travels alone means nothing. |
| `SDK-034` | `seal()` takes `str` only — cannot seal binary artifacts. `Evidence.screenshot_path` already anticipates screenshots; hashing a path proves nothing about the file. |
| `SDK-037` | Append-only is asserted in prose and enforced in memory (`frozen=True`) but has no storage-layer mechanism and no `supersedes`/`corrects` field for the documented correction workflow. |

## Plugins / registry

| ID | Finding |
|---|---|
| `SDK-038` | `load_adapters()` has no per-entry error isolation — one broken third-party package makes **every** adapter undiscoverable, including the built-in. Skipping must log loudly. |
| `SDK-049` | `tool = "httpx"` — the field means "external binary" but names an in-process library, and a separate `httpx` binary exists. Ambiguous in a package where PX-LICENSE hinges on binary-vs-library. |

## Playbook / loader

| ID | Finding |
|---|---|
| `SDK-040` | `run` and `active_only` may overlap; a permissive resolution would run an intrusive step in passive mode. Cheap to reject. |
| `SDK-041` | No `version` field on `Playbook`, unlike lab manifests. Old vs malformed becomes indistinguishable as the schema evolves. |
| `SDK-042` | No file-size bound on `read_text`; YAML alias expansion is not prevented by `safe_load`. Low risk (operator-authored, local). |
| `SDK-043` | **No CI guard asserting PX-DSL compliance.** A grep-based test rejecting `eval`/`exec`/`compile`/`pickle`/`yaml.load` in the SDK would make the repo's most important security invariant an enforced gate rather than a documented intention. Low effort, high leverage. |
| — | `load_playbooks_dir` is non-recursive and case-sensitive; an empty directory is indistinguishable from a misconfigured path. |

## Adapter (`security_headers.py`)

| ID | Finding |
|---|---|
| `SDK-047` | `dict(response.headers)` **silently drops duplicate headers** — httpx's `Headers` is a multi-dict. Two `Content-Security-Policy` headers (browsers intersect them) or two `Set-Cookie` headers lose data **before** sealing, so the digest attests to a lossy capture. Use `multi_items()`. |
| `SDK-048` | `status_code` is captured in the envelope and never read. A `404`/`500`/captive-portal `302` yields the full five findings, identical to a real page. Both lab targets return `200`, so the gate cannot catch it. |
| `SDK-050` | No proxy or TLS control — `AsyncClient` inherits `HTTP_PROXY`/`HTTPS_PROXY` from the environment, so traffic can be silently rerouted with no record in the evidence. No `verify=` control for self-signed certs common in internal engagements. |
| `SDK-052` | `json.loads(raw)` and `payload["target"]`/`["headers"]` unguarded — raises `JSONDecodeError`/`KeyError`/`AttributeError` rather than a typed adapter error. `loader.py` does this correctly with four guarded stages. |
| `SDK-053` | `reproduction_cmd = f"curl -sSI {target}"` interpolates an unvalidated target into a **shell command string** intended to be copy-pasted by a human. Not an injection in Provx, but a latent trap. Use `shlex.quote` or structured argv. |
| `SDK-045` | `HeaderRule` is a mutable hand-written class — `RULES[0].severity = CRITICAL` rewrites the ruleset process-wide, and `cvss` is unvalidated at construction. `@dataclass(frozen=True, slots=True)` is shorter and immutable. |
| `SDK-044` | All five rules carry the same `T1595`. A technique that never varies carries no information for ATT&CK reporting. Per-rule techniques as the ruleset grows. |
| — | No user-agent identification; authorized-testing etiquette (PX-AUTHZ) expects attributable traffic. |
| — | Missing checks: `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, `Server`/`X-Powered-By` disclosure. Scope choice, not a defect. |

## Packaging / process

| ID | Finding |
|---|---|
| `SDK-013` | Dependency constraints are floors with no ceilings (`pydantic>=2`); a Pydantic 3.x release would resolve and break `field_validator`/`ConfigDict`. No lockfile in `packages/adapters/`. |
| `SDK-014` | `lab/` has **no manifest of its own** — no `pyproject.toml`, no declared deps. It is linted and type-checked only because `Makefile` and `ci.yml` name the path explicitly; nothing declares its dependency on `provx_sdk`, `pyyaml`. |
| — | `ADAPTER_GROUP` and the `pyproject.toml` entry-point group are two places that must agree with nothing checking. A packaging test could assert the built distribution advertises the group. |

---

# Positive notes

Worth recording so they are protected in review:

1. **`encode_response`'s `sort_keys=True` + header lowercasing** ([`security_headers.py:98`](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L98)) is the linchpin that makes fixtures portable across servers and makes `EvidenceSeal` digests stable and meaningful. Without it, reproducibility would be accidental.
2. **`parse_output` is genuinely pure and order-stable** — audited specifically: tuple iteration, no set iteration, no dict-order dependence, no clock, no RNG, no I/O, no global state. PX-DETERMINISM fully satisfied in the parsing path.
3. **PX-DSL is fully satisfied** — verified by grep across the SDK and lab: no `eval`, `exec`, `compile`, `pickle`, `__import__`, or unsafe `yaml.load`. The security rationale is documented in [`playbook.py:14-19`](../../packages/adapters/src/provx_sdk/playbook.py#L14) — at the exact file a contributor opens when they sit down to write the evaluator.
4. **`seal()` is called at capture time** ([`scan_runner.py:75`](../../backend/app/services/scan_runner.py#L75)) — the immediately next statement after the probe, before parsing or persistence — and the sealed bytes are verifiably the stored bytes (same object, no re-encoding).
5. **`loader.py`'s duplicate-workflow rejection** ([line 58](../../packages/adapters/src/provx_sdk/loader.py#L58)), with its written reasoning, is exemplary — and is the argument for fixing `SDK-005`.
6. **The `display_id` `{4,}` reasoning** ([`findings.py:30-33`](../../packages/adapters/src/provx_sdk/findings.py#L30)) anticipates a real production bug and keeps the pattern and the `:04d` allocator in agreement past 9999.
7. **The `FindingDraft`/`Finding` split** makes an impossible-to-get-right assignment structurally inexpressible rather than merely discouraged.
8. **`build_command` returning `list[str]`** serves the PX-LICENSE subprocess boundary and shell-injection safety with a single design choice.
9. **The positive/negative lab pairing** pins precision and recall simultaneously — neither can be gamed without failing the other.
10. **The lab's containment posture** — `profiles: [lab]`, `internal: true` network, no published ports — is the correct PX-AUTHZ answer for deliberately-vulnerable targets.
11. **`lab/tests/test_harness.py` tests that the gate FAILS correctly** (5 of 7 tests). Most teams only test the happy path.
12. **`scope.py` resists 7 of 11 attacks tried**, including the two that matter most: userinfo spoofing (`http://example.com@evil.test/`) and suffix confusion (`example.com.evil.test`).
13. **Universal SPDX headers, `from __future__ import annotations`, and explicit `encoding="utf-8"`** across every file. Consistency worth keeping as a house standard.

---

# Test coverage gaps

## Files with **no** test file

| Module | Rule at stake | Note |
|---|---|---|
| [`evidence.py`](../../packages/adapters/src/provx_sdk/evidence.py) | **PX-EVIDENCE** | No `test_evidence.py`. Only indirect coverage from another package. `SDK-009`. |
| [`plugins.py`](../../packages/adapters/src/provx_sdk/plugins.py) | PX-LICENSE, PX-PASSIVE | No conformance test; `isinstance` checks names only. `SDK-010`. |

## Untested functions

| Function | Note |
|---|---|
| [`harness.run`](../../lab/harness.py#L112) | **Zero coverage.** The probe→score pipeline, and the site of `SDK-002`. |
| [`harness.report`](../../lab/harness.py#L122) | **Zero coverage**, including the empty-scores guard. |
| [`harness.main`](../../lab/harness.py#L143) | **Zero coverage** — including exit codes, the gate's entire contract with CI. |
| [`loader.find_workflows_dir`](../../packages/adapters/src/provx_sdk/loader.py#L66) | Failure path untested. |
| [`registry.load_adapters`](../../packages/adapters/src/provx_sdk/registry.py#L24) | Duplicate-name and load-failure paths untested. |

## Untested behaviors, by rule

**PX-SCOPE** — [`test_scope.py`](../../packages/adapters/tests/test_scope.py) is well-chosen (it targets real attacks) but stops at the string matcher and never reaches network behavior, which is where the critical failure lives.

| Gap | Finding |
|---|---|
| **Redirect behavior — no test issues a redirect at all** | `SDK-001` |
| Deny against a *subdomain* of a denied host | `SDK-026` |
| Any IDN/punycode host or rule | `SDK-027` |
| Any IP-literal target (v4, v6, alternate encodings) | `SDK-028` |
| Trailing-dot FQDN (behavior is correct but unpinned) | — |
| Malformed/empty scope rules | `SDK-030` |
| That the harness respects scope (it does not) | `SDK-002` |

**PX-EVIDENCE** — see `SDK-009`; the round-trip verify is the highest-value missing test.

**PX-FIXTURE** — no fixture for a redirect response, an error status code, duplicate headers, or malformed input. Field-level assertions loose (`SDK-054`).

**PX-DSL** — no test asserts the absence of `eval`/`exec`/`compile`/`pickle`. A grep-based guard makes the repo's most important invariant a CI gate (`SDK-043`).

**Accuracy gate** — two findings sharing a `matched_rule` (`SDK-003`), a finding with no `matched_rule` (`SDK-012`), `expect_none` semantics (`SDK-008`), a misplaced manifest (`SDK-007`), malformed manifests (`SDK-055`/`SDK-056`).

**Schema** — no test asserts `extra="forbid"` rejects unknown keys on **any** model, despite this being the most valuable config choice in the codebase. No test asserts `set(FindingDraft.model_fields) <= set(Finding.model_fields)` (`SDK-011`).

---

# Suggested order of work

| # | Action | Closes |
|---|---|---|
| 1 | Pass `ScopePolicy` into `probe()`; re-check every redirect hop or disable redirects; record `response.url` | `SDK-001`, `SDK-002` |
| 2 | Cap/stream the response body (`HEAD` or `stream`) | `SDK-035` |
| 3 | Group `found` by `matched_rule` instead of overwriting | `SDK-003` |
| 4 | Make `Manifest` a Pydantic model with `extra="forbid"`; read `lab/expected.yml` as the authoritative list | `SDK-055`, `SDK-056`, `SDK-007`, `SDK-057`, `SDK-008` |
| 5 | Add `test_evidence.py` including the round-trip verify | `SDK-009`, `SDK-036` |
| 6 | Reject duplicate adapter names; validate `entry.name == adapter.name` | `SDK-005` |
| 7 | `Literal`/enum for `safety` and `category`; `_: ToolAdapter = SecurityHeadersAdapter()` | `SDK-006`, `SDK-010` |
| 8 | Per-target `try/except` in the scan and harness loops | `SDK-051`, `SDK-012` |
| 9 | Tighten fixture assertions field-for-field | `SDK-054` |
| 10 | Deny-side subtree semantics + IDNA/IP normalization in `scope.py` | `SDK-026`, `SDK-027`, `SDK-028` |
| 11 | Add the "present-but-worthless values" lab target; add header value validation | `SDK-058`, `SDK-046` |
| 12 | Grep-based PX-DSL CI guard | `SDK-043` |

Items 1–3 are the ones to do before Provx touches a real engagement.
