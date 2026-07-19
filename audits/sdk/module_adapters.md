# `adapters/security_headers.py` — the one shipped adapter

**File:** [`packages/adapters/src/provx_sdk/adapters/security_headers.py`](../../packages/adapters/src/provx_sdk/adapters/security_headers.py) · 158 lines
**PX rules carried:** PX-PASSIVE, PX-DETERMINISM, PX-FIXTURE, PX-SCOPE, PX-ATTACK, PX-LICENSE.

The reference implementation. Every future adapter will be written by reading this one, so its patterns — good and bad — propagate.

---

## 1. `RECON_TECHNIQUE` — [line 26](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L26)

```python
RECON_TECHNIQUE: Final = "T1595"   # Active Scanning
```

`T1595` is *Active Scanning* — reconnaissance of a target's exposed configuration. Reasonable for a missing-header check, and it satisfies PX-ATTACK's ≥1-technique requirement.

**Every one of the five rules is tagged with the same single technique.** That is honest at this stage but low-value: a technique ID that never varies carries no information for ATT&CK-based reporting or navigator heatmaps. As the rule count grows, per-rule techniques (e.g. `T1189` drive-by compromise for missing CSP, `T1557` AiTM for missing HSTS) would make the mapping actually useful. **`SDK-044`** (low).

`Final` is used correctly here and on `RULES`.

---

## 2. `HeaderRule` — [line 29](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L29)

A plain class with `__slots__ = ("header", "title", "severity", "cvss", "remediation")` and an explicit `__init__`.

`__slots__` prevents attribute typos at runtime and saves memory. Reasonable.

**But this should be a frozen dataclass or a Pydantic model.** As written:
- The five fields are **mutable** — `RULES[0].severity = Severity.CRITICAL` silently rewrites the ruleset at runtime for the whole process. For a deterministic engine whose ruleset *is* the contract, that is the wrong default. `@dataclass(frozen=True, slots=True)` gives immutability, `__eq__`, and `__repr__` for less code than the current `__init__`.
- **`cvss` is unvalidated here.** `HeaderRule(..., cvss=99.0)` constructs fine; the bound is only enforced later when `FindingDraft` is built. The failure surfaces one layer from its cause.
- Nine lines of boilerplate `self.x = x` that a dataclass writes for free (rule Q-11/Q-12 territory).

**`SDK-045`** (low).

---

## 3. `RULES` — [line 44](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L44)

`Final[tuple[HeaderRule, ...]]` — **a tuple, not a list.** The right choice: the ruleset is immutable at the container level and its order is fixed, which is what makes output order stable (PX-DETERMINISM).

Every rule in the tuple, in declaration order:

| # | Header | Title | Severity | CVSS | Remediation gist |
|---|---|---|---|---|---|
| 1 | `content-security-policy` | Missing Content-Security-Policy header | `LOW` | 3.1 | start from `default-src 'self'`; restrict script/style/frame sources |
| 2 | `x-frame-options` | Missing X-Frame-Options header | `LOW` | 3.1 | `DENY`, or a CSP `frame-ancestors` directive |
| 3 | `strict-transport-security` | Missing Strict-Transport-Security header | `LOW` | 3.7 | `max-age=31536000; includeSubDomains` |
| 4 | `x-content-type-options` | Missing X-Content-Type-Options header | `LOW` | 2.4 | `nosniff` |
| 5 | `referrer-policy` | Missing Referrer-Policy header | `LOW` | 2.4 | `strict-origin-when-cross-origin` |

**Quality of the ruleset — genuinely good:**

- **All header names are lowercase in the rule definitions**, matching the lowercasing done in `encode_response` and `parse_output`. Consistent normalization on both sides.
- **CVSS scores are differentiated and defensible.** HSTS highest at 3.7 (its absence enables active downgrade), CSP and XFO at 3.1 (clickjacking/XSS-mitigation loss), nosniff and Referrer-Policy at 2.4 (narrower impact). Someone thought about relative risk rather than pasting one number five times.
- **Remediation text is specific and actionable** — it gives the literal header value to set, not "configure a CSP". This is what makes a client report useful, and it is the deterministic-template fallback PX-AI-OPTIONAL requires: no LLM is needed to produce remediation text.
- **Rule 2 acknowledges the modern alternative** (CSP `frame-ancestors` instead of XFO), which is correct guidance rather than cargo-culted advice.

**Substantive gap — presence is checked, validity is not.** The adapter only asks *"is this header non-blank?"*. So:
- `Content-Security-Policy: default-src *; script-src 'unsafe-inline' 'unsafe-eval'` — a CSP that permits everything — is scored as **present and fine**.
- `Strict-Transport-Security: max-age=0` — which actively *disables* HSTS — passes.
- `X-Frame-Options: ALLOW-FROM https://anything` — deprecated and unsupported in modern browsers — passes.
- `X-Content-Type-Options: yes` (must be exactly `nosniff`) passes.

A hardened-looking target with deliberately neutered header values gets a clean bill of health. For a tool whose value proposition is defensible accuracy, **false negatives on value correctness are the more dangerous error**, and the lab's `clean/hardened` target cannot catch them because it sets correct values. **`SDK-046`** (medium) — the natural next iteration is an optional `validate: Callable[[str], bool]` on `HeaderRule`.

**Also missing:** `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, and the inverse checks (`Server`/`X-Powered-By` version disclosure). Scope choice, not a defect — noted for the roadmap.

---

## 4. `encode_response(target, status_code, headers) -> str` — [line 87](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L87)

```python
payload = {
    "target": target,
    "status_code": status_code,
    "headers": {name.lower(): value for name, value in headers.items()},
}
return json.dumps(payload, indent=2, sort_keys=True)
```

**This function is the PX-DETERMINISM and PX-FIXTURE linchpin, and it is done correctly.**

- **`sort_keys=True`** — the decisive detail. Python dicts preserve insertion order, so header order would otherwise vary by server, by proxy, and by httpx version. Sorting makes the envelope **byte-identical for the same logical response**, which is what allows a fixture recorded from nginx to match a live response from Apache, and what makes `EvidenceSeal.sha256` stable and meaningful. Without this line the seal would be reproducible only by accident.
- **`.lower()` on header names** — HTTP header names are case-insensitive per RFC 7230; different servers use different casing. Normalizing on the way in means the fixture and the live response agree. The docstring says exactly this.
- **`indent=2`** — human-readable evidence. `tool_output` lands in client reports and is what a reviewer reads to confirm a finding in seconds. Costs bytes, buys auditability. Right trade for this product.

**One real bug: duplicate headers are silently dropped.** `dict(response.headers)` at [line 127](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L127) collapses repeated headers — httpx's `Headers` is multi-dict, and `dict()` keeps only one value. A response sending two `Content-Security-Policy` headers (browsers intersect them; a permissive second one is a real attack) or two `Set-Cookie` headers loses data **before** it is sealed. The evidence is then sealed to an incomplete record, and the digest attests to a lossy capture. `response.headers.multi_items()` preserves everything. **`SDK-047`** (low-medium).

**Minor:** no type constraint on `headers` values, and `status_code` is captured in the envelope but **never used** by `parse_output` — a `404` or `500` yields the full set of "missing header" findings, indistinguishable from a real page. See `SDK-048` below.

---

## 5. `SecurityHeadersAdapter`

### 5.1 Class attributes — [line 104](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L104)

```python
name = "security_headers"      # matches the entry-point key ✅
category = "web"               # matches Module.WEB ✅
safety = "passive"             # ✅ accurate
tool = "httpx"
```

`name` agrees with the `pyproject.toml` entry-point key — so `SDK-005` is latent, not live. `category = "web"` agrees with `Module.WEB`. Pinned by [`test_security_headers_adapter.py:34`](../../packages/adapters/tests/test_security_headers_adapter.py#L34).

**`safety = "passive"` is accurate.** PX-PASSIVE requires that no check create, modify, or delete state on a target. This adapter issues one `GET`, reads response headers, and writes nothing. A `GET` is defined as safe and idempotent, and the adapter sends no body, no cookies, and no auth. **PX-PASSIVE is satisfied.**

*(The caveat: a `GET` to an application endpoint can still mutate state on a badly-built target — but that is the target's defect, and no passive scanner can defend against it. The classification is correct.)*

**`tool = "httpx"` is arguably mislabeled.** The field is documented as *"External binary this adapter wraps"*. There is no external binary — `httpx` here is the in-process Python library, and there is also a well-known separate `httpx` binary from ProjectDiscovery. A field meaning "external binary" naming a library, ambiguously, in a package where PX-LICENSE hinges on the binary-vs-library distinction, is worth correcting. **`SDK-049`** (low).

### 5.2 `build_command` — [line 109](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L109)

```python
raise NotImplementedError(
    "security_headers probes in-process with httpx; it has no subprocess form"
)
```

Correct per the dual-path design, with a message that explains *why* rather than just failing. The docstring restates PX-LICENSE: the subprocess path stays on the interface for the copyleft binaries that need it. Tested at [`test_security_headers_adapter.py:87`](../../packages/adapters/tests/test_security_headers_adapter.py#L87).

### 5.3 `probe` — [line 119](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L119)

```python
async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
    response = await client.get(target)
return encode_response(target, response.status_code, dict(response.headers))
```

**Correct:** `async with` guarantees connection cleanup even on exception; `timeout` is threaded through from the caller (`scan_runner` sources it from settings); exactly one `GET`, no retries, no body sent.

This is the adapter's network boundary, and it has **four** problems.

#### ❌ (a) `follow_redirects=True` defeats the scope check — `SDK-001`, HIGH

The critical finding of this audit. Scope is checked against the configured URL in `scan_runner`; httpx then follows up to 20 redirects, none re-checked. An in-scope host returning `302 Location: https://evil.test/` causes Provx to fetch `evil.test` — or `http://169.254.169.254/latest/meta-data/`, making the scanner an SSRF pivot into its own infrastructure.

Compounding it: [line 127](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L127) builds the envelope from the **requested** `target`, never `response.url`. After a redirect the envelope claims one host while the headers came from another — and `seal()` then cryptographically attests to that false attribution, making it *more* convincing, not less.

Full analysis in [module_scope.md](module_scope.md) §5, finding 11.

#### ❌ (b) No response-size limit — `SDK-035`, MEDIUM

`await client.get(target)` reads the **entire body into memory** with no cap, then discards it — only headers are used. A hostile or merely broken target serving a multi-gigabyte response (or an endless stream, bounded only by `timeout`) exhausts the scanner's memory. With concurrent targets, one host can OOM the process.

The adapter needs **none** of the body. Two clean fixes:
- `await client.head(target)` — no body at all (with a `GET` fallback, since some servers mishandle `HEAD`); or
- `client.stream("GET", target)`, read headers, close without consuming.

This is the fix with the best effort-to-value ratio in the file: it eliminates the resource-exhaustion class entirely *and* makes the adapter faster and more passive.

#### ❌ (c) No proxy or transport control — `SDK-050`, LOW

`AsyncClient` is constructed with only `timeout` and `follow_redirects`. It therefore inherits `HTTP_PROXY`/`HTTPS_PROXY` from the environment (httpx honors these by default) — so scanner traffic can be silently routed through an environment-configured proxy with no record in the evidence. For a tool whose value is a defensible chain of custody, the network path should be explicit and recorded. Also no `verify=` control, so TLS verification failures on targets with self-signed certificates (common in internal engagements) raise rather than being reported as a finding.

#### ❌ (d) `status_code` captured but ignored — `SDK-048`, LOW

The envelope records `status_code`; `parse_output` never reads it. A `404`, `500`, or a captive-portal `302` produces the full five "missing security header" findings, identical to a real page. Error pages legitimately omit security headers. This is a false-positive source the lab cannot catch, since both lab targets return `200`.

#### Also absent

No exception handling — a `ConnectError`/`TimeoutException` propagates raw to `scan_runner`, which does not catch it either, so **one unreachable target aborts the entire scan** and the transaction rolls back. A per-target `try/except` recording an unreachable target and continuing is needed. **`SDK-051`** (medium). No retry logic (defensible — retries are non-deterministic). No user-agent identification, which authorized-testing etiquette (PX-AUTHZ) generally expects so a blue team can attribute the traffic.

### 5.4 `parse_output` — [line 129](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L129)

```python
payload: Any = json.loads(raw)
target = str(payload["target"])
headers: dict[str, str] = {
    str(name).lower(): str(value) for name, value in payload["headers"].items()
}

drafts: list[FindingDraft] = []
for rule in RULES:
    if headers.get(rule.header, "").strip():
        continue
    drafts.append(FindingDraft(...))
return drafts
```

#### ✅ PX-DETERMINISM: is it genuinely pure and order-stable?

**Audited specifically for this, and yes — it is clean.**

| Concern | Finding |
|---|---|
| Iteration source | `for rule in RULES` — a **tuple** with fixed declaration order. Not a set, not a dict. |
| Dict iteration | The only dict comprehension iterates `payload["headers"].items()` to **build** the lookup table. Its order affects nothing: the result is used solely via `.get()`. |
| Set usage | **None anywhere.** No set iteration, so no hash-order nondeterminism. |
| Output order | Appends in `RULES` order → always CSP, XFO, HSTS, nosniff, Referrer-Policy. |
| I/O | None. No network, no filesystem, no clock, no RNG. |
| Global state | None read or written. `RULES` is read-only in practice. |
| Hidden nondeterminism | No `uuid4`, no `datetime.now`, no `random`, no `hash()` of a str used for ordering. |

**Verdict: genuinely pure, total, and order-stable.** The same `raw` yields identical drafts in identical order, on any machine, in any process. This is the property PX-FIXTURE depends on, and [`test_security_headers_adapter.py:80`](../../packages/adapters/tests/test_security_headers_adapter.py#L80) asserts it directly (`parse_output(raw) == parse_output(raw)`).

*(One subtlety: `FindingDraft` has no `id` field and no `default_factory=uuid4`, so equality holds. Had drafts carried UUIDs, that determinism test would fail. The Draft/Finding split protects determinism here as a side benefit.)*

#### ✅ Blank-value handling

`headers.get(rule.header, "").strip()` treats a present-but-empty header (`X-Frame-Options:` or `"   "`) as **missing**. Correct — a blank header provides no protection. Tested at [`test_security_headers_adapter.py:66`](../../packages/adapters/tests/test_security_headers_adapter.py#L66).

#### ✅ Draft construction

Each draft carries: `title`, `target`, `module=Module.WEB`, `severity`, `cvss`, `confidence=HIGH`, `attack_techniques=[RECON_TECHNIQUE]` (**PX-ATTACK satisfied**), `remediation`, and `Evidence(tool_output=raw, matched_rule=f"{self.name}:{rule.header}", reproduction_cmd=f"curl -sSI {target}")`.

- **`confidence=HIGH` is honest** — header absence is directly observed, not inferred. Correct use of the PX-HUMAN confidence field.
- **`matched_rule = "security_headers:x-frame-options"`** — a stable machine identity, namespaced by adapter, and the key the entire accuracy gate matches on. Excellent choice.
- **`reproduction_cmd = f"curl -sSI {target}"`** — a reviewer can verify in one paste. `-I` (HEAD) is the right verb for a header check and doubles as evidence that the check is passive. This is the "confirm a finding in seconds" promise, delivered.

#### ❌ Unguarded parsing — `SDK-052`, LOW

`json.loads(raw)` and `payload["target"]` / `payload["headers"]` are unguarded. Malformed input raises `JSONDecodeError`, `KeyError`, or `AttributeError` (if `headers` is a list) rather than a typed adapter error. `parse_output` is contracted as pure, and purity does not preclude a clear failure — but it should be a documented exception type, not whatever json/dict internals produce. Note the loader module does this correctly: four guarded stages, all converted to `PlaybookValidationError`. The same discipline belongs here.

#### ❌ `raw` duplicated per draft — `SDK-018`, LOW

`Evidence(tool_output=raw, ...)` embeds the **complete envelope** in every draft. Five missing headers → five full copies of the same string in memory and in the database. Correct for standalone auditability of each finding; wasteful at scale, and worse with `SDK-035` (unbounded response size) since the multiplier applies to an unbounded quantity.

#### ❌ `reproduction_cmd` interpolates an unvalidated target — `SDK-053`, LOW

`f"curl -sSI {target}"` builds a **shell command string** from `target`, which originates in the envelope and ultimately from operator config. A target like `http://x.test; rm -rf ~` produces a stored string that is dangerous **if a human copy-pastes it** — and the field exists precisely to be copy-pasted. Not an injection in Provx (nothing executes it), but the field is a latent trap. Shell-quote it (`shlex.quote`) or store structured argv.

---

## 6. PX-FIXTURE: do the fixtures actually pin the contract?

Two fixtures: [`security_headers_missing.json`](../../packages/adapters/tests/fixtures/security_headers_missing.json) (sends only `x-content-type-options`) and `security_headers_hardened.json`.

The missing-headers fixture is a real recorded envelope — `server: nginx/1.27.4`, `content-length`, sorted keys — matching the lab target's actual output. It is a genuine recording, not a hand-written stub. Good.

**Are the assertions tight or loose?** [`test_security_headers_adapter.py:44`](../../packages/adapters/tests/test_security_headers_adapter.py#L44):

```python
assert [d.title for d in drafts] == [
    "Missing Content-Security-Policy header",
    "Missing X-Frame-Options header",
    "Missing Strict-Transport-Security header",
    "Missing Referrer-Policy header",
]
```

**This is a tight assertion and the best one in the suite.** It is exact list equality, so it pins simultaneously: the count (4, not 5 — `x-content-type-options` is present and correctly suppressed), the exact titles, and **the order**. Adding a rule, reordering `RULES`, or reworking a title all fail CI. That is what PX-FIXTURE asks for.

**But the per-field loop underneath is loose:**

```python
for draft in drafts:
    assert draft.severity is Severity.LOW
    assert draft.cvss is not None and 0.0 <= draft.cvss <= 10.0     # ← any value passes
    assert draft.remediation                                         # ← any non-empty string
    assert draft.evidence is not None and draft.evidence.tool_output # ← any truthy value
```

- **`cvss` is checked only for being in range.** Changing HSTS from 3.7 to 9.8 — a material change to prioritization output, which PX-DETERMINISM says must come from a defensible formula — **passes CI silently**. The exact values should be pinned per rule.
- **`remediation` is checked only for truthiness.** The remediation text is client-deliverable content; `"x"` passes.
- **`matched_rule` is never asserted at all** in this file — the identity the entire accuracy gate depends on is unpinned here. It is exercised indirectly by `lab/tests/test_harness.py`, but that requires a reader to know the coupling.
- **`reproduction_cmd` is never asserted.**

So the fixture pins *which* findings fire and in what order — the important half — while leaving *what they say* largely unpinned. **`SDK-054`** (medium). The fix is a single table-driven assertion comparing each draft field-for-field against expected values per rule.

**Also uncovered:** no fixture for a redirect response, an error status, duplicate headers, or malformed input.

---

## 7. Verdict

| Aspect | Verdict |
|---|---|
| `sort_keys=True` + lowercased header names | ✅ **the linchpin** — makes fixtures and seals meaningful |
| `parse_output` purity and order-stability | ✅ **verified clean** — tuple iteration, no sets, no I/O, no clock |
| `RULES` as a `Final` tuple | ✅ correct |
| Differentiated, defensible CVSS scores | ✅ thoughtful |
| Specific, actionable remediation text | ✅ the PX-AI-OPTIONAL deterministic fallback, delivered |
| `matched_rule` as stable machine identity | ✅ excellent |
| `reproduction_cmd` for second-level verification | ✅ excellent |
| PX-PASSIVE classification | ✅ accurate |
| PX-ATTACK ≥1 technique | ✅ satisfied |
| `build_command` raising per PX-LICENSE | ✅ correct |
| Title/order fixture assertion | ✅ tight and valuable |
| `follow_redirects=True` + target-not-response.url | ❌ **`SDK-001` HIGH** |
| No response-size limit | ❌ `SDK-035` MEDIUM |
| Header presence checked, validity not | ❌ `SDK-046` MEDIUM |
| No exception handling → one bad target kills the scan | ❌ `SDK-051` MEDIUM |
| Fixture assertions loose on cvss/remediation/matched_rule | ❌ `SDK-054` MEDIUM |
| Duplicate headers dropped by `dict()` | ❌ `SDK-047` |
| `status_code` captured but ignored | ❌ `SDK-048` |
| No proxy/TLS control | ❌ `SDK-050` |
| Unguarded `json.loads` / dict access | ❌ `SDK-052` |
| `reproduction_cmd` shell-unsafe | ❌ `SDK-053` |
| `HeaderRule` mutable, hand-written `__init__` | ❌ `SDK-045` |

**The pure half of this adapter is excellent.** `encode_response` and `parse_output` are exactly what a deterministic, fixture-driven, auditable check should look like, and the determinism audit found nothing to fault. **Every serious finding is in `probe()`** — the eight lines that touch the network. That is a good place for the problems to be concentrated, because it is a small, well-isolated surface, and fixing `follow_redirects` plus adding a size cap addresses the two most severe issues in roughly ten lines.
