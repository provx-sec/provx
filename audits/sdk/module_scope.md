> [!WARNING]
> **Superseded.** This describes `scope.py` as it was at audit time (~69 lines, three
> symbols). The safety-in-motion pass rewrote it: `canonical_host`, `_canonical_ip`,
> `is_dangerous_host`, subtree-aware deny, and `allow_dangerous_ranges` were added, closing
> `SDK-025` through `SDK-028`. Read the file itself for current behaviour.

# `scope.py` — PX-SCOPE enforcement (adversarial audit)

**File:** [`packages/adapters/src/provx_sdk/scope.py`](../../packages/adapters/src/provx_sdk/scope.py) · 69 lines
**Rule:** [PX-SCOPE](../../docs/PROVX_RULES.md) — *"Every target and request is checked against the engagement's allow/deny scope at the adapter boundary, before any tool runs. Scope is never trusted from an upstream caller. An out-of-scope action is skipped and logged, never executed."*

This is the most safety-critical file in the SDK. A scope failure in a pentest platform is not a bug — it is unauthorized access to a system the operator was not permitted to touch, with legal consequences. It is audited here adversarially: **every claim below was executed against the real code**, not reasoned about.

---

## 1. Surface

| Symbol | Line | Kind |
|---|---|---|
| `ALLOWED_SCHEMES` | [22](../../packages/adapters/src/provx_sdk/scope.py#L22) | `frozenset({"http", "https"})` |
| `OutOfScopeError` | [25](../../packages/adapters/src/provx_sdk/scope.py#L25) | `ValueError` subclass |
| `target_host` | [29](../../packages/adapters/src/provx_sdk/scope.py#L29) | function |
| `_matches` | [41](../../packages/adapters/src/provx_sdk/scope.py#L41) | private function |
| `ScopePolicy` | [49](../../packages/adapters/src/provx_sdk/scope.py#L49) | Pydantic model |

`ALLOWED_SCHEMES` as a `frozenset` is a correct immutable module constant — no caller can mutate the allowed-scheme set at runtime. `OutOfScopeError` subclassing `ValueError` is idiomatic and lets callers catch either.

---

## 2. `target_host(target: str) -> str` — [line 29](../../packages/adapters/src/provx_sdk/scope.py#L29)

```python
parts = urlsplit(target.strip())
if parts.scheme.lower() not in ALLOWED_SCHEMES or not parts.hostname:
    raise OutOfScopeError(f"target {target!r} is not an http(s) URL with a host")
return parts.hostname.lower()
```

Four things happen, all of them correct:

1. **`.strip()`** — leading/trailing whitespace cannot smuggle a scheme past the check.
2. **`parts.scheme.lower()`** — `HTTP://` and `HtTp://` are accepted; scheme comparison is case-insensitive as RFC 3986 requires.
3. **`not parts.hostname`** — a URL with no host is rejected. Catches `http:///path` and the empty string.
4. **`.hostname` (not `.netloc`)** — this is the single most important line in the file. `urlsplit().hostname` **strips userinfo and the port and lowercases**. `netloc` would not.

**Verified empirically:**

| Input | `.hostname` | Assessment |
|---|---|---|
| `http://example.com@evil.test/` | `evil.test` | ✅ userinfo correctly discarded — the real host wins |
| `https://example.com%2f@evil.test/` | `evil.test` | ✅ encoded-slash userinfo trick also fails |
| `http://user:pw@example.com/` | `example.com` | ✅ credentials stripped |
| `http://EXAMPLE.COM:8080/` | `example.com` | ✅ port stripped, host lowercased |
| `file:///etc/passwd` | — | ✅ `OutOfScopeError` (scheme) |
| `javascript:alert(1)` | — | ✅ `OutOfScopeError` |
| `not a url` | — | ✅ `OutOfScopeError` |

**The userinfo case deserves explicit credit.** `http://example.com@evil.test/` is the classic scope-bypass payload: a human reading the URL sees `example.com`, and a naive `netloc`-based or substring-based check would allow it, while the browser/HTTP client connects to `evil.test`. This implementation resolves it to `evil.test` and denies. It is pinned by [`test_scope.py:44`](../../packages/adapters/tests/test_scope.py#L44). Many commercial scanners get this wrong.

**`.hostname` also strips IPv6 brackets:** `http://[::1]/` → `::1`. Consistent, but see §5.

---

## 3. `_matches(host: str, rule: str) -> bool` — [line 41](../../packages/adapters/src/provx_sdk/scope.py#L41)

```python
rule = rule.strip().lower()
if rule.startswith("*."):
    suffix = rule[1:]                                  # ".example.com"
    return host == rule[2:] or host.endswith(suffix)   # apex OR subdomain
return host == rule
```

The wildcard split is careful: `rule[2:]` is the apex (`example.com`), `rule[1:]` is the dot-prefixed suffix (`.example.com`). Testing `endswith(".example.com")` rather than `endswith("example.com")` is precisely what defeats the `example.com.evil.test` suffix-confusion attack.

**Verified:**

| Host | Rule | Result | Assessment |
|---|---|---|---|
| `example.com` | `*.example.com` | `True` | ✅ apex covered, as documented |
| `evil.example.com` | `*.example.com` | `True` | ✅ subdomain covered |
| `notexample.com` | `*.example.com` | `False` | ✅ **no suffix confusion** |
| `example.com.evil.test` | `*.example.com` | `False` | ✅ **the classic bypass fails** |
| `example.com` | `  *.EXAMPLE.COM  ` | `True` | ✅ rule whitespace + case normalized |

`rule.strip().lower()` normalizes the *rule* on every call — so a sloppily-configured `" *.Example.COM "` still works. Good defensive input handling.

**Asymmetry worth noting:** `_matches` lowercases the **rule** but not the **host**. It is only safe because `target_host()` already lowercased the host before the call. Verified: `_matches("EXAMPLE.COM", "example.com")` returns `False`. The function is not safe in isolation — it carries an undocumented precondition. It is private (`_`-prefixed) and has exactly one caller, so this is latent rather than live, but a future second caller passing a raw host gets a silent scope failure. One `host.lower()` would remove the trap. **`SDK-025`.**

---

## 4. `ScopePolicy.is_in_scope` — [line 61](../../packages/adapters/src/provx_sdk/scope.py#L61)

```python
try:
    host = target_host(target)
except OutOfScopeError:
    return False
if any(_matches(host, rule) for rule in self.deny):
    return False
return any(_matches(host, rule) for rule in self.allow)
```

**Structurally correct in three important ways:**

- **Fail-closed on unparseable input** — the `except` returns `False`, never propagates and never defaults to permit.
- **Deny evaluated first and unconditionally** — deny cannot be out-voted by a broader allow.
- **Empty allow permits nothing** — `any()` over an empty list is `False`. `ScopePolicy()` denies everything. Tested at [`test_scope.py:34`](../../packages/adapters/tests/test_scope.py#L34). The docstring names the reason: *"a misconfigured engagement fails closed rather than scanning the internet."* This is the correct default and it is deliberate.

`allow` and `deny` both use `Field(default_factory=list)` — no shared mutable default. `extra="forbid"` on the model. Both correct.

---

## 5. Attack matrix — what I tried to break, and what happened

Executed against the real `ScopePolicy(allow=["*.example.com"], deny=["prod.example.com", "127.0.0.1", "localhost"])`.

| # | Attack | Payload | Result | Verdict |
|---|---|---|---|---|
| 1 | Suffix confusion | `https://example.com.evil.test/` | out of scope | ✅ **holds** |
| 2 | Userinfo spoof | `http://example.com@evil.test/` | out of scope | ✅ **holds** |
| 3 | Encoded-slash userinfo | `https://example.com%2f@evil.test/` | out of scope | ✅ **holds** |
| 4 | Uppercase deny evasion | `https://PROD.EXAMPLE.COM/` | denied | ✅ **holds** |
| 5 | Port-based deny evasion | `http://prod.example.com:8080/` | denied | ✅ **holds** |
| 6 | Trailing-dot FQDN | `https://prod.example.com./` | out of scope | ✅ **holds** (fails closed) |
| 7 | Non-web scheme | `file://`, `javascript:`, `ftp://` | out of scope | ✅ **holds** |
| 8 | **Deny subdomain escape** | `https://a.b.prod.example.com/` | **IN SCOPE** | ❌ **`SDK-026`** |
| 9 | **IDN / punycode deny evasion** | `https://xn--prd-6na.example.com/` vs deny `pröd.example.com` | **IN SCOPE** | ❌ **`SDK-027`** |
| 10 | **Alternate IP encodings** | `http://2130706433/`, `http://0x7f.0.0.1/`, `http://[::ffff:127.0.0.1]/` vs deny `127.0.0.1` | **not denied** | ❌ **`SDK-028`** |
| 11 | **Post-check redirect** | in-scope host `302`s to `evil.test` | **followed** | ❌ **`SDK-001` — critical** |

Attacks 1–7 all hold. That is a genuinely good result for a 69-line implementation and reflects real care. The four failures follow.

### ❌ Finding 8 — deny rules do not cover subdomains (`SDK-026`)

`deny: ["prod.example.com"]` blocks **exactly that host** and nothing beneath it. Confirmed: `https://a.b.prod.example.com/` is **in scope** under `allow=["*.example.com"], deny=["prod.example.com"]`.

The asymmetry is the danger. On the **allow** side an operator must write `*.example.com` to get subtree semantics, and the docs explain that. On the **deny** side, the natural reading of *"deny prod.example.com"* is *"stay away from prod"* — the whole tree. Instead, `api.prod.example.com`, `db.prod.example.com`, and `admin.prod.example.com` all remain in scope and will be scanned.

This is a carve-out that silently fails to carve. The module docstring advertises the exact use case it breaks: *"Deny always wins, so a broad allow can be carved out precisely."* Deny does win — but only over one label.

**Not tested.** [`test_scope.py:29`](../../packages/adapters/tests/test_scope.py#L29) tests deny against the exact host only, so the gap is invisible to CI.

**Severity: HIGH.** Realistic misconfiguration, silent, and produces exactly the outcome PX-SCOPE exists to prevent — touching a production system the operator carved out.

**Fix:** apply subtree semantics to deny, or require deny rules to be written as `*.prod.example.com` and **reject/warn on a bare-host deny rule** so the operator is told rather than surprised. The first is safer: deny should over-match by default.

### ❌ Finding 9 — IDN/punycode normalization is absent (`SDK-027`)

Neither `target_host` nor `_matches` performs IDNA normalization. `urlsplit` returns whatever form the URL used; `httpx` will IDNA-encode at connect time. So the *matcher* and the *client* can disagree about what a host is.

- **Allow side — fails closed.** Allow `münchen.de`, target `https://xn--mnchen-3ya.de/` → no match, denied. Annoying, not dangerous.
- **Deny side — fails open.** Deny `pröd.example.com` with allow `*.example.com`; target `https://xn--prd-6na.example.com/` matches allow, does not match deny, and **is scanned**. Confirmed `in_scope=True`.

Homograph rules (Cyrillic `а` vs Latin `a`) fail the same way in both directions.

**Severity: MEDIUM** — requires a non-ASCII deny rule, which is uncommon but entirely legitimate for European and Asian engagements.

**Fix:** normalize both host and rule through `idna.encode()` / `.encode("idna")` at the boundary, and reject rules that fail to encode.

### ❌ Finding 10 — no IP-literal normalization (`SDK-028`)

Host matching is pure string comparison, so every alternate encoding of the same address is a distinct "host":

| Payload | `.hostname` | Matches deny `127.0.0.1`? |
|---|---|---|
| `http://127.0.0.1/` | `127.0.0.1` | yes |
| `http://2130706433/` | `2130706433` | **no** |
| `http://0x7f.0.0.1/` | `0x7f.0.0.1` | **no** |
| `http://127.1/` | `127.1` | **no** |
| `http://[::ffff:127.0.0.1]/` | `::ffff:127.0.0.1` | **no** |
| `http://[::1]/` | `::1` | **no** (vs deny `localhost`) |

All of the above resolve to loopback at the OS level. A deny list intended to keep the scanner off localhost or off an internal range does not.

This compounds with `SDK-001`: a redirect to `http://2130706433/` reaches loopback while every string-based guard reports the host as out of scope — or, worse, never gets consulted.

**Severity: MEDIUM standalone; HIGH combined with `SDK-001`.**

**Fix:** attempt `ipaddress.ip_address()` on the host; on success, compare **normalized** addresses (and support CIDR rules like `10.0.0.0/8`, which the current design cannot express at all). Also consider denying private/loopback/link-local ranges by default unless explicitly allowed — `169.254.169.254` (cloud metadata) is the case that matters most.

### ❌❌ Finding 11 — `follow_redirects=True` defeats the scope check entirely (`SDK-001`)

**This is the highest-severity finding in the audit.**

The sequence, across two files:

```python
# scan_runner.py:66 — scope is checked against the CONFIGURED url
if not policy.is_in_scope(target.url):
    skipped += 1; continue

# scan_runner.py:74 — then the adapter is handed that url
raw = await adapter.probe(target.url, timeout=timeout)

# security_headers.py:125 — and the client follows wherever it leads
async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
    response = await client.get(target)
```

Scope authorizes **a URL**. httpx then follows **a chain of URLs**, none of which are re-checked. An in-scope host returning `302 Location: https://evil.test/` causes Provx to issue an authenticated-looking GET to `evil.test`. httpx's default limit is 20 redirects, each unchecked.

**Why this is not theoretical:**

- The redirect target is controlled by the *scanned host* — which in a pentest is, by definition, a system of uncertain trustworthiness. This is the one HTTP client in the codebase pointed at hostile infrastructure.
- Open redirects are commonplace, so the pivot needs no server compromise.
- The destination can be internal: `http://169.254.169.254/latest/meta-data/` (cloud metadata, credential theft), `http://127.0.0.1:5432/`, or any host on the scanner's network. **The scanner is the SSRF pivot.** The `accuracy` compose service sits on the internal `lab` network precisely because it is deliberately network-isolated — that isolation is the only thing containing this today, and it is Docker's doing, not Provx's.
- PX-SCOPE says an out-of-scope action *"is skipped and logged, never executed."* Here it is executed, unlogged, with no audit record — also implicating PX-EVIDENCE.

**And the evidence is mislabeled.** [`security_headers.py:127`](../../packages/adapters/src/provx_sdk/adapters/security_headers.py#L127) builds the envelope from the **requested** `target`, never `response.url`:

```python
return encode_response(target, response.status_code, dict(response.headers))
```

So after a redirect the envelope claims `{"target": "https://in-scope.example.com"}` while the headers came from `evil.test`. That string flows into `FindingDraft.target`, into `dedup_key`, into the sealed `tool_output`, and into the client report. **The evidence is cryptographically sealed to an attribution that is false** — `EvidenceSeal` proves the bytes were not altered after capture, which makes a wrong attribution *more* convincing, not less. A finding is only defensible if it says where it came from.

The `probe()` docstring — *"The caller MUST have cleared the target against engagement scope before calling this"* — is satisfied. The caller did clear the target. The contract is written against the wrong unit: it authorizes a URL, but the method performs a *chain* of requests.

**Severity: HIGH.** Complete bypass of the platform's central safety rule, reachable without compromising anything, plus falsified evidence attribution.

**Fix — three parts, all needed:**

1. **Set `follow_redirects=False`** and treat a 3xx as a finding-worthy observation rather than something to chase. Simplest, and passive-scanner-appropriate.
2. **If redirects must be followed, re-check every hop.** Pass the `ScopePolicy` *into* `probe()` and use an httpx event hook / manual redirect loop that calls `is_in_scope()` on each `Location` before following, aborting and logging on the first out-of-scope hop. This is what PX-SCOPE's *"never trusted from an upstream caller"* actually requires — the boundary that owns the network call must own the check.
3. **Record `response.url`, not the requested target,** in the envelope, so evidence attribution is truthful even when a redirect was followed deliberately.

Note that (2) is the structural fix and also resolves `SDK-002`.

---

## 6. Additional observations

**`ScopePolicy` is not frozen.** `policy.allow.append("evil.test")` works — the model is mutable and `allow` is a plain mutable list. For an authorization object read in a loop, `frozen=True` with tuple fields would make tampering inexpressible. **`SDK-029`** (low).

**No rule validation.** `ScopePolicy(allow=["*"])` constructs fine. `_matches("anything", "*")` is `False` (no `*.` prefix, so exact-match against `"*"`), so it fails closed — but `allow=["*."]` matches any host ending in `.`, and empty-string rules are accepted silently. A `field_validator` rejecting empty rules and malformed wildcards (`*`, `*.`, `a.*.b`, embedded `*`) would turn silent misconfiguration into a startup error. **`SDK-030`** (low).

**Only leading wildcards supported.** No `*.example.*`, no CIDR, no port scoping, no path scoping. Documented as the design, and the right minimal choice — but CIDR is a genuine gap for the infra module on the roadmap.

**Nothing is logged.** PX-SCOPE requires an out-of-scope action be *"skipped and logged"*. `is_in_scope` returns a bare `bool` and logs nothing; the logging lives in `scan_runner` ([line 68](../../backend/app/services/scan_runner.py#L68), a `logger.warning` with engagement id and target). Acceptable — a pure predicate should not log — but it means **every** caller must remember to log a denial. `lab/harness.py` does not call the predicate at all, so it logs nothing.

**No caching.** `is_in_scope` re-parses and re-matches per call, O(len(deny) + len(allow)) with a `.strip().lower()` per rule per call. Irrelevant at current scale; worth pre-normalizing rules at construction if scope lists grow.

---

## 7. Test coverage

[`test_scope.py`](../../packages/adapters/tests/test_scope.py) — 9 tests. What it covers, well:

- exact allow, unlisted host, wildcard apex + subdomain, **suffix confusion** (`example.com.evil.test`), deny-over-allow, empty policy, port + userinfo, case-insensitivity, non-web schemes, `target_host` raising.

**What it does not cover** — and each maps to a finding above:

| Gap | Finding |
|---|---|
| Deny against a *subdomain* of a denied host | `SDK-026` |
| Any IDN/punycode host or rule | `SDK-027` |
| Any IP-literal target (v4, v6, or alternate encoding) | `SDK-028` |
| Redirect behavior — no test issues a redirect at all | `SDK-001` |
| Trailing-dot FQDN (`example.com.`) | behavior is correct but unpinned |
| Malformed/empty scope rules | `SDK-030` |
| `_matches` with a non-lowercased host | `SDK-025` |

The existing tests are well-chosen — they target real attacks rather than trivial paths. The gap is that they stop at the string matcher and never reach the network behavior, which is where the critical failure lives.

---

## 8. Module verdict

`scope.py` is a **well-built string matcher wired into the wrong place.**

The matcher itself resists seven of the classic bypasses, including the two that matter most (userinfo spoofing and suffix confusion), and it fails closed on every parse error and on empty configuration. The code is short, readable, and its docstrings explain the *why*. That is real quality.

The failures are not in the matching logic — they are in **scope, in the other sense**:

1. It normalizes hostnames as strings, so anything with two spellings (IDN, IP literals) has a second spelling that evades deny.
2. Deny is exact-match while allow is subtree, so carve-outs silently under-apply.
3. Most importantly, it authorizes **one URL** while the adapter performs **a chain of requests** — and only the first is checked.

Fixing `SDK-001` by moving the policy inside `probe()` also fixes `SDK-002`, and is the change that would bring this file into genuine compliance with PX-SCOPE as written.
