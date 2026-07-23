# Known issues

Defects and residual risks that are **known and reproduced**. Each entry says what it is, why
it was deferred, and what would make it urgent. Resolved entries stay, marked, with what
closed them — the history of a defect is worth as much as its absence.

An issue that is merely undiscovered does not belong here; an issue that is understood does.

This file is the counterpart to [audits/](../audits/): the audit says what is wrong, this says
what we decided to do about it and when.

---

## KI-001 — The accuracy gate collapses findings that share a rule id

**Severity:** Medium · **Status:** ✅ RESOLVED · **Source:** audit `SDK-003`
**Site:** [`lab/harness.py`](../lab/harness.py) — `score_target`

`score_target` builds its lookup with `found = {check_id(d): d for d in drafts}`. A dict
comprehension is last-wins, so when two findings on one target share a `matched_rule`, only
the last survives — and with a `min_severity` floor, which one survives decides the verdict.

Reproduced by execution:

```text
HIGH,INFO  -> passed=False   TP=0 FP=1
INFO,HIGH  -> passed=True    TP=1 FP=0
```

Identical findings, opposite results. This is **PX-DETERMINISM violated inside the gate that
enforces determinism**, which is why it is recorded rather than shrugged off.

**Why it was deferred:** unreachable at the time. The one shipped adapter emits a unique
`matched_rule` per header, so a single target could not produce a collision — but a second
adapter, or any check firing more than once per target, would have made it live.

**✅ Resolved.** `score_target` now groups by rule id via `group_by_rule` and keeps every
instance; a rule counts as a true positive when *any* instance meets the severity floor.
Order-independent by construction. `lab/tests/test_harness.py` asserts the original
reproduction scores identically both ways.

---

## KI-002 — `display_id` allocation races between concurrent scans

**Severity:** Medium · **Status:** ✅ RESOLVED · **Source:** audit `F-H1`
**Site:** [`backend/app/services/scan_runner.py`](../backend/app/services/scan_runner.py) — `run_scan`

Allocation reads the existing count and then writes: `allocated = len(already_seen)`, with no
lock. Two concurrent scans on one engagement both compute `PVX-{N+1}`.

**Why it was deferred:** it appeared to fail safe — the unique constraint should make the
loser's transaction roll back rather than write a duplicate, with an unretried 500 as the only
symptom. Fixing it revealed that assumption was never actually tested (see below).

**✅ Resolved.** `_persist_scan` retries on `IntegrityError`: it rolls back, re-reads the
allocation count, and renumbers, up to `MAX_PERSIST_ATTEMPTS`, then raises the domain error
`ScanPersistError` rather than an internal one. Retry covers persistence only — re-running the
probe would re-seal evidence and break PX-EVIDENCE.

Chosen over `pg_advisory_xact_lock` because the suite runs on SQLite: an advisory lock would
have left the production path as the one path no test exercises, which is the blind-spot
pattern this codebase has already been bitten by once.

Fixing it also exposed a second bug: the unique constraint existed **only in the migration**,
not on the model, so every `create_all`-built test schema lacked it and the "fails safe"
property had never actually been exercised. Now declared in `FindingRow.__table_args__`, with
a drift test in `backend/tests/test_migrations.py`.

---

## KI-003 — Dangerous-range refusal applies to IP literals, not resolved hostnames

**Severity:** Medium · **Status:** accepted residual risk · **Source:** safety-in-motion pass
**Site:** [`packages/adapters/src/provx_sdk/scope.py`](../packages/adapters/src/provx_sdk/scope.py) — `is_dangerous_host`

`ScopePolicy` refuses loopback, RFC-1918, link-local, reserved, and multicast targets by
default, and canonicalizes every IP spelling so `2130706433` and `0x7f.0.0.1` cannot evade a
rule. That protection applies to **IP literals only**. A hostname that resolves to
`169.254.169.254` is not caught, because nothing here resolves it.

**Why deferred:** resolving at check time does not actually close it — it opens a
DNS-rebinding (TOCTOU) window instead, where the name resolves to a safe address for the
check and a dangerous one for the request. Doing this properly needs the resolution pinned
and the connection made to the already-resolved address, which is a real piece of design.

**What makes it urgent:** any deployment where an untrusted party can put a hostname into an
engagement's scope. Today the API has no auth at all, so this sits behind a larger problem
(audit `F-C1`); it becomes the top item the moment auth lands and scope becomes
user-supplied in earnest.

**Update (`feat/authenticated-scanning`):** *authenticated scanning* is not the same as *API
authentication* — the explicit-credential feature landed **without** API RBAC or user-supplied
scope, so this issue's urgency trigger (an untrusted party supplying a hostname) is still not
reached. Unchanged and open; the pinned-resolution transport remains the fix and is out of scope
for the credential work.

**Fix sketch:** resolve once, validate the resolved address, then connect to that address
with the original `Host` header — a pinned-resolution transport rather than a pre-flight
lookup.

---

## KI-004 — Sensitive material in sealed evidence

**Severity:** Medium · **Status:** ✅ RESOLVED (with residuals) · **Source:** safety review (PX-SECRETS)
**Site:** [`packages/adapters/src/provx_sdk/fetch.py`](../packages/adapters/src/provx_sdk/fetch.py),
[`backend/app/models/tables.py`](../backend/app/models/tables.py) —
[`backend/app/security/evidence_crypto.py`](../backend/app/security/evidence_crypto.py)

An adapter's `raw` envelope is both `seal()`-hashed and embedded verbatim into
`Evidence.tool_output`, then written to the insert-only `finding.evidence_tool_output` column. The
envelopes serialized full response header dicts and raw `Set-Cookie` values, so a live session token
could land in an evidence row that has **no delete path** (PX-EVIDENCE append-only) — retaining
session material and tensioning PX-SECRETS. `parse_output` already dropped the cookie value for
*analysis*; the stored envelope did not.

**✅ Resolved — two layers, by concern:**

1. **Redaction at the egress boundary.** `fetch_within_scope` now redacts the values of sensitive
   headers (`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`) in `FetchOutcome` before
   anything serializes or seals them, substituting `<redacted:sha256:…>` — a fingerprint that
   preserves evidentiary integrity (same secret → same tag) without keeping the secret. Cookie *name*
   and *attributes* are kept, so `cookie_flags` is unaffected. One choke point (reinforces PX-EGRESS);
   every current and future adapter is covered with no adapter change.
2. **Encryption at rest.** `evidence_tool_output` is AES-256-GCM encrypted on write and decrypted on
   read (the single `to_contract` seam), so the whole blob is unreadable in the database regardless of
   content. The seal is unchanged — `evidence_sha256` is over the redacted plaintext, which decryption
   reproduces exactly, so the capture-time hash still verifies.

**Residual risks:**

- **Request-side credential headers** — ✅ addressed by `feat/authenticated-scanning`. An
  authenticated scan's injected header is attached at the one egress boundary and its name is added
  to the redaction denylist for that fetch (`Authorization`/`Cookie` were already covered; a custom
  header name is added), so a reflected copy is sealed as `<redacted:sha256:...>` exactly like a
  server-sent secret. The credential is also scrubbed from the body if echoed (below).
- **Body content beyond headers** — ⏳ now **best-effort**, not complete. `provx_sdk.fetch.redact_body`
  scrubs the exact injected credential plus high-precision secret shapes (JWTs, `Bearer` tokens,
  reflected `Authorization`/`Set-Cookie` lines) from a response body before it is sealed. It is
  **deliberately not a completeness guarantee** — general body redaction is undecidable — so at-rest
  encryption remains the backstop for anything the patterns miss. (Note: the shipping passive adapters
  seal response *headers*, not bodies, so this primarily hardens future body-sealing adapters and the
  reflected-credential case.)
- **URL userinfo** in evidence envelopes (`redirect_chain`/`redirect_location`) is not redacted;
  `redact_url` covers the log path only. Low exposure today. **Still open.**
- **Key management:** the AES key is HKDF-derived from `SECRET_KEY` — used now for both evidence and
  the credential value at rest. A dedicated, rotated **KMS-backed key** (and a distinct HKDF `info`
  label to separate evidence and credential keys) is the production upgrade. **Still open.**
- **SDK-004 (inline-seal)** remains open: the seal still lives outside the `Evidence` model and is
  threaded through `scan_runner`, so a consumer that bypasses it holds unsealed evidence. Tracked in
  `audits/sdk/99_FINDINGS.md`; this change is compatible with resolving it later.

---

## KI-005 — Report ATT&CK coverage uses a static in-repo technique→tactic map

**Severity:** Low · **Status:** Open (accepted) · **Source:** `feat/report-hardening`
**Site:** [`backend/app/services/report_attack.py`](../backend/app/services/report_attack.py)

The report's "MITRE ATT&CK coverage" section maps technique ids to tactics from a small
hand-maintained table covering the techniques the shipping passive adapters emit. It is not
the full ATT&CK catalogue: a technique the table does not know falls into an `Unmapped`
tactic (it is never dropped, so no finding is lost from coverage).

**Why deferred:** the report is built offline, in air-gapped deployments too — it must not
fetch the live ATT&CK catalogue (rule PX-EGRESS). A static table is correct and deterministic
for the current adapter set. It becomes urgent only when many more techniques ship; the fix is
to generate the table from a vendored ATT&CK STIX bundle at build time, still offline.

**Related deferral (not a defect):** the additive `Finding.description` field and its
`finding.description` column exist but no adapter populates them yet, so the report falls back
to the finding `title`. Adapters can start emitting a richer description in a later PR with no
schema change.

---

## KI-006 — Authenticated scanning supports explicit credentials only (no form-login/session)

**Severity:** Low · **Status:** Open (deferred by design) · **Source:** `feat/authenticated-scanning`
**Site:** [`packages/adapters/src/provx_sdk/auth.py`](../packages/adapters/src/provx_sdk/auth.py),
[`backend/app/models/tables.py`](../backend/app/models/tables.py) — `Credential`

Authenticated scanning presents an operator-supplied credential — a **bearer token, a cookie
string, or a custom header** — injected at the single egress boundary. It deliberately does **not**
do form-login auto-detection, CSRF token handling, SSO/MFA flows, or session recording/replay. An
app that only issues a session through an interactive login form cannot be scanned authenticated
yet; the operator must supply an already-obtained cookie/bearer/header.

**Why deferred:** explicit credentials are the safe, deterministic 80% and carry no brittle,
app-specific automation. Form-login and session capture are a materially larger design (per-app
login recipes, CSRF extraction, re-auth on expiry) and are the right next increment, not a
same-PR add-on. Scoped as **explicit creds only in v0.2**; form-login/session-record is a later
capability.

**What makes it urgent:** a concrete engagement whose target cannot mint a token/cookie out of
band and only authenticates via a login form.

---

## KI-007 — Third-party httpx/httpcore wire-debug logging echoes a reflected credential

**Severity:** Low · **Status:** Open (operational note) · **Source:** `fix/auth-test-hardening`
**Site:** [`packages/adapters/src/provx_sdk/fetch.py`](../packages/adapters/src/provx_sdk/fetch.py)

Provx redacts credentials at the single egress boundary before anything is sealed, stored, or
logged, and Provx's own loggers (`app`, `provx_sdk`) never carry a header value or a response body.
But `httpx`/`httpcore` ship their own DEBUG-level "wire" logging, and when that is enabled it logs
raw request and response bytes — including a credential the target reflects back in a header or
body — **before** Provx's redaction runs. This is third-party diagnostic output, off by default,
and is not a Provx control.

**How to stay safe:** do **not** enable `httpx`/`httpcore` DEBUG (wire-debug) logging in production
or in any environment where logs are retained. The integration test asserts credential absence only
against Provx's own loggers (`app`/`provx_sdk`) for exactly this reason; the wire-debug channel is
out of Provx's redaction reach by construction.

**Why deferred:** the leak requires an operator to opt into third-party debug logging that Provx
never turns on. The durable fix (a logging filter that scrubs the httpcore wire logger, or refusing
to configure it) is a small hardening item, not a shipped-behavior defect.

---

## Not listed here

Absent features are not issues. Authentication, the job queue, the PX-DSL expression
evaluator, Active mode, exploitation, additional adapters, and PDF reporting are **declared
scaffolding** — see [ROADMAP.md](ROADMAP.md) §4 for what is intentionally out of the current
phase.
