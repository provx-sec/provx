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

**Fix sketch:** resolve once, validate the resolved address, then connect to that address
with the original `Host` header — a pinned-resolution transport rather than a pre-flight
lookup.

---

## Not listed here

Absent features are not issues. Authentication, the job queue, the PX-DSL expression
evaluator, Active mode, exploitation, additional adapters, and PDF reporting are **declared
scaffolding** — see [ROADMAP.md](ROADMAP.md) §4 for what is intentionally out of the current
phase.
