# Module — `app/services` (+ `app/templates`)

**Path:** `/Users/mac/Projects/mine/provx/backend/app/services/`
**Purpose:** the deterministic business logic — the scan pipeline, report rendering, and the retest
stub. This is where the safety-critical ordering lives.

---

## Files

| File | Purpose | Exported symbols |
|---|---|---|
| [`services/__init__.py`](../../backend/app/services/__init__.py) | Docstring only: "Deterministic and auditable; no AI in these paths." Factually accurate. | — |
| [`services/scan_runner.py`](../../backend/app/services/scan_runner.py) | Scope gate → probe → seal → normalize → dedup → allocate → persist. | `DEFAULT_ADAPTER`, `display_id_for`, `run_scan`, `_existing_dedup_keys`, `logger` |
| [`services/report.py`](../../backend/app/services/report.py) | Jinja environment + HTML rendering. | `TEMPLATE_DIR`, `REPORT_TEMPLATE`, `get_environment`, `render_report` |
| [`services/retest.py`](../../backend/app/services/retest.py) | Documented stub for the deterministic verify loop. | `retest` |
| [`templates/report.html.j2`](../../backend/app/templates/report.html.j2) | The engagement findings report. | — |

**Dependencies:** `provx_sdk.evidence` (`seal`, `EvidenceSeal`), `provx_sdk.findings`
(`FindingDraft`, `Finding`), `provx_sdk.registry.load_adapter`, `provx_sdk.scope.ScopePolicy`,
`sqlmodel`, `jinja2`, `app.config`, `app.models.tables`.

**Tables touched:** reads `target`, `finding`; writes `scan`, `finding`.

---

## `scan_runner.py`

### Constants

`DEFAULT_ADAPTER = "security_headers"` — the adapter name resolved through the `provx.adapters`
entry-point group. Hardcoded because the workflow engine that would select an adapter is a later
phase.

### `display_id_for(sequence: int) -> str` — [line 36](../../backend/app/services/scan_runner.py#L36)

`f"PVX-{sequence:04d}"`. Four digits is a **minimum width, not a cap** — sequence 10000 yields
`PVX-10000`, which the SDK's `^PVX-\d{4,}$` deliberately accepts. Directly regression-tested at
[`test_scan_runner.py:47-57`](../../backend/tests/test_scan_runner.py#L47). Well handled; see
**F-M8** in `module_api.md` for the lexicographic-ordering interaction this creates.

### `async run_scan(session, engagement, adapter_name=DEFAULT_ADAPTER) -> Scan` — [line 41](../../backend/app/services/scan_runner.py#L41)

Runs one adapter across the engagement's in-scope targets and persists the results in a single
transaction. Full stage-by-stage trace, the B-FA-04 transaction analysis, and the concurrency
verdict are in [`01_ARCHITECTURE.md` §2](01_ARCHITECTURE.md). Summary of what the code gets right
and what it does not:

✅ **Right:**
- The scope check is on the line before the probe, in the same loop, with `continue` — there is no
  path to `adapter.probe` that skips it (PX-SCOPE).
- `seal(raw)` is the statement immediately after the probe, before parsing (PX-EVIDENCE).
- Single `commit()` at the end; a mid-scan exception rolls back the flushed `Scan` row, leaving no
  orphan (B-FA-04).
- Deterministic throughout: fixed rule order in the adapter, stable dedup key, sequential allocation
  — the same input yields the same findings in the same order (PX-DETERMINISM).
- Skips are counted **and** logged with structured context, not silently dropped.

⚠️ **Not right:**
- **F-H1** — `allocated = len(already_seen)` (line 80) reads a sequence counter with no lock. Two
  concurrent scans on one engagement both compute the same next number and the second to commit dies
  on `uq_finding_engagement_display_id`, losing the whole scan with an unretried 500. Fixes, in
  ascending order of effort: (a) `pg_advisory_xact_lock(hashtext(engagement_id))` at the top of
  `run_scan`; (b) `SELECT … FOR UPDATE` on the engagement row to serialize scans per engagement;
  (c) a per-engagement counter column incremented atomically; (d) catch `IntegrityError` and retry.
  (a) or (b) is the right call at this stage — one line, and it also fixes the duplicate-work case.
- **F-M2** — `engagement.mode` is never read. Nothing prevents an `active` engagement from scanning.
  The check belongs here, at the point of execution, not only on the create schema (PX-ACTIVE).
- **F-H3** — `SAFE_MODE` is never consulted either. This function is the single place an org-wide
  safety lock would take effect.
- **F-M10** — `adapter.safety` is never checked. The `ToolAdapter` protocol declares
  `safety: "passive" | "intrusive"`
  ([`plugins.py`](../../packages/adapters/src/provx_sdk/plugins.py)), and `run_scan` accepts an
  `adapter_name` parameter, so the moment a second adapter is installed the runner will happily
  execute an intrusive one against a passive engagement. Asserting
  `adapter.safety == "passive"` (or matching it against `engagement.mode`) is two lines now and a
  much harder retrofit later. This is the seam where PX-ACTIVE will actually be enforced.
- **F-M1** — no scan record survives a failure (see `module_models.md`).
- **F-M11** — a single probe failure aborts the entire scan. One unreachable host among twenty means
  zero findings persisted and nineteen wasted probes. `adapter.probe` is raw `httpx` with no
  `try/except`, so `ConnectError`, `ReadTimeout`, and `TooManyRedirects` are all fatal to the run.
  Per-target error capture (a `targets_failed` counter, or a per-target error record) is the
  natural shape.

**Ordering note:** all probes complete before any dedup or persistence begins (`captured` is
accumulated, then drained). This keeps evidence sealing adjacent to capture and keeps the write
phase short — a deliberate and good choice — but it means the whole scan is held in memory and
nothing is durable until the last target returns.

### `async _existing_dedup_keys(session, engagement_id) -> set[tuple[str, str]]` — [line 105](../../backend/app/services/scan_runner.py#L105)

Loads existing `(target, title)` identities so a rescan does not duplicate. Verified against
`FindingDraft.dedup_key`, which is exactly `(self.target, self.title)` — the two definitions agree,
but they are **defined in two places**: the SDK owns the draft's key, and this function
re-implements the same tuple over a row. A change to one silently desynchronizes the other and the
symptom would be duplicate findings, not an error. Extracting a shared key function is the DRY fix
(Q-11). **F-L20.**

Two further notes:
- **F-L1** — selects entire `FindingRow` ORM objects to build a set of two strings. Should be
  `select(FindingRow.target, FindingRow.title)`.
- The dedup key does **not** include `matched_rule` or severity, so two genuinely different findings
  that happen to share a title on the same target collapse into one. Correct for the current
  ruleset (title is 1:1 with the header rule); worth revisiting when adapters emit richer findings.

---

## `report.py`

| Signature | Description |
|---|---|
| `get_environment() -> Environment` | `lru_cache(maxsize=1)`. `FileSystemLoader(TEMPLATE_DIR)` with `autoescape=select_autoescape(default=True, default_for_string=True)`. |
| `render_report(engagement: Engagement, findings: list[Finding]) -> str` | Renders `report.html.j2` with `engagement`, `findings`, and `generated_at=datetime.now(UTC)`. |

### Autoescaping and XSS — verified

`select_autoescape(default=True, default_for_string=True)` is the **correct** call. The default
`select_autoescape()` enables escaping only for `.html`/`.htm`/`.xml` extensions and would **not**
cover `report.html.j2`, whose final extension is `.j2` — a genuine and common footgun that this code
avoids explicitly. `default_for_string=True` additionally covers `Environment.from_string`.

Template review ([`report.html.j2`](../../backend/app/templates/report.html.j2)):

- Every interpolation is a plain `{{ }}` expression. **Zero uses of `| safe`, `Markup`, or
  `{% autoescape false %}`** — verified by reading the whole file.
- Untrusted values rendered: `engagement.name` (twice — `<title>` and `<h1>`), `finding.title`,
  `finding.target`, `finding.remediation`, `finding.attack_techniques`. All escaped.
- No interpolation occurs inside a `<script>` block, an inline event handler, an `href`/`src`
  attribute, or a `<style>` block — the contexts where HTML escaping alone is insufficient. The
  `<style>` block is entirely static. This is the part most templates get wrong, and this one is
  clean.
- `finding.target` is rendered as **text**, never as a link. That neutralizes `javascript:` and
  `data:` URI injection through a scan target. Deliberate or lucky, it is right.
- Covered by [`test_hostile_scan_output_is_escaped_not_executed`](../../backend/tests/test_report.py#L54),
  which asserts both directions: the raw payload absent *and* the escaped form present. Good test.

**Verdict: no XSS. S-06 satisfied.** The residual item is **F-L14** (no CSP header on the response).

### PX-HUMAN banner

[Lines 29-36](../../backend/app/templates/report.html.j2#L29) render a prominent, unconditional
"Machine-found, unvalidated" banner stating that nothing has been confirmed by a human and that
findings must pass validation before entering a client-facing report. It cannot be suppressed by
data and is asserted by two separate tests. This is PX-HUMAN implemented properly rather than
documented and forgotten.

### Other template details

- `{{ '%.1f' % finding.cvss if finding.cvss is not none else '-' }}` — correct `is not none` guard
  (not a truthiness test, so a CVSS of `0.0` renders as `0.0` rather than `-`).
- `{{ finding.attack_techniques | join(', ') or '-' }}` — correct empty-list fallback.
- `{{ generated_at.strftime('%Y-%m-%d %H:%M:%S %Z') }}` — includes `%Z`, so the UTC marker survives
  into the report. Right for an audit artifact.
- `{{ finding.severity.value }}` / `.confidence.value` — explicit `.value` on the StrEnums.
- **F-L21 (Low)** — the report renders `engagement.mode` and the finding table but **not** the
  engagement's scope, the target list, the scan timestamps, or the evidence sha256. For a report
  intended to be compliance-grade, "what was authorized, what was tested, when, and what proves it"
  are the load-bearing fields, and none of the first three are present. The data is all persisted;
  it is only the template that omits it.

---

## `retest.py`

| Signature | Description |
|---|---|
| `retest(finding_id: str) -> None` | Raises `NotImplementedError("retest() is a documented stub; the verify loop lands later")`. |

An explicitly declared stub with a thorough docstring describing the intended deterministic
behaviour (re-run the single check, compare to original evidence, transition to `fixed` or
`regression`, close the linked tracker issue) and an explicit "no AI involved" note. Pinned by
[`test_retest_is_documented_stub`](../../backend/tests/test_findings.py#L114). Correct handling of
scaffolding: it raises rather than silently returning `None`.

One inconsistency: the parameter is typed `finding_id: str` and the test calls it with
`"PVX-0001"` — a **display_id**, which is only unique *within an engagement*. The SDK is explicit
that `Finding.id` (UUID) is the stable global key. Retesting by display_id alone is ambiguous across
engagements. `RiskAcceptance.finding_id` has the same unresolved ambiguity, acknowledged in its own
comment. Worth deciding before the verify loop is written. **F-L22.**

---

## Module findings summary

| ID | Sev | Summary |
|---|---|---|
| F-H1 | High | `display_id` allocation is a lock-free read-then-write; concurrent scans on one engagement collide and lose a whole scan. |
| F-H3 | High | `SAFE_MODE` never consulted in the one function where it would matter. |
| F-M1 | Medium | Failed scans leave no record; `Scan.status` never set. |
| F-M2 | Medium | `engagement.mode` never re-checked at scan time. |
| F-M10 | Medium | `adapter.safety` never checked against engagement mode — the PX-ACTIVE seam. |
| F-M11 | Medium | One probe failure aborts the entire scan; no per-target error handling. |
| F-L1 | Low | `_existing_dedup_keys` loads full rows to build a two-string key set. |
| F-L20 | Low | Dedup key defined twice (SDK draft property + this function). |
| F-L21 | Low | Report omits scope, target list, scan timestamps, and evidence hashes. |
| F-L22 | Low | `retest`/`RiskAcceptance` keyed on ambiguous `display_id` rather than the UUID. |

✅ **Done well:** scope gate provably precedes the network call; seal taken at capture; single-commit
transaction with a clean rollback path; correct non-obvious `select_autoescape` configuration with
zero `| safe` in the template; unsuppressable PX-HUMAN banner; honest raising stub.
