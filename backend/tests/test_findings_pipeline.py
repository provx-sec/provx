# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
The findings pipeline's first real integration test - **nothing is stubbed**.

Two real adapters probe one real local server over HTTP, their real drafts go through the
real persistence path, and the finding is then driven through its whole lifecycle over the
real API. It proves the load-bearing behaviour end to end:

* ``security_headers`` and ``tls`` both report the missing HSTS header on the same target;
  dedup collapses them into **one** finding that keeps **both** evidences (rules
  PX-DETERMINISM, PX-EVIDENCE) and takes the worse severity.
* a human transition - and only a human transition - moves it to ``validated`` (rule
  PX-HUMAN); the report then shows it as validated rather than machine-found.
* marking another finding a false positive suppresses it on re-scan and records the
  regression intent; toggling ``in_report`` removes a finding from the report.

Each database read uses a short-lived session and extracts plain values immediately: the API
mutations run on the app's own engine, so reusing one long-lived ORM identity map would serve
stale rows. Loopback is a normally-refused range, so the probes use ``allow_dangerous_ranges``
- the one legitimate way to reach a local target (as in test_integration_redirect.py).
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient
from provx_sdk.adapters.security_headers import SecurityHeadersAdapter
from provx_sdk.adapters.tls_transport import TlsTransportAdapter
from provx_sdk.evidence import seal
from provx_sdk.findings import FindingStatus, Severity
from provx_sdk.scope import ScopePolicy
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models.tables import Engagement, FindingEvidenceRow, FindingRow

BIND_HOST = "127.0.0.1"
HSTS_TITLE = "Missing Strict-Transport-Security header"
CSP_TITLE = "Missing Content-Security-Policy header"
REFERRER_TITLE = "Missing Referrer-Policy header"


@dataclass
class LabServer:
    base_url: str
    paths: list[str] = field(default_factory=list)


@dataclass
class StoredFinding:
    """Plain snapshot of a stored finding, so no ORM object outlives its session."""

    id: uuid.UUID
    display_id: str
    status: FindingStatus
    severity: Severity
    cvss: float | None
    regression_intent: bool
    primary_sha256: str
    appended: list[tuple[str, str | None, str]]  # (sha256, matched_rule, source_adapter)


@pytest.fixture
def server() -> Iterator[LabServer]:
    """A real loopback server that answers plain HTTP with no HSTS and no HTTPS redirect, so
    both the security_headers and the tls adapter fire on it."""
    recorded: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - name fixed by BaseHTTPRequestHandler
            recorded.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args: object) -> None:
            """Silence the default stderr access log."""

    httpd = HTTPServer((BIND_HOST, 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]

    yield LabServer(base_url=f"http://{BIND_HOST}:{port}", paths=recorded)

    httpd.shutdown()
    httpd.server_close()


def _policy() -> ScopePolicy:
    return ScopePolicy(allow=[BIND_HOST], allow_dangerous_ranges=True)


@asynccontextmanager
async def _fresh_session(database_url: str) -> AsyncIterator[AsyncSession]:
    """A short-lived session that always reads the latest committed state."""
    engine = create_async_engine(database_url, future=True)
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as session:
        yield session
    await engine.dispose()


async def _run_adapter(
    database_url: str, engagement_id: uuid.UUID, adapter: object, name: str, target: str
) -> None:
    """Probe one real adapter against the target and persist its real drafts through the real
    consolidation path (the same _persist_scan run_scan calls)."""
    from app.services import scan_runner

    raw = await adapter.probe(target, policy=_policy())  # type: ignore[attr-defined]
    stamp = seal(raw)
    captured = [(draft, stamp) for draft in adapter.parse_output(raw)]  # type: ignore[attr-defined]
    async with _fresh_session(database_url) as session:
        engagement = await session.get(Engagement, engagement_id)
        assert engagement is not None
        await scan_runner._persist_scan(session, engagement, name, captured, 1, 0)


async def _stored_findings(database_url: str, engagement_id: uuid.UUID) -> dict[str, StoredFinding]:
    async with _fresh_session(database_url) as session:
        rows = (
            await session.exec(select(FindingRow).where(FindingRow.engagement_id == engagement_id))
        ).all()
        result: dict[str, StoredFinding] = {}
        for row in rows:
            appended = (
                await session.exec(
                    select(FindingEvidenceRow).where(FindingEvidenceRow.finding_id == row.id)
                )
            ).all()
            result[row.title] = StoredFinding(
                id=row.id,
                display_id=row.display_id,
                status=row.status,
                severity=row.severity,
                cvss=row.cvss,
                regression_intent=row.regression_intent,
                primary_sha256=row.evidence_sha256,
                appended=[(a.sha256, a.matched_rule, a.source_adapter) for a in appended],
            )
        return result


async def test_pipeline_dedups_evidence_then_honours_the_lifecycle(
    database_url: str, client: TestClient, server: LabServer
) -> None:
    target = f"{server.base_url}/app"
    async with _fresh_session(database_url) as session:
        engagement = Engagement(name="Pipeline", scope_allow=[BIND_HOST])
        session.add(engagement)
        await session.commit()
        engagement_id = engagement.id

    # Two adapters, same target: security_headers reports five missing headers (HSTS among
    # them); tls reports the missing HSTS and the absent HTTPS redirect.
    await _run_adapter(
        database_url, engagement_id, SecurityHeadersAdapter(), "security_headers", target
    )
    await _run_adapter(database_url, engagement_id, TlsTransportAdapter(), "tls", target)

    # --- Dedup: the two HSTS reports are one finding carrying both evidences, none lost. ---
    stored = await _stored_findings(database_url, engagement_id)
    titles = [t for t in stored if t == HSTS_TITLE]
    assert titles == [HSTS_TITLE], "the two adapters' HSTS reports must collapse into one finding"
    hsts = stored[HSTS_TITLE]
    assert len(hsts.appended) == 1, "the second adapter's evidence must be appended, never dropped"
    # Primary evidence (security_headers) plus one appended (tls) = two distinct references.
    appended_sha, appended_rule, appended_adapter = hsts.appended[0]
    assert appended_sha != hsts.primary_sha256
    assert appended_rule == "tls:hsts-missing"
    assert appended_adapter == "tls"
    # The collapsed finding keeps the worse severity/CVSS (tls MEDIUM/5.3 over headers LOW/3.7).
    assert hsts.severity == Severity.MEDIUM
    assert hsts.cvss == pytest.approx(5.3)

    # The API surfaces the collapse as a count of two.
    listed = client.get(f"/engagements/{engagement_id}/findings")
    assert listed.status_code == 200
    hsts_json = next(f for f in listed.json() if f["title"] == HSTS_TITLE)
    assert hsts_json["evidence_ref_count"] == 2
    assert hsts_json["status"] == "new"

    # --- Lifecycle: only an explicit human transition reaches validated (PX-HUMAN). ---
    base = f"/engagements/{engagement_id}/findings/{hsts.id}"
    assert client.post(f"{base}/transition", json={"to_status": "triaged"}).status_code == 200
    validated = client.post(f"{base}/transition", json={"to_status": "validated"})
    assert validated.status_code == 200
    assert validated.json()["status"] == "validated"

    # An illegal edge is refused deterministically with a stable code, not a 500 (PX-ERRORS).
    illegal = client.post(f"{base}/transition", json={"to_status": "new"})
    assert illegal.status_code == 409
    assert illegal.json()["error_code"] == "illegal_transition"

    # The report now shows the HSTS finding under human-validated, not machine-found.
    report = client.get(f"/engagements/{engagement_id}/report")
    assert report.status_code == 200
    assert "Human-validated findings (1)" in report.text
    assert hsts.display_id in report.text

    # --- False positive: suppressed on re-scan, regression intent recorded. ---
    csp = stored[CSP_TITLE]
    fp = client.post(
        f"/engagements/{engagement_id}/findings/{csp.id}/transition",
        json={"to_status": "false_positive", "note": "template intentionally omits CSP"},
    )
    assert fp.status_code == 200
    assert fp.json()["status"] == "false_positive"

    await _run_adapter(
        database_url, engagement_id, SecurityHeadersAdapter(), "security_headers", target
    )
    after = await _stored_findings(database_url, engagement_id)
    assert len(after) == len(stored), "a re-scan must not duplicate findings"
    csp_again = after[CSP_TITLE]
    assert csp_again.status == FindingStatus.FALSE_POSITIVE, "the FP must stay suppressed"
    assert csp_again.regression_intent is True
    assert csp_again.appended == [], "a suppressed finding gains no further evidence on re-scan"

    report_after_fp = client.get(f"/engagements/{engagement_id}/report")
    assert csp.display_id not in report_after_fp.text, "a false positive is never in the report"

    # --- in_report toggle: removing a finding drops it from the report. ---
    referrer = after[REFERRER_TITLE]
    assert referrer.display_id in report_after_fp.text  # in-report before the toggle
    toggled = client.post(
        f"/engagements/{engagement_id}/findings/{referrer.id}/in-report",
        json={"in_report": False},
    )
    assert toggled.status_code == 200
    assert toggled.json()["in_report"] is False

    report_after_toggle = client.get(f"/engagements/{engagement_id}/report")
    assert referrer.display_id not in report_after_toggle.text
    assert hsts.display_id in report_after_toggle.text  # still in-report, still shown
