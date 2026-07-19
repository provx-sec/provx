# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
End-to-end API tests for the walking skeleton.

The adapter's network probe is stubbed with recorded envelopes so *this module* stays
hermetic. What is exercised for real is everything else: the scope gate, dedup,
per-engagement display-id allocation, persistence, and rendering.

The network boundary itself is deliberately NOT covered here - stubbing `probe` is exactly
what left the old suite blind to the redirect scope-escape. `test_integration_redirect.py`
drives real httpx against a real server for that.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from provx_sdk.adapters.security_headers import SecurityHeadersAdapter, encode_response
from provx_sdk.scope import ScopePolicy

MISSING_HEADERS: dict[str, str] = {"server": "nginx"}
HARDENED_HEADERS: dict[str, str] = {
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
}


@pytest.fixture
def probed(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Stub the adapter's probe, recording every URL it was actually asked to fetch."""
    reached: list[str] = []

    async def fake_probe(
        self: Any, target: str, *, policy: ScopePolicy, timeout: float = 10.0
    ) -> str:
        reached.append(target)
        headers = HARDENED_HEADERS if "hardened" in target else MISSING_HEADERS
        return encode_response(target, 200, headers)

    monkeypatch.setattr(SecurityHeadersAdapter, "probe", fake_probe)
    return reached


def create_engagement(client: TestClient, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": "Acme external web",
        "scope_allow": ["*.example.com"],
        "scope_deny": [],
        "targets": ["https://app.example.com"],
    }
    payload.update(overrides)
    response = client.post("/engagements", json=payload)
    assert response.status_code == 201, response.text
    return dict(response.json())


def test_create_engagement_returns_scope_and_targets(client: TestClient) -> None:
    body = create_engagement(client)

    assert body["name"] == "Acme external web"
    assert body["scope_allow"] == ["*.example.com"]
    assert body["targets"] == ["https://app.example.com"]
    assert body["mode"] == "passive"


def test_create_engagement_rejects_active_mode(client: TestClient) -> None:
    response = client.post(
        "/engagements",
        json={
            "name": "x",
            "scope_allow": ["example.com"],
            "targets": ["https://example.com"],
            "mode": "active",
        },
    )

    assert response.status_code == 422


def test_create_engagement_rejects_empty_scope(client: TestClient) -> None:
    response = client.post(
        "/engagements",
        json={"name": "x", "scope_allow": [], "targets": ["https://example.com"]},
    )

    assert response.status_code == 422


def test_scan_persists_findings_visible_through_the_api(
    client: TestClient, probed: list[str]
) -> None:
    engagement = create_engagement(client)

    scan = client.post(f"/engagements/{engagement['id']}/scan")
    assert scan.status_code == 201, scan.text
    assert scan.json()["targets_scanned"] == 1
    assert scan.json()["targets_skipped_out_of_scope"] == 0

    findings = client.get(f"/engagements/{engagement['id']}/findings").json()
    assert len(findings) == 5
    assert [f["display_id"] for f in findings] == [
        "PVX-0001",
        "PVX-0002",
        "PVX-0003",
        "PVX-0004",
        "PVX-0005",
    ]

    first = findings[0]
    assert first["severity"] == "low"
    assert first["cvss"] is not None
    assert first["attack_techniques"] == ["T1595"]
    assert first["confidence"] == "high"
    assert first["status"] == "new"
    assert first["remediation"]
    # PX-EVIDENCE: a capture-time seal accompanies every stored finding.
    assert len(first["evidence_sha256"]) == 64
    assert first["captured_at"]


def test_out_of_scope_target_is_never_reached(client: TestClient, probed: list[str]) -> None:
    engagement = create_engagement(
        client,
        scope_allow=["*.example.com"],
        targets=["https://app.example.com", "https://not-ours.evil.test"],
    )

    scan = client.post(f"/engagements/{engagement['id']}/scan").json()

    assert scan["targets_scanned"] == 1
    assert scan["targets_skipped_out_of_scope"] == 1
    # The load-bearing assertion for PX-SCOPE: no request was made to the denied host.
    assert probed == ["https://app.example.com"]


def test_denied_host_beats_a_broader_allow(client: TestClient, probed: list[str]) -> None:
    engagement = create_engagement(
        client,
        scope_allow=["*.example.com"],
        scope_deny=["prod.example.com"],
        targets=["https://prod.example.com"],
    )

    scan = client.post(f"/engagements/{engagement['id']}/scan").json()

    assert scan["targets_scanned"] == 0
    assert probed == []


def test_rescanning_does_not_duplicate_findings(client: TestClient, probed: list[str]) -> None:
    engagement = create_engagement(client)

    client.post(f"/engagements/{engagement['id']}/scan")
    client.post(f"/engagements/{engagement['id']}/scan")

    findings = client.get(f"/engagements/{engagement['id']}/findings").json()
    assert len(findings) == 5
    assert len({f["display_id"] for f in findings}) == 5


def test_hardened_target_produces_no_findings(client: TestClient, probed: list[str]) -> None:
    engagement = create_engagement(
        client, scope_allow=["*.example.com"], targets=["https://hardened.example.com"]
    )

    scan = client.post(f"/engagements/{engagement['id']}/scan").json()

    assert scan["targets_scanned"] == 1
    assert scan["findings_count"] == 0


def test_display_ids_restart_per_engagement(client: TestClient, probed: list[str]) -> None:
    first = create_engagement(client)
    second = create_engagement(client, name="Second engagement")
    client.post(f"/engagements/{first['id']}/scan")
    client.post(f"/engagements/{second['id']}/scan")

    second_findings = client.get(f"/engagements/{second['id']}/findings").json()

    assert second_findings[0]["display_id"] == "PVX-0001"


def test_report_renders_findings_and_the_unvalidated_banner(
    client: TestClient, probed: list[str]
) -> None:
    engagement = create_engagement(client)
    client.post(f"/engagements/{engagement['id']}/scan")

    response = client.get(f"/engagements/{engagement['id']}/report")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    body = response.text
    # PX-HUMAN: nothing in a Provx report may read as confirmed.
    assert "Machine-found, unvalidated" in body
    assert "not</strong> been confirmed by a human" in body
    assert "PVX-0001" in body
    assert "T1595" in body
    assert "Missing Content-Security-Policy header" in body


def test_unknown_engagement_returns_a_user_safe_error(client: TestClient) -> None:
    response = client.get(f"/engagements/{uuid.uuid4()}/findings")

    assert response.status_code == 404
    body = response.json()
    assert body["error_code"] == "engagement_not_found"
    assert body["message"] == "Engagement not found."
    # PX-ERRORS: no stack trace, SQL, or driver detail reaches the client.
    assert "Traceback" not in response.text
    assert "sqlalchemy" not in response.text.lower()


def test_findings_response_omits_raw_evidence(client: TestClient, probed: list[str]) -> None:
    engagement = create_engagement(client)
    client.post(f"/engagements/{engagement['id']}/scan")

    findings = client.get(f"/engagements/{engagement['id']}/findings").json()

    # Raw tool output can carry sensitive material; the list view publishes only the seal.
    assert "evidence_tool_output" not in findings[0]


def test_stored_findings_round_trip_through_the_contract(
    client: TestClient, probed: list[str]
) -> None:
    # The report path rebuilds every stored row into an SDK Finding; if a row were written
    # in a shape the contract rejects, this is where the whole engagement would break.
    engagement = create_engagement(client)
    client.post(f"/engagements/{engagement['id']}/scan")

    report = client.get(f"/engagements/{engagement['id']}/report")

    assert report.status_code == 200
    assert "PVX-0001" in report.text


def test_health_still_answers(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
