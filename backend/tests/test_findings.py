# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""Unit tests for the deterministic Finding data model and governance models."""

from __future__ import annotations

import uuid
from datetime import date, datetime

import pytest
from provx_sdk.findings import (
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    Module,
    RiskAcceptance,
    Severity,
)
from pydantic import ValidationError

from app.services.retest import retest


def _finding(**overrides: object) -> Finding:
    base: dict[str, object] = {
        "display_id": "PVX-0001",
        "title": "Missing security headers",
        "target": "https://example.test",
        "module": Module.WEB,
        "severity": Severity.MEDIUM,
    }
    base.update(overrides)
    return Finding(**base)  # type: ignore[arg-type]


def test_finding_defaults() -> None:
    f = _finding()
    assert isinstance(f.id, uuid.UUID)  # auto-generated UUID primary key
    assert f.display_id == "PVX-0001"  # per-engagement human label
    assert f.status is FindingStatus.NEW
    assert f.confidence is Confidence.MEDIUM
    assert f.cvss is None
    assert f.epss is None
    assert f.attack_techniques == []
    assert f.evidence is None


def test_finding_id_is_unique_per_instance() -> None:
    assert _finding().id != _finding().id


def test_display_id_is_required() -> None:
    with pytest.raises(ValidationError):
        Finding(  # type: ignore[call-arg]
            title="x", target="y", module=Module.WEB, severity=Severity.LOW
        )


def test_finding_full_record() -> None:
    f = _finding(
        cvss=5.5,
        epss=0.42,
        confidence=Confidence.HIGH,
        status=FindingStatus.VALIDATED,
        attack_techniques=["T1190"],
        evidence=Evidence(tool_output="server: nginx", matched_rule="headers"),
        remediation="Set the missing headers.",
    )
    assert f.cvss == 5.5
    assert f.epss == 0.42
    assert f.attack_techniques == ["T1190"]
    assert f.evidence is not None and f.evidence.tool_output == "server: nginx"


def test_cvss_out_of_range_rejected() -> None:
    with pytest.raises(ValidationError):
        _finding(cvss=11.0)


def test_epss_out_of_range_rejected() -> None:
    with pytest.raises(ValidationError):
        _finding(epss=1.5)


def test_invalid_enum_rejected() -> None:
    with pytest.raises(ValidationError):
        _finding(severity="apocalyptic")


def test_display_id_format_enforced() -> None:
    with pytest.raises(ValidationError):
        _finding(display_id="BAD-1")


def test_invalid_attack_technique_rejected() -> None:
    with pytest.raises(ValidationError):
        _finding(attack_techniques=["nope"])


def test_risk_acceptance_requires_fields() -> None:
    ra = RiskAcceptance(
        finding_id="PVX-0001",
        owner="secteam",
        reason="Compensating control in place",
        expires_on=date(2026, 12, 31),
        created_at=datetime(2026, 7, 19, 12, 0, 0),
    )
    assert ra.finding_id == "PVX-0001"
    with pytest.raises(ValidationError):
        RiskAcceptance(finding_id="PVX-0001", owner="secteam")  # type: ignore[call-arg]


def test_retest_is_documented_stub() -> None:
    with pytest.raises(NotImplementedError):
        retest("PVX-0001")
