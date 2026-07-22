# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""Report rendering tests - escaping (rule S-06) and the PX-HUMAN banner."""

from __future__ import annotations

from provx_sdk.findings import Confidence, Finding, Module, Severity

from app.services.report import render_report
from tests.conftest import EngagementFactory


def make_finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "display_id": "PVX-0001",
        "title": "Missing Content-Security-Policy header",
        "target": "https://app.example.com",
        "module": Module.WEB,
        "severity": Severity.LOW,
        "cvss": 3.1,
        "confidence": Confidence.HIGH,
        "attack_techniques": ["T1595"],
        "remediation": "Set a Content-Security-Policy header.",
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def test_report_carries_the_unvalidated_banner(make_engagement: EngagementFactory) -> None:
    html = render_report(make_engagement(), [make_finding()])

    assert "Machine-found, unvalidated" in html
    assert "not</strong> been confirmed by a human" in html


def test_report_renders_the_finding_columns(make_engagement: EngagementFactory) -> None:
    html = render_report(make_engagement(), [make_finding()])

    assert "PVX-0001" in html
    assert "Missing Content-Security-Policy header" in html
    assert "https://app.example.com" in html
    assert "low" in html
    assert "3.1" in html
    assert "T1595" in html
    assert "Set a Content-Security-Policy header." in html


def test_hostile_scan_output_is_escaped_not_executed(make_engagement: EngagementFactory) -> None:
    html = render_report(
        make_engagement(name="<script>alert('engagement')</script>"),
        [make_finding(title="<img src=x onerror=alert(1)>")],
    )

    assert "<script>alert('engagement')</script>" not in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_empty_engagement_renders_without_a_table(make_engagement: EngagementFactory) -> None:
    html = render_report(make_engagement(), [])

    assert "No findings have been human-validated yet." in html
    assert "No unvalidated findings are currently in-report." in html
    assert "Machine-found, unvalidated" in html


def test_report_reports_the_finding_count(make_engagement: EngagementFactory) -> None:
    html = render_report(
        make_engagement(),
        [make_finding(), make_finding(display_id="PVX-0002", title="Missing X-Frame-Options")],
    )

    # Both default to NEW, so they sit in the machine-found section.
    assert "Machine-found, unvalidated (2)" in html
    assert "Human-validated findings (0)" in html


def test_validated_finding_is_separated_from_machine_found(
    make_engagement: EngagementFactory,
) -> None:
    from provx_sdk.findings import FindingStatus

    html = render_report(
        make_engagement(),
        [
            make_finding(status=FindingStatus.VALIDATED),
            make_finding(display_id="PVX-0002", title="Missing X-Frame-Options"),
        ],
    )

    assert "Human-validated findings (1)" in html
    assert "Machine-found, unvalidated (1)" in html


def test_missing_cvss_renders_a_placeholder_rather_than_none(
    make_engagement: EngagementFactory,
) -> None:
    html = render_report(make_engagement(), [make_finding(cvss=None, attack_techniques=[])])

    assert "<td>-</td>" in html
    assert "None" not in html
