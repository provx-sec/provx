# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""Report rendering tests - section structure, deterministic ordering, PX-HUMAN separation,
report-membership filtering, evidence-reference safety (PX-SECRETS/PX-EVIDENCE), branding,
and escaping (rule S-06)."""

from __future__ import annotations

from provx_sdk.findings import (
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    Module,
    Severity,
)

from app.config import Settings
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


def test_report_carries_every_documented_section(make_engagement: EngagementFactory) -> None:
    html = render_report(make_engagement(), [make_finding()])

    for heading in (
        "1. Executive summary",
        "2. Scope &amp; rules of engagement",
        "3. Methodology",
        "4. Findings summary",
        "5. Detailed findings",
        "6. MITRE ATT&amp;CK coverage",
        "7. Remediation roadmap",
    ):
        assert heading in html, f"missing section: {heading}"


def test_findings_are_ordered_worst_severity_first(make_engagement: EngagementFactory) -> None:
    html = render_report(
        make_engagement(),
        [
            make_finding(display_id="PVX-0001", severity=Severity.LOW, title="Low finding"),
            make_finding(display_id="PVX-0002", severity=Severity.CRITICAL, title="Crit finding"),
            make_finding(display_id="PVX-0003", severity=Severity.MEDIUM, title="Med finding"),
        ],
    )

    # The summary table is the first place each id appears, and it is globally sorted.
    assert html.index("PVX-0002") < html.index("PVX-0003") < html.index("PVX-0001")


def test_executive_summary_reports_posture_and_counts(make_engagement: EngagementFactory) -> None:
    html = render_report(
        make_engagement(),
        [
            make_finding(display_id="PVX-0001", severity=Severity.HIGH),
            make_finding(display_id="PVX-0002", severity=Severity.LOW),
        ],
    )

    assert "Overall risk posture: <strong>High</strong>" in html


def test_false_positive_is_excluded_from_the_report(make_engagement: EngagementFactory) -> None:
    html = render_report(
        make_engagement(),
        [
            make_finding(display_id="PVX-0001", title="Genuine finding"),
            make_finding(
                display_id="PVX-0002",
                title="Marked false positive",
                status=FindingStatus.FALSE_POSITIVE,
            ),
        ],
    )

    assert "Genuine finding" in html
    assert "Marked false positive" not in html
    assert "PVX-0002" not in html


def test_finding_excluded_from_report_is_not_rendered(
    make_engagement: EngagementFactory,
) -> None:
    html = render_report(
        make_engagement(),
        [
            make_finding(display_id="PVX-0001", title="Kept in report"),
            make_finding(display_id="PVX-0002", title="Human-excluded", in_report=False),
        ],
    )

    assert "Kept in report" in html
    assert "Human-excluded" not in html


def test_evidence_reference_is_shown_but_raw_evidence_never_leaks(
    make_engagement: EngagementFactory,
) -> None:
    # PX-SECRETS/PX-EVIDENCE: the report shows the sealed reference, never the raw body.
    secret = "SUPER-SECRET-SESSION-TOKEN-abc123"
    html = render_report(
        make_engagement(),
        [
            make_finding(
                evidence_sha256="a" * 64,
                evidence=Evidence(tool_output=f"Set-Cookie: session={secret}"),
            )
        ],
    )

    assert secret not in html
    assert "a" * 64 in html


def test_branding_and_classification_are_rendered_from_config(
    make_engagement: EngagementFactory,
) -> None:
    settings = Settings(
        report_classification="SECRET//TEST",
        report_tester_org="Acme Security",
        report_tester_name="Jane Tester",
    )
    html = render_report(
        make_engagement(name="Globex Corp"),
        [make_finding()],
        settings=settings,
    )

    assert "SECRET//TEST" in html
    assert "Acme Security" in html
    assert "Jane Tester" in html
    assert "Globex Corp" in html  # client name comes from the engagement


def test_default_classification_marks_the_report_confidential(
    make_engagement: EngagementFactory,
) -> None:
    html = render_report(make_engagement(), [make_finding()])

    assert "CONFIDENTIAL" in html
