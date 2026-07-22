# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
HTML report rendering: assemble a deterministic, client-ready report context and render it.

Autoescaping is mandatory here: titles and targets come from scan output, which is
attacker-influenced (rule S-06). Every value in the report is produced deterministically -
counts, ordering, risk posture and ATT&CK coverage all come from transparent rules, never a
model (rules PX-DETERMINISM, PX-AI-OPTIONAL). Evidence appears only as its sealed reference
(SHA-256 + capture time), never the raw body (rules PX-SECRETS, PX-EVIDENCE). PDF/Word output
is a later phase; this renders the one client-ready format v0.1 ships: HTML.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from provx_sdk.findings import (
    SEVERITY_ORDER,
    Finding,
    FindingStatus,
    Severity,
    severity_rank,
)

from app.config import Settings, get_settings
from app.models.tables import Engagement
from app.services.report_attack import TACTIC_ORDER, UNMAPPED_TACTIC, tactic_for, technique_name

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
REPORT_TEMPLATE = "report.html.j2"

#: Statuses the deterministic engine can set on its own. Anything else means a human moved
#: the finding forward, so it is presented as validated (rule PX-HUMAN).
_MACHINE_STATUSES: frozenset[FindingStatus] = frozenset({FindingStatus.NEW, FindingStatus.TRIAGED})

#: Remediation priority window per severity. Static and deterministic - a client sees the
#: same SLA guidance for the same severity every time (rule PX-DETERMINISM).
_PRIORITY_WINDOW: dict[Severity, str] = {
    Severity.CRITICAL: "Immediate - remediate within 24-48 hours",
    Severity.HIGH: "Urgent - remediate within 1 week",
    Severity.MEDIUM: "Planned - remediate within 30 days",
    Severity.LOW: "Scheduled - remediate within 90 days",
    Severity.INFO: "Discretionary - address as capacity allows",
}


def _severity_label(severity: Severity) -> str:
    """Title-cased severity for display (e.g. ``critical`` -> ``Critical``)."""
    return severity.value.title()


@dataclass(frozen=True)
class Branding:
    """Report branding and handling marking (config-supplied; client from the engagement)."""

    classification: str
    tester_org: str
    tester_name: str
    tester_contact: str
    client_name: str


@dataclass(frozen=True)
class SeverityCount:
    """One row of the executive-summary severity breakdown."""

    severity: Severity
    label: str
    count: int


@dataclass(frozen=True)
class TechniqueCoverage:
    """A single ATT&CK technique and how many findings map to it."""

    technique: str
    name: str
    count: int


@dataclass(frozen=True)
class TacticCoverage:
    """One ATT&CK tactic with its techniques and total finding count."""

    tactic: str
    count: int
    techniques: list[TechniqueCoverage]


@dataclass(frozen=True)
class RemediationBand:
    """Remediation roadmap grouping: all findings of one severity and their SLA window."""

    severity: Severity
    label: str
    priority_window: str
    findings: list[Finding]


@dataclass(frozen=True)
class ReportContext:
    """Everything the template needs, all computed deterministically in Python."""

    branding: Branding
    generated_at: datetime
    scope_allow: list[str]
    scope_deny: list[str]
    mode: str
    findings: list[Finding]
    machine_findings: list[Finding]
    validated_findings: list[Finding]
    severity_counts: list[SeverityCount]
    total: int
    risk_posture: str
    attack_coverage: list[TacticCoverage]
    remediation_roadmap: list[RemediationBand]


def _report_findings(findings: list[Finding]) -> list[Finding]:
    """Filter to the report-worthy findings and order them deterministically.

    A human-excluded finding and a false positive never appear (rule PX-HUMAN). This is the
    single place that decides report membership, so the route cannot drift from the template.
    Sort by severity (worst first) then display_id, so the ordering is stable and reproducible
    (rule PX-DETERMINISM).
    """
    keep = [f for f in findings if f.in_report and f.status != FindingStatus.FALSE_POSITIVE]
    return sorted(keep, key=lambda f: (-severity_rank(f.severity), f.display_id))


def _risk_posture(findings: list[Finding]) -> str:
    """Overall posture from the worst severity present - a transparent rule, not a judgement."""
    if not findings:
        return "No material risk identified"
    worst = max(findings, key=lambda f: severity_rank(f.severity)).severity
    return {
        Severity.CRITICAL: "Critical",
        Severity.HIGH: "High",
        Severity.MEDIUM: "Elevated",
        Severity.LOW: "Low",
        Severity.INFO: "Informational",
    }[worst]


def _severity_counts(findings: list[Finding]) -> list[SeverityCount]:
    """Finding counts per severity band, in worst-first order (every band shown, even zero)."""
    return [
        SeverityCount(
            severity=sev,
            label=_severity_label(sev),
            count=sum(1 for f in findings if f.severity == sev),
        )
        for sev in SEVERITY_ORDER
    ]


def _attack_coverage(findings: list[Finding]) -> list[TacticCoverage]:
    """Group findings by ATT&CK tactic -> technique -> count, deterministically ordered."""
    # tactic -> technique -> count
    tactic_techniques: dict[str, dict[str, int]] = {}
    for finding in findings:
        for technique in finding.attack_techniques:
            tactic = tactic_for(technique)
            tactic_techniques.setdefault(tactic, {})
            tactic_techniques[tactic][technique] = tactic_techniques[tactic].get(technique, 0) + 1

    ordered_tactics = [t for t in TACTIC_ORDER if t in tactic_techniques]
    if UNMAPPED_TACTIC in tactic_techniques:
        ordered_tactics.append(UNMAPPED_TACTIC)

    coverage: list[TacticCoverage] = []
    for tactic in ordered_tactics:
        techniques = [
            TechniqueCoverage(technique=tech, name=technique_name(tech), count=count)
            for tech, count in sorted(tactic_techniques[tactic].items())
        ]
        coverage.append(
            TacticCoverage(
                tactic=tactic,
                count=sum(t.count for t in techniques),
                techniques=techniques,
            )
        )
    return coverage


def _remediation_roadmap(findings: list[Finding]) -> list[RemediationBand]:
    """Group findings by severity band with their SLA window; only non-empty bands appear."""
    roadmap: list[RemediationBand] = []
    for sev in SEVERITY_ORDER:
        band = [f for f in findings if f.severity == sev]
        if not band:
            continue
        roadmap.append(
            RemediationBand(
                severity=sev,
                label=_severity_label(sev),
                priority_window=_PRIORITY_WINDOW[sev],
                findings=band,
            )
        )
    return roadmap


def build_report_context(
    engagement: Engagement,
    findings: list[Finding],
    *,
    settings: Settings | None = None,
    generated_at: datetime | None = None,
) -> ReportContext:
    """Assemble the deterministic report context from an engagement and its findings."""
    settings = settings or get_settings()
    report_findings = _report_findings(findings)
    machine = [f for f in report_findings if f.status in _MACHINE_STATUSES]
    validated = [f for f in report_findings if f.status not in _MACHINE_STATUSES]

    return ReportContext(
        branding=Branding(
            classification=settings.report_classification,
            tester_org=settings.report_tester_org,
            tester_name=settings.report_tester_name,
            tester_contact=settings.report_tester_contact,
            client_name=engagement.name,
        ),
        generated_at=generated_at or datetime.now(UTC),
        scope_allow=list(engagement.scope_allow),
        scope_deny=list(engagement.scope_deny),
        mode=engagement.mode,
        findings=report_findings,
        machine_findings=machine,
        validated_findings=validated,
        severity_counts=_severity_counts(report_findings),
        total=len(report_findings),
        risk_posture=_risk_posture(report_findings),
        attack_coverage=_attack_coverage(report_findings),
        remediation_roadmap=_remediation_roadmap(report_findings),
    )


@lru_cache(maxsize=1)
def get_environment() -> Environment:
    """Return the Jinja environment used for reports, with autoescaping enabled."""
    return Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(default=True, default_for_string=True),
    )


def render_report(
    engagement: Engagement,
    findings: list[Finding],
    *,
    settings: Settings | None = None,
) -> str:
    """Render an engagement's findings into a standalone, client-ready HTML report."""
    context = build_report_context(engagement, findings, settings=settings)
    template = get_environment().get_template(REPORT_TEMPLATE)
    return template.render(report=context, engagement=engagement)
