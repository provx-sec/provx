# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Persistence tables for the walking skeleton.

``provx_sdk.Finding`` stays the single source of truth for what a finding *is*; these rows
are how one is stored. ``FindingRow.to_contract`` is the only conversion, so a field added
to the contract has exactly one place to be wired through (audit finding M4).

Evidence rows are insert-only. There is deliberately no update or delete path: a correction
is a new record referencing the prior one (rule PX-EVIDENCE).
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

from provx_sdk.evidence import EvidenceSeal
from provx_sdk.findings import (
    DISPLAY_ID_PATTERN,
    Confidence,
    Evidence,
    Finding,
    FindingDraft,
    FindingStatus,
    Module,
    Severity,
    validate_attack_techniques,
)
from sqlalchemy import DateTime, UniqueConstraint
from sqlmodel import JSON, Column, Field, SQLModel

from app.security.evidence_crypto import decrypt_evidence, encrypt_evidence


def _now() -> datetime:
    return datetime.now(UTC)


def _timestamp_column(nullable: bool = False) -> Column[datetime]:
    """A timezone-aware timestamp column.

    Explicit because the default maps to TIMESTAMP WITHOUT TIME ZONE, which PostgreSQL
    rejects for the aware datetimes recorded here - and an audit trail with ambiguous
    local times is not an audit trail (rule PX-EVIDENCE).
    """
    return Column(DateTime(timezone=True), nullable=nullable)


class Engagement(SQLModel, table=True):
    """One authorized piece of work: a client, a scope, and the targets inside it."""

    __tablename__ = "engagement"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str = Field(index=True)
    # Engagement scope as allow/deny host rules, enforced before any target is reached
    # (rule PX-SCOPE).
    scope_allow: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    scope_deny: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    # "passive" only today; Active mode requires recorded authorization (rule PX-ACTIVE).
    mode: str = Field(default="passive")
    created_at: datetime = Field(default_factory=_now, sa_column=_timestamp_column())


class Target(SQLModel, table=True):
    """A single URL belonging to an engagement."""

    __tablename__ = "target"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    engagement_id: uuid.UUID = Field(foreign_key="engagement.id", index=True)
    url: str
    created_at: datetime = Field(default_factory=_now, sa_column=_timestamp_column())


class Scan(SQLModel, table=True):
    """One execution of one adapter against an engagement's targets."""

    __tablename__ = "scan"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    engagement_id: uuid.UUID = Field(foreign_key="engagement.id", index=True)
    adapter: str
    status: str = Field(default="completed")
    targets_scanned: int = Field(default=0)
    targets_skipped_out_of_scope: int = Field(default=0)
    started_at: datetime = Field(default_factory=_now, sa_column=_timestamp_column())
    finished_at: datetime | None = Field(default=None, sa_column=_timestamp_column(nullable=True))


class FindingRow(SQLModel, table=True):
    """A stored finding. Mirrors the SDK contract plus its evidence seal and provenance."""

    __tablename__ = "finding"
    # Declared on the model, not only in the migration. Without it here, a schema built from
    # this metadata (every test) lacks the constraint that production relies on to catch a
    # display_id collision - and `alembic revision --autogenerate` would emit a DROP for it.
    __table_args__ = (
        UniqueConstraint("engagement_id", "display_id", name="uq_finding_engagement_display_id"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    engagement_id: uuid.UUID = Field(foreign_key="engagement.id", index=True)
    scan_id: uuid.UUID = Field(foreign_key="scan.id", index=True)
    # Human-facing label, numbered per engagement (PVX-0001) and unique within it.
    display_id: str = Field(index=True)
    title: str
    target: str
    module: Module
    severity: Severity
    cvss: float | None = Field(default=None)
    epss: float | None = Field(default=None)
    confidence: Confidence = Field(default=Confidence.MEDIUM)
    status: FindingStatus = Field(default=FindingStatus.NEW)
    attack_techniques: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    remediation: str | None = Field(default=None)
    evidence_tool_output: str | None = Field(default=None)
    evidence_matched_rule: str | None = Field(default=None)
    evidence_reproduction_cmd: str | None = Field(default=None)
    # Integrity stamp taken at capture time, over the raw artifact (rule PX-EVIDENCE).
    evidence_sha256: str
    captured_at: datetime = Field(sa_column=_timestamp_column())

    @classmethod
    def from_draft(
        cls,
        draft: FindingDraft,
        *,
        engagement_id: uuid.UUID,
        scan_id: uuid.UUID,
        display_id: str,
        stamp: EvidenceSeal,
    ) -> FindingRow:
        """Build a row from a draft, validating the contract on the way in.

        SQLModel skips Pydantic validation on ``table=True`` classes, so without this the
        only enforcement would be ``to_contract`` at read time - a bad row would write
        cleanly and then break every subsequent read of its engagement. Validating here
        fails where the caller can still do something about it.
        """
        if not re.match(DISPLAY_ID_PATTERN, display_id):
            raise ValueError(f"invalid display_id {display_id!r}; expected e.g. 'PVX-0001'")
        evidence = draft.evidence
        return cls(
            engagement_id=engagement_id,
            scan_id=scan_id,
            display_id=display_id,
            title=draft.title,
            target=draft.target,
            module=draft.module,
            severity=draft.severity,
            cvss=draft.cvss,
            confidence=draft.confidence,
            attack_techniques=validate_attack_techniques(list(draft.attack_techniques)),
            remediation=draft.remediation,
            evidence_tool_output=(
                encrypt_evidence(evidence.tool_output)
                if evidence and evidence.tool_output is not None
                else None
            ),
            evidence_matched_rule=evidence.matched_rule if evidence else None,
            evidence_reproduction_cmd=evidence.reproduction_cmd if evidence else None,
            evidence_sha256=stamp.sha256,
            captured_at=stamp.captured_at,
        )

    def to_contract(self) -> Finding:
        """Rebuild the canonical SDK Finding this row stores."""
        return Finding(
            id=self.id,
            display_id=self.display_id,
            title=self.title,
            target=self.target,
            module=self.module,
            severity=self.severity,
            cvss=self.cvss,
            epss=self.epss,
            confidence=self.confidence,
            status=self.status,
            attack_techniques=list(self.attack_techniques),
            remediation=self.remediation,
            evidence=Evidence(
                tool_output=(
                    decrypt_evidence(self.evidence_tool_output)
                    if self.evidence_tool_output is not None
                    else None
                ),
                matched_rule=self.evidence_matched_rule,
                reproduction_cmd=self.evidence_reproduction_cmd,
            ),
        )
