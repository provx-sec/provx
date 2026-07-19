# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Finding data model and the governance models around it (risk acceptance).

This is the canonical, shared contract for the whole platform: adapters normalize tool
output into these types, the backend reads them, and reports render them. It lives in the
SDK (not the backend) so tool adapters can depend on it without depending on the API.

This is the deterministic, auditable core of the findings pipeline. Prioritization is a
transparent formula (severity + CVSS + EPSS + asset criticality), never "ask the AI what's
important". **AI is an optional advisor layered on later and is absent from these
paths** - every value here is produced deterministically.

Scaffolding status: these are Pydantic model stubs only. There is no database, no
persistence, and no pipeline logic yet (dedup/enrichment/storage come later). Imports are
deliberately limited to Pydantic + stdlib so the models stay dependency-light.
"""

from __future__ import annotations

import re
import uuid
from datetime import date, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Four digits is the zero-padded MINIMUM, not a cap: an engagement that produces more than
# 9999 findings keeps counting (PVX-10000) rather than emitting a label the contract would
# reject. A scanner legitimately exceeding four digits must not be able to write a finding
# that later fails to load.
DISPLAY_ID_PATTERN = r"^PVX-\d{4,}$"
ATTACK_TECHNIQUE_PATTERN = r"^T\d{4}(\.\d{3})?$"


def validate_attack_techniques(techniques: list[str]) -> list[str]:
    """Reject any value that is not a MITRE ATT&CK technique id.

    Shared by every model that carries techniques so the rule is enforced identically at
    each boundary, rather than only where a finding is finally assembled (rule PX-ATTACK).
    """
    for technique in techniques:
        if not re.match(ATTACK_TECHNIQUE_PATTERN, technique):
            raise ValueError(
                f"invalid MITRE ATT&CK technique id {technique!r}; "
                "expected e.g. 'T1190' or 'T1190.001'"
            )
    return techniques


class Severity(StrEnum):
    """Finding severity band."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    """How sure the deterministic engine is. Low-confidence findings can be filtered so
    noise is opt-in (see docs/VALIDATION_and_REFERENCE_SYSTEMS.md §1)."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Module(StrEnum):
    """Which test module produced the finding."""

    WEB = "web"
    API = "api"
    INFRA = "infra"


class FindingStatus(StrEnum):
    """The human-in-the-loop validation lifecycle. The machine proposes; a human confirms
    (see docs/VALIDATION_and_REFERENCE_SYSTEMS.md §1)."""

    NEW = "new"
    TRIAGED = "triaged"
    VALIDATED = "validated"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"
    REGRESSION = "regression"


class Evidence(BaseModel):
    """Evidence-first record so a reviewer can confirm a finding in seconds. All fields are
    optional; an adapter fills in what it captured."""

    model_config = ConfigDict(extra="forbid")

    raw_request: str | None = None
    raw_response: str | None = None
    tool_output: str | None = None
    matched_rule: str | None = None
    reproduction_cmd: str | None = None
    screenshot_path: str | None = None


class Finding(BaseModel):
    """A single normalized finding.

    Two identifiers, deliberately separate:

    * ``id`` - a UUID, the stable database primary key. Globally unique, never reused.
    * ``display_id`` - the human-facing label shown in the UI and reports (e.g.
      ``PVX-0001``). It is numbered **per engagement**, zero-padded to at least 4 digits and
      widening beyond that if an engagement exceeds 9999 findings, and resets for each
      engagement - so two engagements can both have a ``PVX-0001``. The per-engagement
      sequence is assigned when the finding is persisted, not globally.

    CVSS is on a 0-10 scale; EPSS is an optional 0-1 probability of real-world exploitation
    used for deterministic prioritization.
    """

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    display_id: str = Field(pattern=DISPLAY_ID_PATTERN)
    title: str
    target: str
    module: Module
    severity: Severity
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    epss: float | None = Field(default=None, ge=0.0, le=1.0)
    confidence: Confidence = Confidence.MEDIUM
    status: FindingStatus = FindingStatus.NEW
    # MITRE ATT&CK technique IDs (e.g. "T1190"). Stored as plain strings; "MITRE ATT&CK" is
    # only ever a display label, never an identifier. Named `attack_techniques` because
    # `att&ck` is not a valid identifier. At least one is expected once a finding is final.
    attack_techniques: list[str] = Field(default_factory=list)
    evidence: Evidence | None = None
    remediation: str | None = None

    @field_validator("attack_techniques")
    @classmethod
    def _valid_attack_techniques(cls, techniques: list[str]) -> list[str]:
        return validate_attack_techniques(techniques)


class FindingDraft(BaseModel):
    """A normalized finding before the pipeline has given it an identity.

    An adapter cannot know a finding's ``display_id``: that sequence is per-engagement and
    is allocated when the finding is persisted. Adapters therefore emit drafts, and the
    pipeline calls :meth:`to_finding` once it knows the number.
    """

    model_config = ConfigDict(extra="forbid")

    title: str
    target: str
    module: Module
    severity: Severity
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    confidence: Confidence = Confidence.MEDIUM
    attack_techniques: list[str] = Field(default_factory=list)
    evidence: Evidence | None = None
    remediation: str | None = None

    @field_validator("attack_techniques")
    @classmethod
    def _valid_attack_techniques(cls, techniques: list[str]) -> list[str]:
        return validate_attack_techniques(techniques)

    @property
    def dedup_key(self) -> tuple[str, str]:
        """Deterministic identity used to collapse repeats of the same issue (PX-ATTACK)."""
        return (self.target, self.title)

    def to_finding(self, display_id: str) -> Finding:
        """Promote this draft into a full Finding under the given per-engagement label."""
        return Finding(display_id=display_id, **self.model_dump())


class RiskAcceptance(BaseModel):
    """Sign-off that a finding's risk is accepted, with an owner, a reason, and an
    expiration - a permanent audit-trail record (DefectDojo-style governance)."""

    model_config = ConfigDict(extra="forbid")

    # References a Finding. Kept as a string for now; the pipeline decides whether it holds
    # the UUID `Finding.id` or the human `display_id` when the DB layer lands.
    finding_id: str
    owner: str
    reason: str
    expires_on: date
    created_at: datetime
