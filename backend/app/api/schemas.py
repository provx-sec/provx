# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Request and response schemas.

Separate models on the way in and the way out (rule B-FA-01): the response models whitelist
what a client may see, so a column added to a table is never accidentally published. Raw
evidence is deliberately absent from the list response - it is bulky and can carry
sensitive material (rule PX-SECRETS).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from provx_sdk.findings import Confidence, FindingStatus, Module, Severity
from pydantic import BaseModel, ConfigDict, Field


class EngagementCreate(BaseModel):
    """Request body for creating an engagement."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    scope_allow: list[str] = Field(min_length=1, description="Allowed hosts, e.g. *.example.com")
    scope_deny: list[str] = Field(default_factory=list)
    targets: list[str] = Field(min_length=1, description="Target URLs to test")
    # Passive is the only accepted value today; Active requires recorded authorization
    # (rule PX-ACTIVE), which this phase does not implement.
    mode: str = Field(default="passive", pattern="^passive$")


class EngagementRead(BaseModel):
    """An engagement as returned to clients."""

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID
    name: str
    scope_allow: list[str]
    scope_deny: list[str]
    mode: str
    targets: list[str]
    created_at: datetime


class ScanRead(BaseModel):
    """The outcome of one scan run."""

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID
    engagement_id: uuid.UUID
    adapter: str
    status: str
    targets_scanned: int
    targets_skipped_out_of_scope: int
    findings_count: int
    started_at: datetime
    finished_at: datetime | None


class FindingRead(BaseModel):
    """A finding as returned to clients."""

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID
    display_id: str
    title: str
    target: str
    module: Module
    severity: Severity
    cvss: float | None
    confidence: Confidence
    status: FindingStatus
    # Whether this finding is included in the client-facing report.
    in_report: bool
    # How many evidence references back this finding: 1 (its primary evidence) plus one per
    # adapter/scan that corroborated it and was collapsed in by dedup.
    evidence_ref_count: int
    attack_techniques: list[str]
    remediation: str | None
    evidence_sha256: str
    captured_at: datetime


class FindingTransitionRequest(BaseModel):
    """Request body to move a finding through its validation lifecycle."""

    model_config = ConfigDict(extra="forbid")

    to_status: FindingStatus
    # No auth yet, so the actor is caller-supplied; RBAC binds it to a principal later.
    actor: str | None = Field(default=None, max_length=200)
    note: str | None = Field(default=None, max_length=2000)


class InReportRequest(BaseModel):
    """Request body to include or exclude a finding from the client-facing report."""

    model_config = ConfigDict(extra="forbid")

    in_report: bool
    actor: str | None = Field(default=None, max_length=200)
    note: str | None = Field(default=None, max_length=2000)


class ErrorResponse(BaseModel):
    """The user-safe error envelope (rules PX-ERRORS, B-FA-06, S-13)."""

    model_config = ConfigDict(extra="forbid")

    error_code: str
    message: str
    # Populated only when APP_ENV is a development environment; never in production.
    detail: str | None = None
