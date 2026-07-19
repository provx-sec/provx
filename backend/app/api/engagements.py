# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Engagement routes: create, scan, list findings, render the report.

No authentication yet - this is the walking skeleton, and RBAC is a later phase. Every
route declares an explicit response model and status code (rule B-FA-07), and errors leave
here as a stable code plus a generic message (rule PX-ERRORS).
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.api.schemas import EngagementCreate, EngagementRead, FindingRead, ScanRead
from app.db import get_session
from app.models.tables import Engagement, FindingRow, Target
from app.services.report import render_report
from app.services.safety import SCAN_NOT_PERMITTED, ScanNotPermittedError
from app.services.scan_runner import run_scan

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/engagements", tags=["engagements"])

ENGAGEMENT_NOT_FOUND = "engagement_not_found"


async def _get_engagement(session: AsyncSession, engagement_id: uuid.UUID) -> Engagement:
    engagement = await session.get(Engagement, engagement_id)
    if engagement is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_code": ENGAGEMENT_NOT_FOUND, "message": "Engagement not found."},
        )
    return engagement


async def _findings(session: AsyncSession, engagement_id: uuid.UUID) -> list[FindingRow]:
    return list(
        (
            await session.exec(
                select(FindingRow)
                .where(FindingRow.engagement_id == engagement_id)
                .order_by(FindingRow.display_id)
            )
        ).all()
    )


def _to_read(row: FindingRow) -> FindingRead:
    """Project a stored finding onto the public response shape.

    Written out field by field on purpose: a column added to the table stays unpublished
    until someone deliberately adds it here (rule B-FA-01).
    """
    return FindingRead(
        id=row.id,
        display_id=row.display_id,
        title=row.title,
        target=row.target,
        module=row.module,
        severity=row.severity,
        cvss=row.cvss,
        confidence=row.confidence,
        status=row.status,
        attack_techniques=list(row.attack_techniques),
        remediation=row.remediation,
        evidence_sha256=row.evidence_sha256,
        captured_at=row.captured_at,
    )


@router.post("", response_model=EngagementRead, status_code=status.HTTP_201_CREATED)
async def create_engagement(
    payload: EngagementCreate, session: AsyncSession = Depends(get_session)
) -> EngagementRead:
    """Create an engagement with its scope and targets.

    Targets are stored as supplied; nothing is reached until a scan runs, and the scope gate
    is applied then (rule PX-SCOPE).
    """
    engagement = Engagement(
        name=payload.name,
        scope_allow=payload.scope_allow,
        scope_deny=payload.scope_deny,
        mode=payload.mode,
    )
    session.add(engagement)
    await session.flush()
    session.add_all(Target(engagement_id=engagement.id, url=url) for url in payload.targets)
    await session.commit()
    await session.refresh(engagement)

    return EngagementRead(
        id=engagement.id,
        name=engagement.name,
        scope_allow=list(engagement.scope_allow),
        scope_deny=list(engagement.scope_deny),
        mode=engagement.mode,
        targets=list(payload.targets),
        created_at=engagement.created_at,
    )


@router.post("/{engagement_id}/scan", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
async def scan_engagement(
    engagement_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> ScanRead:
    """Run the passive web-baseline adapter across the engagement's in-scope targets."""
    engagement = await _get_engagement(session, engagement_id)
    try:
        scan = await run_scan(session, engagement)
    except ScanNotPermittedError as exc:
        # The operator-facing reason goes to the log; the client gets a stable code and a
        # generic message, with no detail about which control refused (rule PX-ERRORS).
        logger.warning(
            "refusing scan", extra={"engagement_id": str(engagement_id), "reason": exc.reason}
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error_code": SCAN_NOT_PERMITTED,
                "message": "This scan is not permitted by the current safety settings.",
            },
        ) from exc
    findings = await _findings(session, engagement_id)

    return ScanRead(
        id=scan.id,
        engagement_id=scan.engagement_id,
        adapter=scan.adapter,
        status=scan.status,
        targets_scanned=scan.targets_scanned,
        targets_skipped_out_of_scope=scan.targets_skipped_out_of_scope,
        findings_count=len(findings),
        started_at=scan.started_at,
        finished_at=scan.finished_at,
    )


@router.get("/{engagement_id}/findings", response_model=list[FindingRead])
async def list_findings(
    engagement_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> list[FindingRead]:
    """List an engagement's deduplicated findings, ordered by display id."""
    await _get_engagement(session, engagement_id)
    return [_to_read(row) for row in await _findings(session, engagement_id)]


@router.get("/{engagement_id}/report", response_class=HTMLResponse)
async def engagement_report(
    engagement_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    """Render the engagement's HTML findings report."""
    engagement = await _get_engagement(session, engagement_id)
    rows = await _findings(session, engagement_id)
    html = render_report(engagement, [row.to_contract() for row in rows])
    return HTMLResponse(content=html)
