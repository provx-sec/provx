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
from provx_sdk.auth import InvalidCredentialError
from provx_sdk.findings import FindingStatus
from sqlalchemy import func
from sqlmodel import col, select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.api.schemas import (
    CredentialCreate,
    CredentialRead,
    EngagementCreate,
    EngagementRead,
    FindingRead,
    FindingTransitionRequest,
    InReportRequest,
    ScanRead,
    ScanRequest,
)
from app.db import get_session
from app.models.tables import (
    Credential,
    Engagement,
    FindingEventRow,
    FindingEvidenceRow,
    FindingRow,
    Target,
)
from app.services.credentials import get_credential, load_auth
from app.services.lifecycle import IllegalTransitionError, assert_transition
from app.services.report import render_report
from app.services.safety import SCAN_NOT_PERMITTED, ScanNotPermittedError
from app.services.scan_runner import run_scan

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/engagements", tags=["engagements"])

ENGAGEMENT_NOT_FOUND = "engagement_not_found"
FINDING_NOT_FOUND = "finding_not_found"
ILLEGAL_TRANSITION = "illegal_transition"
CREDENTIAL_NOT_FOUND = "credential_not_found"
INVALID_CREDENTIAL = "invalid_credential"
NO_CREDENTIAL = "no_credential"


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


async def _get_finding(
    session: AsyncSession, engagement_id: uuid.UUID, finding_id: uuid.UUID
) -> FindingRow:
    """Load a finding, scoped to its engagement so a mismatched pair is a 404, not a leak."""
    finding = await session.get(FindingRow, finding_id)
    if finding is None or finding.engagement_id != engagement_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_code": FINDING_NOT_FOUND, "message": "Finding not found."},
        )
    return finding


async def _appended_evidence_counts(
    session: AsyncSession, engagement_id: uuid.UUID
) -> dict[uuid.UUID, int]:
    """How many *appended* evidence rows each finding has (dedup collapses beyond the first).
    One grouped query rather than one per finding."""
    rows = (
        await session.exec(
            select(FindingEvidenceRow.finding_id, func.count())
            .join(FindingRow, col(FindingRow.id) == col(FindingEvidenceRow.finding_id))
            .where(FindingRow.engagement_id == engagement_id)
            .group_by(col(FindingEvidenceRow.finding_id))
        )
    ).all()
    return {finding_id: count for finding_id, count in rows}


def _to_read(row: FindingRow, appended_evidence: int) -> FindingRead:
    """Project a stored finding onto the public response shape.

    Written out field by field on purpose: a column added to the table stays unpublished
    until someone deliberately adds it here (rule B-FA-01). ``evidence_ref_count`` is the
    primary evidence (always 1) plus any appended by dedup.
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
        in_report=row.in_report,
        evidence_ref_count=1 + appended_evidence,
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
    engagement_id: uuid.UUID,
    payload: ScanRequest | None = None,
    session: AsyncSession = Depends(get_session),
) -> ScanRead:
    """Run the passive web-baseline adapter across the engagement's in-scope targets.

    With ``authenticated: true`` the engagement's stored credential is presented at the egress
    boundary (rule PX-SECRETS); it attaches only to in-scope hops (rule PX-SCOPE). No body, or
    ``authenticated: false``, runs an anonymous scan.
    """
    engagement = await _get_engagement(session, engagement_id)

    auth = None
    if payload is not None and payload.authenticated:
        auth = await load_auth(session, engagement_id)
        if auth is None:
            # A generic, stable message; the operator sees which engagement in the server log only.
            logger.warning(
                "authenticated scan requested with no credential",
                extra={"engagement_id": str(engagement_id)},
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error_code": NO_CREDENTIAL,
                    "message": "No credential is configured for this engagement.",
                },
            )
    try:
        scan = await run_scan(session, engagement, auth=auth)
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


def _credential_to_read(row: Credential) -> CredentialRead:
    """Project a stored credential onto its public shape - metadata only, never the value."""
    return CredentialRead(
        id=row.id,
        engagement_id=row.engagement_id,
        cred_type=row.cred_type,
        header_name=row.header_name,
        label=row.label,
        created_at=row.created_at,
    )


@router.post(
    "/{engagement_id}/credential",
    response_model=CredentialRead,
    status_code=status.HTTP_201_CREATED,
)
async def set_engagement_credential(
    engagement_id: uuid.UUID,
    payload: CredentialCreate,
    session: AsyncSession = Depends(get_session),
) -> CredentialRead:
    """Store (or replace) the engagement's authenticated-scanning credential.

    Write-only: the value is encrypted at the model seam and never returned (rule PX-SECRETS).
    One credential per engagement, so an existing one is replaced. The request body is never
    logged.
    """
    await _get_engagement(session, engagement_id)
    try:
        credential = Credential.from_input(
            engagement_id=engagement_id,
            cred_type=payload.cred_type,
            value=payload.value,
            header_name=payload.header_name,
            label=payload.label,
        )
    except InvalidCredentialError as exc:
        # The reason may name the credential kind but never the value; still, give the client a
        # generic message and a stable code (rule PX-ERRORS).
        logger.warning("rejecting invalid credential", extra={"engagement_id": str(engagement_id)})
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_code": INVALID_CREDENTIAL,
                "message": "The credential could not be stored; check its type and fields.",
            },
        ) from exc

    existing = await get_credential(session, engagement_id)
    if existing is not None:
        await session.delete(existing)
        await session.flush()
    session.add(credential)
    await session.commit()
    await session.refresh(credential)
    logger.info("stored engagement credential", extra={"engagement_id": str(engagement_id)})
    return _credential_to_read(credential)


@router.get("/{engagement_id}/credential", response_model=CredentialRead)
async def get_engagement_credential(
    engagement_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> CredentialRead:
    """Return the engagement's credential metadata - never its value (rule PX-SECRETS)."""
    await _get_engagement(session, engagement_id)
    credential = await get_credential(session, engagement_id)
    if credential is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_code": CREDENTIAL_NOT_FOUND, "message": "No credential is configured."},
        )
    return _credential_to_read(credential)


@router.delete("/{engagement_id}/credential", status_code=status.HTTP_204_NO_CONTENT)
async def delete_engagement_credential(
    engagement_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> None:
    """Remove the engagement's credential, so later scans run anonymously."""
    await _get_engagement(session, engagement_id)
    credential = await get_credential(session, engagement_id)
    if credential is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_code": CREDENTIAL_NOT_FOUND, "message": "No credential is configured."},
        )
    await session.delete(credential)
    await session.commit()
    logger.info("deleted engagement credential", extra={"engagement_id": str(engagement_id)})


@router.get("/{engagement_id}/findings", response_model=list[FindingRead])
async def list_findings(
    engagement_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> list[FindingRead]:
    """List an engagement's deduplicated findings, ordered by display id."""
    await _get_engagement(session, engagement_id)
    counts = await _appended_evidence_counts(session, engagement_id)
    return [_to_read(row, counts.get(row.id, 0)) for row in await _findings(session, engagement_id)]


@router.post(
    "/{engagement_id}/findings/{finding_id}/transition",
    response_model=FindingRead,
    status_code=status.HTTP_200_OK,
)
async def transition_finding(
    engagement_id: uuid.UUID,
    finding_id: uuid.UUID,
    payload: FindingTransitionRequest,
    session: AsyncSession = Depends(get_session),
) -> FindingRead:
    """Move a finding through the validation lifecycle.

    Only an explicit call here can reach ``validated`` - the machine never self-confirms
    (rule PX-HUMAN). Illegal edges are refused deterministically, and every transition writes
    an append-only audit row (rule PX-EVIDENCE).
    """
    finding = await _get_finding(session, engagement_id, finding_id)
    current = finding.status
    try:
        assert_transition(current, payload.to_status)
    except IllegalTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_code": ILLEGAL_TRANSITION,
                "message": "This lifecycle transition is not allowed.",
            },
        ) from exc

    session.add(
        FindingEventRow(
            finding_id=finding.id,
            event_type="status_change",
            from_status=current,
            to_status=payload.to_status,
            actor=payload.actor,
            note=payload.note,
        )
    )
    finding.status = payload.to_status
    # Marking a false positive records the intent to seed a regression test later; it also
    # suppresses the finding on re-scan (see scan_runner._persist_scan).
    if payload.to_status == FindingStatus.FALSE_POSITIVE:
        finding.regression_intent = True
    session.add(finding)
    await session.commit()
    await session.refresh(finding)

    counts = await _appended_evidence_counts(session, engagement_id)
    return _to_read(finding, counts.get(finding.id, 0))


@router.post(
    "/{engagement_id}/findings/{finding_id}/in-report",
    response_model=FindingRead,
    status_code=status.HTTP_200_OK,
)
async def set_finding_in_report(
    engagement_id: uuid.UUID,
    finding_id: uuid.UUID,
    payload: InReportRequest,
    session: AsyncSession = Depends(get_session),
) -> FindingRead:
    """Include or exclude a finding from the client-facing report, writing an audit row."""
    finding = await _get_finding(session, engagement_id, finding_id)
    session.add(
        FindingEventRow(
            finding_id=finding.id,
            event_type="in_report_toggle",
            from_status=finding.status,
            in_report=payload.in_report,
            actor=payload.actor,
            note=payload.note,
        )
    )
    finding.in_report = payload.in_report
    session.add(finding)
    await session.commit()
    await session.refresh(finding)

    counts = await _appended_evidence_counts(session, engagement_id)
    return _to_read(finding, counts.get(finding.id, 0))


@router.get("/{engagement_id}/report", response_class=HTMLResponse)
async def engagement_report(
    engagement_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    """Render the engagement's client-ready HTML report.

    Only findings a human has kept in-report are shown, and a false positive is never shown
    even if left in-report (rule PX-HUMAN). That report-membership filter, the machine-found
    vs human-validated split, and severity ordering all live in ``build_report_context``, so
    this route only has to load the findings and hand them over.
    """
    engagement = await _get_engagement(session, engagement_id)
    rows = await _findings(session, engagement_id)
    html = render_report(engagement, [row.to_contract() for row in rows])
    return HTMLResponse(content=html)
