# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Scan execution: scope gate, adapter probe, normalize, dedup, persist.

The order here is the safety property. Scope is evaluated *before* the adapter is handed a
target, so an out-of-scope host is never reached - it is counted, logged, and dropped
(rule PX-SCOPE). Evidence is sealed the moment a response comes back, not later
(rule PX-EVIDENCE).

Scans run inline today. The seam for moving them onto a job queue is this module's public
surface: the API awaits :func:`run_scan` and nothing else knows how the work happens.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from provx_sdk.evidence import EvidenceSeal, seal
from provx_sdk.fetch import OutOfScopeRequest
from provx_sdk.findings import FindingDraft, FindingStatus, severity_rank
from provx_sdk.registry import load_adapter
from provx_sdk.scope import ScopePolicy
from sqlalchemy.exc import IntegrityError
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import get_settings
from app.models.tables import Engagement, FindingEvidenceRow, FindingRow, Scan, Target
from app.services.safety import assert_scan_permitted

logger = logging.getLogger(__name__)

DEFAULT_ADAPTER = "security_headers"

#: How many times to renumber and retry when a concurrent scan takes the same labels.
#: Small on purpose - a persistent collision means something worse than contention.
MAX_PERSIST_ATTEMPTS = 3

PERSIST_FAILED = "scan_persist_failed"


class ScanPersistError(RuntimeError):
    """Raised when finding ids could not be allocated despite retrying."""


def display_id_for(sequence: int) -> str:
    """Format a 1-based per-engagement finding label (PVX-0001, PVX-0002, ...)."""
    return f"PVX-{sequence:04d}"


async def run_scan(
    session: AsyncSession, engagement: Engagement, adapter_name: str = DEFAULT_ADAPTER
) -> Scan:
    """Run one adapter across an engagement's in-scope targets and persist the results.

    Returns the completed Scan record. Findings are written in the same transaction as the
    scan itself, so a partial scan never leaves orphaned findings behind (rule B-FA-04).
    """
    adapter = load_adapter(adapter_name)
    settings = get_settings()
    # Before anything is reached: the recorded safety controls must actually permit this.
    assert_scan_permitted(settings, engagement, adapter)

    policy = ScopePolicy(allow=engagement.scope_allow, deny=engagement.scope_deny)
    timeout = settings.http_timeout

    targets = (
        await session.exec(select(Target).where(Target.engagement_id == engagement.id))
    ).all()

    scanned = 0
    skipped = 0
    captured: list[tuple[FindingDraft, EvidenceSeal]] = []

    for target in targets:
        if not policy.is_in_scope(target.url):
            skipped += 1
            logger.warning(
                "skipping out-of-scope target",
                extra={"engagement_id": str(engagement.id), "target": target.url},
            )
            continue

        try:
            raw = await adapter.probe(target.url, policy=policy, timeout=timeout)
        except OutOfScopeRequest:
            # Belt and braces: the pre-flight above should already have skipped this. If a
            # future caller bypasses it, the fetch boundary still refuses, and a refusal is
            # a skip - never a 500.
            skipped += 1
            logger.warning(
                "adapter refused an out-of-scope target",
                extra={"engagement_id": str(engagement.id), "target": target.url},
            )
            continue

        stamp = seal(raw)
        scanned += 1
        captured.extend((draft, stamp) for draft in adapter.parse_output(raw))

    return await _persist_scan(session, engagement, adapter_name, captured, scanned, skipped)


async def _persist_scan(
    session: AsyncSession,
    engagement: Engagement,
    adapter_name: str,
    captured: list[tuple[FindingDraft, EvidenceSeal]],
    scanned: int,
    skipped: int,
) -> Scan:
    """Write the scan, collapsing repeats of the same issue onto one finding.

    A draft whose dedup key already exists does **not** create a second finding and its
    evidence is **not** dropped: it is appended to the existing finding as a
    ``FindingEvidenceRow``, so a finding two adapters reported keeps both evidences (rules
    PX-DETERMINISM, PX-EVIDENCE). The collapsed finding keeps the worst severity/CVSS of the
    set, chosen with ``max`` so the result is independent of scan order. A finding a human has
    marked ``false_positive`` is left untouched - re-scanning it neither duplicates nor
    resurrects it (the suppression in docs/VALIDATION_and_REFERENCE_SYSTEMS.md §5).

    Allocation is a read-then-write, so two concurrent scans on one engagement can compute the
    same ``PVX-NNNN``. The unique constraint on ``(engagement_id, display_id)`` catches it; this
    recovers by re-reading and renumbering rather than failing the whole scan.

    Only persistence is retried. The probe phase is deliberately outside this loop: re-running
    it would re-fetch the targets and re-seal the evidence, and an evidence timestamp must
    record when the artifact was actually captured (rule PX-EVIDENCE).
    """
    # Read once, up front: a rollback expires the ORM object, and touching an expired
    # attribute afterwards triggers lazy IO outside the async context.
    engagement_id = engagement.id

    for attempt in range(1, MAX_PERSIST_ATTEMPTS + 1):
        scan = Scan(engagement_id=engagement_id, adapter=adapter_name)
        session.add(scan)
        await session.flush()

        # Keyed by dedup identity, and updated in place as this run creates findings, so a
        # second draft with the same key collapses onto the first rather than duplicating it.
        by_key = await _existing_findings_by_key(session, engagement_id)
        allocated = len(by_key)
        for draft, stamp in captured:
            existing = by_key.get(draft.dedup_key)
            if existing is not None:
                if existing.status == FindingStatus.FALSE_POSITIVE:
                    continue  # suppressed by an earlier human decision
                session.add(
                    FindingEvidenceRow.from_draft(
                        draft,
                        finding_id=existing.id,
                        source_adapter=adapter_name,
                        source_scan_id=scan.id,
                        stamp=stamp,
                    )
                )
                _keep_worst_severity(existing, draft)
                session.add(existing)
                continue
            allocated += 1
            new_row = FindingRow.from_draft(
                draft,
                engagement_id=engagement_id,
                scan_id=scan.id,
                display_id=display_id_for(allocated),
                stamp=stamp,
            )
            session.add(new_row)
            by_key[draft.dedup_key] = new_row

        scan.targets_scanned = scanned
        scan.targets_skipped_out_of_scope = skipped
        scan.finished_at = datetime.now(UTC)
        session.add(scan)

        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            logger.warning(
                "display_id collision while persisting a scan; retrying",
                extra={"engagement_id": str(engagement_id), "attempt": attempt},
            )
            continue

        await session.refresh(scan)
        return scan

    raise ScanPersistError(
        f"could not allocate finding ids for engagement {engagement_id} "
        f"after {MAX_PERSIST_ATTEMPTS} attempts"
    )


def _keep_worst_severity(row: FindingRow, draft: FindingDraft) -> None:
    """Raise a collapsed finding to the worst severity/CVSS seen, deterministically.

    ``max`` over the pair is order-independent, so the finding's severity does not depend on
    which adapter ran first (rule PX-DETERMINISM)."""
    if severity_rank(draft.severity) > severity_rank(row.severity):
        row.severity = draft.severity
    if draft.cvss is not None and (row.cvss is None or draft.cvss > row.cvss):
        row.cvss = draft.cvss


async def _existing_findings_by_key(
    session: AsyncSession, engagement_id: uuid.UUID
) -> dict[tuple[str, str, str], FindingRow]:
    """The engagement's findings indexed by dedup identity, so a repeat collapses onto the
    finding already recorded. ``len`` is the display-id allocation high-water mark."""
    rows = (
        await session.exec(select(FindingRow).where(FindingRow.engagement_id == engagement_id))
    ).all()
    return {row.dedup_key: row for row in rows}
