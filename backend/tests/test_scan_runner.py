# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Write-path validation tests.

SQLModel skips Pydantic validation on ``table=True`` classes, which once meant a row could
be written that ``to_contract()`` would refuse to read back - breaking every subsequent read
of that engagement, not just the one finding. These pin the contract at the point of write.
"""

from __future__ import annotations

import re
import uuid

import pytest
from provx_sdk.evidence import seal
from provx_sdk.findings import DISPLAY_ID_PATTERN, Confidence, FindingDraft, Module, Severity
from sqlalchemy.exc import IntegrityError
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models.tables import Engagement, FindingRow
from app.services import scan_runner
from app.services.scan_runner import display_id_for


def make_draft(**overrides: object) -> FindingDraft:
    defaults: dict[str, object] = {
        "title": "Missing X-Frame-Options header",
        "target": "http://example.test",
        "module": Module.WEB,
        "severity": Severity.LOW,
        "confidence": Confidence.HIGH,
        "attack_techniques": ["T1595"],
    }
    defaults.update(overrides)
    return FindingDraft(**defaults)  # type: ignore[arg-type]


def build_row(draft: FindingDraft, display_id: str) -> FindingRow:
    return FindingRow.from_draft(
        draft,
        engagement_id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        display_id=display_id,
        stamp=seal("raw"),
    )


@pytest.mark.parametrize("sequence", [1, 2, 42, 9999, 10000, 10001, 123456])
def test_allocated_display_ids_always_satisfy_the_contract(sequence: int) -> None:
    # The regression this suite exists for: `:04d` is a minimum width, so sequence 10000
    # produces a five-digit label. It must still match what Finding will be rebuilt against.
    assert re.match(DISPLAY_ID_PATTERN, display_id_for(sequence))


def test_display_ids_are_zero_padded_to_four_and_then_widen() -> None:
    assert display_id_for(1) == "PVX-0001"
    assert display_id_for(9999) == "PVX-9999"
    assert display_id_for(10000) == "PVX-10000"


def test_row_past_the_old_ceiling_round_trips_through_the_contract() -> None:
    row = build_row(make_draft(), display_id_for(10000))

    contract = row.to_contract()

    assert contract.display_id == "PVX-10000"
    assert contract.attack_techniques == ["T1595"]


def test_malformed_display_id_is_rejected_at_write_not_at_read() -> None:
    with pytest.raises(ValueError):
        build_row(make_draft(), "PVX-1")


def test_malformed_attack_technique_is_rejected_at_write() -> None:
    # A draft cannot normally hold a bad id, so bypass its validator to prove the row
    # constructor is an independent gate rather than relying on the caller.
    draft = make_draft()
    object.__setattr__(draft, "attack_techniques", ["nope"])

    with pytest.raises(ValueError):
        build_row(draft, "PVX-0001")


def test_valid_row_carries_the_evidence_seal() -> None:
    row = build_row(make_draft(), "PVX-0001")

    assert len(row.evidence_sha256) == 64
    assert row.captured_at.tzinfo is not None


# --- KI-002 regression: concurrent allocation of the same display_id ------------------
# Allocation is a read-then-write, so two scans on one engagement can compute the same
# label. The unique constraint catches it; the runner must recover, not 500.


async def test_persist_recovers_when_a_label_is_taken_mid_flight(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    engagement = Engagement(name="Race", scope_allow=["example.test"])
    session.add(engagement)
    await session.flush()

    stamp = seal("raw")
    # A concurrent scan already committed PVX-0001 for this engagement.
    session.add(
        FindingRow.from_draft(
            make_draft(title="Squatter"),
            engagement_id=engagement.id,
            scan_id=uuid.uuid4(),
            display_id="PVX-0001",
            stamp=stamp,
        )
    )
    await session.commit()

    # Simulate the losing side of the race: the first attempt reads a stale count of 0 and
    # therefore allocates PVX-0001, which the unique constraint rejects. The retry re-reads
    # the true count and renumbers around the squatter.
    original_count = scan_runner._existing_finding_count
    attempts = {"n": 0}

    async def stale_on_first_read(db: AsyncSession, engagement_id: uuid.UUID) -> int:
        attempts["n"] += 1
        if attempts["n"] == 1:
            return 0
        return await original_count(db, engagement_id)

    monkeypatch.setattr(scan_runner, "_existing_finding_count", stale_on_first_read)

    # Read before the call: the retry's rollback expires the ORM object, so touching
    # engagement.id afterwards would trigger lazy IO outside the async context.
    engagement_id = engagement.id
    captured = [(make_draft(title=f"Finding {n}"), stamp) for n in range(3)]
    scan = await scan_runner._persist_scan(session, engagement, "security_headers", captured, 1, 0)

    assert attempts["n"] == 2, "the first attempt must genuinely collide, or this proves nothing"

    rows = (
        await session.exec(select(FindingRow).where(FindingRow.engagement_id == engagement_id))
    ).all()
    labels = sorted(row.display_id for row in rows)

    assert scan.id is not None
    # Squatter keeps PVX-0001; the recovered scan numbered around it without duplicating.
    assert labels == ["PVX-0001", "PVX-0002", "PVX-0003", "PVX-0004"]
    assert len(labels) == len(set(labels))


async def test_persist_gives_up_with_a_domain_error_not_an_internal_one(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    engagement = Engagement(name="Always collides", scope_allow=["example.test"])
    session.add(engagement)
    await session.flush()

    async def always_collide(*args: object, **kwargs: object) -> None:
        raise IntegrityError("stmt", {}, Exception("UNIQUE constraint failed"))

    monkeypatch.setattr(scan_runner.AsyncSession, "commit", always_collide)

    with pytest.raises(scan_runner.ScanPersistError):
        await scan_runner._persist_scan(
            session, engagement, "security_headers", [(make_draft(), seal("raw"))], 1, 0
        )
