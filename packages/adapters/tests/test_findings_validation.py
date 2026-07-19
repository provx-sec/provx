# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Contract validation tests for the findings models.

Two invariants are load-bearing: an ATT&CK technique id must be well-formed wherever it
enters the system (rule PX-ATTACK), and a display_id must satisfy the pattern that
``Finding`` will later be reconstructed against - including past 9999.
"""

from __future__ import annotations

import pytest
from provx_sdk.findings import (
    Confidence,
    Finding,
    FindingDraft,
    Module,
    Severity,
    validate_attack_techniques,
)
from pydantic import ValidationError


def make_draft(**overrides: object) -> FindingDraft:
    defaults: dict[str, object] = {
        "title": "Missing X-Frame-Options header",
        "target": "http://example.test",
        "module": Module.WEB,
        "severity": Severity.LOW,
        "confidence": Confidence.HIGH,
    }
    defaults.update(overrides)
    return FindingDraft(**defaults)  # type: ignore[arg-type]


def make_finding(display_id: str) -> Finding:
    return Finding(
        display_id=display_id,
        title="t",
        target="http://example.test",
        module=Module.WEB,
        severity=Severity.LOW,
    )


@pytest.mark.parametrize("technique", ["T1595", "T1190", "T1595.001"])
def test_draft_accepts_valid_attack_technique_ids(technique: str) -> None:
    assert make_draft(attack_techniques=[technique]).attack_techniques == [technique]


@pytest.mark.parametrize("technique", ["T159", "t1595", "1595", "T1595.1", "TA0001", "", "T1595 "])
def test_draft_rejects_malformed_attack_technique_ids(technique: str) -> None:
    # The draft is where an adapter's output first enters the system; catching it here
    # means a bad adapter fails at construction, not at persist time.
    with pytest.raises(ValidationError):
        make_draft(attack_techniques=[technique])


def test_draft_rejects_a_bad_id_mixed_among_good_ones() -> None:
    with pytest.raises(ValidationError):
        make_draft(attack_techniques=["T1595", "nope"])


def test_shared_validator_is_the_one_both_models_use() -> None:
    assert validate_attack_techniques(["T1190"]) == ["T1190"]
    with pytest.raises(ValueError):
        validate_attack_techniques(["nope"])


@pytest.mark.parametrize("display_id", ["PVX-0001", "PVX-9999", "PVX-10000", "PVX-123456"])
def test_finding_accepts_four_or_more_digits(display_id: str) -> None:
    # Four digits is a zero-padded minimum, not a cap: an engagement that exceeds 9999
    # findings must still produce loadable records.
    assert make_finding(display_id).display_id == display_id


@pytest.mark.parametrize("display_id", ["PVX-1", "PVX-001", "pvx-0001", "PVX-ABCD", "0001", ""])
def test_finding_rejects_malformed_display_ids(display_id: str) -> None:
    with pytest.raises(ValidationError):
        make_finding(display_id)


def test_draft_promotes_to_a_finding_past_the_old_four_digit_ceiling() -> None:
    finding = make_draft(attack_techniques=["T1595"]).to_finding("PVX-10000")

    assert finding.display_id == "PVX-10000"
    assert finding.attack_techniques == ["T1595"]
