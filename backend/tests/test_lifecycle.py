# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Lifecycle state-machine tests.

The one rule that must never bend: no path here ever lets the machine reach ``validated`` on
its own - a human transition is the only way in (rule PX-HUMAN). The rest asserts the
allowlist is exactly the documented graph (docs/VALIDATION_and_REFERENCE_SYSTEMS.md §1).
"""

from __future__ import annotations

import pytest
from provx_sdk.findings import FindingStatus

from app.services.lifecycle import (
    ALLOWED_TRANSITIONS,
    IllegalTransitionError,
    assert_transition,
    is_allowed,
)

S = FindingStatus


def test_new_cannot_jump_straight_to_validated() -> None:
    # Validation requires a triage step first; the machine never self-confirms (PX-HUMAN).
    assert not is_allowed(S.NEW, S.VALIDATED)


def test_only_triage_promotes_to_validated() -> None:
    reachable_from = {
        state for state, targets in ALLOWED_TRANSITIONS.items() if S.VALIDATED in targets
    }
    assert reachable_from == {S.TRIAGED, S.FIXED, S.REGRESSION}
    assert S.NEW not in reachable_from


@pytest.mark.parametrize(
    ("current", "requested"),
    [
        (S.NEW, S.TRIAGED),
        (S.NEW, S.FALSE_POSITIVE),
        (S.NEW, S.ACCEPTED_RISK),
        (S.TRIAGED, S.VALIDATED),
        (S.VALIDATED, S.FIXED),
        (S.FIXED, S.REGRESSION),
        (S.REGRESSION, S.VALIDATED),
        (S.FALSE_POSITIVE, S.TRIAGED),
    ],
)
def test_allowed_edges(current: FindingStatus, requested: FindingStatus) -> None:
    assert is_allowed(current, requested)
    assert_transition(current, requested)  # does not raise


@pytest.mark.parametrize(
    ("current", "requested"),
    [
        (S.NEW, S.VALIDATED),
        (S.NEW, S.FIXED),
        (S.VALIDATED, S.NEW),
        (S.FALSE_POSITIVE, S.VALIDATED),
        (S.NEW, S.NEW),  # a no-op is not a transition
    ],
)
def test_rejected_edges(current: FindingStatus, requested: FindingStatus) -> None:
    assert not is_allowed(current, requested)
    with pytest.raises(IllegalTransitionError):
        assert_transition(current, requested)


def test_every_status_has_an_explicit_policy() -> None:
    # No status may fall through to an undefined transition set.
    assert set(ALLOWED_TRANSITIONS) == set(FindingStatus)
