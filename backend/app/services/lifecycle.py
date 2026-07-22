# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
The finding validation lifecycle: a deterministic, allowlisted state machine.

The machine proposes; a human confirms (rule PX-HUMAN). Findings enter as ``new`` and only an
explicit human transition can move one to ``validated`` - no scan, re-scan, or automated path
in this codebase ever writes ``validated``. The allowed edges below mirror the lifecycle in
docs/VALIDATION_and_REFERENCE_SYSTEMS.md §1.

This module is pure and deterministic (no IO, no clock): given a from-state and a to-state it
answers whether the edge is allowed. Persistence and the audit trail live in the API layer.
"""

from __future__ import annotations

from provx_sdk.findings import FindingStatus

#: Allowed transitions, as {from: {to, ...}}. A missing key or absent target means "not
#: allowed". Kept as data, not code branches, so the whole policy is auditable at a glance
#: (rule PX-DETERMINISM).
ALLOWED_TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    # A machine-found finding: a human looks (triaged) or, for obvious noise/known risk, rules
    # on it directly. It can never jump straight to validated - that needs a triage first.
    FindingStatus.NEW: frozenset(
        {FindingStatus.TRIAGED, FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK}
    ),
    # After a human has looked, they confirm, reject, or accept the risk.
    FindingStatus.TRIAGED: frozenset(
        {FindingStatus.VALIDATED, FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK}
    ),
    # A confirmed finding is fixed, or later re-opened as a false positive on review.
    FindingStatus.VALIDATED: frozenset({FindingStatus.FIXED, FindingStatus.FALSE_POSITIVE}),
    # A fix is verified gone, or a re-scan finds it back (regression).
    FindingStatus.FIXED: frozenset({FindingStatus.REGRESSION, FindingStatus.VALIDATED}),
    # A regression is re-confirmed or fixed again.
    FindingStatus.REGRESSION: frozenset({FindingStatus.VALIDATED, FindingStatus.FIXED}),
    # An accepted risk can be revisited: re-triaged when circumstances change.
    FindingStatus.ACCEPTED_RISK: frozenset({FindingStatus.TRIAGED}),
    # A false positive is terminal for the automated pipeline; reopening is a fresh triage.
    FindingStatus.FALSE_POSITIVE: frozenset({FindingStatus.TRIAGED}),
}


class IllegalTransitionError(ValueError):
    """Raised when a requested lifecycle transition is not an allowed edge."""

    def __init__(self, current: FindingStatus, requested: FindingStatus) -> None:
        self.current = current
        self.requested = requested
        super().__init__(f"cannot move a finding from {current.value} to {requested.value}")


def is_allowed(current: FindingStatus, requested: FindingStatus) -> bool:
    """Whether ``current -> requested`` is an allowed edge. A no-op (same state) is not: a
    transition endpoint that changed nothing would still write a misleading audit entry."""
    return requested in ALLOWED_TRANSITIONS.get(current, frozenset())


def assert_transition(current: FindingStatus, requested: FindingStatus) -> None:
    """Raise :class:`IllegalTransitionError` unless the edge is allowed."""
    if not is_allowed(current, requested):
        raise IllegalTransitionError(current, requested)
