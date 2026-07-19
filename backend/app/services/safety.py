# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Scan-time safety gate (rules PX-ACTIVE, PX-PASSIVE).

Provx records three safety controls - the org-wide ``SAFE_MODE``, an engagement's ``mode``,
and an adapter's declared ``safety`` class. Recording them is not enforcing them: a value
checked only when an engagement is *created* says nothing about what is true when a scan
actually runs, and a value nothing reads at all is documentation wearing a control's
clothing.

This module is where all three are read, immediately before any target is touched.
"""

from __future__ import annotations

import logging

from provx_sdk.plugins import ToolAdapter

from app.config import Settings
from app.models.tables import Engagement

logger = logging.getLogger(__name__)

PASSIVE = "passive"
ACTIVE = "active"
KNOWN_MODES = frozenset({PASSIVE, ACTIVE})

SCAN_NOT_PERMITTED = "scan_not_permitted"


class ScanNotPermittedError(RuntimeError):
    """Raised when the safety controls refuse a scan.

    Carries an operator-facing reason for the server log; the API surfaces only a generic
    message and the stable error code (rule PX-ERRORS).
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def assert_scan_permitted(settings: Settings, engagement: Engagement, adapter: ToolAdapter) -> None:
    """Refuse the scan unless every recorded safety control actually permits it.

    Checked at scan time rather than at engagement creation: the row can be modified after
    it is created, and a control that was true once is not a control.
    """
    mode = engagement.mode.strip().lower()

    if mode not in KNOWN_MODES:
        raise ScanNotPermittedError(f"engagement mode {engagement.mode!r} is not a known mode")

    if settings.safe_mode and mode != PASSIVE:
        raise ScanNotPermittedError(f"SAFE_MODE forbids running a {mode!r} engagement")

    if settings.safe_mode and adapter.safety != PASSIVE:
        raise ScanNotPermittedError(
            f"SAFE_MODE forbids the {adapter.safety!r} adapter {adapter.name!r}"
        )

    if mode == PASSIVE and adapter.safety != PASSIVE:
        raise ScanNotPermittedError(
            f"a passive engagement cannot run the {adapter.safety!r} adapter {adapter.name!r}"
        )

    logger.info(
        "scan permitted",
        extra={"mode": mode, "adapter": adapter.name, "safe_mode": settings.safe_mode},
    )
