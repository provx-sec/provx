# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Evidence integrity helpers (rule PX-EVIDENCE).

Every evidence artifact is hashed with SHA-256 and stamped with a capture timestamp *at
capture time*, so the hash attests to what the tool actually saw rather than to whatever
survived later processing. Stored evidence is append-only: a correction is a new record
referencing the prior one, never an edit.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict


class EvidenceSeal(BaseModel):
    """The integrity stamp bound to one captured artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sha256: str
    captured_at: datetime


def seal(raw: str) -> EvidenceSeal:
    """Hash a raw artifact and stamp the moment of capture."""
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return EvidenceSeal(sha256=digest, captured_at=datetime.now(UTC))
