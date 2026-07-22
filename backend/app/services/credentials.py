# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Credential lookup for authenticated scanning (rule PX-SECRETS).

One seam between a stored :class:`Credential` row and the in-memory :class:`AuthCredential` the
scan runner presents. Decryption happens in exactly one place here, mirroring how evidence is
opened only at the ``FindingRow.to_contract`` seam, so a reviewer has a single function to audit
for where a stored secret is unsealed.
"""

from __future__ import annotations

import uuid

from provx_sdk.auth import AuthCredential
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models.tables import Credential


async def get_credential(session: AsyncSession, engagement_id: uuid.UUID) -> Credential | None:
    """The engagement's stored credential row, or None. Metadata only - never decrypted here."""
    return (
        await session.exec(select(Credential).where(Credential.engagement_id == engagement_id))
    ).first()


async def load_auth(session: AsyncSession, engagement_id: uuid.UUID) -> AuthCredential | None:
    """Decrypt the engagement's credential into the header to inject, or None if it has none.

    The plaintext lives only in the returned value, in memory, for the duration of the scan.
    """
    credential = await get_credential(session, engagement_id)
    return credential.to_auth() if credential is not None else None
