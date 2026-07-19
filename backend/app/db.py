# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Database engine and session wiring.

Schema is owned by Alembic, never by ``create_all`` - migrations are the auditable record
of how the schema got to where it is, and the walking skeleton establishes that habit
before there is data to lose.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from functools import lru_cache

from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import get_settings


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    """Return the process-wide async engine.

    ``echo`` stays off: SQL logging would put scan targets and evidence into stdout
    (rules S-03, PX-SECRETS).
    """
    return create_async_engine(get_settings().async_database_url, echo=False, future=True)


@lru_cache(maxsize=1)
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Return the session factory bound to the process-wide engine."""
    return async_sessionmaker(get_engine(), class_=AsyncSession, expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a request-scoped session."""
    async with get_sessionmaker()() as session:
        yield session
