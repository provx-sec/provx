# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Shared test fixtures.

Tests run with ``APP_ENV=testing`` (rule Q-10) against a temporary file-backed SQLite
database, so a suite run never touches a real Postgres instance. A file rather than
``:memory:`` because TestClient drives the app on its own event loop, and an in-memory
database would not be shared across connections.

The app's real session dependency is used unmodified - the wiring under test is the wiring
that ships.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models.tables import Engagement

if TYPE_CHECKING:
    from fastapi.testclient import TestClient

#: Signature of the `make_engagement` fixture, so tests can annotate it.
EngagementFactory = Callable[..., Engagement]

os.environ["APP_ENV"] = "testing"


def _reset_caches() -> None:
    """Drop the cached settings/engine so a test's DATABASE_URL takes effect."""
    from app.config import get_settings
    from app.db import get_engine, get_sessionmaker

    get_settings.cache_clear()
    get_engine.cache_clear()
    get_sessionmaker.cache_clear()


async def _create_schema(url: str) -> None:
    engine = create_async_engine(url, future=True)
    async with engine.begin() as connection:
        await connection.run_sync(SQLModel.metadata.create_all)
    await engine.dispose()


@pytest.fixture
def database_url(tmp_path: Path) -> Iterator[str]:
    """Point the app at a throwaway SQLite database with the schema already applied."""
    from app.models import tables as _tables  # noqa: F401  (populates SQLModel.metadata)

    url = f"sqlite+aiosqlite:///{tmp_path / 'provx-test.db'}"
    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = url
    _reset_caches()
    asyncio.run(_create_schema(url))

    yield url

    if previous is None:
        os.environ.pop("DATABASE_URL", None)
    else:
        os.environ["DATABASE_URL"] = previous
    _reset_caches()


@pytest.fixture
def client(database_url: str) -> Iterator[TestClient]:
    """A TestClient bound to the throwaway database."""
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
async def session(database_url: str) -> AsyncIterator[AsyncSession]:
    """A session over the throwaway database, for testing services directly."""
    engine = create_async_engine(database_url, future=True)
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db_session:
        yield db_session
    await engine.dispose()


@pytest.fixture
def make_engagement() -> EngagementFactory:
    """Build an Engagement without touching the database.

    One factory instead of the three near-identical builders that had grown across the
    suite (rule Q-11). Tests that need a persisted engagement add the result to a session.
    """

    def factory(**overrides: Any) -> Engagement:
        fields: dict[str, Any] = {
            "name": "Acme external web",
            "scope_allow": ["*.example.com"],
            "scope_deny": [],
            "mode": "passive",
        }
        fields.update(overrides)
        return Engagement(**fields)

    return factory
