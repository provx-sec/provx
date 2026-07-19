# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Migration tests.

Schema is owned by Alembic, so the migration - not ``create_all`` - is what has to work.
These assert it applies, creates the expected tables, and reverses cleanly (rule W-03).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import UniqueConstraint, create_engine, inspect

from alembic import command

BACKEND_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_TABLES = {"engagement", "target", "scan", "finding"}


@pytest.fixture
def alembic_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Config:
    """An Alembic config pointed at a throwaway SQLite file."""
    from app.config import get_settings

    db_path = tmp_path / "migrations.db"
    monkeypatch.setitem(os.environ, "DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    get_settings.cache_clear()

    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    config.attributes["sync_url"] = f"sqlite:///{db_path}"
    return config


def _sync_url(config: Config) -> str:
    return str(config.attributes["sync_url"])


def test_upgrade_creates_the_core_tables(alembic_config: Config) -> None:
    command.upgrade(alembic_config, "head")

    engine = create_engine(_sync_url(alembic_config))
    tables = set(inspect(engine).get_table_names())
    engine.dispose()

    assert EXPECTED_TABLES <= tables


def test_finding_display_id_is_unique_per_engagement(alembic_config: Config) -> None:
    command.upgrade(alembic_config, "head")

    engine = create_engine(_sync_url(alembic_config))
    constraints = inspect(engine).get_unique_constraints("finding")
    engine.dispose()

    assert any(set(c["column_names"]) == {"engagement_id", "display_id"} for c in constraints), (
        "display_id must be unique within an engagement, not globally"
    )


def test_downgrade_reverses_the_migration(alembic_config: Config) -> None:
    command.upgrade(alembic_config, "head")
    command.downgrade(alembic_config, "base")

    engine = create_engine(_sync_url(alembic_config))
    tables = set(inspect(engine).get_table_names())
    engine.dispose()

    assert not (EXPECTED_TABLES & tables)


def test_model_metadata_carries_the_same_unique_constraint_as_the_migration() -> None:
    """The constraint must live on the model, not only in the migration.

    It was declared only in the migration, so every schema built from model metadata (i.e.
    the entire test suite) silently lacked it - the collision protection production relies
    on was never actually exercised. `alembic revision --autogenerate` would also have
    emitted a DROP for it.
    """
    from app.models.tables import FindingRow

    constraints = {
        tuple(sorted(column.name for column in constraint.columns))
        for constraint in FindingRow.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    }

    assert ("display_id", "engagement_id") in constraints
