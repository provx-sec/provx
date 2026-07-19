# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Configuration drift guard (rule B-FA-05).

`SAFE_MODE` was documented as an org-wide safety lock, injected by Compose, and read by
nothing: `extra="ignore"` discarded it in silence. Nothing failed, so nobody noticed.

`extra="forbid"` does **not** catch this. pydantic-settings' environment source only pulls
values for *declared* fields, so an undeclared variable is never seen as "extra" and the
flag is a no-op for env-sourced config. The guard has to live here instead: every variable
the deployment injects must be either a declared `Settings` field or explicitly listed
below as not-the-backend's-business, with a reason.

Add a variable to `.env.example` or to Compose without doing one of those two things, and
this test fails.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.config import Settings

REPO_ROOT = Path(__file__).resolve().parents[2]
ENV_EXAMPLE = REPO_ROOT / ".env.example"
COMPOSE = REPO_ROOT / "docker-compose.yml"

#: Variables that reach the backend container but are deliberately not backend settings.
#: Each needs a reason; "we forgot" is not one.
NOT_BACKEND_SETTINGS = {
    "POSTGRES_USER": "consumed by the postgres image to initialise the cluster",
    "POSTGRES_PASSWORD": "consumed by the postgres image to initialise the cluster",
    "POSTGRES_DB": "consumed by the postgres image to initialise the cluster",
    "BACKEND_PORT": "consumed by Compose for host port mapping, not by the app",
    "FRONTEND_PORT": "consumed by Compose for host port mapping, not by the app",
    "PROVX_API_BASE_URL": "consumed by the frontend container only",
}


def declared_setting_names() -> set[str]:
    """The env var names Settings actually reads."""
    return {name.upper() for name in Settings.model_fields}


def env_example_names() -> set[str]:
    """Uncommented variable names declared in .env.example."""
    pattern = re.compile(r"^\s*([A-Z][A-Z0-9_]*)\s*=")
    return {
        match.group(1)
        for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines()
        if (match := pattern.match(line))
    }


def compose_backend_names() -> set[str]:
    """Variable names the compose file names explicitly for the backend service."""
    text = COMPOSE.read_text(encoding="utf-8")
    backend_block = text.split("backend:", 1)[1].split("\n  frontend:", 1)[0]
    return set(re.findall(r"^\s{6}([A-Z][A-Z0-9_]*):", backend_block, flags=re.MULTILINE))


def test_every_injected_variable_is_read_or_explicitly_excluded() -> None:
    injected = env_example_names() | compose_backend_names()
    unaccounted = injected - declared_setting_names() - set(NOT_BACKEND_SETTINGS)

    assert not unaccounted, (
        "these variables are injected into the backend but nothing reads them, and they are "
        f"not listed as intentionally-excluded: {sorted(unaccounted)}. Either add a field to "
        "Settings or add them to NOT_BACKEND_SETTINGS with a reason."
    )


def test_the_safety_lock_is_a_declared_setting() -> None:
    # The specific regression: SAFE_MODE injected, discarded, and silently inert.
    assert "SAFE_MODE" in declared_setting_names()


def test_app_env_is_documented_for_operators() -> None:
    # APP_ENV gates whether internal error detail reaches clients (PX-ERRORS); an operator
    # cannot set what .env.example never mentions.
    assert "APP_ENV" in env_example_names()


def test_exclusion_list_carries_a_reason_for_every_entry() -> None:
    assert all(reason.strip() for reason in NOT_BACKEND_SETTINGS.values())


@pytest.mark.parametrize("name", sorted(NOT_BACKEND_SETTINGS))
def test_excluded_variables_are_not_also_declared_settings(name: str) -> None:
    # Prevents the list rotting into a lie once a variable does become a backend setting.
    assert name not in declared_setting_names()
