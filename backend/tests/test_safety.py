# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Scan-time safety gate tests (rules PX-ACTIVE, PX-PASSIVE, PX-ERRORS).

The audit's finding was that these controls were recorded and never read. The point of
these tests is that they now fail if a control ever stops being consulted - a gate nothing
tests is a gate that quietly becomes documentation again.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.services.safety import ScanNotPermittedError, assert_scan_permitted
from tests.conftest import EngagementFactory


class FakeAdapter:
    """Minimal stand-in carrying only what the gate inspects."""

    def __init__(self, safety: str = "passive") -> None:
        self.name = "fake"
        self.category = "web"
        self.safety = safety
        self.tool = "fake"


def settings(**overrides: Any) -> Settings:
    return Settings(app_env="testing", **overrides)


def test_passive_engagement_with_a_passive_adapter_is_permitted(
    make_engagement: EngagementFactory,
) -> None:
    assert_scan_permitted(settings(safe_mode=True), make_engagement(), FakeAdapter())


def test_safe_mode_refuses_an_active_engagement(make_engagement: EngagementFactory) -> None:
    with pytest.raises(ScanNotPermittedError, match="SAFE_MODE"):
        assert_scan_permitted(
            settings(safe_mode=True), make_engagement(mode="active"), FakeAdapter()
        )


def test_safe_mode_refuses_an_intrusive_adapter(make_engagement: EngagementFactory) -> None:
    with pytest.raises(ScanNotPermittedError, match="SAFE_MODE"):
        assert_scan_permitted(
            settings(safe_mode=True), make_engagement(), FakeAdapter(safety="intrusive")
        )


def test_passive_engagement_refuses_an_intrusive_adapter_even_with_safe_mode_off(
    make_engagement: EngagementFactory,
) -> None:
    # Turning off the org-wide lock must not silently upgrade an engagement's own mode.
    with pytest.raises(ScanNotPermittedError, match="passive engagement"):
        assert_scan_permitted(
            settings(safe_mode=False), make_engagement(), FakeAdapter(safety="intrusive")
        )


def test_an_unknown_mode_is_refused_rather_than_treated_as_passive(
    make_engagement: EngagementFactory,
) -> None:
    # A tampered or mis-migrated row must fail closed.
    with pytest.raises(ScanNotPermittedError, match="not a known mode"):
        assert_scan_permitted(
            settings(safe_mode=False), make_engagement(mode="aggressive"), FakeAdapter()
        )


def test_mode_comparison_ignores_case_and_padding(make_engagement: EngagementFactory) -> None:
    assert_scan_permitted(
        settings(safe_mode=True), make_engagement(mode="  PASSIVE "), FakeAdapter()
    )


def test_safe_mode_defaults_to_on() -> None:
    # A deployment that forgets the variable gets the safe behaviour, not the permissive one.
    assert Settings(app_env="testing").safe_mode is True


def test_scan_refused_at_runtime_returns_a_user_safe_403(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    created = client.post(
        "/engagements",
        json={
            "name": "Tampered",
            "scope_allow": ["example.com"],
            "targets": ["https://example.com"],
        },
    ).json()

    # The mode passes the create schema, then changes underneath - exactly the case a
    # creation-time-only check misses.
    #
    # Imported here, not at module scope, for the reason conftest documents: importing
    # app.services pulls app.config before the `database_url` fixture has set DATABASE_URL.
    # Patching scan_runner's binding (not safety's) is deliberate - that is the name the
    # call site actually resolves.
    from app.services import scan_runner

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise ScanNotPermittedError("SAFE_MODE forbids running an 'active' engagement")

    monkeypatch.setattr(scan_runner, "assert_scan_permitted", refuse)

    response = client.post(f"/engagements/{created['id']}/scan")

    assert response.status_code == 403
    body = response.json()
    assert body["error_code"] == "scan_not_permitted"
    # PX-ERRORS: the client learns that it was refused, not which control refused it.
    assert "SAFE_MODE" not in response.text
    assert "Traceback" not in response.text
