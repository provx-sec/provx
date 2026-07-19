# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""Fixture test: the deterministic playbook loader parses workflows/web-baseline.yaml."""

from __future__ import annotations

from pathlib import Path

import pytest
from provx_sdk.loader import find_workflows_dir, load_playbook
from provx_sdk.playbook import Playbook, PlaybookValidationError


def _web_baseline_path() -> Path:
    return find_workflows_dir() / "web-baseline.yaml"


def test_web_baseline_parses() -> None:
    pb = load_playbook(_web_baseline_path())

    assert isinstance(pb, Playbook)
    assert pb.workflow == "web-baseline"

    # At least one discovery rule, and the login rule carries Active-only intrusive steps.
    assert len(pb.on_discovery) >= 1
    active_only_steps = [step for rule in pb.on_discovery for step in rule.active_only]
    assert "auth_bypass" in active_only_steps
    assert "default_creds" in active_only_steps

    # Routing carries a deterministic validator, exposed via the `if` alias.
    assert pb.routing[0].if_.startswith("finding.type")
    assert pb.routing[0].then_validate == ["active_options_probe"]


def test_missing_required_field_raises(tmp_path: Path) -> None:
    # A discovery rule with no `run` list violates the schema.
    bad = tmp_path / "bad.yaml"
    bad.write_text('workflow: bad\non_discovery:\n  - when: "x == true"\n', encoding="utf-8")
    with pytest.raises(PlaybookValidationError):
        load_playbook(bad)


def test_empty_workflow_name_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("workflow: '   '\non_discovery:\n  - when: x\n    run: [a]\n", encoding="utf-8")
    with pytest.raises(PlaybookValidationError):
        load_playbook(bad)


def test_non_mapping_yaml_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(PlaybookValidationError):
        load_playbook(bad)


def test_load_missing_file_raises() -> None:
    with pytest.raises(PlaybookValidationError):
        load_playbook("does/not/exist.yaml")
