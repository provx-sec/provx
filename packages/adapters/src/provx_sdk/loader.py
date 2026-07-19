# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Playbook loader + validator.

Reads deterministic playbook YAML files into validated :class:`Playbook` models. This is
loading and validation ONLY — there is no execution engine. Evaluating ``when`` / ``if``
expressions and running steps is a later phase.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from provx_sdk.playbook import Playbook, PlaybookValidationError


def load_playbook(path: str | Path) -> Playbook:
    """Load and validate a single playbook YAML file.

    Raises :class:`PlaybookValidationError` if the file is missing, is not valid YAML,
    is not a mapping, or does not satisfy the playbook schema.
    """
    p = Path(path)
    try:
        raw_text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise PlaybookValidationError(f"cannot read playbook {p}: {exc}") from exc

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise PlaybookValidationError(f"invalid YAML in {p}: {exc}") from exc

    if not isinstance(data, dict):
        raise PlaybookValidationError(f"playbook {p} must be a YAML mapping")

    try:
        return Playbook.model_validate(data)
    except ValidationError as exc:
        raise PlaybookValidationError(f"playbook {p} failed schema validation:\n{exc}") from exc


def load_playbooks_dir(directory: str | Path) -> dict[str, Playbook]:
    """Load every ``*.yaml`` / ``*.yml`` playbook in a directory, keyed by workflow name."""
    d = Path(directory)
    if not d.is_dir():
        raise PlaybookValidationError(f"{d} is not a directory")

    playbooks: dict[str, Playbook] = {}
    for file in sorted([*d.glob("*.yaml"), *d.glob("*.yml")]):
        pb = load_playbook(file)
        playbooks[pb.workflow] = pb
    return playbooks


def find_workflows_dir(start: str | Path | None = None) -> Path:
    """Walk upward from ``start`` (default: this file) to locate the repo's ``workflows/``
    directory. Convenience for tests and tooling; not used by any engine."""
    here = Path(start) if start is not None else Path(__file__).resolve()
    for parent in [here, *here.parents]:
        candidate = parent / "workflows"
        if candidate.is_dir():
            return candidate
    raise PlaybookValidationError("could not locate a 'workflows/' directory")
