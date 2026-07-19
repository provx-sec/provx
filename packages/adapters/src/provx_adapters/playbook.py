# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Deterministic playbook models — the schema for Provx's "brain".

A playbook encodes pentest methodology as auditable rules (see docs/PLAYBOOK_SCHEMA.md and
docs/DETERMINISTIC_CORE_and_NonAI_Strengths.md §3). These Pydantic models are the enforced
schema; ``loader.py`` reads YAML into them.

Scaffolding boundary: the ``when`` / ``if`` expression strings are stored verbatim and are
NOT parsed or evaluated here. There is no execution engine yet — this module only models
and validates playbook structure. No AI is involved anywhere in this path.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator


class PlaybookValidationError(ValueError):
    """Raised when a playbook fails to load or validate."""


def _non_empty(value: str, field_name: str) -> str:
    if not value or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty expression string")
    return value


class DiscoveryRule(BaseModel):
    """A rule the engine evaluates against discovered facts.

    ``run`` steps are passive/safe; ``active_only`` steps are intrusive and gated to
    Active mode — they never run in passive/test.
    """

    model_config = ConfigDict(extra="forbid")

    when: str
    run: list[str] = Field(min_length=1)
    active_only: list[str] = Field(default_factory=list)

    @field_validator("when")
    @classmethod
    def _check_when(cls, v: str) -> str:
        return _non_empty(v, "when")


class RoutingRule(BaseModel):
    """Post-finding routing to a deterministic validator or sub-workflow."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    # `if` is a Python keyword; expose it as the YAML alias while using `if_` internally.
    if_: str = Field(alias="if")
    then_validate: list[str] = Field(min_length=1)

    @field_validator("if_")
    @classmethod
    def _check_if(cls, v: str) -> str:
        return _non_empty(v, "if")


class Playbook(BaseModel):
    """A complete deterministic playbook (one YAML file)."""

    model_config = ConfigDict(extra="forbid")

    workflow: str
    on_discovery: list[DiscoveryRule] = Field(min_length=1)
    routing: list[RoutingRule] = Field(default_factory=list)

    @field_validator("workflow")
    @classmethod
    def _check_workflow(cls, v: str) -> str:
        return _non_empty(v, "workflow")
