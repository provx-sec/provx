# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Provx plugin-type interfaces.

Two deterministic plugin types extend Provx without core edits. Both are declared here so
the Playbook type sits *alongside* the tool-adapter type:

* ``ToolAdapter``  — wraps an external tool, normalizes output into Findings.
* ``PlaybookPlugin`` — a loaded, validated deterministic playbook.

These are interface stubs (scaffolding). No command-building, parsing, or execution logic
is implemented yet — that lands with the walking skeleton and the workflow engine.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class ToolAdapter(Protocol):
    """
    Contract every tool adapter implements (see packages/adapters/README.md §contract).

    Scaffolding only — signatures document the boundary; there are no bodies yet.
    """

    #: Adapter name, e.g. "httpx".
    name: str
    #: Module category: "web" | "api" | "infra-ad" | ...
    category: str
    #: Safety class: "passive" | "intrusive".
    safety: str
    #: External binary this adapter wraps, e.g. "httpx".
    tool: str

    def build_command(self, *, targets: list[str], use_cases: list[str]) -> list[str]:
        """Build the tool invocation from scope-checked targets + selected use-cases.

        Scope MUST be enforced here, at the adapter boundary — never trusted upstream.
        """
        ...

    def parse_output(self, raw: str) -> list[object]:
        """Normalize the tool's raw output into Finding objects."""
        ...


@runtime_checkable
class PlaybookPlugin(Protocol):
    """A deterministic playbook, discoverable as a plugin (entry-point group
    ``provx.playbooks``). The concrete model is ``provx_sdk.playbook.Playbook``."""

    #: Unique playbook name, e.g. "web-baseline".
    workflow: str
