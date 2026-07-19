# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Provx plugin-type interfaces.

Two deterministic plugin types extend Provx without core edits. Both are declared here so
the Playbook type sits *alongside* the tool-adapter type:

* ``ToolAdapter`` - wraps an external tool, normalizes output into Findings.
* ``PlaybookPlugin`` - a loaded, validated deterministic playbook.

Adapters are discovered through the ``provx.adapters`` entry-point group; see
``provx_sdk.registry``. The workflow engine that decides *which* adapter runs when is a
later phase - today the caller names the adapter directly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from provx_sdk.findings import FindingDraft
    from provx_sdk.scope import ScopePolicy


@runtime_checkable
class ToolAdapter(Protocol):
    """
    Contract every tool adapter implements (see packages/adapters/README.md §contract).

    Scaffolding only - signatures document the boundary; there are no bodies yet.
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

        Copyleft tools may only be invoked as separate subprocesses (rule PX-LICENSE), so
        this stays the path for external binaries. An in-process adapter raises
        NotImplementedError here and implements ``probe`` instead.
        """
        ...

    async def probe(self, target: str, *, policy: ScopePolicy, timeout: float = 10.0) -> str:
        """Collect raw output for one target and return it in this adapter's envelope.

        The counterpart to ``build_command``: an in-process adapter implements this and
        raises NotImplementedError from ``build_command``; a subprocess adapter does the
        reverse. Exactly one of the two is live for any given adapter.

        ``policy`` is a required parameter, not an assumption. This method touches the
        network, so the scope contract belongs in its signature where the type checker
        enforces it - a docstring asking callers to be careful is not a control
        (rule PX-SCOPE). Implementations MUST re-check scope on every redirect hop; use
        ``provx_sdk.fetch.fetch_within_scope`` rather than rolling your own.
        """
        ...

    def parse_output(self, raw: str) -> list[FindingDraft]:
        """Normalize the tool's raw output into finding drafts.

        Drafts, not Findings: ``display_id`` is a per-engagement sequence the persistence
        layer allocates, so an adapter is not in a position to assign one.

        Implementations MUST be pure and deterministic - the same raw input yields the same
        drafts every time, which is what a recorded fixture asserts in CI (rule PX-FIXTURE).
        """
        ...


@runtime_checkable
class PlaybookPlugin(Protocol):
    """A deterministic playbook, discoverable as a plugin (entry-point group
    ``provx.playbooks``). The concrete model is ``provx_sdk.playbook.Playbook``."""

    #: Unique playbook name, e.g. "web-baseline".
    workflow: str
