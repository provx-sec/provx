# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
provx_adapters — Provx's deterministic plugin SDK.

This package defines the two plugin types that extend Provx WITHOUT touching the core:

* **Tool adapters** — wrap an external security tool and normalize its output into
  Findings (see ``plugins.ToolAdapter``).
* **Playbooks** — declarative YAML methodology that the deterministic workflow engine
  evaluates to decide what to run next (see ``playbook.Playbook`` and ``loader``).

Both are deterministic and auditable. **No AI lives here** — AI is an optional advisor
layered on elsewhere, off by default.

Scaffolding status: models and the playbook loader/validator exist; the execution engine
does not.
"""

from provx_adapters.playbook import (
    DiscoveryRule,
    Playbook,
    PlaybookValidationError,
    RoutingRule,
)

__all__ = [
    "DiscoveryRule",
    "Playbook",
    "PlaybookValidationError",
    "RoutingRule",
]

__version__ = "0.0.0"
