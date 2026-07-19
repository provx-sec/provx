# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
provx_sdk - Provx's deterministic plugin SDK.

This package defines the two plugin types that extend Provx WITHOUT touching the core:

* **Tool adapters** - wrap an external security tool and normalize its output into
  Findings (see ``plugins.ToolAdapter``).
* **Playbooks** - declarative YAML methodology that the deterministic workflow engine
  evaluates to decide what to run next (see ``playbook.Playbook`` and ``loader``).

Both are deterministic and auditable. **No AI lives here** - AI is an optional advisor
layered on elsewhere, off by default.

The scoped HTTP boundary (``fetch_within_scope``) is part of this package's public contract,
not an implementation detail: it is where PX-SCOPE is enforced for every adapter, so it is
exported here where a reader looking for the platform's egress control will find it.

Scaffolding status: the findings contract, scope enforcement, the scoped fetch boundary,
adapter discovery, and one passive adapter exist; the playbook execution engine does not.
"""

from provx_sdk.evidence import EvidenceSeal, seal
from provx_sdk.fetch import (
    MISSING_LOCATION,
    OUT_OF_SCOPE_REDIRECT,
    TOO_MANY_REDIRECTS,
    FetchOutcome,
    OutOfScopeRequest,
    fetch_within_scope,
)
from provx_sdk.findings import (
    Confidence,
    Evidence,
    Finding,
    FindingDraft,
    FindingStatus,
    Module,
    RiskAcceptance,
    Severity,
    validate_attack_techniques,
)
from provx_sdk.playbook import (
    DiscoveryRule,
    Playbook,
    PlaybookValidationError,
    RoutingRule,
)
from provx_sdk.plugins import PlaybookPlugin, ToolAdapter
from provx_sdk.registry import AdapterNotFoundError, load_adapter, load_adapters
from provx_sdk.scope import (
    OutOfScopeError,
    ScopePolicy,
    canonical_host,
    is_dangerous_host,
    target_host,
)

__all__ = [
    "MISSING_LOCATION",
    "OUT_OF_SCOPE_REDIRECT",
    "TOO_MANY_REDIRECTS",
    "AdapterNotFoundError",
    "Confidence",
    "DiscoveryRule",
    "Evidence",
    "EvidenceSeal",
    "FetchOutcome",
    "Finding",
    "FindingDraft",
    "FindingStatus",
    "Module",
    "OutOfScopeError",
    "OutOfScopeRequest",
    "Playbook",
    "PlaybookPlugin",
    "PlaybookValidationError",
    "RiskAcceptance",
    "RoutingRule",
    "ScopePolicy",
    "Severity",
    "ToolAdapter",
    "canonical_host",
    "fetch_within_scope",
    "is_dangerous_host",
    "load_adapter",
    "load_adapters",
    "seal",
    "target_host",
    "validate_attack_techniques",
]

__version__ = "0.0.0"
