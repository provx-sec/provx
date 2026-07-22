# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Static MITRE ATT&CK technique -> tactic mapping for the report's coverage section.

This is a deliberately small, in-repo lookup table (rule PX-EGRESS): the report is built
offline, in air-gapped deployments too, so it never fetches the live ATT&CK catalogue. It
covers the techniques the shipping passive adapters emit; anything unknown falls into the
``UNMAPPED`` tactic rather than being dropped, so coverage never silently loses a finding.
"MITRE ATT&CK" is only ever a display label here - the stored value is the technique id
string (rule PX-ATTACK).
"""

from __future__ import annotations

UNMAPPED_TACTIC = "Unmapped"

#: Tactic display order, following the ATT&CK kill-chain for the tactics we cover. Unmapped
#: is appended last by the context builder, so it is not listed here.
TACTIC_ORDER: tuple[str, ...] = (
    "Reconnaissance",
    "Initial Access",
    "Credential Access",
    "Collection",
)

#: technique id -> (tactic, friendly name). Sub-techniques fall back to their parent id.
TECHNIQUE_INFO: dict[str, tuple[str, str]] = {
    "T1595": ("Reconnaissance", "Active Scanning"),
    "T1591": ("Reconnaissance", "Gather Victim Org Information"),
    "T1190": ("Initial Access", "Exploit Public-Facing Application"),
    "T1539": ("Credential Access", "Steal Web Session Cookie"),
    "T1557": ("Credential Access", "Adversary-in-the-Middle"),
    "T1040": ("Credential Access", "Network Sniffing"),
    "T1185": ("Collection", "Browser Session Hijacking"),
}


def _lookup(technique: str) -> tuple[str, str] | None:
    """Resolve a technique id, falling back from a sub-technique to its parent."""
    if technique in TECHNIQUE_INFO:
        return TECHNIQUE_INFO[technique]
    parent, _, sub = technique.partition(".")
    if sub and parent in TECHNIQUE_INFO:
        return TECHNIQUE_INFO[parent]
    return None


def tactic_for(technique: str) -> str:
    """The ATT&CK tactic a technique belongs to, or ``UNMAPPED`` if we do not map it."""
    info = _lookup(technique)
    return info[0] if info else UNMAPPED_TACTIC


def technique_name(technique: str) -> str:
    """A friendly technique name for display, falling back to the id itself."""
    info = _lookup(technique)
    return info[1] if info else technique
