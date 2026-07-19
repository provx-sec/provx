# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Adapter discovery.

Adapters are found through the ``provx.adapters`` entry-point group, never imported by name
from the backend. That is what makes a third-party adapter a drop-in: install the package,
and the platform picks it up with no core edit.
"""

from __future__ import annotations

from importlib.metadata import entry_points

from provx_sdk.plugins import ToolAdapter

ADAPTER_GROUP = "provx.adapters"


class AdapterNotFoundError(LookupError):
    """Raised when a requested adapter is not installed."""


def load_adapters() -> dict[str, ToolAdapter]:
    """Instantiate every installed adapter, keyed by its declared name."""
    discovered: dict[str, ToolAdapter] = {}
    for entry in entry_points(group=ADAPTER_GROUP):
        adapter = entry.load()()
        discovered[adapter.name] = adapter
    return discovered


def load_adapter(name: str) -> ToolAdapter:
    """Load a single adapter by name, raising AdapterNotFoundError if absent."""
    try:
        return load_adapters()[name]
    except KeyError as exc:
        raise AdapterNotFoundError(f"no adapter named {name!r} is installed") from exc
