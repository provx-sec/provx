# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""Adapter discovery tests - the built-in adapter must resolve through its entry point."""

from __future__ import annotations

import pytest
from provx_sdk.adapters.security_headers import SecurityHeadersAdapter
from provx_sdk.plugins import ToolAdapter
from provx_sdk.registry import AdapterNotFoundError, load_adapter, load_adapters


def test_built_in_adapter_is_discovered_via_entry_point() -> None:
    assert isinstance(load_adapters().get("security_headers"), SecurityHeadersAdapter)


def test_loaded_adapter_satisfies_the_tool_adapter_protocol() -> None:
    assert isinstance(load_adapter("security_headers"), ToolAdapter)


def test_unknown_adapter_name_raises() -> None:
    with pytest.raises(AdapterNotFoundError):
        load_adapter("no-such-adapter")
