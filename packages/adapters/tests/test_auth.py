# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Unit tests for explicit-credential normalization (rule PX-SECRETS).

``build_auth`` is the single place three credential kinds collapse to one request header, so its
normalization and validation are the contract the egress boundary depends on. The redacting repr is
part of the secrecy guarantee and is asserted here too.
"""

from __future__ import annotations

import pytest
from provx_sdk.auth import (
    AuthCredential,
    InvalidCredentialError,
    build_auth,
    resolve_header_name,
)


def test_bearer_maps_to_authorization_and_adds_prefix_once() -> None:
    cred = build_auth("bearer", "abc.def.ghi")
    assert cred == AuthCredential("Authorization", "Bearer abc.def.ghi")

    # A value already carrying the scheme is not doubled.
    already = build_auth("bearer", "Bearer abc.def.ghi")
    assert already.header_value == "Bearer abc.def.ghi"


def test_cookie_maps_to_cookie_header_verbatim() -> None:
    cred = build_auth("cookie", "sid=xyz; theme=dark")
    assert cred == AuthCredential("Cookie", "sid=xyz; theme=dark")


def test_custom_header_uses_supplied_name_and_value() -> None:
    cred = build_auth("header", "k3y", header_name="X-API-Key")
    assert cred == AuthCredential("X-API-Key", "k3y")


def test_type_is_case_insensitive_and_trimmed() -> None:
    assert build_auth("  BEARER ", "t").header_name == "Authorization"
    assert resolve_header_name("Cookie", None) == "Cookie"


@pytest.mark.parametrize(
    ("cred_type", "value", "header_name"),
    [
        ("bearer", "", None),  # empty secret
        ("cookie", "", None),
        ("header", "v", None),  # custom header with no name
        ("header", "v", "   "),  # blank name
        ("magic", "v", None),  # unknown type
    ],
)
def test_invalid_inputs_are_refused(cred_type: str, value: str, header_name: str | None) -> None:
    with pytest.raises(InvalidCredentialError):
        build_auth(cred_type, value, header_name)


def test_repr_never_reveals_the_secret() -> None:
    cred = build_auth("bearer", "s3cr3t-token-value")
    text = repr(cred)
    assert "s3cr3t-token-value" not in text
    assert "<redacted>" in text
    # The header name is safe to show - it says which control was applied, not the secret.
    assert "Authorization" in text
