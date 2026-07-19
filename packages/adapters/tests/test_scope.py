# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""Scope policy tests (rule PX-SCOPE). Scope fails closed and deny always wins."""

from __future__ import annotations

import pytest
from provx_sdk.scope import OutOfScopeError, ScopePolicy, canonical_host, target_host


def test_exact_host_in_allow_list_is_in_scope() -> None:
    policy = ScopePolicy(allow=["app.example.com"])

    assert policy.is_in_scope("https://app.example.com/login")


def test_unlisted_host_is_out_of_scope() -> None:
    policy = ScopePolicy(allow=["app.example.com"])

    assert not policy.is_in_scope("https://other.example.com/")


def test_wildcard_covers_subdomains_and_the_apex() -> None:
    policy = ScopePolicy(allow=["*.example.com"])

    assert policy.is_in_scope("https://api.example.com/")
    assert policy.is_in_scope("https://example.com/")
    assert not policy.is_in_scope("https://example.com.evil.test/")


def test_deny_overrides_a_broader_allow() -> None:
    policy = ScopePolicy(allow=["*.example.com"], deny=["prod.example.com"])

    assert policy.is_in_scope("https://staging.example.com/")
    assert not policy.is_in_scope("https://prod.example.com/")


def test_empty_policy_permits_nothing() -> None:
    assert not ScopePolicy().is_in_scope("https://example.com/")


def test_port_and_credentials_do_not_defeat_matching() -> None:
    policy = ScopePolicy(allow=["example.com"], deny=["evil.test"])

    assert policy.is_in_scope("http://example.com:8080/x")
    assert not policy.is_in_scope("http://example.com@evil.test/")


def test_host_matching_is_case_insensitive() -> None:
    assert ScopePolicy(allow=["example.com"]).is_in_scope("https://EXAMPLE.COM/")


@pytest.mark.parametrize(
    "target",
    ["file:///etc/passwd", "javascript:alert(1)", "not a url", "ftp://example.com/"],
)
def test_non_web_targets_are_out_of_scope(target: str) -> None:
    assert not ScopePolicy(allow=["*.example.com", "example.com"]).is_in_scope(target)


def test_target_host_rejects_a_non_web_scheme() -> None:
    with pytest.raises(OutOfScopeError):
        target_host("file:///etc/passwd")


# --- Bypass regressions (audit SDK-026/027/028) --------------------------------------
# Each of these was IN SCOPE before the safety-in-motion pass. They are the reason the
# matcher canonicalizes hosts and treats deny as subtree-wide.


def test_deny_covers_subdomains_of_the_denied_host() -> None:
    # Was: deny matched the exact label only, so a deeper subdomain slipped the carve-out.
    policy = ScopePolicy(allow=["*.example.com"], deny=["prod.example.com"])

    assert not policy.is_in_scope("https://prod.example.com/")
    assert not policy.is_in_scope("https://a.b.prod.example.com/")


@pytest.mark.parametrize(
    "target",
    [
        "http://2130706433/",
        "http://0x7f.0.0.1/",
        "http://0177.0.0.1/",
        "http://127.1/",
        "http://[::ffff:127.0.0.1]/",
    ],
)
def test_alternate_ip_encodings_cannot_evade_a_deny(target: str) -> None:
    # Was: each spelling is a distinct string, so none matched deny=["127.0.0.1"].
    # One deny rule, written once, must cover every spelling of the same host.
    policy = ScopePolicy(allow=["127.0.0.1"], deny=["127.0.0.1"], allow_dangerous_ranges=True)

    assert not policy.is_in_scope(target)


def test_trailing_dot_host_still_matches_its_rule() -> None:
    # The fully-qualified form names the same host; failing to match it was a false negative.
    assert ScopePolicy(allow=["example.com"]).is_in_scope("http://example.com./")


# --- Dangerous ranges (PX-SCOPE, SSRF containment) -----------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "http://127.0.0.1:8080/",  # loopback
        "http://10.0.0.5/",  # RFC-1918
        "http://192.168.1.1/",  # RFC-1918
        "http://2852039166/",  # metadata, integer-encoded
    ],
)
def test_dangerous_ranges_are_refused_even_when_explicitly_allowed(target: str) -> None:
    # Scope is an engagement boundary; it must not be usable to authorize an SSRF pivot.
    policy = ScopePolicy(allow=["*"] + [target_host(target)])

    assert not policy.is_in_scope(target)


def test_dangerous_ranges_are_reachable_only_behind_the_explicit_override() -> None:
    target = "http://127.0.0.1:8080/"

    assert not ScopePolicy(allow=["127.0.0.1"]).is_in_scope(target)
    assert ScopePolicy(allow=["127.0.0.1"], allow_dangerous_ranges=True).is_in_scope(target)


def test_public_addresses_are_unaffected_by_the_dangerous_range_check() -> None:
    assert ScopePolicy(allow=["8.8.8.8"]).is_in_scope("http://8.8.8.8/")


# --- Host canonicalization ------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2130706433", "127.0.0.1"),
        ("127.1", "127.0.0.1"),
        ("::ffff:127.0.0.1", "127.0.0.1"),
        ("0x7f.0.0.1", "127.0.0.1"),
        ("0177.0.0.1", "127.0.0.1"),
        ("2852039166", "169.254.169.254"),
        ("127.0.0.1", "127.0.0.1"),
        ("EXAMPLE.COM", "example.com"),
        ("example.com.", "example.com"),
        ("example.com", "example.com"),
    ],
)
def test_canonical_host_folds_equivalent_spellings(raw: str, expected: str) -> None:
    assert canonical_host(raw) == expected


def test_canonical_host_punycodes_non_ascii_labels() -> None:
    # A homograph must not be able to present itself as a different ASCII host.
    assert canonical_host("exämple.com").startswith("xn--")
