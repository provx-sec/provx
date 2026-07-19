# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""Fixture tests for the security-headers adapter (rule PX-FIXTURE).

The recorded envelopes in ``fixtures/`` are the contract: if the adapter's output ever
drifts from what these assert, CI fails rather than users.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from provx_sdk.adapters.security_headers import (
    RECON_TECHNIQUE,
    RULES,
    SecurityHeadersAdapter,
    encode_response,
)
from provx_sdk.findings import Confidence, Module, Severity

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def adapter() -> SecurityHeadersAdapter:
    return SecurityHeadersAdapter()


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_adapter_declares_passive_web_metadata(adapter: SecurityHeadersAdapter) -> None:
    assert adapter.name == "security_headers"
    assert adapter.category == "web"
    assert adapter.safety == "passive"


def test_missing_headers_fixture_yields_expected_findings(
    adapter: SecurityHeadersAdapter,
) -> None:
    drafts = adapter.parse_output(read_fixture("security_headers_missing.json"))

    # The fixture sends only X-Content-Type-Options, so every other rule should fire.
    assert [d.title for d in drafts] == [
        "Missing Content-Security-Policy header",
        "Missing X-Frame-Options header",
        "Missing Strict-Transport-Security header",
        "Missing Referrer-Policy header",
    ]
    for draft in drafts:
        assert draft.target == "http://lab-missing-headers"
        assert draft.module is Module.WEB
        assert draft.severity is Severity.LOW
        assert draft.confidence is Confidence.HIGH
        assert draft.cvss is not None and 0.0 <= draft.cvss <= 10.0
        assert draft.attack_techniques == [RECON_TECHNIQUE]
        assert draft.remediation
        assert draft.evidence is not None and draft.evidence.tool_output


def test_hardened_fixture_yields_no_findings(adapter: SecurityHeadersAdapter) -> None:
    assert adapter.parse_output(read_fixture("security_headers_hardened.json")) == []


def test_blank_header_value_counts_as_missing(adapter: SecurityHeadersAdapter) -> None:
    raw = encode_response("http://example.test", 200, {"X-Frame-Options": "   "})
    titles = [d.title for d in adapter.parse_output(raw)]

    assert "Missing X-Frame-Options header" in titles


def test_header_matching_is_case_insensitive(adapter: SecurityHeadersAdapter) -> None:
    raw = encode_response(
        "http://example.test", 200, {rule.header.upper(): "set" for rule in RULES}
    )

    assert adapter.parse_output(raw) == []


def test_parse_output_is_deterministic(adapter: SecurityHeadersAdapter) -> None:
    raw = read_fixture("security_headers_missing.json")

    assert adapter.parse_output(raw) == adapter.parse_output(raw)


def test_redirected_fixture_attributes_findings_to_the_responding_host(
    adapter: SecurityHeadersAdapter,
) -> None:
    # PX-EVIDENCE: after a redirect the finding must name the host that sent the headers,
    # not the one that was asked.
    drafts = adapter.parse_output(read_fixture("security_headers_redirected.json"))

    assert drafts
    assert {d.target for d in drafts} == {"http://lab-redirect/final"}


def test_envelope_records_the_redirect_chain_and_both_urls() -> None:
    raw = encode_response(
        "http://a.example.test",
        200,
        {},
        final_url="http://b.example.test",
        redirect_chain=["http://a.example.test", "http://b.example.test"],
    )
    payload = json.loads(raw)

    assert payload["target"] == "http://a.example.test"
    assert payload["final_url"] == "http://b.example.test"
    assert payload["redirect_chain"] == ["http://a.example.test", "http://b.example.test"]


def test_build_command_is_rejected_for_an_in_process_adapter(
    adapter: SecurityHeadersAdapter,
) -> None:
    with pytest.raises(NotImplementedError):
        adapter.build_command(targets=["http://example.test"], use_cases=["security_headers"])
