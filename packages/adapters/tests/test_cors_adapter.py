# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""Fixture tests for the CORS-misconfiguration adapter (rule PX-FIXTURE).

The recorded envelopes in ``fixtures/`` are the contract: each permissive CORS shape yields
its finding and a policy with no cross-origin sharing yields none, so a drift in the adapter's
output fails CI rather than users.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from provx_sdk.adapters.cors import (
    EXPLOIT_TECHNIQUE,
    SESSION_THEFT_TECHNIQUE,
    CorsAdapter,
    encode_cors,
)
from provx_sdk.findings import Confidence, Module, Severity

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def adapter() -> CorsAdapter:
    return CorsAdapter()


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def rule_ids_from_raw(adapter: CorsAdapter, raw: str) -> list[str]:
    return [d.evidence.matched_rule for d in adapter.parse_output(raw) if d.evidence]


def test_adapter_declares_passive_web_metadata(adapter: CorsAdapter) -> None:
    assert adapter.name == "cors"
    assert adapter.category == "web"
    assert adapter.safety == "passive"


def test_wildcard_origin_is_flagged(adapter: CorsAdapter) -> None:
    drafts = adapter.parse_output(read_fixture("cors_wildcard.json"))

    assert [d.title for d in drafts] == ["CORS allows requests from any origin"]
    draft = drafts[0]
    assert draft.target == "http://lab-cors-wildcard"
    assert draft.module is Module.WEB
    assert draft.severity is Severity.MEDIUM
    assert draft.confidence is Confidence.HIGH
    assert draft.cvss is not None and 0.0 <= draft.cvss <= 10.0
    assert draft.attack_techniques
    assert draft.remediation
    assert draft.evidence is not None and draft.evidence.tool_output
    assert draft.evidence.matched_rule == "cors:wildcard-origin"


def test_wildcard_with_credentials_is_the_high_severity_case(adapter: CorsAdapter) -> None:
    raw = encode_cors(
        "http://api.example.test",
        200,
        {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    drafts = adapter.parse_output(raw)

    assert rule_ids_from_raw(adapter, raw) == ["cors:wildcard-with-credentials"]
    assert drafts[0].severity is Severity.HIGH


def test_null_origin_is_flagged(adapter: CorsAdapter) -> None:
    assert rule_ids_from_raw(adapter, read_fixture("cors_null.json")) == ["cors:null-origin"]


def test_credentialed_specific_origin_is_flagged_at_reduced_confidence(
    adapter: CorsAdapter,
) -> None:
    drafts = adapter.parse_output(read_fixture("cors_credentialed.json"))

    assert [d.evidence.matched_rule for d in drafts if d.evidence] == ["cors:credentialed-origin"]
    # Passive observation cannot confirm the origin is reflected, only that it is credentialed.
    assert drafts[0].confidence is Confidence.MEDIUM
    assert drafts[0].severity is Severity.HIGH


def test_no_cors_headers_yields_no_findings(adapter: CorsAdapter) -> None:
    # The clean-baseline tripwire.
    assert adapter.parse_output(read_fixture("cors_clean.json")) == []


def test_specific_origin_without_credentials_is_not_a_finding(adapter: CorsAdapter) -> None:
    # A fixed allowlisted origin is an intended, common configuration.
    raw = encode_cors(
        "http://api.example.test", 200, {"Access-Control-Allow-Origin": "https://app.example"}
    )

    assert adapter.parse_output(raw) == []


def test_header_matching_is_case_insensitive(adapter: CorsAdapter) -> None:
    raw = encode_cors("http://api.example.test", 200, {"ACCESS-CONTROL-ALLOW-ORIGIN": "*"})

    assert rule_ids_from_raw(adapter, raw) == ["cors:wildcard-origin"]


def test_findings_carry_valid_attack_techniques(adapter: CorsAdapter) -> None:
    raw = encode_cors(
        "http://api.example.test",
        200,
        {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"},
    )
    techniques = {t for d in adapter.parse_output(raw) for t in d.attack_techniques}

    assert techniques <= {EXPLOIT_TECHNIQUE, SESSION_THEFT_TECHNIQUE}
    assert techniques


def test_parse_output_is_deterministic(adapter: CorsAdapter) -> None:
    raw = read_fixture("cors_wildcard.json")

    assert adapter.parse_output(raw) == adapter.parse_output(raw)


def test_findings_are_attributed_to_the_responding_host(adapter: CorsAdapter) -> None:
    # PX-EVIDENCE: after a redirect the finding names the host that answered.
    raw = encode_cors(
        "http://asked.test",
        200,
        {"Access-Control-Allow-Origin": "*"},
        final_url="http://answered.test",
    )
    drafts = adapter.parse_output(raw)

    assert drafts
    assert {d.target for d in drafts} == {"http://answered.test"}


def test_build_command_is_rejected_for_an_in_process_adapter(adapter: CorsAdapter) -> None:
    with pytest.raises(NotImplementedError):
        adapter.build_command(targets=["http://example.test"], use_cases=["cors"])
