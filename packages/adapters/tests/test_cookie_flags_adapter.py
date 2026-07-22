# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""Fixture tests for the cookie-flags adapter (rule PX-FIXTURE).

The recorded envelopes in ``fixtures/`` are the contract: a cookie missing protective
attributes yields one finding per missing attribute, and a fully-flagged cookie yields none,
so a drift in the adapter's output fails CI rather than users.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from provx_sdk.adapters.cookie_flags import (
    SESSION_HIJACK_TECHNIQUE,
    SESSION_THEFT_TECHNIQUE,
    CookieFlagsAdapter,
    encode_cookies,
    parse_cookie,
)
from provx_sdk.findings import Confidence, Module, Severity

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def adapter() -> CookieFlagsAdapter:
    return CookieFlagsAdapter()


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def rule_ids_from_raw(adapter: CookieFlagsAdapter, raw: str) -> list[str]:
    return [d.evidence.matched_rule for d in adapter.parse_output(raw) if d.evidence]


def test_adapter_declares_passive_web_metadata(adapter: CookieFlagsAdapter) -> None:
    assert adapter.name == "cookie_flags"
    assert adapter.category == "web"
    assert adapter.safety == "passive"


def test_flagless_cookie_flags_every_missing_attribute(adapter: CookieFlagsAdapter) -> None:
    drafts = adapter.parse_output(read_fixture("cookie_flags_insecure.json"))

    # Emitted in fixed RULES order for the one cookie the response set.
    assert [d.title for d in drafts] == [
        "Cookie 'sid' is set without the Secure flag",
        "Cookie 'sid' is set without the HttpOnly flag",
        "Cookie 'sid' is set without a SameSite attribute",
    ]
    for draft in drafts:
        assert draft.target == "http://lab-cookies-insecure"
        assert draft.module is Module.WEB
        assert draft.severity in (Severity.LOW, Severity.MEDIUM)
        assert draft.confidence is Confidence.HIGH
        assert draft.cvss is not None and 0.0 <= draft.cvss <= 10.0
        assert draft.attack_techniques
        assert draft.remediation
        assert draft.evidence is not None and draft.evidence.tool_output


def test_fully_flagged_cookie_yields_no_findings(adapter: CookieFlagsAdapter) -> None:
    # The clean-baseline tripwire: Secure + HttpOnly + SameSite present.
    assert adapter.parse_output(read_fixture("cookie_flags_clean.json")) == []


def test_no_set_cookie_header_yields_no_findings(adapter: CookieFlagsAdapter) -> None:
    raw = encode_cookies("http://example.test", 200, [])

    assert adapter.parse_output(raw) == []


def test_attribute_matching_is_case_insensitive(adapter: CookieFlagsAdapter) -> None:
    raw = encode_cookies("http://example.test", 200, ["sid=x; SECURE; httponly; samesite=lax"])

    assert adapter.parse_output(raw) == []


def test_each_cookie_is_scored_independently(adapter: CookieFlagsAdapter) -> None:
    raw = encode_cookies(
        "http://example.test",
        200,
        ["a=1; Secure; HttpOnly; SameSite=Lax", "b=2; Path=/"],
    )

    # Only the second, unflagged cookie fires - once per missing attribute.
    assert rule_ids_from_raw(adapter, raw) == [
        "cookie_flags:secure-missing",
        "cookie_flags:httponly-missing",
        "cookie_flags:samesite-missing",
    ]
    assert [d.title for d in adapter.parse_output(raw)] == [
        "Cookie 'b' is set without the Secure flag",
        "Cookie 'b' is set without the HttpOnly flag",
        "Cookie 'b' is set without a SameSite attribute",
    ]


def test_findings_carry_valid_attack_techniques(adapter: CookieFlagsAdapter) -> None:
    drafts = adapter.parse_output(read_fixture("cookie_flags_insecure.json"))
    techniques = {t for d in drafts for t in d.attack_techniques}

    assert techniques <= {SESSION_THEFT_TECHNIQUE, SESSION_HIJACK_TECHNIQUE}
    assert techniques


def test_analysis_survives_a_redacted_cookie_value(adapter: CookieFlagsAdapter) -> None:
    # The fetch boundary redacts the cookie value (PX-SECRETS) but keeps the name + attributes,
    # so the hygiene checks still fire on exactly what they read - the value was never needed.
    raw = encode_cookies(
        "http://example.test",
        200,
        ["sid=<redacted:sha256:deadbeef>; Path=/"],
    )
    drafts = adapter.parse_output(raw)

    assert [d.title for d in drafts] == [
        "Cookie 'sid' is set without the Secure flag",
        "Cookie 'sid' is set without the HttpOnly flag",
        "Cookie 'sid' is set without a SameSite attribute",
    ]


def test_parse_cookie_extracts_name_and_attribute_keys() -> None:
    name, attributes = parse_cookie("sid=abc; Path=/; Secure; SameSite=Strict")

    assert name == "sid"
    assert attributes == {"path", "secure", "samesite"}


def test_parse_output_is_deterministic(adapter: CookieFlagsAdapter) -> None:
    raw = read_fixture("cookie_flags_insecure.json")

    assert adapter.parse_output(raw) == adapter.parse_output(raw)


def test_findings_are_attributed_to_the_responding_host(adapter: CookieFlagsAdapter) -> None:
    # PX-EVIDENCE: after a redirect the finding names the host that answered.
    raw = encode_cookies("http://asked.test", 200, ["s=1"], final_url="http://answered.test")
    drafts = adapter.parse_output(raw)

    assert drafts
    assert {d.target for d in drafts} == {"http://answered.test"}


def test_build_command_is_rejected_for_an_in_process_adapter(
    adapter: CookieFlagsAdapter,
) -> None:
    with pytest.raises(NotImplementedError):
        adapter.build_command(targets=["http://example.test"], use_cases=["cookies"])
