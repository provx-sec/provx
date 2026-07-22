# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""Fixture tests for the well-known security.txt adapter (rule PX-FIXTURE).

The recorded envelopes in ``fixtures/`` are the contract: an absent file and a served-but-
invalid file each yield their finding, and a valid RFC 9116 security.txt yields none, so a
drift in the adapter's output fails CI rather than users.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from provx_sdk.adapters.wellknown import (
    DISCLOSURE_TECHNIQUE,
    WellKnownAdapter,
    encode_wellknown,
)
from provx_sdk.findings import Confidence, Module, Severity

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def adapter() -> WellKnownAdapter:
    return WellKnownAdapter()


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def rule_ids_from_raw(adapter: WellKnownAdapter, raw: str) -> list[str]:
    return [d.evidence.matched_rule for d in adapter.parse_output(raw) if d.evidence]


def test_adapter_declares_passive_web_metadata(adapter: WellKnownAdapter) -> None:
    assert adapter.name == "wellknown"
    assert adapter.category == "web"
    assert adapter.safety == "passive"


def test_absent_security_txt_is_flagged(adapter: WellKnownAdapter) -> None:
    drafts = adapter.parse_output(read_fixture("wellknown_missing.json"))

    assert [d.title for d in drafts] == ["No /.well-known/security.txt is published"]
    draft = drafts[0]
    assert draft.target == "http://lab-wellknown-missing/.well-known/security.txt"
    assert draft.module is Module.WEB
    assert draft.severity is Severity.LOW
    assert draft.confidence is Confidence.HIGH
    assert draft.cvss is not None and 0.0 <= draft.cvss <= 10.0
    assert draft.attack_techniques == [DISCLOSURE_TECHNIQUE]
    assert draft.remediation
    assert draft.evidence is not None and draft.evidence.tool_output
    assert draft.evidence.matched_rule == "wellknown:security-txt-missing"


def test_soft_404_html_is_flagged_as_unparseable(adapter: WellKnownAdapter) -> None:
    # A 200 that returns an HTML page rather than a security.txt is the soft-404 trap the
    # body check exists to catch.
    assert rule_ids_from_raw(adapter, read_fixture("wellknown_unparseable.json")) == [
        "wellknown:security-txt-unparseable"
    ]


def test_valid_security_txt_yields_no_findings(adapter: WellKnownAdapter) -> None:
    # The clean-baseline tripwire: a 200 whose body carries the mandatory Contact field.
    assert adapter.parse_output(read_fixture("wellknown_clean.json")) == []


def test_contact_field_matching_is_case_insensitive(adapter: WellKnownAdapter) -> None:
    raw = encode_wellknown(
        "http://example.test",
        200,
        "CONTACT: mailto:security@example.test\n",
        security_txt_url="http://example.test/.well-known/security.txt",
    )

    assert adapter.parse_output(raw) == []


def test_a_contact_mention_inside_prose_is_not_a_valid_file(adapter: WellKnownAdapter) -> None:
    raw = encode_wellknown(
        "http://example.test",
        200,
        "<p>Please use our contact: form to reach us.</p>",
        security_txt_url="http://example.test/.well-known/security.txt",
    )

    assert rule_ids_from_raw(adapter, raw) == ["wellknown:security-txt-unparseable"]


def test_parse_output_is_deterministic(adapter: WellKnownAdapter) -> None:
    raw = read_fixture("wellknown_missing.json")

    assert adapter.parse_output(raw) == adapter.parse_output(raw)


def test_findings_are_attributed_to_the_probed_resource(adapter: WellKnownAdapter) -> None:
    # PX-EVIDENCE: the finding names the security.txt URL that actually answered.
    raw = encode_wellknown(
        "http://asked.test",
        404,
        "",
        security_txt_url="http://answered.test/.well-known/security.txt",
    )
    drafts = adapter.parse_output(raw)

    assert drafts
    assert {d.target for d in drafts} == {"http://answered.test/.well-known/security.txt"}


def test_build_command_is_rejected_for_an_in_process_adapter(
    adapter: WellKnownAdapter,
) -> None:
    with pytest.raises(NotImplementedError):
        adapter.build_command(targets=["http://example.test"], use_cases=["wellknown"])
