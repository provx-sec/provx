# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""Fixture tests for the TLS / transport-hygiene adapter (rule PX-FIXTURE).

The recorded envelopes in ``fixtures/`` are the contract: HTTP-derivable checks (HSTS and the
HTTP->HTTPS upgrade) and certificate/protocol checks are all exercised here as pure parsing,
so a drift in the adapter's output fails CI rather than users. The live TLS handshake is
covered separately in ``test_fetch.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from provx_sdk.adapters.tls_transport import (
    AITM_TECHNIQUE,
    SNIFF_TECHNIQUE,
    TlsTransportAdapter,
    encode_transport,
)
from provx_sdk.findings import Confidence, Module, Severity

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def adapter() -> TlsTransportAdapter:
    return TlsTransportAdapter()


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def rule_ids(adapter: TlsTransportAdapter, fixture: str) -> list[str]:
    drafts = adapter.parse_output(read_fixture(fixture))
    return [d.evidence.matched_rule for d in drafts if d.evidence]


def test_adapter_declares_passive_web_metadata(adapter: TlsTransportAdapter) -> None:
    assert adapter.name == "tls"
    assert adapter.category == "web"
    assert adapter.safety == "passive"


def test_insecure_target_flags_hsts_and_missing_upgrade(adapter: TlsTransportAdapter) -> None:
    drafts = adapter.parse_output(read_fixture("tls_insecure.json"))

    # Emitted in fixed RULES order: the upgrade check precedes the header check.
    assert [d.title for d in drafts] == [
        "HTTP does not redirect to HTTPS",
        "Missing Strict-Transport-Security header",
    ]
    for draft in drafts:
        assert draft.target == "http://lab-tls-insecure"
        assert draft.module is Module.WEB
        assert draft.severity is Severity.MEDIUM
        assert draft.confidence is Confidence.HIGH
        assert draft.cvss is not None and 0.0 <= draft.cvss <= 10.0
        assert draft.attack_techniques
        assert draft.remediation
        assert draft.evidence is not None and draft.evidence.tool_output


def test_secure_http_target_yields_no_findings(adapter: TlsTransportAdapter) -> None:
    # Redirects to HTTPS and sends HSTS on the 301: the clean-baseline tripwire.
    assert adapter.parse_output(read_fixture("tls_secure.json")) == []


def test_clean_https_target_yields_no_findings(adapter: TlsTransportAdapter) -> None:
    assert adapter.parse_output(read_fixture("tls_https_clean.json")) == []


def test_expired_certificate_is_reported(adapter: TlsTransportAdapter) -> None:
    assert rule_ids(adapter, "tls_cert_expired.json") == ["tls:cert-expired"]


def test_self_signed_certificate_is_reported_as_untrusted(
    adapter: TlsTransportAdapter,
) -> None:
    assert rule_ids(adapter, "tls_untrusted.json") == ["tls:cert-untrusted"]


def test_weak_protocol_is_reported(adapter: TlsTransportAdapter) -> None:
    assert rule_ids(adapter, "tls_weak_protocol.json") == ["tls:weak-protocol"]


def test_findings_carry_valid_attack_techniques(adapter: TlsTransportAdapter) -> None:
    drafts = adapter.parse_output(read_fixture("tls_insecure.json"))
    techniques = {t for d in drafts for t in d.attack_techniques}

    assert techniques <= {AITM_TECHNIQUE, SNIFF_TECHNIQUE}
    assert techniques


def test_blank_hsts_value_counts_as_missing(adapter: TlsTransportAdapter) -> None:
    raw = encode_transport(
        "https://example.test",
        200,
        {"Strict-Transport-Security": "   "},
        final_url="https://example.test",
    )

    assert "tls:hsts-missing" in rule_ids_from_raw(adapter, raw)


def test_header_matching_is_case_insensitive(adapter: TlsTransportAdapter) -> None:
    raw = encode_transport(
        "https://example.test",
        200,
        {"STRICT-TRANSPORT-SECURITY": "max-age=31536000"},
        final_url="https://example.test",
    )

    assert adapter.parse_output(raw) == []


def test_https_target_does_not_flag_a_missing_upgrade(adapter: TlsTransportAdapter) -> None:
    # An https target is already on secure transport; the upgrade check must not fire.
    raw = encode_transport(
        "https://example.test",
        200,
        {"strict-transport-security": "max-age=31536000"},
        final_url="https://example.test",
    )

    assert "tls:no-https-redirect" not in rule_ids_from_raw(adapter, raw)


def test_parse_output_is_deterministic(adapter: TlsTransportAdapter) -> None:
    raw = read_fixture("tls_insecure.json")

    assert adapter.parse_output(raw) == adapter.parse_output(raw)


def test_findings_are_attributed_to_the_responding_host(adapter: TlsTransportAdapter) -> None:
    # PX-EVIDENCE: after a redirect the finding names the host that answered.
    raw = encode_transport(
        "http://asked.test",
        200,
        {},
        final_url="http://answered.test",
    )
    drafts = adapter.parse_output(raw)

    assert drafts
    assert {d.target for d in drafts} == {"http://answered.test"}


def test_build_command_is_rejected_for_an_in_process_adapter(
    adapter: TlsTransportAdapter,
) -> None:
    with pytest.raises(NotImplementedError):
        adapter.build_command(targets=["https://example.test"], use_cases=["tls"])


def rule_ids_from_raw(adapter: TlsTransportAdapter, raw: str) -> list[str]:
    return [d.evidence.matched_rule for d in adapter.parse_output(raw) if d.evidence]
