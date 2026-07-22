# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Tests for evidence-at-rest encryption (rules PX-SECRETS, PX-EVIDENCE, PX-ERRORS).

The property that matters: a stored evidence blob is ciphertext that does not contain the
plaintext, it round-trips back exactly (so the capture-time seal still verifies), legacy
plaintext keeps reading, and a missing key fails closed in production.
"""

from __future__ import annotations

import hashlib

import pytest

from app.config import Settings
from app.security import evidence_crypto
from app.security.evidence_crypto import (
    EvidenceDecryptError,
    EvidenceKeyError,
    decrypt_evidence,
    encrypt_evidence,
)

PLAINTEXT = '{"headers": {"set-cookie": "sid=<redacted:sha256:deadbeef>; Path=/"}}'


def test_round_trip_recovers_the_exact_plaintext() -> None:
    assert decrypt_evidence(encrypt_evidence(PLAINTEXT)) == PLAINTEXT


def test_ciphertext_is_tagged_and_hides_the_plaintext() -> None:
    stored = encrypt_evidence("super-secret-token-value")

    assert stored.startswith("enc:v1:")
    assert "super-secret-token-value" not in stored


def test_same_plaintext_encrypts_differently_each_time() -> None:
    # A fresh nonce per call: identical evidence must not produce identical ciphertext.
    assert encrypt_evidence(PLAINTEXT) != encrypt_evidence(PLAINTEXT)


def test_the_seal_still_verifies_after_a_round_trip() -> None:
    # evidence_sha256 is taken over the plaintext at capture time; decryption must reproduce
    # exactly those bytes or the append-only integrity guarantee breaks (PX-EVIDENCE).
    at_capture = hashlib.sha256(PLAINTEXT.encode("utf-8")).hexdigest()

    recovered = decrypt_evidence(encrypt_evidence(PLAINTEXT))

    assert hashlib.sha256(recovered.encode("utf-8")).hexdigest() == at_capture


def test_legacy_plaintext_without_the_prefix_is_returned_unchanged() -> None:
    # Rows written before encryption existed have no prefix and must keep reading.
    assert decrypt_evidence("server: nginx") == "server: nginx"


def test_tampered_ciphertext_raises_a_domain_error() -> None:
    stored = encrypt_evidence(PLAINTEXT)
    tampered = stored[:-4] + ("AAAA" if not stored.endswith("AAAA") else "BBBB")

    with pytest.raises(EvidenceDecryptError):
        decrypt_evidence(tampered)


def test_garbage_after_the_prefix_raises_a_domain_error() -> None:
    with pytest.raises(EvidenceDecryptError):
        decrypt_evidence("enc:v1:not-valid-base64!!")


def test_missing_secret_key_fails_closed_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        evidence_crypto, "get_settings", lambda: Settings(app_env="production", secret_key="")
    )

    with pytest.raises(EvidenceKeyError):
        encrypt_evidence(PLAINTEXT)


def test_missing_secret_key_falls_back_to_a_dev_key_outside_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        evidence_crypto, "get_settings", lambda: Settings(app_env="testing", secret_key="")
    )

    assert decrypt_evidence(encrypt_evidence(PLAINTEXT)) == PLAINTEXT


def test_a_configured_secret_key_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        evidence_crypto,
        "get_settings",
        lambda: Settings(app_env="production", secret_key="operator provided key"),
    )

    assert decrypt_evidence(encrypt_evidence(PLAINTEXT)) == PLAINTEXT
