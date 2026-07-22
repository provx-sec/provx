# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Evidence-at-rest encryption (rules PX-SECRETS, PX-EVIDENCE, PX-ERRORS).

Defence in depth behind the boundary redaction in ``provx_sdk.fetch``: redaction strips known
sensitive *header* values before they are ever sealed, and this layer encrypts the whole stored
``evidence_tool_output`` blob at rest, so anything that slips past redaction (a token echoed in a
body, a future adapter that records more) is still not readable from the database.

The seal is unaffected: ``evidence_sha256`` is computed over the redacted *plaintext* envelope at
capture time, and :func:`decrypt_evidence` reproduces exactly that plaintext, so the capture-time
hash still verifies and the append-only integrity guarantee holds.

Key management is deliberately minimal for this phase: the AES key is derived from ``SECRET_KEY``
via HKDF, so there is no second secret to distribute. A dedicated, rotated KMS-backed key is the
production upgrade (tracked as a residual in docs/KNOWN_ISSUES.md, KI-004).
"""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import DEBUG_ENVIRONMENTS, get_settings

#: Marks an encrypted value and pins the scheme, so a future rotation can add ``v2`` and still
#: read ``v1`` rows. A value without this prefix is a legacy plaintext row.
_PREFIX = "enc:v1:"
_NONCE_BYTES = 12
_KEY_BYTES = 32
_HKDF_INFO = b"provx-evidence-at-rest"
#: Deterministic key material for non-production runs that configure no SECRET_KEY, so the test
#: and local suites exercise the real encrypt/decrypt path without a secret. Never used in prod.
_DEV_KEY_SEED = "provx-evidence-at-rest-dev-key"


class EvidenceKeyError(RuntimeError):
    """No key is available to protect evidence at rest in this environment."""


class EvidenceDecryptError(RuntimeError):
    """Stored evidence could not be decrypted - wrong key, corruption, or tampering."""


def _evidence_key() -> bytes:
    """Derive the 32-byte evidence key from SECRET_KEY (rule PX-SECRETS).

    Fails closed: without a configured secret, a production environment raises rather than
    protecting evidence under a predictable key. Non-production environments fall back to a
    fixed dev seed so the suite still runs the real cipher (rule PX-ERRORS, APP_ENV gate).
    """
    settings = get_settings()
    secret = settings.secret_key.strip()
    if not secret:
        if settings.app_env.strip().lower() not in DEBUG_ENVIRONMENTS:
            raise EvidenceKeyError(
                "SECRET_KEY must be set to encrypt evidence at rest in this environment"
            )
        secret = _DEV_KEY_SEED
    return HKDF(algorithm=hashes.SHA256(), length=_KEY_BYTES, salt=None, info=_HKDF_INFO).derive(
        secret.encode("utf-8")
    )


def encrypt_evidence(plaintext: str) -> str:
    """Encrypt an evidence blob for storage, returning a ``enc:v1:`` tagged base64 string.

    A fresh random nonce per call keeps AES-GCM secure across rows; the ciphertext need not be
    deterministic because the integrity hash is taken over the plaintext, not the stored form.
    """
    nonce = os.urandom(_NONCE_BYTES)
    ciphertext = AESGCM(_evidence_key()).encrypt(nonce, plaintext.encode("utf-8"), None)
    return _PREFIX + base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt_evidence(stored: str) -> str:
    """Recover the plaintext for a stored evidence blob.

    A value without the ``enc:v1:`` prefix is treated as a legacy plaintext row and returned
    unchanged, so existing rows keep reading. A prefixed value that fails to authenticate raises
    a domain error rather than leaking the underlying crypto exception (rule PX-ERRORS).
    """
    if not stored.startswith(_PREFIX):
        return stored
    try:
        blob = base64.b64decode(stored[len(_PREFIX) :], validate=True)
        nonce, ciphertext = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
        return AESGCM(_evidence_key()).decrypt(nonce, ciphertext, None).decode("utf-8")
    except (InvalidTag, ValueError) as exc:
        raise EvidenceDecryptError("stored evidence could not be decrypted") from exc
