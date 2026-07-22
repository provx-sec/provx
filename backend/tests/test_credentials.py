# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Credential storage + authenticated-scan wiring (rules PX-SECRETS, PX-ERRORS).

These prove the write-only contract at the API and the model seam: the secret is encrypted at
rest, never returned by any endpoint, and an authenticated scan with no credential fails safe with
a user-safe error. The end-to-end proof that the credential actually authenticates a request and
never reaches sealed evidence lives in ``test_integration_authenticated.py`` (no stubs).
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models.tables import Credential


def _create_engagement(client: TestClient, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": "Acme external web",
        "scope_allow": ["*.example.com"],
        "scope_deny": [],
        "targets": ["https://app.example.com"],
    }
    payload.update(overrides)
    response = client.post("/engagements", json=payload)
    assert response.status_code == 201, response.text
    return dict(response.json())


def test_post_credential_never_returns_the_value(client: TestClient) -> None:
    engagement = _create_engagement(client)
    response = client.post(
        f"/engagements/{engagement['id']}/credential",
        json={"cred_type": "bearer", "value": "s3cr3t-token", "label": "staging"},
    )
    assert response.status_code == 201, response.text
    body = response.json()

    assert body["cred_type"] == "bearer"
    assert body["header_name"] == "Authorization"
    assert body["label"] == "staging"
    # Write-only: the value never appears in any field of the response (rule PX-SECRETS).
    assert "s3cr3t-token" not in response.text
    assert "value" not in body


def test_get_credential_returns_metadata_only(client: TestClient) -> None:
    engagement = _create_engagement(client)
    client.post(
        f"/engagements/{engagement['id']}/credential",
        json={"cred_type": "header", "value": "k3y", "header_name": "X-API-Key"},
    )

    response = client.get(f"/engagements/{engagement['id']}/credential")
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["cred_type"] == "header"
    assert body["header_name"] == "X-API-Key"
    assert "k3y" not in response.text


def test_get_credential_404_when_absent(client: TestClient) -> None:
    engagement = _create_engagement(client)
    response = client.get(f"/engagements/{engagement['id']}/credential")
    assert response.status_code == 404
    assert response.json()["error_code"] == "credential_not_found"


def test_post_credential_replaces_the_existing_one(client: TestClient) -> None:
    engagement = _create_engagement(client)
    url = f"/engagements/{engagement['id']}/credential"
    client.post(url, json={"cred_type": "bearer", "value": "first"})
    client.post(url, json={"cred_type": "cookie", "value": "sid=second"})

    body = client.get(url).json()
    assert body["cred_type"] == "cookie"
    assert body["header_name"] == "Cookie"


def test_delete_credential(client: TestClient) -> None:
    engagement = _create_engagement(client)
    url = f"/engagements/{engagement['id']}/credential"
    client.post(url, json={"cred_type": "bearer", "value": "tok"})

    assert client.delete(url).status_code == 204
    assert client.get(url).status_code == 404
    # Deleting again is a clean 404, not a 500.
    assert client.delete(url).status_code == 404


def test_custom_header_without_a_name_is_rejected(client: TestClient) -> None:
    engagement = _create_engagement(client)
    response = client.post(
        f"/engagements/{engagement['id']}/credential",
        json={"cred_type": "header", "value": "k3y"},
    )
    assert response.status_code == 400
    assert response.json()["error_code"] == "invalid_credential"


def test_unknown_credential_type_is_rejected_by_schema(client: TestClient) -> None:
    engagement = _create_engagement(client)
    response = client.post(
        f"/engagements/{engagement['id']}/credential",
        json={"cred_type": "oauth", "value": "x"},
    )
    assert response.status_code == 422  # schema pattern rejects it before the handler


def test_credential_on_a_missing_engagement_is_404(client: TestClient) -> None:
    response = client.post(
        f"/engagements/{uuid.uuid4()}/credential",
        json={"cred_type": "bearer", "value": "tok"},
    )
    assert response.status_code == 404


def test_authenticated_scan_without_a_credential_fails_safe(client: TestClient) -> None:
    engagement = _create_engagement(client)
    response = client.post(f"/engagements/{engagement['id']}/scan", json={"authenticated": True})
    assert response.status_code == 400
    body = response.json()
    assert body["error_code"] == "no_credential"
    # User-safe: no internal detail leaked (rule PX-ERRORS).
    assert "traceback" not in response.text.lower()


async def test_value_is_encrypted_at_rest_and_round_trips(session: AsyncSession) -> None:
    credential = Credential.from_input(
        engagement_id=uuid.uuid4(),
        cred_type="bearer",
        value="plaintext-token",
        label="lab",
    )
    # Stored form is the enc:v1: envelope, not the secret (rule PX-SECRETS).
    assert credential.value_encrypted.startswith("enc:v1:")
    assert "plaintext-token" not in credential.value_encrypted

    # Decrypted only in memory at scan time, normalized into the header to inject.
    auth = credential.to_auth()
    assert auth.header_name == "Authorization"
    assert auth.header_value == "Bearer plaintext-token"


@pytest.mark.parametrize(
    ("cred_type", "value", "header_name", "expected_name", "expected_value"),
    [
        ("bearer", "tok", None, "Authorization", "Bearer tok"),
        ("cookie", "sid=abc", None, "Cookie", "sid=abc"),
        ("header", "k3y", "X-API-Key", "X-API-Key", "k3y"),
    ],
)
def test_model_to_auth_normalizes_each_kind(
    cred_type: str,
    value: str,
    header_name: str | None,
    expected_name: str,
    expected_value: str,
) -> None:
    credential = Credential.from_input(
        engagement_id=uuid.uuid4(),
        cred_type=cred_type,
        value=value,
        header_name=header_name,
    )
    auth = credential.to_auth()
    assert (auth.header_name, auth.header_value) == (expected_name, expected_value)
