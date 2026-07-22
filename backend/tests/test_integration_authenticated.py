# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Integration test for authenticated scanning - **nothing is stubbed**.

This is the reason authenticated scanning was designed before it was built. It drives the real API
(real SQLite persistence, the shipping ``run_scan`` path) against a real HTTP server on loopback
that *requires* a credential: 401 without, 200 with. Neither the egress nor the persistence is
stubbed - a stub could encode the very mistake the feature exists to prevent.

It proves four things end to end:

* (a) the authenticated scan succeeds where an unauthenticated one is refused (401 -> 200);
* (b) the real credential authenticated the request - asserted against the server's own log of the
  ``Authorization`` header it received, not the code's report of itself;
* (c) the credential value appears **nowhere** it should not - not in the sealed evidence, the
  finding, the rendered report, or the logs - and a reflected copy is sealed as ``<redacted:...>``;
* (d) a redirect to an OFF-SCOPE host is stopped **and** carries no credential - the off-scope path
  is never requested at all, so the secret cannot leave scope (rules PX-SCOPE, PX-SECRETS).

The in-scope identity is the hostname ``localhost``; the off-scope redirect targets the loopback
*IP literal* ``127.0.0.1``, which the scope engine refuses as a dangerous range without an explicit
override. Same machine, two identities - so the server genuinely answers the off-scope address if
asked, and the test proves restraint, not inability. Uses stdlib ``http.server`` for the same
reason ``test_integration_redirect.py`` does: a no-stub test must not introduce a stub.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.security.evidence_crypto import decrypt_evidence

BIND_HOST = "127.0.0.1"
#: The in-scope identity: a hostname reaches the loopback server without the dangerous-range
#: override (a hostname is not an IP literal, so the scope engine does not classify it as
#: dangerous), which lets the full API path run against a local target.
IN_SCOPE_NAME = "localhost"
TOKEN = "s3cr3t-bearer-token-value-xyz"
EXPECTED_AUTH = f"Bearer {TOKEN}"


@dataclass
class AuthServer:
    """A live local server that requires a bearer credential, plus what it actually received."""

    base_url: str
    requests: list[tuple[str, str | None]] = field(default_factory=list)


@pytest.fixture
def auth_server() -> Iterator[AuthServer]:
    """A real HTTP server on loopback: 401 without the bearer token, 200 with it."""
    received: list[tuple[str, str | None]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - name fixed by BaseHTTPRequestHandler
            authorization = self.headers.get("Authorization")
            received.append((self.path, authorization))
            port = self.server.server_address[1]

            if self.path == "/needs-auth":
                if authorization == EXPECTED_AUTH:
                    # Reflect the credential back in a response header (a realistic echo) so the
                    # test can prove the seal redacts it rather than storing it raw.
                    self._send(200, {"Authorization": authorization, "server": "nginx"})
                else:
                    self._send(401, {"server": "nginx"})
            elif self.path == "/go-off":
                # Redirect to the loopback IP literal: reachable, but out of scope.
                self._send(302, {"Location": f"http://{BIND_HOST}:{port}/steal"})
            elif self.path == "/steal":
                self._send(200, {"server": "evil"})
            else:
                self._send(404, {})

        def _send(self, status: int, headers: dict[str, str]) -> None:
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args: object) -> None:
            """Silence the default stderr access log."""

    httpd = HTTPServer((BIND_HOST, 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]

    yield AuthServer(base_url=f"http://{IN_SCOPE_NAME}:{port}", requests=received)

    httpd.shutdown()
    httpd.server_close()


def _create_engagement(client: TestClient, targets: list[str]) -> str:
    response = client.post(
        "/engagements",
        json={
            "name": "Authenticated web",
            "scope_allow": [IN_SCOPE_NAME],
            "scope_deny": [],
            "targets": targets,
        },
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def _store_bearer(client: TestClient, engagement_id: str) -> None:
    response = client.post(
        f"/engagements/{engagement_id}/credential",
        json={"cred_type": "bearer", "value": TOKEN},
    )
    assert response.status_code == 201, response.text


def _sealed_evidence(database_url: str) -> list[str]:
    """Every finding's sealed evidence envelope, decrypted - what actually landed at rest."""
    db_file = database_url.split("///", 1)[1]
    connection = sqlite3.connect(db_file)
    try:
        rows = connection.execute("SELECT evidence_tool_output FROM finding").fetchall()
    finally:
        connection.close()
    return [decrypt_evidence(row[0]) for row in rows if row[0] is not None]


def test_unauthenticated_scan_is_refused_where_authenticated_succeeds(
    client: TestClient, auth_server: AuthServer
) -> None:
    target = f"{auth_server.base_url}/needs-auth"

    # (a) Anonymous: the server refuses with 401 and sees no credential.
    anon = _create_engagement(client, [target])
    assert client.post(f"/engagements/{anon}/scan").status_code == 201
    anon_hits = [r for r in auth_server.requests if r[0] == "/needs-auth"]
    assert anon_hits == [("/needs-auth", None)]

    auth_server.requests.clear()

    # (a) + (b) Authenticated: 200, and the server logs the exact credential it received.
    authed = _create_engagement(client, [target])
    _store_bearer(client, authed)
    assert (
        client.post(f"/engagements/{authed}/scan", json={"authenticated": True}).status_code == 201
    )
    authed_hits = [r for r in auth_server.requests if r[0] == "/needs-auth"]
    assert authed_hits == [("/needs-auth", EXPECTED_AUTH)]


def test_credential_never_appears_in_evidence_finding_report_or_logs(
    client: TestClient,
    auth_server: AuthServer,
    database_url: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    target = f"{auth_server.base_url}/needs-auth"
    engagement = _create_engagement(client, [target])
    _store_bearer(client, engagement)

    with caplog.at_level(logging.DEBUG):
        assert (
            client.post(f"/engagements/{engagement}/scan", json={"authenticated": True}).status_code
            == 201
        )

    # (c) The sealed evidence exists, redacts the reflected credential, and never carries the token.
    envelopes = _sealed_evidence(database_url)
    assert envelopes, "the authenticated scan should have produced sealed evidence"
    joined = "\n".join(envelopes)
    assert TOKEN not in joined
    assert "<redacted:sha256:" in joined  # the reflected Authorization header, redacted in the seal

    # (c) Nor in the findings list, the rendered report, or the captured logs.
    findings = client.get(f"/engagements/{engagement}/findings")
    assert findings.status_code == 200
    assert TOKEN not in findings.text

    report = client.get(f"/engagements/{engagement}/report")
    assert report.status_code == 200
    assert TOKEN not in report.text

    # (c) Provx's own logs never carry the credential. Scoped to Provx loggers deliberately: the
    # third-party httpcore/httpx wire-debug logger echoes the server's reflected response header
    # before Provx ever redacts it, but that diagnostic is off by default in production and is not
    # a Provx control. What this feature owns - the app and SDK loggers - must stay clean.
    provx_logs = "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name.startswith(("app", "provx_sdk"))
    )
    assert TOKEN not in provx_logs


def test_off_scope_redirect_is_stopped_and_carries_no_credential(
    client: TestClient, auth_server: AuthServer, database_url: str
) -> None:
    # An in-scope target that redirects to the off-scope loopback IP literal.
    engagement = _create_engagement(client, [f"{auth_server.base_url}/go-off"])
    _store_bearer(client, engagement)

    assert (
        client.post(f"/engagements/{engagement}/scan", json={"authenticated": True}).status_code
        == 201
    )

    paths = [path for path, _ in auth_server.requests]
    # (d) The credential rode the in-scope hop but the off-scope target was never requested at all,
    # so the secret never left scope. This is the assertion only a real server can make.
    assert ("/go-off", EXPECTED_AUTH) in auth_server.requests
    assert "/steal" not in paths

    # (d) And the sealed evidence records the refusal, not a fetched off-scope response.
    assert any("out_of_scope_redirect" in envelope for envelope in _sealed_evidence(database_url))


def test_anonymous_scan_still_works_with_no_body(
    client: TestClient, auth_server: AuthServer
) -> None:
    # An old client that sends no scan body is unchanged - authenticated scanning is additive.
    engagement = _create_engagement(client, [f"{auth_server.base_url}/needs-auth"])
    response: Any = client.post(f"/engagements/{engagement}/scan")
    assert response.status_code == 201
    assert auth_server.requests[-1] == ("/needs-auth", None)
