# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Integration test for authenticated scanning - **nothing is stubbed**.

This is the reason authenticated scanning was designed before it was built. It drives the real API
(real SQLite persistence, the shipping ``run_scan`` path) against a real HTTP server on loopback
that *requires* a credential: 401 without, 200 with. Neither the egress nor the persistence is
stubbed - a stub could encode the very mistake the feature exists to prevent.

What each assertion actually establishes (stated honestly - the two are not the same claim):

* **PROOF** - the assertion fails if its named production control is reverted, so it *proves* the
  control works. Every sealed-evidence check below is a proof: the credential value is absent from
  the decrypted envelope, header **and** body, and the reflected copy is sealed as
  ``<redacted:...>``.
* **REGRESSION GUARD** - the assertion passes today because the surface it inspects (the findings
  API projection, the rendered report, Provx's own loggers) carries no evidence *by construction*,
  so no current redaction line is what keeps the token out. It would catch a *future* change that
  started rendering evidence there. It does **not** prove a redaction control today. Making these
  into proofs would need a production change (an evidence excerpt on ``FindingRead`` or the report),
  which is out of scope for this test; the guards are labelled as such at each call site.

The proofs, by control:

* (a) an authenticated scan succeeds where an unauthenticated one is refused (401 -> 200), and the
  real credential authenticated the request - asserted against the server's own log of the
  ``Authorization`` header it received, not the code's report of itself;
* (b) a credential reflected in a **response header** is sealed redacted, across all three
  credential kinds (bearer, cookie, custom header). The custom-header case is the one that
  exercises the ``extra_sensitive`` denylist extension - an unredacted custom header would be a
  real leak (rules PX-SECRETS, PX-EVIDENCE);
* (c) a credential reflected in a **response body** is scrubbed before the body is sealed - the
  ``redact_body`` control, driven end to end through the body-sealing ``wellknown`` adapter;
* (d) an off-scope redirect is stopped and carries no credential, proven for **two** off-scope
  identities: a dangerous-range IP literal (``127.0.0.1``) and a plain hostname
  (``provx-offscope.test``). The hostname case isolates the allow-list branch of the scope check -
  a non-dangerous host can only be refused by the allow list, never by the dangerous-range guard -
  so it pins the redirect scope re-check specifically (rules PX-SCOPE, PX-SECRETS).

The in-scope identity is the hostname ``localhost``; the IP-literal off-scope redirect targets the
loopback literal ``127.0.0.1``, which the scope engine refuses as a dangerous range without an
explicit override. Same machine, two identities - so the server genuinely answers the off-scope
address if asked, and the test proves restraint, not inability. The hostname off-scope target uses
the ``.test`` TLD, which RFC 6761 guarantees never resolves, so it can never be reached even if the
guard were removed. Uses stdlib ``http.server`` for the same reason ``test_integration_redirect.py``
does: a no-stub test must not introduce a stub.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import threading
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models.tables import Engagement
from app.security.evidence_crypto import decrypt_evidence
from app.services.credentials import load_auth
from app.services.scan_runner import run_scan

BIND_HOST = "127.0.0.1"
#: The in-scope identity: a hostname reaches the loopback server without the dangerous-range
#: override (a hostname is not an IP literal, so the scope engine does not classify it as
#: dangerous), which lets the full API path run against a local target.
IN_SCOPE_NAME = "localhost"
#: An off-scope host that is a hostname, not an IP literal, so only the scope allow-list - never the
#: dangerous-range guard - can refuse it. ``.test`` is reserved by RFC 6761 and never resolves.
OFF_SCOPE_NAME = "provx-offscope.test"
TOKEN = "s3cr3t-bearer-token-value-xyz"
EXPECTED_AUTH = f"Bearer {TOKEN}"
#: A custom credential header whose name is not in the base sensitive-header denylist, so its
#: redaction depends on the per-fetch ``extra_sensitive`` extension.
CUSTOM_HEADER = "X-Api-Key"
#: A JWT-shaped string the body test plants alongside the raw token, to exercise the pattern arm of
#: ``redact_body`` (the ``eyJ...`` shape) as well as its exact-string arm.
JWT_SHAPED = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwcm92eCJ9.c2lnbmF0dXJlLXZhbHVl"


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
            elif self.path == "/reflect":
                # Always 200, echoing whichever credential header rode in - the vehicle for proving
                # redaction across all three credential kinds without a per-kind auth gate.
                self._send(200, {**self._reflected_credentials(), "server": "nginx"})
            elif self.path == "/.well-known/security.txt":
                # A 200 whose body echoes the credential (raw token + a JWT shape) and omits the
                # RFC 9116 Contact field, so the wellknown adapter seals this body as evidence.
                body = json.dumps({"echoed_token": TOKEN, "session_jwt": JWT_SHAPED}).encode()
                self._send(200, {"Content-Type": "application/json"}, body)
            elif self.path == "/go-off":
                # Redirect to the loopback IP literal: reachable, but off scope (dangerous range).
                self._send(302, {"Location": f"http://{BIND_HOST}:{port}/steal"})
            elif self.path == "/go-off-host":
                # Redirect to an off-scope *hostname*: only the allow-list check can refuse it.
                self._send(302, {"Location": f"http://{OFF_SCOPE_NAME}:{port}/steal"})
            elif self.path == "/steal":
                self._send(200, {"server": "evil"})
            else:
                self._send(404, {})

        def _reflected_credentials(self) -> dict[str, str]:
            """Echo each credential header this request carried, one response header per kind.

            A cookie rides in as ``Cookie`` and is echoed as a ``Set-Cookie`` (the realistic
            server shape); the others are echoed under their own name. An empty result means no
            credential arrived, which the redaction assertions would then catch.
            """
            reflected: dict[str, str] = {}
            authorization = self.headers.get("Authorization")
            if authorization:
                reflected["Authorization"] = authorization
            cookie = self.headers.get("Cookie")
            if cookie:
                reflected["Set-Cookie"] = cookie
            custom = self.headers.get(CUSTOM_HEADER)
            if custom:
                reflected[CUSTOM_HEADER] = custom
            return reflected

        def _send(self, status: int, headers: dict[str, str], body: bytes = b"") -> None:
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

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


def _store_credential(
    client: TestClient,
    engagement_id: str,
    *,
    cred_type: str = "bearer",
    header_name: str | None = None,
) -> None:
    body: dict[str, Any] = {"cred_type": cred_type, "value": TOKEN}
    if header_name is not None:
        body["header_name"] = header_name
    response = client.post(f"/engagements/{engagement_id}/credential", json=body)
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


def _run_adapter_scan(database_url: str, engagement_id: str, adapter_name: str) -> None:
    """Run one adapter through the real ``run_scan`` path on a fresh session, authenticated.

    The HTTP ``/scan`` endpoint only drives ``security_headers``, whose envelope seals headers
    alone; reaching the body-redaction control needs a body-sealing adapter (``wellknown``). This
    stays no-stub - real session, real fetch, real seal, real AES persist - it just selects the
    adapter the endpoint does not expose. ``run_scan`` commits internally.
    """
    engagement_uuid = uuid.UUID(engagement_id)

    async def _run() -> None:
        engine = create_async_engine(database_url, future=True)
        maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with maker() as session:
                engagement = await session.get(Engagement, engagement_uuid)
                assert engagement is not None
                auth = await load_auth(session, engagement_uuid)
                await run_scan(session, engagement, adapter_name=adapter_name, auth=auth)
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_unauthenticated_scan_is_refused_where_authenticated_succeeds(
    client: TestClient, auth_server: AuthServer
) -> None:
    target = f"{auth_server.base_url}/needs-auth"

    # (a) PROOF. Anonymous: the server refuses with 401 and sees no credential.
    anon = _create_engagement(client, [target])
    assert client.post(f"/engagements/{anon}/scan").status_code == 201
    anon_hits = [r for r in auth_server.requests if r[0] == "/needs-auth"]
    assert anon_hits == [("/needs-auth", None)]

    auth_server.requests.clear()

    # (a) PROOF. Authenticated: 200, and the server logs the exact credential it received - the
    # proof the real token authenticated, asserted against the server, not the code's self-report.
    authed = _create_engagement(client, [target])
    _store_credential(client, authed)
    assert (
        client.post(f"/engagements/{authed}/scan", json={"authenticated": True}).status_code == 201
    )
    authed_hits = [r for r in auth_server.requests if r[0] == "/needs-auth"]
    assert authed_hits == [("/needs-auth", EXPECTED_AUTH)]


@pytest.mark.parametrize(
    ("cred_type", "header_name"),
    [
        pytest.param("bearer", None, id="bearer"),
        pytest.param("cookie", None, id="cookie"),
        pytest.param("header", CUSTOM_HEADER, id="custom-header"),
    ],
)
def test_reflected_credential_header_is_redacted_in_sealed_evidence(
    client: TestClient,
    auth_server: AuthServer,
    database_url: str,
    cred_type: str,
    header_name: str | None,
) -> None:
    # (b) PROOF. Each credential kind is presented, reflected in a response header, and must be
    # sealed redacted. The redaction marker being present also proves the credential rode (an empty
    # reflection would produce no marker).
    engagement = _create_engagement(client, [f"{auth_server.base_url}/reflect"])
    _store_credential(client, engagement, cred_type=cred_type, header_name=header_name)

    assert (
        client.post(f"/engagements/{engagement}/scan", json={"authenticated": True}).status_code
        == 201
    )

    joined = "\n".join(_sealed_evidence(database_url))
    assert joined, "the authenticated scan should have produced sealed evidence"
    # What each parametrized case pins (verified by reverting the named control and watching only
    # that case fail):
    #   - custom-header -> PROOF of the extra_sensitive extension in fetch.redact_headers /
    #     fetch_within_scope. X-Api-Key is in no base denylist, so nothing else covers it.
    #   - cookie        -> PROOF of the base "set-cookie" entry in fetch.SENSITIVE_HEADERS. The
    #     cookie rides in as `Cookie` but is reflected as `Set-Cookie`, which extra_sensitive
    #     (keyed on the injected name "cookie") does not cover.
    #   - bearer        -> regression check, not a single-line proof: `Authorization` is covered
    #     by BOTH the base denylist AND extra_sensitive (the injected header name *is*
    #     Authorization), so it survives reverting either one alone. It still fails if both go.
    assert TOKEN not in joined
    assert "<redacted:sha256:" in joined


def test_reflected_credential_in_body_is_redacted_in_sealed_evidence(
    client: TestClient, auth_server: AuthServer, database_url: str
) -> None:
    # (c) PROOF. The body-sealing wellknown adapter seals a response body that echoes the credential
    # and a JWT-shaped string; redact_body must scrub both before the seal.
    engagement = _create_engagement(client, [auth_server.base_url])
    _store_credential(client, engagement)

    _run_adapter_scan(database_url, engagement, "wellknown")

    envelopes = _sealed_evidence(database_url)
    assert envelopes, "the wellknown scan should have sealed the security.txt body as evidence"
    joined = "\n".join(envelopes)
    # PROOF. Fails if redact_body is reverted (fetch._outcome no longer wraps the body, or the
    # exact/JWT/bearer substitutions are removed): the raw token or the JWT would survive into the
    # sealed body. The marker confirms the scrub fired rather than the body simply being empty.
    assert TOKEN not in joined
    assert JWT_SHAPED not in joined
    assert "<redacted:body>" in joined


def test_credential_never_appears_in_finding_report_or_logs(
    client: TestClient,
    auth_server: AuthServer,
    database_url: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    target = f"{auth_server.base_url}/reflect"
    engagement = _create_engagement(client, [target])
    _store_credential(client, engagement)

    with caplog.at_level(logging.DEBUG):
        assert (
            client.post(f"/engagements/{engagement}/scan", json={"authenticated": True}).status_code
            == 201
        )

    # REGRESSION GUARD (not a proof). The findings API projection (FindingRead) carries no evidence
    # field, so the token cannot appear here regardless of any redaction control - this would pass
    # even if every redaction were removed. It guards against a *future* change that starts
    # projecting an evidence excerpt onto the findings response without redacting it. Making it a
    # proof would require a production change (an evidence excerpt on FindingRead), out of scope
    # here. See docs/KNOWN_ISSUES.md KI-007 for the related wire-debug caveat.
    findings = client.get(f"/engagements/{engagement}/findings")
    assert findings.status_code == 200
    assert TOKEN not in findings.text

    # REGRESSION GUARD (not a proof). The rendered report references sealed evidence by hash and
    # capture time only, never a raw excerpt, so the token cannot appear here by construction. Same
    # standing as the findings guard above: it protects a future report change, it does not prove a
    # control today.
    report = client.get(f"/engagements/{engagement}/report")
    assert report.status_code == 200
    assert TOKEN not in report.text

    # REGRESSION GUARD (not a proof). Provx's own loggers (app, provx_sdk) do not log header values
    # or bodies, so the token is absent here by construction. Scoped to Provx loggers deliberately:
    # the third-party httpcore/httpx wire-debug logger echoes the server's reflected header before
    # Provx ever redacts it, but that diagnostic is off by default in production and is not a Provx
    # control (docs/KNOWN_ISSUES.md KI-007). getMessage() excludes the structured `extra` payload,
    # which is where a future accidental credential log would most likely land - a known limit of
    # this guard, recorded here rather than implied away.
    provx_logs = "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name.startswith(("app", "provx_sdk"))
    )
    assert TOKEN not in provx_logs


def test_off_scope_redirect_to_ip_literal_is_stopped_and_carries_no_credential(
    client: TestClient, auth_server: AuthServer, database_url: str
) -> None:
    # (d) PROOF. An in-scope target that redirects to the off-scope loopback IP literal.
    engagement = _create_engagement(client, [f"{auth_server.base_url}/go-off"])
    _store_credential(client, engagement)

    assert (
        client.post(f"/engagements/{engagement}/scan", json={"authenticated": True}).status_code
        == 201
    )

    paths = [path for path, _ in auth_server.requests]
    # PROOF. The credential rode the in-scope hop but the off-scope target was never requested at
    # all, so the secret never left scope. This is the assertion only a real server can make.
    assert ("/go-off", EXPECTED_AUTH) in auth_server.requests
    assert "/steal" not in paths

    # PROOF. Fails if the redirect scope re-check (fetch_within_scope) is reverted: the sealed
    # evidence records the refusal reason, not a fetched off-scope response.
    assert any("out_of_scope_redirect" in envelope for envelope in _sealed_evidence(database_url))


def test_off_scope_redirect_to_hostname_is_stopped_by_the_allow_list(
    client: TestClient, auth_server: AuthServer, database_url: str
) -> None:
    # (d) PROOF, isolating the allow-list branch. The off-scope host is a plain hostname, not a
    # dangerous-range IP literal, so is_dangerous_host cannot be what refuses it - only the scope
    # allow-list can. This pins the redirect scope re-check to the allow-list path, which the
    # IP-literal case above cannot distinguish.
    engagement = _create_engagement(client, [f"{auth_server.base_url}/go-off-host"])
    _store_credential(client, engagement)

    assert (
        client.post(f"/engagements/{engagement}/scan", json={"authenticated": True}).status_code
        == 201
    )

    paths = [path for path, _ in auth_server.requests]
    assert ("/go-off-host", EXPECTED_AUTH) in auth_server.requests
    assert "/steal" not in paths
    # PROOF. Fails if the allow-list branch of ScopePolicy.is_in_scope is reverted: a non-dangerous
    # off-scope host would no longer be classified out of scope, so no out_of_scope_redirect reason
    # would be sealed (the scan would instead try to follow the unreachable .test host).
    assert any("out_of_scope_redirect" in envelope for envelope in _sealed_evidence(database_url))


def test_anonymous_scan_still_works_with_no_body(
    client: TestClient, auth_server: AuthServer
) -> None:
    # An old client that sends no scan body is unchanged - authenticated scanning is additive.
    engagement = _create_engagement(client, [f"{auth_server.base_url}/needs-auth"])
    response: Any = client.post(f"/engagements/{engagement}/scan")
    assert response.status_code == 201
    assert auth_server.requests[-1] == ("/needs-auth", None)
