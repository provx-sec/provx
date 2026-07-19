# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Integration test for the scoped fetch boundary - **nothing is stubbed here**.

Every other test in this repo monkeypatches ``probe``, which is precisely where scope,
redirects, and evidence attribution live. That left the suite structurally blind: the
redirect scope-escape this pass fixes could not have been caught by any existing test,
because no existing test made a real request.

This one runs a real HTTP server on loopback and drives real httpx against it:

* an in-scope redirect is followed, and the seal names the host that *answered*;
* an out-of-scope redirect is refused, and the target is never contacted - asserted against
  the server's own request log, not against the code's report of itself.

The "foreign" host is ``localhost``: the same machine under a different name, so the scope
engine sees a different identity while the address stays bindable everywhere. That makes
the refusal test *stronger* than pointing at an unreachable host would - the redirect target
genuinely works, so following it would succeed and be recorded. The test proves restraint,
not inability.

Loopback is a normally-refused range, so these also exercise ``allow_dangerous_ranges``,
which is the only legitimate way to reach a local target.

Uses stdlib ``http.server`` deliberately: respx and pytest-httpserver are not installed, and
a test whose point is "do not trust the stub" should not introduce a new stub.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from provx_sdk.adapters.security_headers import SecurityHeadersAdapter
from provx_sdk.evidence import seal
from provx_sdk.fetch import OUT_OF_SCOPE_REDIRECT, OutOfScopeRequest, fetch_within_scope
from provx_sdk.scope import ScopePolicy

BIND_HOST = "127.0.0.1"
#: Same machine, different name - a distinct identity to the scope engine.
FOREIGN_NAME = "localhost"

Routes = dict[str, tuple[int, dict[str, str]]]


@dataclass
class LabServer:
    """A live local server plus the paths it was actually asked for."""

    base_url: str
    paths: list[str] = field(default_factory=list)


@pytest.fixture
def server() -> Iterator[tuple[LabServer, Routes]]:
    """A real HTTP server on loopback whose routes the test fills in."""
    routes: Routes = {}
    recorded: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - name fixed by BaseHTTPRequestHandler
            recorded.append(self.path)
            status, headers = routes.get(self.path, (404, {}))
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
    lab = LabServer(base_url=f"http://{BIND_HOST}:{port}", paths=recorded)

    yield lab, routes

    httpd.shutdown()
    httpd.server_close()


def in_scope_policy() -> ScopePolicy:
    return ScopePolicy(allow=[BIND_HOST], allow_dangerous_ranges=True)


async def test_in_scope_redirect_seals_the_host_that_actually_responded(
    server: tuple[LabServer, Routes],
) -> None:
    lab, routes = server
    routes["/start"] = (302, {"Location": "/final"})
    routes["/final"] = (200, {"server": "nginx"})

    outcome = await fetch_within_scope(f"{lab.base_url}/start", in_scope_policy())

    assert lab.paths == ["/start", "/final"]
    assert outcome.requested_url == f"{lab.base_url}/start"
    # PX-EVIDENCE: the responder, not the request.
    assert outcome.final_url == f"{lab.base_url}/final"
    assert outcome.redirect_chain == [f"{lab.base_url}/start", f"{lab.base_url}/final"]
    assert outcome.stopped_reason is None


async def test_probe_envelope_and_findings_name_the_responder(
    server: tuple[LabServer, Routes],
) -> None:
    lab, routes = server
    routes["/start"] = (302, {"Location": "/final"})
    routes["/final"] = (200, {"server": "nginx"})

    raw = await SecurityHeadersAdapter().probe(f"{lab.base_url}/start", policy=in_scope_policy())
    payload = json.loads(raw)

    assert payload["target"] == f"{lab.base_url}/start"
    assert payload["final_url"] == f"{lab.base_url}/final"
    # The seal is taken over the envelope that names the responder, so the hash cannot
    # vouch for headers a host did not send.
    assert len(seal(raw).sha256) == 64

    drafts = SecurityHeadersAdapter().parse_output(raw)
    assert drafts
    assert {draft.target for draft in drafts} == {f"{lab.base_url}/final"}


async def test_out_of_scope_redirect_is_refused_and_never_contacted(
    server: tuple[LabServer, Routes],
) -> None:
    lab, routes = server
    port = lab.base_url.rsplit(":", 1)[1]
    # Reachable, and out of scope. Following it would succeed - and be recorded.
    routes["/start"] = (302, {"Location": f"http://{FOREIGN_NAME}:{port}/steal"})
    routes["/steal"] = (200, {"server": "evil"})

    outcome = await fetch_within_scope(f"{lab.base_url}/start", in_scope_policy())

    assert outcome.stopped_reason == OUT_OF_SCOPE_REDIRECT
    assert outcome.final_url == f"{lab.base_url}/start"
    # The assertion only a real server can make: the out-of-scope URL was never requested.
    assert lab.paths == ["/start"]
    assert "/steal" not in lab.paths


async def test_redirect_into_a_dangerous_range_is_refused(
    server: tuple[LabServer, Routes],
) -> None:
    lab, routes = server
    routes["/start"] = (302, {"Location": "http://169.254.169.254/latest/meta-data/"})

    outcome = await fetch_within_scope(f"{lab.base_url}/start", in_scope_policy())

    assert outcome.stopped_reason == OUT_OF_SCOPE_REDIRECT
    assert lab.paths == ["/start"]


async def test_loopback_requires_the_dangerous_range_override(
    server: tuple[LabServer, Routes],
) -> None:
    lab, routes = server
    routes["/start"] = (200, {})

    with pytest.raises(OutOfScopeRequest):
        await fetch_within_scope(f"{lab.base_url}/start", ScopePolicy(allow=[BIND_HOST]))

    assert lab.paths == []
