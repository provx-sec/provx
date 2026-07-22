# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Unit tests for the scoped HTTP boundary (rule PX-SCOPE).

These drive ``fetch_within_scope`` through a stubbed transport so every branch of the
redirect loop is covered cheaply. The companion integration test in the backend suite
exercises the same code over real HTTP against a real server - both matter: this one for
coverage, that one because a stub can encode the same mistaken assumption as the code.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from dataclasses import field as dc_field

import httpx
import pytest
from provx_sdk import fetch
from provx_sdk.fetch import (
    MISSING_LOCATION,
    OUT_OF_SCOPE_REDIRECT,
    TOO_MANY_REDIRECTS,
    OutOfScopeRequest,
    TlsHandshake,
    _hash_tag,
    fetch_within_scope,
    probe_tls_within_scope,
    redact_cookie_value,
    redact_url,
)
from provx_sdk.scope import ScopePolicy

IN_SCOPE = ScopePolicy(allow=["*.example.com"])


def transport(routes: dict[str, httpx.Response], seen: list[str]) -> httpx.MockTransport:
    """A transport that serves `routes` and records every URL actually requested."""

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        try:
            return routes[str(request.url)]
        except KeyError:  # pragma: no cover - a miss means the test itself is wrong
            raise AssertionError(f"unexpected request to {request.url}") from None

    return httpx.MockTransport(handler)


@dataclass
class MockNet:
    """The stubbed network: what it serves, and what was actually asked for."""

    routes: dict[str, httpx.Response] = dc_field(default_factory=dict)
    seen: list[str] = dc_field(default_factory=list)


@pytest.fixture
def net(monkeypatch: pytest.MonkeyPatch) -> MockNet:
    """Route the fetch helper's client through a mock transport."""
    mock = MockNet()
    original = httpx.AsyncClient.__init__

    def init(self: httpx.AsyncClient, **kwargs: object) -> None:
        kwargs["transport"] = transport(mock.routes, mock.seen)
        original(self, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(httpx.AsyncClient, "__init__", init)
    return mock


def redirect(to: str, status: int = 302) -> httpx.Response:
    return httpx.Response(status, headers={"location": to})


def ok(**headers: str) -> httpx.Response:
    return httpx.Response(200, headers=headers)


async def test_non_redirect_response_is_returned_directly(net: MockNet) -> None:
    net.routes["https://app.example.com/"] = ok(server="nginx")

    outcome = await fetch_within_scope("https://app.example.com/", IN_SCOPE)

    assert outcome.final_url == "https://app.example.com/"
    assert outcome.status_code == 200
    assert outcome.stopped_reason is None
    assert outcome.redirect_chain == ["https://app.example.com/"]


async def test_in_scope_redirect_is_followed_and_records_the_responder(
    net: MockNet,
) -> None:
    net.routes.update(
        {
            "https://app.example.com/": redirect("https://www.example.com/final"),
            "https://www.example.com/final": ok(server="nginx"),
        }
    )

    outcome = await fetch_within_scope("https://app.example.com/", IN_SCOPE)

    assert outcome.requested_url == "https://app.example.com/"
    assert outcome.final_url == "https://www.example.com/final"
    assert outcome.stopped_reason is None
    assert outcome.redirect_chain == [
        "https://app.example.com/",
        "https://www.example.com/final",
    ]


async def test_out_of_scope_redirect_is_refused_and_never_requested(
    net: MockNet,
) -> None:
    # The whole point of the pass: the hop is evaluated BEFORE it is fetched.
    net.routes["https://app.example.com/"] = redirect("https://evil.test/steal")

    outcome = await fetch_within_scope("https://app.example.com/", IN_SCOPE)

    assert outcome.stopped_reason == OUT_OF_SCOPE_REDIRECT
    assert outcome.final_url == "https://app.example.com/"
    assert "https://evil.test/steal" not in net.seen
    assert net.seen == ["https://app.example.com/"]


async def test_redirect_into_a_dangerous_range_is_refused(net: MockNet) -> None:
    # An in-scope host redirecting at cloud metadata is the SSRF pivot this blocks.
    net.routes["https://app.example.com/"] = redirect("http://169.254.169.254/latest/meta-data/")

    outcome = await fetch_within_scope("https://app.example.com/", IN_SCOPE)

    assert outcome.stopped_reason == OUT_OF_SCOPE_REDIRECT
    assert "http://169.254.169.254/latest/meta-data/" not in net.seen


async def test_relative_redirect_is_resolved_against_the_issuing_hop(
    net: MockNet,
) -> None:
    net.routes.update(
        {
            "https://app.example.com/a/b": redirect("/c"),
            "https://app.example.com/c": ok(),
        }
    )

    outcome = await fetch_within_scope("https://app.example.com/a/b", IN_SCOPE)

    assert outcome.final_url == "https://app.example.com/c"


async def test_scheme_downgrade_to_a_non_web_scheme_is_refused(net: MockNet) -> None:
    net.routes["https://app.example.com/"] = redirect("file:///etc/passwd")

    outcome = await fetch_within_scope("https://app.example.com/", IN_SCOPE)

    assert outcome.stopped_reason == OUT_OF_SCOPE_REDIRECT


async def test_redirect_without_a_location_header_stops_the_chain(
    net: MockNet,
) -> None:
    net.routes["https://app.example.com/"] = httpx.Response(302)

    outcome = await fetch_within_scope("https://app.example.com/", IN_SCOPE)

    assert outcome.stopped_reason == MISSING_LOCATION


async def test_redirect_loop_is_bounded(net: MockNet) -> None:
    net.routes.update(
        {
            "https://app.example.com/a": redirect("https://app.example.com/b"),
            "https://app.example.com/b": redirect("https://app.example.com/a"),
        }
    )

    outcome = await fetch_within_scope("https://app.example.com/a", IN_SCOPE, max_redirects=3)

    assert outcome.stopped_reason == TOO_MANY_REDIRECTS
    assert len(net.seen) == 4


async def test_out_of_scope_start_url_makes_no_request_at_all(net: MockNet) -> None:
    with pytest.raises(OutOfScopeRequest):
        await fetch_within_scope("https://evil.test/", IN_SCOPE)

    assert net.seen == []


def test_credentials_are_stripped_before_a_url_is_logged() -> None:
    # PX-SECRETS: the redirect logger writes URLs, which can carry basic-auth material.
    assert redact_url("http://user:t0ken@example.com/p?q=1") == "http://example.com/p?q=1"
    assert redact_url("http://example.com:8080/p") == "http://example.com:8080/p"


async def test_zero_max_redirects_permits_a_direct_response(net: MockNet) -> None:
    net.routes["https://app.example.com/"] = ok(server="nginx")

    outcome = await fetch_within_scope("https://app.example.com/", IN_SCOPE, max_redirects=0)

    assert outcome.status_code == 200
    assert outcome.stopped_reason is None


async def test_zero_max_redirects_refuses_to_follow_one(net: MockNet) -> None:
    net.routes["https://app.example.com/"] = redirect("https://app.example.com/b")

    outcome = await fetch_within_scope("https://app.example.com/", IN_SCOPE, max_redirects=0)

    assert outcome.stopped_reason == TOO_MANY_REDIRECTS
    assert net.seen == ["https://app.example.com/"]


@pytest.mark.parametrize("bad", [-1, -5])
async def test_negative_max_redirects_is_a_clean_error_not_an_internal_one(
    net: MockNet, bad: int
) -> None:
    # Previously fell through the loop and raised UnboundLocalError, i.e. an internal Python
    # error escaping to the caller (rule PX-ERRORS).
    with pytest.raises(ValueError, match="max_redirects"):
        await fetch_within_scope("https://app.example.com/", IN_SCOPE, max_redirects=bad)

    assert net.seen == []


async def test_outcome_exposes_an_unfollowed_redirect_location(net: MockNet) -> None:
    # A transport check needs to see where an HTTP URL intends to upgrade without following
    # into a host that may not answer.
    net.routes["https://app.example.com/"] = redirect("https://app.example.com/secure", 301)

    outcome = await fetch_within_scope("https://app.example.com/", IN_SCOPE, max_redirects=0)

    assert outcome.redirect_location == "https://app.example.com/secure"
    assert outcome.stopped_reason == TOO_MANY_REDIRECTS


async def test_a_non_redirect_response_carries_no_redirect_location(net: MockNet) -> None:
    net.routes["https://app.example.com/"] = ok(server="nginx")

    outcome = await fetch_within_scope("https://app.example.com/", IN_SCOPE)

    assert outcome.redirect_location is None


async def test_outcome_captures_the_response_body(net: MockNet) -> None:
    # A content-inspecting passive check reads the body the boundary already fetched rather
    # than opening a second request off the one egress path (PX-EGRESS).
    net.routes["https://app.example.com/.well-known/security.txt"] = httpx.Response(
        200, text="Contact: mailto:security@example.com\n"
    )

    outcome = await fetch_within_scope("https://app.example.com/.well-known/security.txt", IN_SCOPE)

    assert "Contact: mailto:security@example.com" in outcome.body


async def test_outcome_preserves_each_set_cookie_separately_and_redacts_the_value(
    net: MockNet,
) -> None:
    # dict(headers) would comma-merge these into one unsplittable string (a comma is legal
    # inside an Expires date); the cookie check depends on them staying distinct. The boundary
    # also redacts the value while keeping the name + attributes (PX-SECRETS).
    net.routes["https://app.example.com/"] = httpx.Response(
        200,
        headers=[
            (b"set-cookie", b"sid=s3cr3t; Path=/; Secure; HttpOnly"),
            (b"set-cookie", b"theme=dark; Expires=Wed, 09 Jun 2021 10:18:14 GMT"),
        ],
    )

    outcome = await fetch_within_scope("https://app.example.com/", IN_SCOPE)

    sid, theme = outcome.set_cookies
    assert sid == f"sid={_hash_tag('s3cr3t')}; Path=/; Secure; HttpOnly"
    assert theme == f"theme={_hash_tag('dark')}; Expires=Wed, 09 Jun 2021 10:18:14 GMT"
    # The live values are gone; the attributes a cookie check reads are intact.
    assert "s3cr3t" not in sid and "Secure" in sid and "HttpOnly" in sid


async def test_outcome_redacts_sensitive_response_headers(net: MockNet) -> None:
    # A response that reflects credential material must not survive raw into evidence (PX-SECRETS).
    net.routes["https://app.example.com/"] = httpx.Response(
        200,
        headers=[
            (b"authorization", b"Bearer eyJhbGciOi.token.value"),
            (b"set-cookie", b"sid=liveTokenValue; Path=/"),
            (b"server", b"nginx"),
        ],
    )

    outcome = await fetch_within_scope("https://app.example.com/", IN_SCOPE)

    assert outcome.headers["authorization"] == _hash_tag("Bearer eyJhbGciOi.token.value")
    assert outcome.headers["set-cookie"] == _hash_tag("sid=liveTokenValue; Path=/")
    # A non-sensitive header is untouched.
    assert outcome.headers["server"] == "nginx"
    assert "liveTokenValue" not in outcome.body + repr(outcome.headers) + repr(outcome.set_cookies)


def test_redaction_helpers_are_deterministic_and_value_free() -> None:
    # Same secret -> same tag (evidentiary integrity); the secret itself never appears.
    assert _hash_tag("t0ken") == _hash_tag("t0ken")
    assert "t0ken" not in _hash_tag("t0ken")
    # The value in the name=value head is redacted; every attribute after the first ';' is kept.
    redacted = redact_cookie_value("sid=abc; Path=/; SameSite=Lax")
    assert redacted == f"sid={_hash_tag('abc')}; Path=/; SameSite=Lax"
    # A first segment with no '=' is not a name=value pair, so there is nothing to redact.
    assert redact_cookie_value("=only; Path=/") == f"={_hash_tag('only')}; Path=/"
    assert redact_cookie_value("bareword") == "bareword"


# --- probe_tls_within_scope: the second scope-checked egress path (PX-EGRESS/PX-SCOPE) ----


async def test_tls_probe_refuses_an_out_of_scope_host(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []
    monkeypatch.setattr(fetch, "_tls_handshake", lambda *args: calls.append(args))

    with pytest.raises(OutOfScopeRequest):
        await probe_tls_within_scope("https://evil.test/", IN_SCOPE)

    assert calls == []


async def test_tls_probe_parses_host_and_defaults_to_port_443(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    def stub(host: str, port: int, timeout: float) -> TlsHandshake:
        seen.update(host=host, port=port, timeout=timeout)
        return TlsHandshake(host=host, port=port, protocol="TLSv1.3")

    monkeypatch.setattr(fetch, "_tls_handshake", stub)

    result = await probe_tls_within_scope("https://app.example.com/x", IN_SCOPE, timeout=4.0)

    assert seen == {"host": "app.example.com", "port": 443, "timeout": 4.0}
    assert result.protocol == "TLSv1.3"


async def test_tls_probe_honours_an_explicit_port(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def stub(host: str, port: int, timeout: float) -> TlsHandshake:
        seen["port"] = port
        return TlsHandshake(host=host, port=port)

    monkeypatch.setattr(fetch, "_tls_handshake", stub)

    await probe_tls_within_scope("https://app.example.com:8443/", IN_SCOPE)

    assert seen["port"] == 8443


def test_certificate_verification_codes_map_to_stable_labels() -> None:
    exc = ssl.SSLCertVerificationError()
    exc.verify_code = 10
    assert fetch._classify_cert_error(exc) == "expired"
    exc.verify_code = 18
    assert fetch._classify_cert_error(exc) == "self_signed"
    exc.verify_code = 99
    assert fetch._classify_cert_error(exc) == "invalid"
