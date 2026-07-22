# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
The scoped HTTP boundary (rules PX-SCOPE, PX-EVIDENCE).

Every adapter that speaks HTTP goes through :func:`fetch_within_scope`, so there is exactly
one place where the network is touched and exactly one place where scope is enforced. That
is what makes the control auditable: reviewing this module reviews the whole platform's
egress.

Redirects are followed manually, never by the client. An HTTP client that follows redirects
itself would carry the request off-scope *after* the gate passed - the check would apply to
the URL an operator authorized while the request landed somewhere else entirely. Here each
hop is re-checked before it is requested, and a hop that leaves scope is refused rather than
followed.

The outcome records the URL that actually responded. Evidence is sealed over that, not over
what was asked for, so a hash never attests to a host that did not send the bytes.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from provx_sdk.scope import ScopePolicy

logger = logging.getLogger(__name__)

DEFAULT_MAX_REDIRECTS = 5

#: Why a chain stopped early. None means it ended at a non-redirect response.
OUT_OF_SCOPE_REDIRECT = "out_of_scope_redirect"
TOO_MANY_REDIRECTS = "too_many_redirects"
MISSING_LOCATION = "missing_location"


def redact_url(url: str) -> str:
    """Strip any embedded credentials from a URL before it is logged (rule PX-SECRETS).

    ``http://user:token@host/path`` becomes ``http://host/path``.
    """
    parts = urlsplit(url)
    if not parts.hostname:
        return url
    netloc = parts.hostname
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


#: Headers whose value is credential or session material and must never be logged, sealed, or
#: stored raw (rule PX-SECRETS). Matched case-insensitively.
SENSITIVE_HEADERS: frozenset[str] = frozenset(
    {"authorization", "proxy-authorization", "cookie", "set-cookie"}
)


def _hash_tag(value: str) -> str:
    """A stable fingerprint that stands in for a secret.

    Keeping a SHA-256 of the original value preserves evidentiary integrity - two captures of the
    same token still match, and a stored hash can be checked against a suspected value - without
    retaining the secret itself (rules PX-SECRETS, PX-EVIDENCE).
    """
    return f"<redacted:sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}>"


def redact_cookie_value(set_cookie: str) -> str:
    """Redact only the cookie's value, keeping its name and attributes.

    ``sid=SECRET; Path=/; Secure`` becomes ``sid=<redacted:sha256:...>; Path=/; Secure``. The name
    and attributes are what a cookie-hygiene check needs (Secure/HttpOnly/SameSite); the value is
    live session material and is replaced with a fingerprint (rule PX-SECRETS). An input with no
    ``name=value`` head (attribute-only or malformed) is returned unchanged - there is nothing that
    looks like a value to remove.
    """
    head, sep, rest = set_cookie.partition(";")
    name, eq, value = head.partition("=")
    if not eq:
        return set_cookie
    return f"{name}={_hash_tag(value.strip())}{sep}{rest}"


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Replace the values of sensitive headers with a fingerprint before they leave (PX-SECRETS).

    ``set-cookie`` in this flattened dict is the comma-joined form and is not parsed for attributes
    by any adapter (that reads :attr:`FetchOutcome.set_cookies` instead), so its value is redacted
    whole like any other sensitive header.
    """
    return {
        name: (_hash_tag(value) if name.lower() in SENSITIVE_HEADERS else value)
        for name, value in headers.items()
    }


class OutOfScopeRequest(RuntimeError):
    """Raised when a fetch is attempted against a target the policy does not permit."""

    def __init__(self, url: str) -> None:
        super().__init__(f"target {redact_url(url)!r} is not in engagement scope")
        self.url = url


@dataclass(frozen=True)
class FetchOutcome:
    """The result of a scope-enforced fetch."""

    #: The URL originally requested.
    requested_url: str
    #: The URL that actually produced the returned response.
    final_url: str
    status_code: int
    headers: dict[str, str]
    #: Every URL requested, in order, starting with ``requested_url``.
    redirect_chain: list[str] = field(default_factory=list)
    #: Set when the chain was cut short; None when it ended naturally.
    stopped_reason: str | None = None
    #: The Location the responding hop pointed at, even when it was not followed. Lets a
    #: caller see a redirect's intent (e.g. an HTTP->HTTPS upgrade) without chasing it.
    redirect_location: str | None = None
    #: The decoded response body of the responding hop. A passive check that inspects content
    #: (e.g. parsing /.well-known/security.txt) needs the bytes the boundary already read;
    #: keeping it here avoids a second, unaudited request off the one egress path (PX-EGRESS).
    body: str = ""
    #: Every ``Set-Cookie`` header, one entry per cookie. ``headers`` flattens duplicate names
    #: into a single comma-joined string, which is lossy and unsafe for cookies (a comma is
    #: legal inside an ``Expires`` date), so the raw list is preserved for a cookie check.
    set_cookies: list[str] = field(default_factory=list)


def _is_redirect(status_code: int) -> bool:
    return status_code in (301, 302, 303, 307, 308)


async def fetch_within_scope(
    url: str,
    policy: ScopePolicy,
    *,
    timeout: float = 10.0,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
) -> FetchOutcome:
    """GET a URL, re-checking engagement scope before every hop.

    Two distinct refusals, deliberately shaped differently:

    * The **starting** URL being out of scope raises :class:`OutOfScopeRequest`. Asking to
      fetch something the policy forbids is a caller error, and returning a normal-looking
      outcome for it would let the mistake pass unnoticed.
    * A **redirect** leaving scope is not a caller error - it is the remote host's doing, and
      the response already in hand is still legitimate evidence. That returns normally with
      ``stopped_reason`` set to :data:`OUT_OF_SCOPE_REDIRECT`, and the off-scope URL is never
      requested.

    ``max_redirects`` bounds the chain; ``0`` permits no redirects at all. Negative values are
    rejected rather than silently treated as zero.
    """
    if max_redirects < 0:
        raise ValueError(f"max_redirects must be >= 0, got {max_redirects}")

    if not policy.is_in_scope(url):
        logger.warning("refusing an out-of-scope target", extra={"url": redact_url(url)})
        raise OutOfScopeRequest(url)

    chain: list[str] = []
    current = url

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        # The final hop is fetched, then rejected for exceeding the budget, so the loop runs
        # max_redirects + 1 times. `response` is therefore always bound after it.
        for _ in range(max_redirects + 1):
            chain.append(current)
            response = await client.get(current)

            if not _is_redirect(response.status_code):
                return _outcome(url, current, response, chain, None)

            location = response.headers.get("location")
            if not location:
                return _outcome(url, current, response, chain, MISSING_LOCATION)

            # Relative redirects are resolved against the hop that issued them.
            candidate = urljoin(current, location)
            if not policy.is_in_scope(candidate):
                logger.warning(
                    "refusing an out-of-scope redirect",
                    extra={"from_url": redact_url(current), "to_url": redact_url(candidate)},
                )
                return _outcome(url, current, response, chain, OUT_OF_SCOPE_REDIRECT)

            current = candidate

        return _outcome(url, current, response, chain, TOO_MANY_REDIRECTS)


def _outcome(
    requested: str,
    final: str,
    response: httpx.Response,
    chain: list[str],
    reason: str | None,
) -> FetchOutcome:
    # Redaction happens here, at the one egress boundary, so every downstream consumer - the
    # adapters' envelopes, the evidence seal, and the logs - only ever sees redacted material
    # (rules PX-SECRETS, PX-EGRESS). set_cookies keeps each cookie's name and attributes for the
    # cookie-hygiene check; only the value is removed.
    return FetchOutcome(
        requested_url=requested,
        final_url=final,
        status_code=response.status_code,
        headers=redact_headers(dict(response.headers)),
        redirect_chain=list(chain),
        stopped_reason=reason,
        redirect_location=response.headers.get("location"),
        body=response.text,
        set_cookies=[redact_cookie_value(c) for c in response.headers.get_list("set-cookie")],
    )


#: OpenSSL verification codes we translate into a stable, tool-agnostic label. 10 is an
#: expired certificate; 18/19 are self-signed (leaf and in-chain).
_CERT_EXPIRED_CODE = 10
_CERT_SELF_SIGNED_CODES = frozenset({18, 19})
DEFAULT_TLS_PORT = 443


@dataclass(frozen=True)
class TlsHandshake:
    """The result of a scope-enforced TLS handshake, normalized for a transport check.

    The verdict is reached here, at capture time, not by the parser: ``cert_error`` records
    what OpenSSL made of the certificate while the system clock was live, so parsing stays
    pure and deterministic (rule PX-DETERMINISM). ``error`` is set when the connection or
    handshake never completed, in which case the certificate fields are all None.
    """

    host: str
    port: int
    protocol: str | None = None
    cipher: str | None = None
    #: Certificate expiry as epoch seconds, when the handshake verified successfully.
    not_after_epoch: float | None = None
    #: "expired" | "self_signed" | "invalid" when verification failed; None when it passed.
    cert_error: str | None = None
    #: The exception class name when the connection/handshake failed outright.
    error: str | None = None


def _classify_cert_error(exc: ssl.SSLCertVerificationError) -> str:
    code = exc.verify_code
    if code == _CERT_EXPIRED_CODE:
        return "expired"
    if code in _CERT_SELF_SIGNED_CODES:
        return "self_signed"
    return "invalid"


def _tls_handshake(host: str, port: int, timeout: float) -> TlsHandshake:
    """Open a verifying TLS connection and read back the transport's hygiene facts.

    Read-only by construction (rule PX-PASSIVE): it completes a handshake and inspects the
    peer certificate, never sending an application-layer byte. A verification failure is data,
    not an exception to leak - it is captured as ``cert_error`` (rule PX-ERRORS).
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert() or {}
                not_after = cert.get("notAfter")
                cipher = ssock.cipher()
                return TlsHandshake(
                    host=host,
                    port=port,
                    protocol=ssock.version(),
                    cipher=cipher[0] if cipher else None,
                    not_after_epoch=(
                        float(ssl.cert_time_to_seconds(not_after))
                        if isinstance(not_after, str)
                        else None
                    ),
                )
    except ssl.SSLCertVerificationError as exc:
        return TlsHandshake(host=host, port=port, cert_error=_classify_cert_error(exc))
    except (OSError, ssl.SSLError) as exc:
        return TlsHandshake(host=host, port=port, error=type(exc).__name__)


async def probe_tls_within_scope(
    url: str,
    policy: ScopePolicy,
    *,
    timeout: float = 10.0,
) -> TlsHandshake:
    """Complete a TLS handshake to ``url``'s host, re-checking scope before the socket opens.

    The HTTP boundary above cannot carry handshake facts - a certificate's validity, the
    negotiated protocol and cipher live below the response object. Rather than let an adapter
    open its own socket (which would be a second, unaudited egress path, PX-EGRESS), this
    keeps the socket here, next to ``fetch_within_scope``, behind the same scope gate
    (PX-SCOPE). The blocking handshake runs in a worker thread so callers stay async.
    """
    if not policy.is_in_scope(url):
        logger.warning("refusing an out-of-scope TLS target", extra={"url": redact_url(url)})
        raise OutOfScopeRequest(url)

    parts = urlsplit(url)
    host = parts.hostname
    if host is None:
        raise ValueError(f"cannot probe TLS for a URL without a host: {redact_url(url)!r}")
    port = parts.port or DEFAULT_TLS_PORT
    return await asyncio.to_thread(_tls_handshake, host, port, timeout)
