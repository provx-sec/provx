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

import logging
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
    return FetchOutcome(
        requested_url=requested,
        final_url=final,
        status_code=response.status_code,
        headers=dict(response.headers),
        redirect_chain=list(chain),
        stopped_reason=reason,
    )
