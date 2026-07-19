# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Engagement scope enforcement (rule PX-SCOPE).

Every target is checked against the engagement's allow/deny list at the adapter boundary,
before any tool runs. Scope is never trusted from an upstream caller: the code that owns the
network call is the code that asks. An out-of-scope target is skipped and logged, never
reached - including a target arrived at part-way through a redirect chain (see
``provx_sdk.fetch``).

Matching is host-based and operates on a *canonical* host, so the same machine cannot be
addressed under a spelling the rules do not recognize. An allow rule is either an exact host
(``app.example.com``) or a leading wildcard covering a domain and its subdomains
(``*.example.com``).

Two asymmetries here are deliberate, and both fail safe:

* **Deny is subtree-aware, allow is not.** Denying ``prod.example.com`` also denies
  ``a.b.prod.example.com``. A carve-out that only covered the exact label would be a
  carve-out that silently fails to carve.
* **Dangerous address ranges are refused even when allowed.** Loopback, RFC-1918,
  link-local (including the ``169.254.169.254`` cloud-metadata address), reserved, and
  multicast targets require an explicit, logged override.

**Known residual risk:** classification applies to IP *literals*. A hostname that resolves
to a dangerous address is not caught, because resolving here would introduce a DNS-rebinding
window between the check and the request. See docs/KNOWN_ISSUES.md.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

ALLOWED_SCHEMES = frozenset({"http", "https"})


class OutOfScopeError(ValueError):
    """Raised when a caller demands a target the engagement scope does not permit."""


def canonical_host(host: str) -> str:
    """Fold a hostname to the single spelling scope rules are matched against.

    Lowercases, drops a trailing root dot, punycodes non-ASCII labels so a homograph cannot
    masquerade as an ASCII host, and reduces every IP literal form to one canonical string -
    ``2130706433``, ``0x7f.0.0.1``, and ``0177.0.0.1`` all become ``127.0.0.1``. Without
    this, a deny rule can be sidestepped by rewriting the same address a different way.
    """
    folded = host.strip().rstrip(".").lower()
    if not folded:
        return folded

    try:
        folded = folded.encode("idna").decode("ascii")
    except UnicodeError:
        # Not encodable as IDNA (e.g. an over-long label); keep the folded form and let the
        # rules fail to match rather than guessing at an intended host.
        pass

    return _canonical_ip(folded) or folded


def _unmap(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Render an address canonically, folding IPv4-mapped IPv6 to its IPv4 form.

    ``::ffff:127.0.0.1`` and ``127.0.0.1`` are the same host, so a deny rule written either
    way has to match the other.
    """
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(address)


def _canonical_ip(host: str) -> str | None:
    """Return the canonical string for any IP literal spelling, or None if not an IP."""
    try:
        return _unmap(ipaddress.ip_address(int(host)))
    except (ValueError, OverflowError):
        pass
    try:
        return _unmap(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        # Catches dotted hex/octal/short forms such as 0x7f.0.0.1, 0177.0.0.1 and 127.1.
        return _unmap(ipaddress.ip_address(socket.inet_ntoa(socket.inet_aton(host))))
    except (OSError, ValueError):
        return None


def is_dangerous_host(host: str) -> bool:
    """Whether a canonical host is an IP literal in a range Provx refuses by default.

    ``is_private`` already covers loopback and link-local (and therefore the cloud-metadata
    address); reserved and multicast are checked alongside it.
    """
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_private or address.is_reserved or address.is_multicast


def target_host(target: str) -> str:
    """Extract the canonical hostname from a target URL, without port or credentials.

    Raises OutOfScopeError if the target is not a plain http(s) URL with a host - an
    unparseable or non-web target is treated as out of scope rather than guessed at.
    """
    parts = urlsplit(target.strip())
    if parts.scheme.lower() not in ALLOWED_SCHEMES or not parts.hostname:
        raise OutOfScopeError(f"target {target!r} is not an http(s) URL with a host")
    return canonical_host(parts.hostname)


def _matches_allow(host: str, rule: str) -> bool:
    """Exact host, or ``*.domain`` covering the domain and its subdomains."""
    rule = canonical_host(rule)
    if rule.startswith("*."):
        apex = rule[2:]
        return host == apex or host.endswith(f".{apex}")
    return host == rule


def _matches_deny(host: str, rule: str) -> bool:
    """A deny rule always covers the host and everything beneath it."""
    rule = canonical_host(rule)
    apex = rule[2:] if rule.startswith("*.") else rule
    return host == apex or host.endswith(f".{apex}")


class ScopePolicy(BaseModel):
    """An engagement's allow/deny list, evaluated deny-first.

    An empty allow list permits nothing: scope is opt-in, so a misconfigured engagement
    fails closed rather than scanning the internet.
    """

    model_config = ConfigDict(extra="forbid")

    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)
    # Off by default: reaching loopback/RFC-1918/link-local turns a scanner into an SSRF
    # pivot, so permitting it is a decision an operator makes explicitly and that is logged
    # when exercised. Local lab targets are the legitimate use.
    allow_dangerous_ranges: bool = False

    def is_in_scope(self, target: str) -> bool:
        """Report whether the target may be reached under this policy."""
        try:
            host = target_host(target)
        except OutOfScopeError:
            return False

        if is_dangerous_host(host):
            if not self.allow_dangerous_ranges:
                return False
            logger.warning(
                "permitting a target in a normally-refused address range",
                extra={"host": host},
            )

        if any(_matches_deny(host, rule) for rule in self.deny):
            return False
        return any(_matches_allow(host, rule) for rule in self.allow)
